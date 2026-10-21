//! Affinity-weight sensitivity sweep (driven by `bench/sweep.sh`).
//!
//! The antigen's six group weights (`AntigenConfig::w_*`) are engineered,
//! all 1.0 by default. The fair critique is "you hand-tuned them until the
//! demo worked". This sweep answers it with numbers: for each perturbed
//! weight vector it retrains the whole immune pipeline from scratch (self
//! model → negative selection → clonal maturation) and re-measures the
//! held-out detection rate and benign false positives, then reports how
//! far the outcome moves from the default weights.
//!
//! Every file is analyzed once, in memory; only the antigen projection and
//! the training depend on the weights.
//!
//! Usage:
//!   cargo run --release -p agat-engine --example sweep -- CORPUS [--random N] [--json]
//!
//! CORPUS must contain `train-benign/`, `train-family/`, `heldout-family/`
//! and `heldout-benign/`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use agat_antigen::{Antigen, AntigenConfig};
use agat_core::{SampleId, Severity};
use agat_engine::{analyze_bytes, antigen_config, ImmuneModel};
use agat_immune::{generate_repertoire, mature, ClonalConfig, MemoryPool, NsaConfig, SelfModel};
use anyhow::{bail, Context, Result};
use serde::Serialize;

const FAMILY: &str = "family";
const WEIGHTS: [&str; 6] = ["opcode", "block", "struct", "entropy", "style", "imports"];

type Features = HashMap<String, serde_json::Value>;

struct Sample {
    id: SampleId,
    features: Features,
}

fn load_dir(dir: &Path) -> Result<Vec<Sample>> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let bytes = std::fs::read(&p)?;
        let (sample, features) = analyze_bytes(&bytes, None)?;
        out.push(Sample {
            id: sample.id,
            features,
        });
    }
    Ok(out)
}

fn get(cfg: &AntigenConfig, i: usize) -> f64 {
    [
        cfg.w_opcode,
        cfg.w_block,
        cfg.w_struct,
        cfg.w_entropy,
        cfg.w_style,
        cfg.w_imports,
    ][i]
}

fn set(cfg: &mut AntigenConfig, i: usize, v: f64) {
    match i {
        0 => cfg.w_opcode = v,
        1 => cfg.w_block = v,
        2 => cfg.w_struct = v,
        3 => cfg.w_entropy = v,
        4 => cfg.w_style = v,
        _ => cfg.w_imports = v,
    }
}

/// Train the full immune pipeline under `cfg`.
fn train(cfg: &AntigenConfig, benign: &[Sample], family: &[Sample]) -> ImmuneModel {
    let antigens: Vec<(String, Antigen)> = benign
        .iter()
        .map(|s| (s.id.to_hex(), Antigen::from_feature_map(&s.features, cfg)))
        .collect();
    let labelled: Vec<(&str, &Antigen)> = antigens.iter().map(|(id, a)| (id.as_str(), a)).collect();
    let self_model = SelfModel::build(&labelled, 3);
    let nsa = NsaConfig {
        seed: 1,
        ..NsaConfig::default()
    };
    let repertoire = generate_repertoire(&self_model, self_model.dim, &nsa);
    let mut memory = MemoryPool::new(self_model.dim);
    for s in family {
        let a = Antigen::from_feature_map(&s.features, cfg);
        mature(
            &a,
            FAMILY,
            &mut memory,
            Some(&repertoire),
            &ClonalConfig::default(),
        );
    }
    ImmuneModel::from_parts(repertoire, &memory, Some(self_model)).with_antigen_config(*cfg)
}

#[derive(Serialize)]
struct Outcome {
    label: String,
    weights: [f64; 6],
    detection_rate: f64,
    fp_nonclean_rate: f64,
    fp_malicious_rate: f64,
    fp_family_rate: f64,
    /// Fraction of all held-out samples whose severity differs from the
    /// default-weight run.
    flipped_vs_default: f64,
    #[serde(skip)]
    severities: Vec<Severity>,
}

fn evaluate(
    label: String,
    cfg: &AntigenConfig,
    c: &Corpus,
    baseline: Option<&[Severity]>,
) -> Result<Outcome> {
    let model = train(cfg, &c.train_benign, &c.train_family);
    let mut severities = Vec::new();
    let mut detected = 0;
    for s in &c.heldout_family {
        let r = model.scan(&s.id, None, &s.features)?;
        if r.recognition.recognized && r.recognition.family.as_deref() == Some(FAMILY) {
            detected += 1;
        }
        severities.push(r.severity());
    }
    let (mut nonclean, mut malicious, mut fam) = (0, 0, 0);
    for s in &c.heldout_benign {
        let r = model.scan(&s.id, None, &s.features)?;
        nonclean += (r.severity() != Severity::Clean) as usize;
        malicious += (r.severity() == Severity::Malicious) as usize;
        fam += (r.recognition.family.as_deref() == Some(FAMILY)) as usize;
        severities.push(r.severity());
    }
    let nb = c.heldout_benign.len().max(1) as f64;
    let flipped = baseline.map_or(0.0, |b| {
        b.iter().zip(&severities).filter(|(a, b)| a != b).count() as f64 / b.len().max(1) as f64
    });
    let mut weights = [0.0; 6];
    for (i, w) in weights.iter_mut().enumerate() {
        *w = get(cfg, i);
    }
    Ok(Outcome {
        label,
        weights,
        detection_rate: detected as f64 / c.heldout_family.len().max(1) as f64,
        fp_nonclean_rate: nonclean as f64 / nb,
        fp_malicious_rate: malicious as f64 / nb,
        fp_family_rate: fam as f64 / nb,
        flipped_vs_default: flipped,
        severities,
    })
}

struct Corpus {
    train_benign: Vec<Sample>,
    train_family: Vec<Sample>,
    heldout_family: Vec<Sample>,
    heldout_benign: Vec<Sample>,
}

/// Deterministic xorshift for the random perturbations (no extra deps).
fn next(state: &mut u64) -> f64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 11) as f64 / (1u64 << 53) as f64
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut corpus_dir = None;
    let mut random = 20usize;
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--random" => random = it.next().context("--random N")?.parse()?,
            "--json" => json = true,
            other if corpus_dir.is_none() => corpus_dir = Some(PathBuf::from(other)),
            other => bail!("unexpected argument {other}"),
        }
    }
    let dir = corpus_dir.context("usage: sweep CORPUS [--random N] [--json]")?;
    let c = Corpus {
        train_benign: load_dir(&dir.join("train-benign"))?,
        train_family: load_dir(&dir.join("train-family"))?,
        heldout_family: load_dir(&dir.join("heldout-family"))?,
        heldout_benign: load_dir(&dir.join("heldout-benign"))?,
    };

    let base_cfg = antigen_config();
    let base = evaluate("default".into(), &base_cfg, &c, None)?;
    let mut runs = vec![];

    // One weight at a time, halved and doubled.
    for i in 0..WEIGHTS.len() {
        for factor in [0.5, 2.0] {
            let mut cfg = base_cfg;
            set(&mut cfg, i, get(&base_cfg, i) * factor);
            runs.push(evaluate(
                format!("{} x{factor}", WEIGHTS[i]),
                &cfg,
                &c,
                Some(&base.severities),
            )?);
        }
    }
    // All six at once, each log-uniform in [0.5, 2].
    let mut state = 0x5EED_1234_ABCD_0001u64;
    for k in 0..random {
        let mut cfg = base_cfg;
        for i in 0..WEIGHTS.len() {
            set(
                &mut cfg,
                i,
                get(&base_cfg, i) * 2f64.powf(next(&mut state) * 2.0 - 1.0),
            );
        }
        runs.push(evaluate(
            format!("random #{}", k + 1),
            &cfg,
            &c,
            Some(&base.severities),
        )?);
    }

    let min = |f: fn(&Outcome) -> f64| runs.iter().map(f).fold(f64::INFINITY, f64::min);
    let max = |f: fn(&Outcome) -> f64| runs.iter().map(f).fold(f64::NEG_INFINITY, f64::max);
    let mean = |f: fn(&Outcome) -> f64| runs.iter().map(f).sum::<f64>() / runs.len().max(1) as f64;

    if json {
        let report = serde_json::json!({
            "corpus": {
                "train_benign": c.train_benign.len(), "train_family": c.train_family.len(),
                "heldout_family": c.heldout_family.len(), "heldout_benign": c.heldout_benign.len(),
            },
            "default": base,
            "perturbed": runs,
            "summary": {
                "detection_rate": {"min": min(|o| o.detection_rate), "max": max(|o| o.detection_rate)},
                "fp_malicious_rate": {"min": min(|o| o.fp_malicious_rate), "max": max(|o| o.fp_malicious_rate)},
                "fp_nonclean_rate": {"min": min(|o| o.fp_nonclean_rate), "max": max(|o| o.fp_nonclean_rate)},
                "flipped_vs_default": {"mean": mean(|o| o.flipped_vs_default), "max": max(|o| o.flipped_vs_default)},
            }
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!(
        "corpus: self {} benign · family trained on {} · held out {} family + {} benign",
        c.train_benign.len(),
        c.train_family.len(),
        c.heldout_family.len(),
        c.heldout_benign.len()
    );
    println!(
        "\n{:<16} {:>8} {:>10} {:>10} {:>9} {:>9}",
        "weights", "detect", "FP any", "FP malic", "FP fam", "flipped"
    );
    let row = |o: &Outcome| {
        println!(
            "{:<16} {:>7.1}% {:>9.1}% {:>9.1}% {:>8.1}% {:>8.1}%",
            o.label,
            o.detection_rate * 100.0,
            o.fp_nonclean_rate * 100.0,
            o.fp_malicious_rate * 100.0,
            o.fp_family_rate * 100.0,
            o.flipped_vs_default * 100.0
        )
    };
    row(&base);
    for o in &runs {
        row(o);
    }
    println!(
        "\nacross {} perturbed weightings (each weight x0.5..x2):",
        runs.len()
    );
    println!(
        "  detection     {:.1}% .. {:.1}%   (default {:.1}%)",
        min(|o| o.detection_rate) * 100.0,
        max(|o| o.detection_rate) * 100.0,
        base.detection_rate * 100.0
    );
    println!(
        "  FP malicious  {:.1}% .. {:.1}%   (default {:.1}%)",
        min(|o| o.fp_malicious_rate) * 100.0,
        max(|o| o.fp_malicious_rate) * 100.0,
        base.fp_malicious_rate * 100.0
    );
    println!(
        "  FP non-clean  {:.1}% .. {:.1}%   (default {:.1}%)",
        min(|o| o.fp_nonclean_rate) * 100.0,
        max(|o| o.fp_nonclean_rate) * 100.0,
        base.fp_nonclean_rate * 100.0
    );
    println!(
        "  verdicts changed vs default: mean {:.1}%, worst {:.1}%",
        mean(|o| o.flipped_vs_default) * 100.0,
        max(|o| o.flipped_vs_default) * 100.0
    );
    Ok(())
}
