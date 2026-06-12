//! Artificial Immune System commands: build the self-model, generate
//! the detector repertoire by negative selection, mature it via clonal
//! selection, and recognize unknown samples (recognition + danger).
//!
//! All antigens are built with the default [`AntigenConfig`] so the
//! self-model, repertoire, memory, and queried samples share one metric
//! space and dimensionality.

use agat_ai::AiFeatures;
use agat_antigen::{Antigen, AntigenConfig};
use agat_core::SampleId;
use agat_immune::danger::{assess, signals_from_features, DangerAssessment, SignalClass};
use agat_immune::{
    generate_repertoire, mature, recognize, DangerConfig, MemoryPool, NsaConfig, Recognition,
    Repertoire, SelfModel,
};
use agat_poly::PolyFeatures;
use agat_static::StaticFeatures;
use agat_store::Store;
use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use std::collections::HashMap;

/// Single named slot for each persisted immune structure.
const SLOT: &str = "default";

fn antigen_config() -> AntigenConfig {
    AntigenConfig::default()
}

// ---- loading / persistence helpers --------------------------------

fn feature_map(store: &Store, id: &SampleId) -> Result<HashMap<String, serde_json::Value>> {
    let mut map = HashMap::new();
    for name in ["static", "disasm", "poly", "meta", "ai"] {
        if let Some(rec) = store.get_features(id, name)? {
            map.insert(name.to_string(), rec.features);
        }
    }
    Ok(map)
}

fn typed<T: DeserializeOwned>(map: &HashMap<String, serde_json::Value>, name: &str) -> Option<T> {
    map.get(name)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

fn antigen_from_map(map: &HashMap<String, serde_json::Value>) -> Antigen {
    Antigen::from_feature_map(map, &antigen_config())
}

fn load_self_model(store: &Store) -> Result<Option<SelfModel>> {
    match store.get_self_model(SLOT)? {
        Some(j) => Ok(Some(serde_json::from_str(&j).context("decoding self-model")?)),
        None => Ok(None),
    }
}

fn load_repertoire(store: &Store) -> Result<Option<Repertoire>> {
    match store.get_repertoire(SLOT)? {
        Some(j) => Ok(Some(serde_json::from_str(&j).context("decoding repertoire")?)),
        None => Ok(None),
    }
}

fn load_memory(store: &Store) -> Result<MemoryPool> {
    match store.get_memory(SLOT)? {
        Some(j) => Ok(serde_json::from_str(&j).context("decoding memory pool")?),
        None => Ok(MemoryPool::default()),
    }
}

// ---- commands ------------------------------------------------------

/// `agat self build [ids...] [--k K]` — model the benign region of
/// signature space. With no ids, every sample tagged/family "benign" is
/// used.
pub fn cmd_self_build(inputs: Vec<String>, k: usize, store: &Store) -> Result<()> {
    let ids: Vec<SampleId> = if inputs.is_empty() {
        let benign: Vec<SampleId> = store
            .list_samples()?
            .into_iter()
            .filter(|s| {
                s.sample.metadata.family.as_deref() == Some("benign")
                    || s.sample.metadata.tags.iter().any(|t| t == "benign")
            })
            .map(|s| s.sample.id)
            .collect();
        if benign.is_empty() {
            bail!(
                "no benign samples given and none tagged 'benign'.\n\
                 pass ids explicitly: `agat self build <id> <id> ...`, or tag samples as benign."
            );
        }
        benign
    } else {
        inputs
            .iter()
            .map(|s| crate::resolve_sample_id(s, store))
            .collect::<Result<_>>()?
    };

    // Build antigens, keeping ownership so we can borrow for the model.
    let mut owned: Vec<(String, Antigen)> = Vec::new();
    for id in &ids {
        let map = feature_map(store, id)?;
        if map.is_empty() {
            eprintln!(
                "  skipping {} — no analyzer features (run `agat analyze` first)",
                id.short()
            );
            continue;
        }
        owned.push((id.to_hex(), antigen_from_map(&map)));
    }
    if owned.is_empty() {
        bail!("no usable benign antigens — analyze the benign samples first");
    }

    let labelled: Vec<(&str, &Antigen)> =
        owned.iter().map(|(id, a)| (id.as_str(), a)).collect();
    let model = SelfModel::build(&labelled, k);
    store.put_self_model(SLOT, &serde_json::to_string(&model)?)?;

    println!(
        "built self-model: {} benign antigen{} · dim {} · k {} · mean self-radius {:.3}",
        model.points.len(),
        if model.points.len() == 1 { "" } else { "s" },
        model.dim,
        model.k,
        model.mean_radius
    );
    println!("saved as self-model '{SLOT}'.");
    Ok(())
}

/// `agat repertoire generate` — negative selection against the self-model.
pub fn cmd_repertoire_generate(
    max_detectors: Option<usize>,
    tolerance: Option<f64>,
    coverage: Option<f64>,
    seed: Option<u64>,
    store: &Store,
) -> Result<()> {
    let self_model = load_self_model(store)?
        .context("no self-model yet — run `agat self build` first")?;

    let mut cfg = NsaConfig::default();
    if let Some(m) = max_detectors {
        cfg.max_detectors = m;
    }
    if let Some(t) = tolerance {
        cfg.self_tolerance = t;
    }
    if let Some(c) = coverage {
        cfg.coverage = c;
    }
    if let Some(s) = seed {
        cfg.seed = s;
    }

    let repertoire = generate_repertoire(&self_model, self_model.dim, &cfg);
    store.put_repertoire(SLOT, &serde_json::to_string(&repertoire)?)?;

    let (naive, matured) = repertoire.composition();
    println!(
        "negative selection: {} detector{} generated (dim {})",
        repertoire.len(),
        if repertoire.len() == 1 { "" } else { "s" },
        repertoire.dim
    );
    println!(
        "  self-tolerance {:.3} · target coverage {:.2} · seed {:#x}",
        cfg.self_tolerance, cfg.coverage, cfg.seed
    );
    println!("  composition: {naive} naive (anomaly) · {matured} matured (family)");
    println!("saved as repertoire '{SLOT}'.");
    Ok(())
}

/// `agat mature <id> --family <name>` — clonal selection onto a
/// confirmed family variant.
pub fn cmd_mature(input: String, family: String, store: &Store) -> Result<()> {
    let id = crate::resolve_sample_id(&input, store)?;
    let map = feature_map(store, &id)?;
    if map.is_empty() {
        bail!("sample {} has no analyzer features — run `agat analyze` first", id.short());
    }
    let antigen = antigen_from_map(&map);

    let mut memory = load_memory(store)?;
    if memory.dim == 0 {
        memory.dim = antigen.signature.len();
    }
    let repertoire = load_repertoire(store)?;

    let cfg = agat_immune::ClonalConfig::default();
    let m = mature(&antigen, &family, &mut memory, repertoire.as_ref(), &cfg);
    store.put_memory(SLOT, &serde_json::to_string(&memory)?)?;

    println!("clonal selection on {} → family '{}'", id.short(), m.family);
    println!(
        "  {} memory cell for the family ({} variant{} incorporated)",
        if m.new_cell { "formed a new" } else { "reinforced the" },
        m.variants,
        if m.variants == 1 { "" } else { "s" }
    );
    println!(
        "  covering radius {:.3} · affinity-maturation residual {:.3} · {} family cell{}",
        m.radius,
        m.matured_distance,
        m.family_cells,
        if m.family_cells == 1 { "" } else { "s" }
    );
    Ok(())
}

/// `agat recognize <id>` — present the sample's antigen to the immune
/// system: recognition (non-self / family / affinity) and danger.
pub fn cmd_recognize(input: String, store: &Store) -> Result<()> {
    let id = crate::resolve_sample_id(&input, store)?;
    let map = feature_map(store, &id)?;
    if map.is_empty() {
        bail!("sample {} has no analyzer features — run `agat analyze` first", id.short());
    }
    let antigen = antigen_from_map(&map);

    let repertoire = load_repertoire(store)?
        .context("no repertoire yet — run `agat self build` then `agat repertoire generate`")?;
    let memory = load_memory(store)?;
    let self_model = load_self_model(store)?;

    // Merge the innate (negative-selection) repertoire with the learned
    // memory cells for a single recognition pass.
    let mut detectors = repertoire.detectors.clone();
    detectors.extend(memory.detectors());
    let combined = Repertoire { dim: repertoire.dim, detectors };

    let recognition = recognize(&antigen, &combined, self_model.as_ref());

    // Danger layer over the same sample's real harm signals.
    let static_features: Option<StaticFeatures> = typed(&map, "static");
    let poly: Option<PolyFeatures> = typed(&map, "poly");
    let ai: Option<AiFeatures> = typed(&map, "ai");
    let signals = signals_from_features(
        static_features.as_ref(),
        poly.as_ref(),
        ai.as_ref(),
        recognition.self_surface_distance,
    );
    let danger = assess(&signals, &DangerConfig::default());

    print_report(&id, &antigen, &recognition, &danger, memory.families().len());
    Ok(())
}

fn print_report(
    id: &SampleId,
    antigen: &Antigen,
    rec: &Recognition,
    danger: &DangerAssessment,
    known_families: usize,
) {
    println!("immune assessment — {}", id.short());

    // --- antigen ---------------------------------------------------
    println!("\nantigen");
    println!(
        "  signature dim {} · {} canonical block{}",
        antigen.dim(),
        antigen.block_tokens.len(),
        if antigen.block_tokens.len() == 1 { "" } else { "s" }
    );
    println!(
        "  cfg fingerprint   {}",
        antigen.cfg_fingerprint.as_deref().unwrap_or("-")
    );
    println!(
        "  plaintext finger  {}",
        antigen.plaintext_fingerprint.as_deref().unwrap_or("-")
    );

    // --- recognition axis ------------------------------------------
    println!("\nrecognition  ({known_families} known famil{})", if known_families == 1 { "y" } else { "ies" });
    println!("  verdict      {}", rec.verdict());
    println!("  family       {}", rec.family.as_deref().unwrap_or("-"));
    let aff = rec.best.as_ref().map(|b| b.affinity).unwrap_or(0.0);
    println!("  affinity     {:.3}", aff);
    println!("  bound detectors {}", rec.bound_count);
    println!(
        "  secondary response {}",
        if rec.from_memory { "yes (memory cell)" } else { "no" }
    );
    if let Some(d) = rec.self_surface_distance {
        println!("  distance from self  {:+.3}", d);
    }

    // --- danger axis -----------------------------------------------
    println!("\ndanger  (DCA-style signal fusion)");
    println!(
        "  score {:.3}  ·  context {}  ·  P {:.2} / D {:.2} / S {:.2}",
        danger.danger_score,
        danger.context.label(),
        danger.signals.pamp,
        danger.signals.danger,
        danger.signals.safe
    );
    if !danger.signals.contributors.is_empty() {
        let mut cs = danger.signals.contributors.clone();
        cs.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));
        println!("  signals:");
        for c in cs.iter().take(6) {
            let class = match c.class {
                SignalClass::Pamp => "PAMP  ",
                SignalClass::Danger => "danger",
                SignalClass::Safe => "safe  ",
            };
            println!("    [{}] {:<32} {:.2}", class, c.name, c.value);
        }
    }

    // --- fused priority (two axes, not collapsed) ------------------
    println!("\npriority");
    let line = match (rec.recognized, danger.context) {
        (true, agat_immune::DangerContext::Dangerous) => {
            "NON-SELF + DANGEROUS — investigate (recognition and danger agree)"
        }
        (true, agat_immune::DangerContext::Ambiguous) => {
            "non-self with ambiguous danger — worth a look"
        }
        (true, _) => "non-self but low danger — likely benign-but-unusual (false-positive guard)",
        (false, agat_immune::DangerContext::Dangerous) => {
            "within self yet dangerous signals present — anomaly worth review"
        }
        (false, _) => "within self / unrecognized — no action",
    };
    println!("  {line}");
}
