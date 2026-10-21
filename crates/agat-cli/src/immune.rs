//! Artificial Immune System commands: build the self-model, generate
//! the detector repertoire by negative selection, mature it via clonal
//! selection, and recognize unknown samples (recognition + danger).
//!
//! The loading/persistence helpers and the recognition+danger pipeline
//! now live in `agat-engine`; this module is the command surface over
//! them. `recognize` delegates to [`agat_engine::scan_sample`] and
//! renders the returned [`ScanResult`] — the engine is the single source
//! of the verdict, so the CLI, JSON output, and any future API agree.

use crate::style::{palette, Style};
use agat_antigen::Antigen;
use agat_core::{ScanResult, Severity};
use agat_engine::{
    antigen_from_map, feature_map, load_memory, load_repertoire, load_self_model, ImmuneModel,
    ScanPolicy, SLOT,
};
use agat_immune::{generate_repertoire, mature, NsaConfig, SelfModel};
use agat_store::Store;
use anyhow::{bail, Result};

pub use crate::config::OutputFormat;

// ---- commands ------------------------------------------------------

/// `agat self build [ids...] [--k K]` — model the benign region of
/// signature space. With no ids, every sample tagged/family "benign" is
/// used.
pub fn cmd_self_build(inputs: Vec<String>, k: usize, store: &Store) -> Result<()> {
    let ids: Vec<agat_core::SampleId> = if inputs.is_empty() {
        let benign: Vec<agat_core::SampleId> = store
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

    let labelled: Vec<(&str, &Antigen)> = owned.iter().map(|(id, a)| (id.as_str(), a)).collect();
    let model = SelfModel::build(&labelled, k);
    store.put_self_model(SLOT, &serde_json::to_string(&model)?)?;
    // Retrained locally: the model is no longer the pack that was imported.
    store.clear_pack_info(SLOT)?;

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
        .ok_or_else(|| anyhow::anyhow!("no self-model yet — run `agat self build` first"))?;

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
    // Retrained locally: the model is no longer the pack that was imported.
    store.clear_pack_info(SLOT)?;

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
        bail!(
            "sample {} has no analyzer features — run `agat analyze` first",
            id.short()
        );
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
    // Retrained locally: the model is no longer the pack that was imported.
    store.clear_pack_info(SLOT)?;

    println!("clonal selection on {} → family '{}'", id.short(), m.family);
    println!(
        "  {} memory cell for the family ({} variant{} incorporated)",
        if m.new_cell {
            "formed a new"
        } else {
            "reinforced the"
        },
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
/// system (recognition + danger) via the engine, and render the
/// resulting [`ScanResult`].
///
/// Returns the verdict severity; the caller maps it to the process exit
/// code so a pipeline can branch on the outcome without parsing output.
pub fn cmd_recognize(
    input: String,
    format: OutputFormat,
    policy: ScanPolicy,
    store: &Store,
) -> Result<Severity> {
    let id = crate::resolve_sample_id(&input, store)?;
    let model = ImmuneModel::load(store)?.with_policy(policy);
    let result = model.scan(&id, None, &feature_map(store, &id)?)?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
        OutputFormat::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&agat_engine::sarif::to_sarif(std::slice::from_ref(
                &result
            )))?
        ),
        OutputFormat::Text => print_report(&result),
        OutputFormat::Table => print_table(std::slice::from_ref(&result)),
    }
    Ok(result.severity())
}

/// Render a [`ScanResult`] as the human-readable, two-axis report.
pub fn print_report(r: &ScanResult) {
    let st = Style::new(crate::style::use_color());
    let head = |t: &str| println!("\n{}", st.bold(&st.fg(palette::CYAN, t)));
    let kv = |k: &str, v: String| println!("  {:<20}{}", k, v);

    // header line: badge + id + name
    let name = r.sample.name.as_deref().unwrap_or("");
    println!(
        "{}  {}{}",
        st.severity_badge(r.verdict.severity),
        st.bold(&r.sample.short),
        if name.is_empty() {
            String::new()
        } else {
            format!("  {}", st.dim(name))
        },
    );
    println!("  {}", st.dim(&r.verdict.summary));
    if r.verdict.policy.is_some() {
        println!(
            "  {}",
            st.dim("(verdict set by operator policy; the axes below are unchanged)")
        );
    }

    head("ANTIGEN");
    kv(
        "signature",
        format!(
            "dim {} · {} canonical block{}",
            r.antigen.dim,
            r.antigen.blocks,
            if r.antigen.blocks == 1 { "" } else { "s" }
        ),
    );
    kv(
        "cfg fingerprint",
        r.antigen
            .cfg_fingerprint
            .clone()
            .unwrap_or_else(|| "-".into()),
    );
    kv(
        "plaintext finger",
        r.antigen
            .plaintext_fingerprint
            .clone()
            .unwrap_or_else(|| "-".into()),
    );

    let rec = &r.recognition;
    let fam = rec.known_families;
    head(&format!(
        "RECOGNITION  ({fam} known famil{})",
        if fam == 1 { "y" } else { "ies" }
    ));
    kv(
        "is it non-self?",
        if rec.recognized {
            st.fg(palette::YELLOW, "yes")
        } else {
            st.fg(palette::GREEN, "no (self / unknown)")
        },
    );
    kv("family", rec.family.clone().unwrap_or_else(|| "-".into()));
    kv("affinity", meter(&st, rec.affinity, palette::VIOLET));
    kv(
        "memory cell",
        if rec.secondary_response {
            "yes (secondary response)".into()
        } else {
            "no".into()
        },
    );
    if let Some(d) = rec.self_surface_distance {
        kv("distance from self", format!("{d:+.3}"));
    }

    let d = &r.danger;
    head("DANGER  (dendritic-cell signal fusion)");
    kv(
        "is it harmful?",
        format!(
            "{}  context {}  ·  P {:.2} / D {:.2} / S {:.2}",
            meter(&st, d.score, palette::RED),
            d.context,
            d.pamp,
            d.danger,
            d.safe
        ),
    );
    for c in d.signals.iter().take(6) {
        let (tag, col) = match c.class.as_str() {
            "pamp" => ("PAMP  ", palette::RED),
            "danger" => ("danger", palette::YELLOW),
            _ => ("safe  ", palette::GREEN),
        };
        println!("    {} {:<32} {:.2}", st.fg(col, tag), c.name, c.value);
    }

    if let Some(m) = &r.model {
        head("MODEL");
        kv("source", describe_model(m));
    }
}

/// A compact 0..1 meter: the value, then a colored bar.
fn meter(st: &Style, value: f64, color: (u8, u8, u8)) -> String {
    let v = value.clamp(0.0, 1.0);
    let filled = (v * 16.0).round() as usize;
    let bar = format!(
        "{}{}",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(16 - filled)
    );
    format!("{:.3}  {}", value, st.fg(color, &bar))
}

/// Render results as one line per file plus a batch summary.
pub fn print_table(results: &[ScanResult]) {
    let st = Style::new(crate::style::use_color());
    let header = format!(
        "{:<11} {:<16} {:>8}  {:<18} FILE",
        "SEVERITY", "FAMILY", "AFFINITY", "DANGER"
    );
    println!("{}", st.bold(&st.fg(palette::CYAN, &header)));
    println!("{}", st.dim(&"─".repeat(header.len().min(78))));
    for r in results {
        let sev = r.severity();
        let label = match sev {
            Severity::Malicious => "MALICIOUS",
            other => other.label(),
        };
        let affinity = if r.recognition.recognized {
            format!("{:.3}", r.recognition.affinity)
        } else {
            "-".to_string()
        };
        let mut family = r.recognition.family.clone().unwrap_or_else(|| "-".into());
        if family.chars().count() > 16 {
            family = family.chars().take(15).collect::<String>() + "…";
        }
        let name = r
            .sample
            .name
            .clone()
            .unwrap_or_else(|| r.sample.short.clone());
        let policy = r
            .verdict
            .policy
            .as_deref()
            .map(|p| format!("  [{p}]"))
            .unwrap_or_default();
        println!(
            "{} {:<16} {:>8}  {:<18} {}{}",
            {
                let lbl = st.severity(sev);
                let pad = 11usize.saturating_sub(label.chars().count());
                format!("{lbl}{}", " ".repeat(pad))
            },
            family,
            affinity,
            format!("{:.2} {}", r.danger.score, r.danger.context),
            name,
            st.dim(&policy)
        );
    }
    let count = |s: Severity| results.iter().filter(|r| r.severity() == s).count();
    if let Some(m) = results.first().and_then(|r| r.model.as_ref()) {
        println!("\n{}  {}", st.dim("model"), describe_model(m));
    }
    let tally = format!(
        "{} scanned · {} malicious · {} suspicious · {} review · {} clean",
        results.len(),
        count(Severity::Malicious),
        count(Severity::Suspicious),
        count(Severity::Review),
        count(Severity::Clean)
    );
    println!("\n{}", st.bold(&tally));
}

/// One-line description of the model that produced a result.
pub fn describe_model(m: &agat_core::ModelRef) -> String {
    match m.source.as_str() {
        "pack" => format!(
            "pack {} v{} · {}",
            m.name.as_deref().unwrap_or("?"),
            m.version.as_deref().unwrap_or("?"),
            match &m.signer {
                Some(k) => format!("signed by {k}"),
                None => "unsigned".to_string(),
            }
        ),
        _ => "trained locally".to_string(),
    }
}
