//! The agat scan facade.
//!
//! This crate is the one place that turns agat's persisted immune state
//! — the self-model, the detector repertoire, and the learned memory
//! pool — plus a sample's analyzer features into a single
//! [`ScanResult`](agat_core::ScanResult). Every front end (the operator
//! CLI, and later `agat serve` and any embedding library) calls
//! [`scan_sample`] so they all produce byte-identical verdicts from the
//! same inputs.
//!
//! Before this crate existed, the recognition + danger pipeline was
//! inlined in the CLI's `recognize` command and its result was printed
//! as free text. Lifting it here gives agat a reusable engine boundary
//! and a machine-readable contract, without changing any of the
//! underlying immune logic.
//!
//! The loading/persistence helpers are also exposed here so the
//! `self build` / `mature` commands share one definition of where each
//! immune structure lives and how it is (de)serialized.

pub mod sarif;

use std::collections::HashMap;

use agat_ai::AiFeatures;
use agat_antigen::{Antigen, AntigenConfig};
use agat_core::{
    AntigenSummary, DangerSummary, RecognitionSummary, SampleId, SampleRef, ScanResult,
    SignalSummary, SCAN_SCHEMA_VERSION,
};
use agat_immune::danger::{assess, signals_from_features, DangerAssessment, SignalClass};
use agat_immune::{
    DangerConfig, DangerContext, MemoryPool, Recognition, Repertoire, SelfModel,
};
use agat_poly::PolyFeatures;
use agat_static::StaticFeatures;
use agat_store::Store;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;

/// Single named slot for each persisted immune structure. agat keeps one
/// active self-model / repertoire / memory pool per store.
pub const SLOT: &str = "default";

/// The default antigen configuration. Every antigen — self-model inputs,
/// matured variants, and queried samples — must be built with the same
/// config so they share one metric space and dimensionality.
pub fn antigen_config() -> AntigenConfig {
    AntigenConfig::default()
}

/// Collect every analyzer's stored feature bundle for a sample.
pub fn feature_map(store: &Store, id: &SampleId) -> Result<HashMap<String, serde_json::Value>> {
    let mut map = HashMap::new();
    for name in ["static", "disasm", "poly", "meta", "ai"] {
        if let Some(rec) = store.get_features(id, name)? {
            map.insert(name.to_string(), rec.features);
        }
    }
    Ok(map)
}

/// Decode one analyzer's features into its typed form, if present.
pub fn typed<T: DeserializeOwned>(
    map: &HashMap<String, serde_json::Value>,
    name: &str,
) -> Option<T> {
    map.get(name)
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Project a feature map into an antigen using the default config.
pub fn antigen_from_map(map: &HashMap<String, serde_json::Value>) -> Antigen {
    Antigen::from_feature_map(map, &antigen_config())
}

/// Load the persisted self-model, if one has been built.
pub fn load_self_model(store: &Store) -> Result<Option<SelfModel>> {
    match store.get_self_model(SLOT)? {
        Some(j) => Ok(Some(serde_json::from_str(&j).context("decoding self-model")?)),
        None => Ok(None),
    }
}

/// Load the persisted detector repertoire, if one has been generated.
pub fn load_repertoire(store: &Store) -> Result<Option<Repertoire>> {
    match store.get_repertoire(SLOT)? {
        Some(j) => Ok(Some(serde_json::from_str(&j).context("decoding repertoire")?)),
        None => Ok(None),
    }
}

/// Load the learned memory pool, or an empty pool if none exists yet.
pub fn load_memory(store: &Store) -> Result<MemoryPool> {
    match store.get_memory(SLOT)? {
        Some(j) => Ok(serde_json::from_str(&j).context("decoding memory pool")?),
        None => Ok(MemoryPool::default()),
    }
}

/// Errors a scan can fail with that aren't "something went wrong" but
/// "agat isn't ready to scan yet" — useful for a front end that wants to
/// give the operator a precise next step.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("sample {0} has no analyzer features — run `agat analyze` first")]
    NoFeatures(String),
    #[error("no repertoire yet — run `agat self build` then `agat repertoire generate`")]
    NoRepertoire,
}

/// Scan one already-analyzed sample: present its antigen to the immune
/// system (recognition + danger) and assemble the fused [`ScanResult`].
///
/// `name` is an optional original file name/path to echo back in the
/// result; it does not affect the verdict.
///
/// This is the exact pipeline the CLI's `recognize` command used, lifted
/// verbatim so behavior is unchanged — only the output is now a typed,
/// serializable object instead of printed text.
pub fn scan_sample(store: &Store, id: &SampleId, name: Option<String>) -> Result<ScanResult> {
    let map = feature_map(store, id)?;
    if map.is_empty() {
        return Err(ScanError::NoFeatures(id.short()).into());
    }
    let antigen = antigen_from_map(&map);

    let repertoire = load_repertoire(store)?.ok_or(ScanError::NoRepertoire)?;
    let memory = load_memory(store)?;
    let self_model = load_self_model(store)?;

    // Merge the innate (negative-selection) repertoire with the learned
    // memory cells for a single recognition pass.
    let mut detectors = repertoire.detectors.clone();
    detectors.extend(memory.detectors());
    let combined = Repertoire { dim: repertoire.dim, detectors };

    let recognition = agat_immune::recognize(&antigen, &combined, self_model.as_ref());

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

    Ok(assemble(
        id,
        name,
        &antigen,
        &recognition,
        &danger,
        memory.families().len(),
    ))
}

/// Assemble a [`ScanResult`] from the internal immune outputs. Kept
/// separate from [`scan_sample`] so the conversion is unit-testable and
/// so a future embedding that already holds a `Recognition` /
/// `DangerAssessment` can reuse it.
pub fn assemble(
    id: &SampleId,
    name: Option<String>,
    antigen: &Antigen,
    rec: &Recognition,
    danger: &DangerAssessment,
    known_families: usize,
) -> ScanResult {
    let mut signals: Vec<SignalSummary> = danger
        .signals
        .contributors
        .iter()
        .map(|c| SignalSummary {
            class: match c.class {
                SignalClass::Pamp => "pamp",
                SignalClass::Danger => "danger",
                SignalClass::Safe => "safe",
            }
            .to_string(),
            name: c.name.clone(),
            value: c.value,
        })
        .collect();
    signals.sort_by(|a, b| b.value.partial_cmp(&a.value).unwrap_or(std::cmp::Ordering::Equal));

    let verdict = ScanResult::fuse(
        rec.recognized,
        matches!(danger.context, DangerContext::Dangerous),
        matches!(danger.context, DangerContext::Ambiguous),
    );

    ScanResult {
        schema_version: SCAN_SCHEMA_VERSION.to_string(),
        agat_version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_at: chrono::Utc::now().to_rfc3339(),
        sample: SampleRef {
            id: id.to_hex(),
            short: id.short(),
            name,
        },
        antigen: AntigenSummary {
            dim: antigen.dim(),
            blocks: antigen.block_tokens.len(),
            cfg_fingerprint: antigen.cfg_fingerprint.clone(),
            plaintext_fingerprint: antigen.plaintext_fingerprint.clone(),
        },
        recognition: RecognitionSummary {
            recognized: rec.recognized,
            verdict: rec.verdict().to_string(),
            family: rec.family.clone(),
            affinity: rec.best.as_ref().map(|b| b.affinity).unwrap_or(0.0),
            bound_detectors: rec.bound_count,
            secondary_response: rec.from_memory,
            self_surface_distance: rec.self_surface_distance,
            known_families,
        },
        danger: DangerSummary {
            score: danger.danger_score,
            context: danger.context.label().to_string(),
            pamp: danger.signals.pamp,
            danger: danger.signals.danger,
            safe: danger.signals.safe,
            signals,
        },
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_antigen::Antigen;
    use agat_immune::danger::{DangerSignals, SignalContribution};
    use agat_immune::detectors::DetectorOrigin;
    use agat_immune::recognition::DetectorMatch;
    use std::collections::BTreeSet;

    fn antigen() -> Antigen {
        let mut blocks = BTreeSet::new();
        blocks.insert("blk-a".to_string());
        blocks.insert("blk-b".to_string());
        Antigen {
            signature: vec![0.1, 0.2, 0.3, 0.4],
            block_tokens: blocks,
            cfg_fingerprint: Some("cfg123".to_string()),
            plaintext_fingerprint: None,
        }
    }

    fn danger(score: f64, context: DangerContext) -> DangerAssessment {
        DangerAssessment {
            signals: DangerSignals {
                pamp: 0.8,
                danger: 0.5,
                safe: 0.1,
                contributors: vec![
                    SignalContribution { name: "mild".into(), class: SignalClass::Safe, value: 0.2 },
                    SignalContribution { name: "loud".into(), class: SignalClass::Pamp, value: 0.9 },
                    SignalContribution { name: "mid".into(), class: SignalClass::Danger, value: 0.5 },
                ],
            },
            csm: 0.0,
            semi: 0.0,
            mat: 0.0,
            danger_score: score,
            context,
        }
    }

    fn recognition_nonself_family() -> Recognition {
        Recognition {
            recognized: true,
            bound_count: 3,
            best: Some(DetectorMatch {
                affinity: 0.77,
                family: Some("emotet".into()),
                generation: 2,
                origin: DetectorOrigin::Memory,
                detector_index: 5,
            }),
            family: Some("emotet".into()),
            from_memory: true,
            self_surface_distance: Some(0.42),
        }
    }

    #[test]
    fn maps_fields_sorts_signals_and_roundtrips_json() {
        let id = SampleId([3u8; 32]);
        let danger = danger(0.81, DangerContext::Dangerous);
        let result = assemble(&id, Some("x.exe".into()), &antigen(), &recognition_nonself_family(), &danger, 4);

        // sample
        assert_eq!(result.sample.short, id.short());
        assert_eq!(result.sample.name.as_deref(), Some("x.exe"));
        // antigen
        assert_eq!(result.antigen.dim, 4);
        assert_eq!(result.antigen.blocks, 2);
        assert_eq!(result.antigen.cfg_fingerprint.as_deref(), Some("cfg123"));
        assert!(result.antigen.plaintext_fingerprint.is_none());
        // recognition
        assert!(result.recognition.recognized);
        assert_eq!(result.recognition.family.as_deref(), Some("emotet"));
        assert!((result.recognition.affinity - 0.77).abs() < 1e-9);
        assert_eq!(result.recognition.bound_detectors, 3);
        assert!(result.recognition.secondary_response);
        assert_eq!(result.recognition.known_families, 4);
        // danger: signals sorted strongest-first
        assert_eq!(result.danger.context, "dangerous");
        assert_eq!(result.danger.signals.first().unwrap().name, "loud");
        assert!(result.danger.signals.windows(2).all(|w| w[0].value >= w[1].value));
        // fused verdict: non-self + dangerous ⇒ malicious
        assert_eq!(result.severity(), agat_core::Severity::Malicious);
        // schema + contract
        assert_eq!(result.schema_version, agat_core::SCAN_SCHEMA_VERSION);
        // JSON round-trips without loss of the severity decision
        let json = serde_json::to_string(&result).unwrap();
        let back: agat_core::ScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.severity(), agat_core::Severity::Malicious);
        assert_eq!(back.recognition.family.as_deref(), Some("emotet"));
    }

    #[test]
    fn within_self_and_calm_is_clean() {
        let id = SampleId([1u8; 32]);
        let rec = Recognition {
            recognized: false,
            bound_count: 0,
            best: None,
            family: None,
            from_memory: false,
            self_surface_distance: Some(-0.3),
        };
        let result = assemble(&id, None, &antigen(), &rec, &danger(0.05, DangerContext::Safe), 2);
        assert_eq!(result.severity(), agat_core::Severity::Clean);
        assert_eq!(result.recognition.affinity, 0.0);
        assert!(result.sample.name.is_none());
    }
}
