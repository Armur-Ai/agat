//! Immune operations the TUI can run itself, so the analyst drives agat
//! from menus instead of the shell. All of these read extracted features
//! and the learned model from the store and write the model back — none
//! needs the encrypted vault, so the TUI stays password-free.

use agat_antigen::Antigen;
use agat_core::SampleId;
use agat_engine::{
    antigen_from_map, feature_map, load_memory, load_repertoire, load_self_model, SLOT,
};
use agat_immune::{generate_repertoire, mature, ClonalConfig, NsaConfig, SelfModel};
use agat_store::{Store, StoredSample};
use anyhow::{bail, Context, Result};

/// Build the self-model from the benign samples (family/tag "benign", or
/// all analyzed samples if none are tagged). Returns a status message.
pub fn build_self(store: &Store, samples: &[StoredSample]) -> Result<String> {
    let benign: Vec<&StoredSample> = samples
        .iter()
        .filter(|s| {
            s.sample.metadata.family.as_deref() == Some("benign")
                || s.sample.metadata.tags.iter().any(|t| t == "benign")
        })
        .collect();
    let chosen: Vec<&StoredSample> = if benign.is_empty() {
        samples.iter().collect()
    } else {
        benign
    };

    let mut owned: Vec<(String, Antigen)> = Vec::new();
    for s in &chosen {
        let map = feature_map(store, &s.sample.id)?;
        if !map.is_empty() {
            owned.push((s.sample.id.to_hex(), antigen_from_map(&map)));
        }
    }
    if owned.is_empty() {
        bail!("no analyzed samples to build 'self' from");
    }
    let labelled: Vec<(&str, &Antigen)> = owned.iter().map(|(id, a)| (id.as_str(), a)).collect();
    let model = SelfModel::build(&labelled, 3);
    store.put_self_model(SLOT, &serde_json::to_string(&model)?)?;
    store.clear_pack_info(SLOT)?;
    Ok(format!(
        "built self-model from {} benign sample{} (dim {})",
        owned.len(),
        if owned.len() == 1 { "" } else { "s" },
        model.dim
    ))
}

/// Generate the detector repertoire by negative selection against the
/// current self-model.
pub fn generate_repertoire_action(store: &Store) -> Result<String> {
    let self_model = load_self_model(store)?.context("no self-model yet — build 'self' first")?;
    let repertoire = generate_repertoire(&self_model, self_model.dim, &NsaConfig::default());
    store.put_repertoire(SLOT, &serde_json::to_string(&repertoire)?)?;
    store.clear_pack_info(SLOT)?;
    let (naive, matured) = repertoire.composition();
    Ok(format!(
        "generated {} detectors ({naive} naive, {matured} matured)",
        repertoire.len()
    ))
}

/// Mature the selected sample into `family` (clonal selection).
pub fn mature_action(store: &Store, id: &SampleId, family: &str) -> Result<String> {
    let family = family.trim();
    if family.is_empty() {
        bail!("family name is empty");
    }
    let map = feature_map(store, id)?;
    if map.is_empty() {
        bail!("sample has no analyzer features");
    }
    let antigen = antigen_from_map(&map);
    let mut memory = load_memory(store)?;
    if memory.dim == 0 {
        memory.dim = antigen.signature.len();
    }
    let repertoire = load_repertoire(store)?;
    let m = mature(
        &antigen,
        family,
        &mut memory,
        repertoire.as_ref(),
        &ClonalConfig::default(),
    );
    store.put_memory(SLOT, &serde_json::to_string(&memory)?)?;
    store.clear_pack_info(SLOT)?;
    Ok(format!(
        "matured {} → family '{}' ({} variant{})",
        id.short(),
        m.family,
        m.variants,
        if m.variants == 1 { "" } else { "s" }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_core::{Sample, SampleKind, SampleMetadata};

    fn trained_samples(store: &Store) -> Vec<StoredSample> {
        // Insert a couple of samples with minimal static features so the
        // antigen builder has something to project.
        let mut out = Vec::new();
        for i in 0..4u8 {
            let id = SampleId([i; 32]);
            let sample = Sample {
                id,
                kind: SampleKind::Elf64,
                size: 100,
                metadata: SampleMetadata {
                    family: Some("benign".into()),
                    ..Default::default()
                },
            };
            store.insert_sample(&sample).unwrap();
            let feat = serde_json::json!({
                "size": 100, "parsed": {"format":"Elf","arch":"X86_64","bits":64,
                    "entry_point":0,"sections":[],"imports":[],"exports":[]},
                "hashes": {"sha256":"","md5":"","imphash":null},
                "entropy": {"window_size":0,"step":0,"overall": 3.0 + i as f64 * 0.1,
                    "points":[],"high_entropy_regions":[]},
                "strings": {"min_len":4,"ascii_count":0,"utf16le_count":0,"samples":[]}
            });
            store
                .insert_features(
                    &id,
                    &agat_core::FeatureBundle {
                        analyzer: "static",
                        version: "0.1.0",
                        features: feat,
                        artifacts: vec![],
                    },
                )
                .unwrap();
            out.push(store.get_sample(&id).unwrap().unwrap());
        }
        out
    }

    #[test]
    fn build_self_then_repertoire_then_mature() {
        let store = Store::open_in_memory().unwrap();
        let samples = trained_samples(&store);

        let msg = build_self(&store, &samples).unwrap();
        assert!(msg.contains("self-model"));
        assert!(load_self_model(&store).unwrap().is_some());

        let msg = generate_repertoire_action(&store).unwrap();
        assert!(msg.contains("detectors"));
        assert!(load_repertoire(&store).unwrap().is_some());

        let msg = mature_action(&store, &samples[0].sample.id, "fam").unwrap();
        assert!(msg.contains("family 'fam'"));
        assert!(!load_memory(&store).unwrap().families().is_empty());

        // Guard rails.
        assert!(mature_action(&store, &samples[0].sample.id, "  ").is_err());
    }

    #[test]
    fn repertoire_before_self_errors() {
        let store = Store::open_in_memory().unwrap();
        assert!(generate_repertoire_action(&store).is_err());
    }
}
