//! The antigen: a mutation-invariant behavioral signature.
//!
//! An [`Antigen`] is agat's computational analogue of a pathogen's
//! antigen — the stable surface the immune system recognizes despite
//! the organism mutating everything around it. We build it by
//! projecting the existing behavioral [`FeatureBundle`]s (static,
//! disasm, poly, meta, ai) into:
//!
//! - a fixed-dimensional, normalized real-valued **signature vector**
//!   (`signature`), the metric space all immune mechanisms operate in;
//!   and
//! - the raw **canonical-block token set** (`block_tokens`) from
//!   `agat-meta`, for a set-similarity (Jaccard) view.
//!
//! The deliberate property — and the entire reason recognition can
//! generalize to unseen variants — is that the dominant features
//! (opcode-class distribution, canonical-block histogram, CFG shape)
//! are *invariant* to register renaming, operand-width changes, and
//! NOP insertion, and only move under genuine algorithm substitution.
//! Polymorphism and metamorphism rewrite the surface; the antigen
//! holds still.
//!
//! [`FeatureBundle`]: agat_core analyzers' output, persisted as JSON.

use crate::opcode::{classify, OPCODE_CLASSES, OPCODE_CLASS_COUNT};
use agat_ai::AiFeatures;
use agat_disasm::DisasmFeatures;
use agat_meta::MetaFeatures;
use agat_poly::PolyFeatures;
use agat_static::StaticFeatures;
use std::collections::{BTreeSet, HashMap};

/// Tuning for antigen construction. The per-group weights scale each
/// sub-vector's contribution to the cosine metric, so they are the
/// honest, explicit "what matters" knobs of the representation.
#[derive(Debug, Clone, Copy)]
pub struct AntigenConfig {
    /// Number of buckets the canonical-block tokens are feature-hashed
    /// into for the signature vector. (The raw token set is also kept
    /// for exact Jaccard.)
    pub block_dims: usize,
    pub w_opcode: f64,
    pub w_block: f64,
    pub w_struct: f64,
    pub w_entropy: f64,
    pub w_style: f64,
    pub w_imports: f64,
}

impl Default for AntigenConfig {
    fn default() -> Self {
        Self {
            block_dims: 16,
            w_opcode: 1.0,
            w_block: 1.0,
            w_struct: 1.0,
            w_entropy: 1.0,
            w_style: 1.0,
            w_imports: 1.0,
        }
    }
}

/// References to the per-analyzer feature blobs an antigen is built
/// from. All optional: a non-x86 sample has no disasm/meta, a benign
/// sample may have no recovered payload, etc. Missing inputs contribute
/// zeroed sub-vectors rather than failing.
#[derive(Default, Clone, Copy)]
pub struct AntigenInput<'a> {
    pub static_features: Option<&'a StaticFeatures>,
    pub disasm: Option<&'a DisasmFeatures>,
    pub poly: Option<&'a PolyFeatures>,
    pub meta: Option<&'a MetaFeatures>,
    pub ai: Option<&'a AiFeatures>,
}

/// A sample's mutation-invariant behavioral signature.
#[derive(Debug, Clone)]
pub struct Antigen {
    /// Fixed-dimensional normalized feature vector — the metric space.
    pub signature: Vec<f64>,
    /// Canonical-block fingerprints (register/width/NOP-invariant), for
    /// the Jaccard set-similarity view.
    pub block_tokens: BTreeSet<String>,
    /// The metamorphic CFG fingerprint, if the sample disassembled.
    pub cfg_fingerprint: Option<String>,
    /// The polymorphic plaintext fingerprint (invariant across decryptor
    /// implementations), if a payload was recovered.
    pub plaintext_fingerprint: Option<String>,
}

impl Antigen {
    pub fn dim(&self) -> usize {
        self.signature.len()
    }

    /// Build an antigen from per-analyzer features.
    pub fn build(input: &AntigenInput, cfg: &AntigenConfig) -> Antigen {
        let mut sig = Vec::new();

        // --- 1. opcode-class distribution (16 dims) ----------------
        let opcode = opcode_distribution(input.disasm);
        push_scaled(&mut sig, &opcode, cfg.w_opcode);

        // --- 2. canonical-block hashed histogram (block_dims) ------
        let block_hist = block_histogram(input.meta, cfg.block_dims);
        push_scaled(&mut sig, &block_hist, cfg.w_block);

        // --- 3. CFG shape (4 dims) ---------------------------------
        let structure = cfg_shape(input.disasm);
        push_scaled(&mut sig, &structure, cfg.w_struct);

        // --- 4. entropy summary (3 dims) ---------------------------
        let entropy = entropy_summary(input.static_features);
        push_scaled(&mut sig, &entropy, cfg.w_entropy);

        // --- 5. stylometry (5 dims) --------------------------------
        let style = stylometry_summary(input.ai);
        push_scaled(&mut sig, &style, cfg.w_style);

        // --- 6. import / section profile (3 dims) ------------------
        let imports = import_profile(input.static_features);
        push_scaled(&mut sig, &imports, cfg.w_imports);

        let block_tokens: BTreeSet<String> = input
            .meta
            .map(|m| m.block_fingerprints.iter().cloned().collect())
            .unwrap_or_default();
        let cfg_fingerprint = input
            .meta
            .map(|m| m.cfg_fingerprint.clone())
            .filter(|s| !s.is_empty());
        let plaintext_fingerprint = input
            .poly
            .and_then(|p| p.recovered.as_ref())
            .map(|r| r.plaintext_fingerprint.clone())
            .filter(|s| !s.is_empty());

        Antigen {
            signature: sig,
            block_tokens,
            cfg_fingerprint,
            plaintext_fingerprint,
        }
    }

    /// Build an antigen directly from a map of analyzer-name → features
    /// JSON (the shape persisted in the store and carried in
    /// `AnalysisContext.previous_features`). Unknown/garbled entries are
    /// skipped rather than fatal.
    pub fn from_feature_map(
        map: &HashMap<String, serde_json::Value>,
        cfg: &AntigenConfig,
    ) -> Antigen {
        let static_features: Option<StaticFeatures> =
            map.get("static").and_then(|v| serde_json::from_value(v.clone()).ok());
        let disasm: Option<DisasmFeatures> =
            map.get("disasm").and_then(|v| serde_json::from_value(v.clone()).ok());
        let poly: Option<PolyFeatures> =
            map.get("poly").and_then(|v| serde_json::from_value(v.clone()).ok());
        let meta: Option<MetaFeatures> =
            map.get("meta").and_then(|v| serde_json::from_value(v.clone()).ok());
        let ai: Option<AiFeatures> =
            map.get("ai").and_then(|v| serde_json::from_value(v.clone()).ok());

        let input = AntigenInput {
            static_features: static_features.as_ref(),
            disasm: disasm.as_ref(),
            poly: poly.as_ref(),
            meta: meta.as_ref(),
            ai: ai.as_ref(),
        };
        Antigen::build(&input, cfg)
    }
}

/// Human-readable label for every signature dimension, in order. Used
/// for the antigen summary in the CLI/TUI and for debugging why two
/// variants do (or don't) collapse.
pub fn signature_labels(cfg: &AntigenConfig) -> Vec<String> {
    let mut labels = Vec::new();
    for c in OPCODE_CLASSES {
        labels.push(format!("opcode:{c}"));
    }
    for i in 0..cfg.block_dims {
        labels.push(format!("block:{i}"));
    }
    for s in ["blocks", "edges", "mean_block", "cyclomatic"] {
        labels.push(format!("cfg:{s}"));
    }
    for s in ["overall", "regions", "region_mean"] {
        labels.push(format!("entropy:{s}"));
    }
    for s in ["diversity", "underscore", "str_len", "long_str", "idioms"] {
        labels.push(format!("style:{s}"));
    }
    for s in ["import_n", "wx_frac", "x_frac"] {
        labels.push(format!("imports:{s}"));
    }
    labels
}

fn push_scaled(out: &mut Vec<f64>, v: &[f64], w: f64) {
    out.extend(v.iter().map(|x| x * w));
}

/// `x / (x + k)` — a smooth squash of an unbounded count into `[0, 1)`.
fn squash(x: f64, k: f64) -> f64 {
    if x <= 0.0 {
        0.0
    } else {
        x / (x + k)
    }
}

fn normalize_sum(v: &mut [f64]) {
    let total: f64 = v.iter().sum();
    if total > 0.0 {
        for x in v.iter_mut() {
            *x /= total;
        }
    }
}

fn opcode_distribution(disasm: Option<&DisasmFeatures>) -> Vec<f64> {
    let mut v = vec![0.0; OPCODE_CLASS_COUNT];
    if let Some(df) = disasm {
        for (mnemonic, &count) in &df.opcode_histogram {
            v[classify(&mnemonic.to_ascii_lowercase())] += count as f64;
        }
    }
    normalize_sum(&mut v);
    v
}

fn block_histogram(meta: Option<&MetaFeatures>, dims: usize) -> Vec<f64> {
    let dims = dims.max(1);
    let mut v = vec![0.0; dims];
    if let Some(m) = meta {
        for fp in &m.block_fingerprints {
            v[(fnv1a(fp.as_bytes()) as usize) % dims] += 1.0;
        }
    }
    normalize_sum(&mut v);
    v
}

fn cfg_shape(disasm: Option<&DisasmFeatures>) -> Vec<f64> {
    let df = match disasm {
        Some(d) => d,
        None => return vec![0.0; 4],
    };
    let blocks = df.block_count as f64;
    let edges = df.edges.len() as f64;
    let mean_block = if df.block_count > 0 {
        df.instruction_count as f64 / df.block_count as f64
    } else {
        0.0
    };
    // McCabe cyclomatic complexity proxy: E - N + 2 (single component).
    let cyclomatic = (edges - blocks + 2.0).max(0.0);
    vec![
        squash(blocks, 8.0),
        squash(edges, 8.0),
        squash(mean_block, 8.0),
        squash(cyclomatic, 8.0),
    ]
}

fn entropy_summary(sf: Option<&StaticFeatures>) -> Vec<f64> {
    let sf = match sf {
        Some(s) => s,
        None => return vec![0.0; 3],
    };
    let overall = (sf.entropy.overall / 8.0).clamp(0.0, 1.0);
    let regions = squash(sf.entropy.high_entropy_regions.len() as f64, 2.0);
    let region_mean = sf
        .entropy
        .high_entropy_regions
        .iter()
        .map(|r| r.mean_entropy)
        .fold(0.0_f64, f64::max)
        / 8.0;
    vec![overall, regions, region_mean.clamp(0.0, 1.0)]
}

fn stylometry_summary(ai: Option<&AiFeatures>) -> Vec<f64> {
    let s = match ai {
        Some(a) => &a.stylometry,
        None => return vec![0.0; 5],
    };
    vec![
        squash(s.opcode_diversity, 4.0),
        (s.underscore_density * 10.0).clamp(0.0, 1.0),
        squash(s.mean_string_length, 40.0),
        squash(s.long_string_count as f64, 8.0),
        squash(s.llm_idiom_hits.len() as f64, 4.0),
    ]
}

fn import_profile(sf: Option<&StaticFeatures>) -> Vec<f64> {
    let sf = match sf {
        Some(s) => s,
        None => return vec![0.0; 3],
    };
    let import_n = squash(sf.parsed.imports.len() as f64, 32.0);
    let sections = sf.parsed.sections.len().max(1) as f64;
    let wx = sf
        .parsed
        .sections
        .iter()
        .filter(|s| s.characteristics.writable && s.characteristics.executable)
        .count() as f64
        / sections;
    let x = sf
        .parsed
        .sections
        .iter()
        .filter(|s| s.characteristics.executable)
        .count() as f64
        / sections;
    vec![import_n, wx, x]
}

/// 64-bit FNV-1a — a tiny, dependency-free hash for feature-hashing
/// block fingerprints into the signature's block buckets.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
