//! Affinity and distance functions over antigen signatures.
//!
//! The whole immune machinery downstream — negative selection
//! (censoring detectors against self), recognition (matching antigen to
//! detectors), clonal selection (cloning ∝ affinity, mutating ∝
//! 1/affinity) and the danger layer — operates in the metric space
//! defined here. The functions are deliberately explicit and the blend
//! is configurable, as the affinity threshold is the single most
//! important knob in a negative-selection algorithm (Forrest et al.,
//! 1994).
//!
//! Two complementary notions of similarity are exposed:
//!
//! 1. **Cosine** over the real-valued [`super::Antigen::signature`]
//!    vector — the primary metric. Because every signature component is
//!    non-negative, cosine lands in `[0, 1]`, so `distance = 1 - cosine`
//!    is a clean, bounded affinity threshold.
//! 2. **Jaccard** over the canonical-block token set — a set-similarity
//!    view that is exactly 1.0 for two metamorphic variants sharing all
//!    canonical blocks and degrades gracefully as blocks diverge.
//!
//! [`affinity`] blends the two; [`euclidean_distance`] is provided for
//! the V-detector geometry used by negative selection, which needs a
//! true vector-space metric with detector radii.

use crate::antigen::Antigen;
use std::collections::BTreeSet;

/// How [`affinity`] blends the cosine and Jaccard views.
#[derive(Debug, Clone, Copy)]
pub struct AffinityConfig {
    /// Weight on cosine similarity of the signature vector.
    pub alpha: f64,
    /// Weight on Jaccard similarity of the canonical-block token set.
    pub beta: f64,
}

impl Default for AffinityConfig {
    fn default() -> Self {
        // Equal blend. When a sample has no canonical blocks (non-x86,
        // or nothing disassembled) the Jaccard term is undefined and
        // `affinity` falls back to pure cosine — see below.
        Self { alpha: 0.5, beta: 0.5 }
    }
}

impl AffinityConfig {
    /// Cosine-only affinity (ignores the block-token set entirely).
    pub fn cosine_only() -> Self {
        Self { alpha: 1.0, beta: 0.0 }
    }
}

/// Cosine similarity of two equal-length non-negative vectors, in
/// `[0, 1]`. Returns 0.0 if either vector has zero magnitude.
pub fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len(), "antigen signatures must be the same length");
    let n = a.len().min(b.len());
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for i in 0..n {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if na == 0.0 || nb == 0.0 {
        return 0.0;
    }
    (dot / (na.sqrt() * nb.sqrt())).clamp(0.0, 1.0)
}

/// Euclidean (L2) distance between two equal-length vectors. Used by
/// the real-valued negative-selection / V-detector geometry, where
/// detectors are points with radii in signature space.
pub fn euclidean_distance(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len(), "antigen signatures must be the same length");
    let n = a.len().min(b.len());
    let mut acc = 0.0;
    for i in 0..n {
        let d = a[i] - b[i];
        acc += d * d;
    }
    acc.sqrt()
}

/// Jaccard similarity of two canonical-block token sets, in `[0, 1]`.
/// Two empty sets are defined here as `0.0` (no shared structure to
/// speak of), and the caller decides whether to fall back to cosine.
pub fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// Blended affinity between two antigens, in `[0, 1]`. When either
/// antigen carries no canonical-block tokens the Jaccard term is
/// undefined, so we fall back to pure cosine rather than penalizing a
/// perfectly valid non-x86 antigen for having no blocks.
pub fn affinity(a: &Antigen, b: &Antigen, cfg: &AffinityConfig) -> f64 {
    let cos = cosine_similarity(&a.signature, &b.signature);
    if a.block_tokens.is_empty() || b.block_tokens.is_empty() || cfg.beta == 0.0 {
        return cos;
    }
    let jac = jaccard(&a.block_tokens, &b.block_tokens);
    let total = cfg.alpha + cfg.beta;
    if total == 0.0 {
        return cos;
    }
    ((cfg.alpha * cos + cfg.beta * jac) / total).clamp(0.0, 1.0)
}

/// `1 - affinity`, the bounded distance used for affinity thresholds.
pub fn distance(a: &Antigen, b: &Antigen, cfg: &AffinityConfig) -> f64 {
    1.0 - affinity(a, b, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_basic() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-9);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-9);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn euclidean_basic() {
        assert!((euclidean_distance(&[0.0, 0.0], &[3.0, 4.0]) - 5.0).abs() < 1e-9);
        assert_eq!(euclidean_distance(&[1.0, 2.0], &[1.0, 2.0]), 0.0);
    }

    #[test]
    fn jaccard_basic() {
        let a: BTreeSet<String> = ["x", "y", "z"].iter().map(|s| s.to_string()).collect();
        let b: BTreeSet<String> = ["y", "z", "w"].iter().map(|s| s.to_string()).collect();
        // intersection {y,z}=2, union {x,y,z,w}=4
        assert!((jaccard(&a, &b) - 0.5).abs() < 1e-9);
        assert_eq!(jaccard(&a, &a), 1.0);
        assert_eq!(jaccard(&BTreeSet::new(), &BTreeSet::new()), 0.0);
    }
}
