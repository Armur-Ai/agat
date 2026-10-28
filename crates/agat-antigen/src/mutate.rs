//! Antigen-space mutation — a synthetic adversary's operators (R2/R3).
//!
//! These functions perturb an [`Antigen`] **in feature space only**. They do
//! not emit bytes, do not disassemble, and can never produce an executable
//! variant — they shift the *behavioral signature* so the immune system can be
//! trained and tested against the shape of a variant without ever holding a
//! working one. This is the defensive-only guarantee the roadmap depends on:
//! we sharpen the detector, never build a weapon.
//!
//! Each [`MutationClass`] models one real mutation axis and preserves the
//! invariants that axis would preserve in the wild — e.g. a repack
//! (polymorphic re-encryption) keeps the *plaintext* fingerprint, because the
//! payload is unchanged; an LLM rewrite changes both the control-flow and the
//! plaintext fingerprints, because the algorithm itself was substituted.
//!
//! Everything here is deterministic given the [`StdRng`] passed in.

use crate::antigen::Antigen;
use rand::rngs::StdRng;
use rand::Rng;

/// A mutation axis. Each preserves the behavioral invariants its real-world
/// counterpart would, so a synthesized variant lands where a true one would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationClass {
    /// Polymorphic re-encryption: same payload, new key/stub. Small signature
    /// jitter; CFG and plaintext fingerprints preserved.
    Repack,
    /// Metamorphic rewrite: register/encoding/instruction variants. Moderate
    /// jitter; CFG fingerprint changes, plaintext preserved.
    Metamorph,
    /// Recompilation with a new toolchain: broad, mild drift across groups.
    Recompile,
    /// LLM algorithm substitution: same behavior, different algorithm. Large
    /// structural jitter; both fingerprints change.
    LlmRewrite,
}

impl MutationClass {
    /// Base signature-jitter magnitude for this class.
    pub fn base_scale(self) -> f64 {
        match self {
            MutationClass::Repack => 0.03,
            MutationClass::Recompile => 0.06,
            MutationClass::Metamorph => 0.10,
            MutationClass::LlmRewrite => 0.16,
        }
    }

    fn changes_cfg(self) -> bool {
        matches!(self, MutationClass::Metamorph | MutationClass::LlmRewrite)
    }

    fn changes_plaintext(self) -> bool {
        matches!(self, MutationClass::LlmRewrite)
    }
}

/// Jitter a normalized signature uniformly in `[-scale, scale]` per component,
/// clamped back into `[0, 1]` (the antigen signature's normalized range).
pub fn perturb_signature(sig: &[f64], rng: &mut StdRng, scale: f64) -> Vec<f64> {
    sig.iter()
        .map(|&x| {
            let delta = if scale > 0.0 {
                rng.gen_range(-scale..scale)
            } else {
                0.0
            };
            (x + delta).clamp(0.0, 1.0)
        })
        .collect()
}

/// A fresh, deterministic pseudo-fingerprint (16 hex chars) derived from the
/// rng — stands in for the WL/plaintext hash of a synthesized variant.
fn fresh_fingerprint(rng: &mut StdRng) -> String {
    let v: u64 = rng.gen();
    format!("{v:016x}")
}

/// Produce one synthetic variant of `parent` under `class`, scaled by
/// `scale_mul` (1.0 = the class default). Feature-space only.
pub fn mutate(parent: &Antigen, class: MutationClass, rng: &mut StdRng, scale_mul: f64) -> Antigen {
    let scale = class.base_scale() * scale_mul.max(0.0);
    let signature = perturb_signature(&parent.signature, rng, scale);

    let cfg_fingerprint = if class.changes_cfg() {
        parent
            .cfg_fingerprint
            .as_ref()
            .map(|_| fresh_fingerprint(rng))
    } else {
        parent.cfg_fingerprint.clone()
    };
    let plaintext_fingerprint = if class.changes_plaintext() {
        parent
            .plaintext_fingerprint
            .as_ref()
            .map(|_| fresh_fingerprint(rng))
    } else {
        parent.plaintext_fingerprint.clone()
    };

    Antigen {
        signature,
        block_tokens: parent.block_tokens.clone(),
        cfg_fingerprint,
        plaintext_fingerprint,
    }
}

/// Draw `n` variants of `parent` across a spread of classes — a small,
/// diverse batch for one generation of self-play.
pub fn variant_batch(parent: &Antigen, rng: &mut StdRng, n: usize) -> Vec<Antigen> {
    const CLASSES: [MutationClass; 4] = [
        MutationClass::Repack,
        MutationClass::Recompile,
        MutationClass::Metamorph,
        MutationClass::LlmRewrite,
    ];
    (0..n)
        .map(|i| {
            let class = CLASSES[i % CLASSES.len()];
            // Vary the magnitude a little within the class for diversity.
            let mul = 0.6 + rng.gen_range(0.0..0.8);
            mutate(parent, class, rng, mul)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use std::collections::BTreeSet;

    fn parent() -> Antigen {
        Antigen {
            signature: vec![0.5, 0.5, 0.0, 1.0, 0.25],
            block_tokens: BTreeSet::from(["blk_a".to_string(), "blk_b".to_string()]),
            cfg_fingerprint: Some("1e7c267c1f7fdc74".into()),
            plaintext_fingerprint: Some("2f31df54ff38302a".into()),
        }
    }

    #[test]
    fn deterministic_for_a_seed() {
        let p = parent();
        let a = mutate(
            &p,
            MutationClass::Metamorph,
            &mut StdRng::seed_from_u64(7),
            1.0,
        );
        let b = mutate(
            &p,
            MutationClass::Metamorph,
            &mut StdRng::seed_from_u64(7),
            1.0,
        );
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.cfg_fingerprint, b.cfg_fingerprint);
    }

    #[test]
    fn signature_stays_in_unit_range() {
        let p = parent();
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..50 {
            let v = mutate(&p, MutationClass::LlmRewrite, &mut rng, 2.0);
            assert!(v.signature.iter().all(|&x| (0.0..=1.0).contains(&x)));
        }
    }

    #[test]
    fn repack_preserves_both_fingerprints() {
        let p = parent();
        let v = mutate(
            &p,
            MutationClass::Repack,
            &mut StdRng::seed_from_u64(1),
            1.0,
        );
        assert_eq!(v.cfg_fingerprint, p.cfg_fingerprint);
        assert_eq!(v.plaintext_fingerprint, p.plaintext_fingerprint);
    }

    #[test]
    fn metamorph_changes_cfg_but_keeps_plaintext() {
        let p = parent();
        let v = mutate(
            &p,
            MutationClass::Metamorph,
            &mut StdRng::seed_from_u64(9),
            1.0,
        );
        assert_ne!(v.cfg_fingerprint, p.cfg_fingerprint);
        assert_eq!(v.plaintext_fingerprint, p.plaintext_fingerprint);
    }

    #[test]
    fn llm_rewrite_changes_both_fingerprints() {
        let p = parent();
        let v = mutate(
            &p,
            MutationClass::LlmRewrite,
            &mut StdRng::seed_from_u64(5),
            1.0,
        );
        assert_ne!(v.cfg_fingerprint, p.cfg_fingerprint);
        assert_ne!(v.plaintext_fingerprint, p.plaintext_fingerprint);
    }

    #[test]
    fn batch_is_diverse_and_bounded() {
        let p = parent();
        let batch = variant_batch(&p, &mut StdRng::seed_from_u64(11), 8);
        assert_eq!(batch.len(), 8);
        // Not all identical.
        assert!(batch.iter().any(|v| v.signature != p.signature));
    }
}
