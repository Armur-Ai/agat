//! Drift classification — benign change vs. slow-burn attack (R4 · living self).
//!
//! The living self must fold *benign* drift (a new build, a new vendor tool)
//! into its model, while refusing to silently absorb a "boil-the-frog" attacker
//! who nudges the environment one safe-looking step at a time. This module is
//! the gate: given a candidate antigen and the current [`SelfModel`], decide
//! whether it is close enough to be re-tolerized, far enough to be suspicious,
//! or in between and held for a human.
//!
//! This is a conservative v1 heuristic over the self-surface distance; the
//! open research problem (see `ROADMAP.md` R4) is a fuller drift model. The
//! default is deliberately cautious — anything not clearly benign is held.

use crate::self_model::SelfModel;

/// What to do with a candidate benign observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftVerdict {
    /// Close to self — safe to fold in (re-tolerize).
    BenignDrift,
    /// Ambiguous — do not absorb; surface for review.
    Hold,
    /// Far from self and moving — treat as a possible staged attack.
    Suspicious,
}

/// Thresholds, expressed as multiples of the model's `mean_radius`.
#[derive(Debug, Clone)]
pub struct DriftConfig {
    /// Absorb when the surface distance is within this × mean_radius.
    pub absorb_within: f64,
    /// Flag as suspicious when the surface distance exceeds this × mean_radius.
    pub suspicious_beyond: f64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            absorb_within: 1.0,
            suspicious_beyond: 4.0,
        }
    }
}

/// Classify a candidate signature against the current self model.
pub fn classify(sig: &[f64], model: &SelfModel, cfg: &DriftConfig) -> DriftVerdict {
    // No model, or a degenerate radius: cannot judge — hold.
    if model.is_empty() || model.mean_radius <= 0.0 {
        return DriftVerdict::Hold;
    }
    match model.surface_distance(sig) {
        // Inside or on the self surface (distance ≤ 0) ⇒ clearly benign.
        Some(d) if d <= cfg.absorb_within * model.mean_radius => DriftVerdict::BenignDrift,
        Some(d) if d >= cfg.suspicious_beyond * model.mean_radius => DriftVerdict::Suspicious,
        Some(_) => DriftVerdict::Hold,
        None => DriftVerdict::Hold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_antigen::Antigen;
    use std::collections::BTreeSet;

    fn antigen(c: f64) -> Antigen {
        Antigen {
            signature: vec![c, c],
            block_tokens: BTreeSet::new(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    fn model() -> SelfModel {
        let a = antigen(0.50);
        let b = antigen(0.52);
        let c = antigen(0.48);
        SelfModel::build(&[("a", &a), ("b", &b), ("c", &c)], 1)
    }

    #[test]
    fn near_self_is_benign_drift() {
        let m = model();
        assert_eq!(
            classify(&[0.51, 0.51], &m, &DriftConfig::default()),
            DriftVerdict::BenignDrift
        );
    }

    #[test]
    fn far_from_self_is_suspicious() {
        let m = model();
        assert_eq!(
            classify(&[5.0, 5.0], &m, &DriftConfig::default()),
            DriftVerdict::Suspicious
        );
    }

    #[test]
    fn empty_model_holds() {
        let m = SelfModel::build::<&str>(&[], 1);
        assert_eq!(
            classify(&[0.5, 0.5], &m, &DriftConfig::default()),
            DriftVerdict::Hold
        );
    }
}
