//! Negative selection — generating a non-self detector repertoire.
//!
//! Forrest, Perelson, Allen & Cherukuri, *Self-Nonself Discrimination
//! in a Computer*, IEEE S&P 1994; real-valued V-detector form, Ji &
//! Dasgupta, *Real-Valued Negative Selection Algorithm with
//! Variable-Sized Detectors*, GECCO 2004.
//!
//! The principle: T-cells mature in the thymus and any that react to
//! the body's own proteins are eliminated, so the survivors react only
//! to non-self. agat does the same in signature space: it samples
//! candidate detectors at random, **censors** any that fall within the
//! self region (the [`SelfModel`]), and keeps the survivors. Each
//! survivor's radius is grown to reach just short of the nearest self
//! ball — the V-detector rule — so the repertoire covers as much
//! non-self space as possible with as few detectors as possible.
//!
//! Generation terminates either on a detector/attempt budget or on the
//! V-detector coverage estimate: once a long run of fresh non-self
//! candidates all land inside detectors we already have, the non-self
//! space is deemed covered.
//!
//! Honest scope (docs/AIS_REBUILD_PLAN.md §7): NSA knows *only* self, so
//! these detectors provide **anomaly coverage** — "not benign" — not
//! family identity. Family specificity comes later, from clonal
//! selection maturing detectors onto confirmed variants. NSA's coverage
//! is also only as representative as the benign corpus; we measure it
//! rather than assert completeness.

use crate::detectors::{Detector, DetectorOrigin, Repertoire};
use crate::self_model::SelfModel;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Parameters for negative selection. The self-tolerance threshold is,
/// per Forrest et al., the single most consequential knob: it sets how
/// close to self a detector may sit, trading false positives against
/// non-self coverage.
#[derive(Debug, Clone, Copy)]
pub struct NsaConfig {
    /// Hard cap on repertoire size.
    pub max_detectors: usize,
    /// Hard cap on candidate draws (safety bound; coverage usually stops
    /// generation first).
    pub max_attempts: usize,
    /// How far outside the self balls a candidate must sit to survive
    /// censoring; also subtracted from each detector's radius. ≥ 0.
    pub self_tolerance: f64,
    /// Discard detectors whose radius would be smaller than this — they
    /// hug self too tightly to be worth keeping.
    pub min_radius: f64,
    /// Target non-self coverage in `[0, 1)`; drives the termination
    /// estimate (a run of `1/(1-coverage)` already-covered candidates).
    pub coverage: f64,
    /// Lower/upper bound of the sampling hypercube per dimension.
    /// Antigen sub-vectors are normalized into `[0, 1]`.
    pub lo: f64,
    pub hi: f64,
    /// RNG seed — generation is fully deterministic for reproducibility.
    pub seed: u64,
}

impl Default for NsaConfig {
    fn default() -> Self {
        Self {
            max_detectors: 2000,
            max_attempts: 200_000,
            self_tolerance: 0.0,
            min_radius: 0.01,
            coverage: 0.95,
            lo: 0.0,
            hi: 1.0,
            seed: 0xA6A7_0000_0000_0001,
        }
    }
}

/// Generate a non-self detector repertoire by negative selection
/// against `self_model`. `dim` is the antigen signature dimensionality;
/// it must match the dimension the self-model and all future antigens
/// were built with.
pub fn generate(self_model: &SelfModel, dim: usize, cfg: &NsaConfig) -> Repertoire {
    let mut rng = StdRng::seed_from_u64(cfg.seed);
    let mut repertoire = Repertoire::new(dim);

    // V-detector coverage estimate: stop once this many *consecutive*
    // fresh non-self candidates were already covered by existing
    // detectors. Larger coverage target ⇒ longer required run.
    let required_streak = if cfg.coverage >= 1.0 {
        cfg.max_attempts
    } else {
        (1.0 / (1.0 - cfg.coverage)).ceil() as usize
    };
    let mut covered_streak = 0usize;

    for _ in 0..cfg.max_attempts {
        if repertoire.len() >= cfg.max_detectors {
            break;
        }
        // Draw a candidate detector center uniformly from the hypercube.
        let center: Vec<f64> = (0..dim).map(|_| rng.gen_range(cfg.lo..cfg.hi)).collect();

        // Censor: how far is the candidate from the self surface? With
        // no self at all, treat everything as non-self with a generous
        // radius.
        let surface = self_model.surface_distance(&center).unwrap_or(cfg.hi - cfg.lo);
        if surface <= cfg.self_tolerance {
            // Reacts to self → eliminated, exactly like a thymic T-cell.
            continue;
        }

        // Already covered by an existing detector? Then it tells us
        // nothing new — advance the coverage estimate.
        if repertoire.covers(&center) {
            covered_streak += 1;
            if covered_streak >= required_streak {
                break;
            }
            continue;
        }

        // A fresh patch of non-self space. Grow the detector to reach
        // just short of the nearest self ball (the V-detector radius).
        let radius = surface - cfg.self_tolerance;
        if radius < cfg.min_radius {
            continue;
        }
        covered_streak = 0;
        repertoire
            .detectors
            .push(Detector::new(center, radius, DetectorOrigin::NegativeSelection));
    }

    repertoire
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_antigen::Antigen;

    fn ag(sig: &[f64]) -> Antigen {
        Antigen {
            signature: sig.to_vec(),
            block_tokens: Default::default(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    /// A small benign cluster in the corner of a 3-D unit cube.
    fn self_model() -> SelfModel {
        let pts = [
            [0.10, 0.10, 0.10],
            [0.12, 0.08, 0.11],
            [0.08, 0.12, 0.09],
            [0.11, 0.09, 0.12],
            [0.09, 0.11, 0.08],
        ];
        let antigens: Vec<Antigen> = pts.iter().map(|p| ag(p)).collect();
        let labelled: Vec<(String, &Antigen)> =
            antigens.iter().enumerate().map(|(i, a)| (format!("s{i}"), a)).collect();
        SelfModel::build(&labelled, 2)
    }

    #[test]
    fn no_detector_reacts_to_self() {
        let sm = self_model();
        let rep = generate(&sm, 3, &NsaConfig::default());
        assert!(!rep.is_empty(), "should generate some detectors");
        for p in &sm.points {
            assert!(
                !rep.covers(&p.signature),
                "a detector must never bind a self sample — that is the entire NSA guarantee"
            );
        }
    }

    #[test]
    fn covers_most_non_self_space() {
        let sm = self_model();
        let rep = generate(&sm, 3, &NsaConfig::default());
        // Sample random points; those that are non-self should mostly be
        // covered by the repertoire.
        let mut rng = StdRng::seed_from_u64(42);
        let (mut non_self, mut covered) = (0, 0);
        for _ in 0..500 {
            let p: Vec<f64> = (0..3).map(|_| rng.gen_range(0.0..1.0)).collect();
            if !sm.is_self(&p, 0.0) {
                non_self += 1;
                if rep.covers(&p) {
                    covered += 1;
                }
            }
        }
        let frac = covered as f64 / non_self as f64;
        assert!(frac > 0.8, "expected >80% non-self coverage, got {frac:.2}");
    }

    #[test]
    fn generation_is_deterministic() {
        let sm = self_model();
        let a = generate(&sm, 3, &NsaConfig::default());
        let b = generate(&sm, 3, &NsaConfig::default());
        assert_eq!(a.len(), b.len());
        for (x, y) in a.detectors.iter().zip(b.detectors.iter()) {
            assert_eq!(x.center, y.center);
            assert_eq!(x.radius, y.radius);
        }
    }

    #[test]
    fn no_self_means_all_non_self() {
        // An empty self-model: nothing is self, so detectors can sit
        // anywhere and generation still terminates.
        let empty = SelfModel { dim: 3, k: 1, points: vec![], mean_radius: 0.0 };
        let rep = generate(&empty, 3, &NsaConfig::default());
        assert!(!rep.is_empty());
    }
}
