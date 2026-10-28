//! The vaccine forecaster — immunize before the strain is written (R3).
//!
//! The proactive twin of the germinal center ([`crate::evolve`]). Instead of
//! answering attacks, it projects a family's mutation space *forward* along
//! realistic drift trajectories (recompile / re-encrypt / obfuscate /
//! LLM-rewrite), synthesizes attenuated antigens along them, and pre-matures
//! memory cells for variants nobody has written yet. When the real variant
//! lands months later it falls straight into a pre-built cell.
//!
//! This is forecasting, not prophecy: a [`DriftModel`] is an inspectable,
//! deterministic step model, and projected points are bounded to stay
//! *in-family* so a forecast never swallows non-self. Novel families are still
//! the job of the self/non-self + danger baseline — this only buys a head start
//! on families already known.

use crate::clonal::{mature, ClonalConfig};
use crate::memory::MemoryPool;
use agat_antigen::Antigen;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::BTreeSet;

/// A projected drift path: one drift kind, as an ordered list of antigen-space
/// points moving away from the family center.
pub type Trajectory = Vec<Vec<f64>>;

/// Projects a family center forward into the strains it is likely to drift into.
pub trait DriftModel {
    /// One trajectory per drift kind, each with `steps` points.
    fn trajectories(&self, center: &[f64], steps: usize) -> Vec<Trajectory>;
}

/// A simple, inspectable v1 drift model: a fixed set of deterministic directions
/// (one per drift kind), each stepped a bounded distance from the center.
#[derive(Debug, Clone)]
pub struct LinearDriftModel {
    pub seed: u64,
    /// Distance travelled per step.
    pub step: f64,
    /// Hard cap on how far a projected point may sit from the center — keeps
    /// the forecast *in-family* so it cannot absorb non-self.
    pub max_in_family: f64,
    /// Number of drift directions (kinds) to project along.
    pub directions: usize,
}

impl Default for LinearDriftModel {
    fn default() -> Self {
        Self {
            seed: 0xF01E_CA57_0000_0001,
            step: 0.03,
            max_in_family: 0.25,
            directions: 4,
        }
    }
}

fn unit_direction(dim: usize, rng: &mut StdRng) -> Vec<f64> {
    let raw: Vec<f64> = (0..dim).map(|_| rng.gen_range(-1.0..1.0)).collect();
    let norm = raw.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm <= 0.0 {
        vec![0.0; dim]
    } else {
        raw.iter().map(|x| x / norm).collect()
    }
}

impl DriftModel for LinearDriftModel {
    fn trajectories(&self, center: &[f64], steps: usize) -> Vec<Trajectory> {
        let mut rng = StdRng::seed_from_u64(self.seed);
        (0..self.directions)
            .map(|_| {
                let dir = unit_direction(center.len(), &mut rng);
                (1..=steps)
                    .map(|s| {
                        let dist = (s as f64 * self.step).min(self.max_in_family);
                        center
                            .iter()
                            .zip(&dir)
                            .map(|(c, d)| (c + d * dist).clamp(0.0, 1.0))
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }
}

/// Parameters for a forecast run.
#[derive(Debug, Clone)]
pub struct ForecastConfig {
    /// Steps per trajectory (how far into the future to project).
    pub steps: usize,
    /// Clonal config used to pre-mature the projected points.
    pub clonal: ClonalConfig,
}

impl Default for ForecastConfig {
    fn default() -> Self {
        Self {
            steps: 6,
            clonal: ClonalConfig::default(),
        }
    }
}

/// What a forecast produced.
#[derive(Debug, Clone, PartialEq)]
pub struct ForecastReport {
    pub family: String,
    /// Projected (attenuated) antigens pre-matured.
    pub projected: usize,
    pub cells_before: usize,
    pub cells_after: usize,
}

/// Project `family`'s center forward and pre-immunize `memory` against the
/// strains it is likely to drift into. Deterministic given the drift model's
/// seed. Returns a report.
pub fn forecast(
    memory: &mut MemoryPool,
    family: &str,
    center: &[f64],
    drift: &dyn DriftModel,
    cfg: &ForecastConfig,
) -> ForecastReport {
    let cells_before = memory.cells.len();
    let mut projected = 0usize;
    for traj in drift.trajectories(center, cfg.steps) {
        for point in traj {
            let antigen = Antigen {
                signature: point,
                block_tokens: BTreeSet::new(),
                cfg_fingerprint: None,
                plaintext_fingerprint: None,
            };
            mature(&antigen, family, memory, None, &cfg.clonal);
            projected += 1;
        }
    }
    ForecastReport {
        family: family.to_string(),
        projected,
        cells_before,
        cells_after: memory.cells.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> (MemoryPool, ForecastReport) {
        let mut memory = MemoryPool::new(6);
        let center = vec![0.5; 6];
        let report = forecast(
            &mut memory,
            "ransom.aux",
            &center,
            &LinearDriftModel::default(),
            &ForecastConfig::default(),
        );
        (memory, report)
    }

    #[test]
    fn pre_immunizes_memory() {
        let (memory, report) = run();
        assert_eq!(report.cells_before, 0);
        assert!(
            report.cells_after > 0,
            "forecast must pre-build memory cells"
        );
        assert!(report.projected >= 6);
        assert!(!memory.cells.is_empty());
    }

    #[test]
    fn projected_points_are_bounded_in_family() {
        let center = vec![0.5; 6];
        let drift = LinearDriftModel::default();
        for traj in drift.trajectories(&center, 20) {
            for p in traj {
                let d = agat_antigen::euclidean_distance(&center, &p);
                assert!(
                    d <= drift.max_in_family + 1e-9,
                    "projected point drifted out of family: {d}"
                );
            }
        }
    }

    #[test]
    fn a_future_variant_falls_into_a_prebuilt_cell() {
        let (memory, _r) = run();
        // A point along the first trajectory, within the projected horizon.
        let center = vec![0.5; 6];
        let traj = &LinearDriftModel::default().trajectories(&center, 6)[0];
        let future = &traj[3];
        assert!(
            memory.cells.iter().any(|c| c.matches(future)),
            "a forecast variant should hit a pre-built memory cell"
        );
    }

    #[test]
    fn is_deterministic() {
        let (_m1, r1) = run();
        let (_m2, r2) = run();
        assert_eq!(r1, r2);
    }
}
