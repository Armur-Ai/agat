//! The germinal center — self-play affinity maturation (R2).
//!
//! A bounded, deterministic **generate → test → promote** loop. A synthetic
//! adversary (the [`agat_antigen::mutate`] operators) produces variant
//! antigens of known families; the ones that **evade** the current model —
//! not covered by any detector and not matched by any memory cell — are the
//! valuable ones, and are absorbed by clonal selection ([`crate::clonal::mature`]).
//! Over generations, coverage of the family's mutation neighborhood climbs and
//! the gaps the adversary found are sealed.
//!
//! Everything is synthetic and in antigen space (see the defensive-only note in
//! [`agat_antigen::mutate`]) and fully seeded, so a run is reproducible.
//!
//! This is the reactive half of the roadmap; the proactive twin is
//! [`crate::forecast`] (R3).

use crate::clonal::{mature, ClonalConfig};
use crate::detectors::Repertoire;
use crate::memory::MemoryPool;
use agat_antigen::{variant_batch, Antigen};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Parameters for a self-play run. All stochastic steps derive from `seed`.
#[derive(Debug, Clone)]
pub struct EvolveConfig {
    /// How many generations to run.
    pub generations: usize,
    /// Variants synthesized per seed family, per generation.
    pub population: usize,
    /// Stop early once a generation's coverage reaches this (in `[0, 1]`).
    pub coverage_target: f64,
    /// Clonal-selection config used to absorb evaders.
    pub clonal: ClonalConfig,
    pub seed: u64,
}

impl Default for EvolveConfig {
    fn default() -> Self {
        Self {
            generations: 5,
            population: 16,
            coverage_target: 0.995,
            clonal: ClonalConfig::default(),
            seed: 0xE001_1E55_0000_0001,
        }
    }
}

/// What one generation of self-play produced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GenerationReport {
    pub generation: usize,
    /// Variants synthesized this generation.
    pub generated: usize,
    /// Variants the current model already caught.
    pub caught: usize,
    /// Variants that evaded and were absorbed.
    pub evaded: usize,
    /// Fraction caught, `caught / generated`.
    pub coverage: f64,
}

/// The full run report — a coverage curve plus the final model state counts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvolveReport {
    pub generations: Vec<GenerationReport>,
    /// Memory cells before / after the run.
    pub cells_before: usize,
    pub cells_after: usize,
    pub seed: u64,
}

impl EvolveReport {
    /// Coverage of the first and last generations — the headline climb.
    pub fn coverage_climb(&self) -> Option<(f64, f64)> {
        Some((
            self.generations.first()?.coverage,
            self.generations.last()?.coverage,
        ))
    }
}

/// Is `sig` caught by the current model (a detector binds, or a memory cell of
/// `family` matches)?
fn caught(repertoire: &Repertoire, memory: &MemoryPool, family: &str, sig: &[f64]) -> bool {
    repertoire.covers(sig)
        || memory
            .cells
            .iter()
            .any(|c| c.family == family && c.matches(sig))
}

/// Run a self-play maturation loop against `memory` (mutated in place), using
/// `repertoire` as the fixed innate layer and `seeds` (family-labelled parent
/// antigens) as the families to harden. Returns a deterministic report.
pub fn evolve(
    memory: &mut MemoryPool,
    repertoire: &Repertoire,
    seeds: &[(String, Antigen)],
    cfg: &EvolveConfig,
) -> EvolveReport {
    let cells_before = memory.cells.len();
    let mut generations = Vec::with_capacity(cfg.generations);

    for g in 0..cfg.generations {
        // Per-generation seeded rng, so the run is reproducible.
        let mut rng = StdRng::seed_from_u64(cfg.seed ^ (g as u64).wrapping_mul(0x9E3779B97F4A7C15));
        let mut generated = 0usize;
        let mut caught_n = 0usize;
        // Collect evaders first so maturation does not change mid-generation
        // the model that later variants this generation are tested against.
        let mut evaders: Vec<(String, Antigen)> = Vec::new();

        for (family, parent) in seeds {
            for v in variant_batch(parent, &mut rng, cfg.population) {
                generated += 1;
                if caught(repertoire, memory, family, &v.signature) {
                    caught_n += 1;
                } else {
                    evaders.push((family.clone(), v));
                }
            }
        }

        // Absorb the evaders (clonal selection) — this is where coverage grows.
        for (family, antigen) in &evaders {
            mature(antigen, family, memory, Some(repertoire), &cfg.clonal);
        }

        let coverage = if generated == 0 {
            1.0
        } else {
            caught_n as f64 / generated as f64
        };
        generations.push(GenerationReport {
            generation: g + 1,
            generated,
            caught: caught_n,
            evaded: evaders.len(),
            coverage,
        });
        if coverage >= cfg.coverage_target {
            break;
        }
    }

    EvolveReport {
        generations,
        cells_before,
        cells_after: memory.cells.len(),
        seed: cfg.seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn antigen(center: f64) -> Antigen {
        Antigen {
            signature: vec![center; 6],
            block_tokens: BTreeSet::new(),
            cfg_fingerprint: Some("deadbeefdeadbeef".into()),
            plaintext_fingerprint: Some("feedfacefeedface".into()),
        }
    }

    fn run() -> (MemoryPool, EvolveReport) {
        let mut memory = MemoryPool::new(6);
        let repertoire = Repertoire::new(6); // empty innate layer: everything evades at first
        let seeds = vec![("alpha".to_string(), antigen(0.5))];
        let cfg = EvolveConfig {
            generations: 4,
            population: 6,
            coverage_target: 1.01, // never early-stop, so we see all 4 generations
            ..Default::default()
        };
        let report = evolve(&mut memory, &repertoire, &seeds, &cfg);
        (memory, report)
    }

    #[test]
    fn absorbs_evaders_into_memory() {
        let (memory, report) = run();
        assert_eq!(report.cells_before, 0);
        assert!(
            report.cells_after > 0,
            "evaders must be absorbed into memory"
        );
        assert_eq!(memory.cells.len(), report.cells_after);
        assert_eq!(report.generations.len(), 4);
    }

    #[test]
    fn coverage_climbs_across_generations() {
        let (_m, report) = run();
        let (first, last) = report.coverage_climb().unwrap();
        // Generation 1 starts from an empty model (everything evades),
        // later generations catch more as memory fills.
        assert!(first <= last, "coverage should not fall: {first} -> {last}");
        assert!(last > first, "coverage should rise as evaders are absorbed");
    }

    #[test]
    fn is_deterministic_for_a_seed() {
        let (_m1, r1) = run();
        let (_m2, r2) = run();
        assert_eq!(r1, r2, "a seeded run must be bit-for-bit reproducible");
    }
}
