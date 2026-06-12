//! Clonal selection and affinity maturation — CLONALG.
//!
//! de Castro & Von Zuben, *Learning and Optimization Using the Clonal
//! Selection Principle (CLONALG)*, IEEE Trans. Evol. Comput. 2002.
//!
//! When a confirmed variant of a known family is ingested, the immune
//! system mounts an adaptive response: the detectors that already bind
//! the antigen best are **cloned** in proportion to their affinity, and
//! each clone is **hypermutated** with a rate *inversely* proportional
//! to its affinity (high-affinity clones explore locally; low-affinity
//! clones explore widely). The best matured clone is selected and
//! promoted to a [`MemoryCell`]. Over successive variants the family's
//! memory cell becomes a covering ball over the family's neighborhood —
//! so agat recognizes variants it has never seen.
//!
//! This is the stage where agat *measurably generalizes*: see the
//! `generalizes_to_held_out_variant` test, the computational form of the
//! README's central claim.

use crate::detectors::Repertoire;
use crate::memory::{MemoryCell, MemoryPool};
use agat_antigen::{euclidean_distance, Antigen};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// CLONALG parameters.
#[derive(Debug, Clone, Copy)]
pub struct ClonalConfig {
    /// Total clone budget per generation (distributed across parents in
    /// proportion to affinity).
    pub clone_count: usize,
    /// Number of parent candidates carried between generations.
    pub selection: usize,
    /// CLONALG iterations per maturation.
    pub generations: usize,
    /// Base hypermutation magnitude (scaled by `1 - affinity` per clone).
    pub mutation_scale: f64,
    /// How strongly a clone is pulled toward the antigen each step
    /// (affinity maturation), in `[0, 1]`.
    pub learning_rate: f64,
    /// Memory-cell radius for a single-variant family, before spread.
    pub base_radius: f64,
    /// Slack multiplier (≥ 1) applied to the covering radius — the
    /// generalization knob.
    pub generalization: f64,
    /// Max memory cells retained per family.
    pub max_memory_per_family: usize,
    pub seed: u64,
}

impl Default for ClonalConfig {
    fn default() -> Self {
        Self {
            clone_count: 30,
            selection: 4,
            generations: 6,
            mutation_scale: 0.15,
            learning_rate: 0.5,
            base_radius: 0.05,
            generalization: 1.5,
            max_memory_per_family: 2,
            seed: 0xC10A_1234_5678_9001,
        }
    }
}

/// What a single maturation produced.
#[derive(Debug, Clone)]
pub struct Maturation {
    pub family: String,
    /// Variants incorporated into the responsible memory cell so far.
    pub variants: u32,
    /// The memory cell's current covering radius.
    pub radius: f64,
    /// Total memory cells for this family after maturation.
    pub family_cells: usize,
    /// Distance from the matured detector center to the antigen — a
    /// measure of affinity-maturation quality (smaller is better).
    pub matured_distance: f64,
    /// Whether this maturation created a brand-new memory cell.
    pub new_cell: bool,
}

/// Affinity-mature the repertoire onto a confirmed `family` variant and
/// promote the result into `memory`. `repertoire`, if given, seeds the
/// clonal search with the nearest existing detectors (reusing innate
/// coverage); otherwise the search seeds from the antigen itself.
pub fn mature(
    antigen: &Antigen,
    family: &str,
    memory: &mut MemoryPool,
    repertoire: Option<&Repertoire>,
    cfg: &ClonalConfig,
) -> Maturation {
    let sig = &antigen.signature;
    if memory.dim == 0 {
        memory.dim = sig.len();
    }
    // Deterministic, but varied per family and per maturation count.
    let mut rng = StdRng::seed_from_u64(
        cfg.seed ^ fnv1a(family.as_bytes()) ^ (memory.cells.len() as u64).wrapping_mul(0x9E3779B1),
    );

    // Seed the clonal search: existing family memory cells + nearest
    // naive detectors.
    let mut seeds: Vec<Vec<f64>> = memory
        .cells
        .iter()
        .filter(|c| c.family == family)
        .map(|c| c.center.clone())
        .collect();
    if let Some(rep) = repertoire {
        let mut by_dist: Vec<&crate::detectors::Detector> = rep.detectors.iter().collect();
        by_dist.sort_by(|a, b| {
            a.distance(sig)
                .partial_cmp(&b.distance(sig))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for d in by_dist.into_iter().take(cfg.selection) {
            seeds.push(d.center.clone());
        }
    }

    let matured = clonal_optimize(sig, &seeds, cfg, &mut rng);
    let matured_distance = euclidean_distance(&matured, sig);

    // Integrate the matured detector into memory: grow the nearest
    // same-family cell, or create a new one (capped per family).
    let new_cell;
    match memory.nearest_family_cell(family, &matured) {
        Some(i) => {
            memory.cells[i].incorporate(&matured, cfg.base_radius, cfg.generalization);
            new_cell = false;
        }
        None => {
            memory.cells.push(MemoryCell::new(
                family.to_string(),
                matured.clone(),
                cfg.base_radius,
                cfg.generalization,
            ));
            new_cell = true;
            // Retire the oldest family cell if over capacity.
            retire_over_capacity(memory, family, cfg.max_memory_per_family);
        }
    }

    let family_cells = memory.cells.iter().filter(|c| c.family == family).count();
    let cell = memory
        .nearest_family_cell(family, &matured)
        .map(|i| &memory.cells[i]);
    Maturation {
        family: family.to_string(),
        variants: cell.map(|c| c.variants).unwrap_or(0),
        radius: cell.map(|c| c.radius).unwrap_or(0.0),
        family_cells,
        matured_distance,
        new_cell,
    }
}

/// The CLONALG optimization loop: clone ∝ affinity, hypermutate ∝
/// `1 - affinity`, pull toward the antigen, select the best. Returns the
/// matured detector center (high affinity to the antigen).
fn clonal_optimize(
    antigen: &[f64],
    seeds: &[Vec<f64>],
    cfg: &ClonalConfig,
    rng: &mut StdRng,
) -> Vec<f64> {
    let dim = antigen.len();
    let mut pool: Vec<Vec<f64>> = if seeds.is_empty() {
        vec![antigen.to_vec()]
    } else {
        seeds.to_vec()
    };
    let mut best = pool[0].clone();
    let mut best_d = euclidean_distance(&best, antigen);

    for _ in 0..cfg.generations.max(1) {
        let mut clones: Vec<Vec<f64>> = Vec::new();
        for c in &pool {
            let d = euclidean_distance(c, antigen);
            let affinity = 1.0 / (1.0 + d); // (0, 1]
            let n_clones = ((cfg.clone_count as f64) * affinity).round().max(1.0) as usize;
            let mutation = cfg.mutation_scale * (1.0 - affinity);
            for _ in 0..n_clones {
                let mut clone = c.clone();
                for i in 0..dim {
                    // Affinity maturation: step toward the antigen...
                    clone[i] += cfg.learning_rate * (antigen[i] - clone[i]);
                    // ...then hypermutate, inversely proportional to affinity.
                    if mutation > 0.0 {
                        clone[i] += rng.gen_range(-mutation..mutation);
                    }
                }
                clones.push(clone);
            }
        }
        clones.extend(pool.iter().cloned());
        clones.sort_by(|x, y| {
            euclidean_distance(x, antigen)
                .partial_cmp(&euclidean_distance(y, antigen))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        clones.truncate(cfg.selection.max(1));
        pool = clones;
        let d0 = euclidean_distance(&pool[0], antigen);
        if d0 < best_d {
            best_d = d0;
            best = pool[0].clone();
        }
    }
    best
}

fn retire_over_capacity(memory: &mut MemoryPool, family: &str, cap: usize) {
    let cap = cap.max(1);
    loop {
        let count = memory.cells.iter().filter(|c| c.family == family).count();
        if count <= cap {
            break;
        }
        // Retire the lowest-generation (least-reinforced) family cell.
        if let Some((idx, _)) = memory
            .cells
            .iter()
            .enumerate()
            .filter(|(_, c)| c.family == family)
            .min_by_key(|(_, c)| c.generation)
        {
            memory.cells.remove(idx);
        } else {
            break;
        }
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recognition::recognize;
    use crate::Repertoire;

    fn ag(p: &[f64]) -> Antigen {
        Antigen {
            signature: p.to_vec(),
            block_tokens: Default::default(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    fn recognize_against_memory(memory: &MemoryPool, probe: &Antigen) -> crate::Recognition {
        let rep = Repertoire { dim: memory.dim, detectors: memory.detectors() };
        recognize(probe, &rep, None)
    }

    #[test]
    fn affinity_maturation_converges_to_the_antigen() {
        let cfg = ClonalConfig::default();
        let mut rng = StdRng::seed_from_u64(1);
        // Start far from the antigen; CLONALG should pull a clone in close.
        let best = clonal_optimize(&[0.5, 0.5], &[vec![0.0, 0.0]], &cfg, &mut rng);
        assert!(euclidean_distance(&best, &[0.5, 0.5]) < 0.05);
    }

    #[test]
    fn generalizes_to_held_out_variant() {
        // The headline claim. A family lives on a ring of variants
        // around (0.5, 0.5). We mature on five of them and HOLD OUT a
        // sixth the system never sees. Recognition of the held-out
        // variant must improve as the repertoire matures, and end in a
        // confident, family-attributed hit — generalization, not
        // memorization. A far-away other family must NOT be recognized.
        let cfg = ClonalConfig::default();
        let train = [
            [0.65, 0.50],
            [0.35, 0.50],
            [0.50, 0.65],
            [0.50, 0.35],
            [0.60, 0.60],
        ];
        let held_out = [0.40, 0.62]; // on the family ring, never matured
        let other_family = [0.05, 0.95]; // a different family, far away

        let mut memory = MemoryPool::new(2);
        let mut affinities = Vec::new();
        let mut recognized = Vec::new();
        for v in &train {
            mature(&ag(v), "famA", &mut memory, None, &cfg);
            let r = recognize_against_memory(&memory, &ag(&held_out));
            recognized.push(r.recognized);
            affinities.push(r.best.map(|b| b.affinity).unwrap_or(0.0));
        }

        // Started unable to recognize the held-out variant...
        assert!(!recognized[0], "one variant should not yet cover the held-out variant");
        // ...ended recognizing it, attributed to the family, via memory.
        let final_r = recognize_against_memory(&memory, &ag(&held_out));
        assert!(final_r.recognized, "held-out variant should be recognized after maturation");
        assert_eq!(final_r.family.as_deref(), Some("famA"));
        assert!(final_r.from_memory);

        // Generalization improved monotonically-ish: end affinity beats start.
        assert!(
            affinities.last().unwrap() > &affinities[0],
            "recognition of the unseen variant should strengthen as more variants mature in: {affinities:?}"
        );

        // No overgeneralization: a far-off different family stays unseen.
        let other = recognize_against_memory(&memory, &ag(&other_family));
        assert!(!other.recognized, "a different family must not be swallowed by famA's memory");
    }

    #[test]
    fn capacity_is_bounded_per_family() {
        let mut cfg = ClonalConfig::default();
        cfg.max_memory_per_family = 1;
        let mut memory = MemoryPool::new(2);
        // Two distant "sub-clusters" of the same family; with cap 1 only
        // one cell survives (the search keeps merging into the nearest).
        for v in &[[0.1, 0.1], [0.1, 0.12], [0.9, 0.9], [0.9, 0.88]] {
            mature(&ag(v), "famA", &mut memory, None, &cfg);
        }
        let cells = memory.cells.iter().filter(|c| c.family == "famA").count();
        assert!(cells <= 1, "per-family memory must respect the cap, got {cells}");
    }
}
