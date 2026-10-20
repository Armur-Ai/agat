//! Memory cells — the matured, long-lived, family-specific detectors.
//!
//! Clonal selection promotes its best matured detectors to **memory
//! cells**: persistent, high-affinity detectors that give a fast
//! *secondary response* to a family it has met before. A memory cell is
//! the computational analogue of a memory B/T-cell.
//!
//! Crucially for generalization, a memory cell is not a point — it is a
//! **covering ball** over a family's confirmed variants. Its center is
//! the running centroid of the matured variant signatures it has
//! incorporated, and its radius grows to cover their spread plus a
//! generalization slack. That slack is exactly what lets a memory cell
//! recognize a *new* variant of the family it has never seen, as long
//! as that variant lands in the family's signature neighborhood — i.e.
//! generalization, not memorization.

use crate::detectors::{Detector, DetectorOrigin};
use agat_antigen::euclidean_distance;
use serde::{Deserialize, Serialize};

/// A matured, family-labelled covering ball in signature space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCell {
    pub family: String,
    /// Running centroid of the incorporated variant signatures.
    pub center: Vec<f64>,
    /// Recognition radius: `(base_radius + spread) * generalization`.
    pub radius: f64,
    /// Estimated spread — the radius needed to cover the variants seen
    /// so far (a running max over incorporated centers).
    pub spread: f64,
    /// How many confirmed variants have been incorporated.
    pub variants: u32,
    /// Clonal-selection generation (incremented per maturation).
    pub generation: u32,
    /// The matured variant points incorporated so far, kept so `spread`
    /// is the exact covering distance rather than an ever-growing bound.
    /// Empty for cells persisted before this field existed; those fall
    /// back to the incremental bound.
    #[serde(default)]
    pub members: Vec<Vec<f64>>,
}

impl MemoryCell {
    /// A fresh memory cell from the first matured variant of a family.
    pub fn new(family: String, center: Vec<f64>, base_radius: f64, generalization: f64) -> Self {
        Self {
            family,
            members: vec![center.clone()],
            center,
            radius: base_radius * generalization,
            spread: 0.0,
            variants: 1,
            generation: 1,
        }
    }

    /// Incorporate another confirmed variant: move the center toward the
    /// running centroid, grow the spread to keep covering the variants
    /// seen so far, and recompute the radius (with generalization slack).
    pub fn incorporate(&mut self, point: &[f64], base_radius: f64, generalization: f64) {
        let n = self.variants as f64;
        let new_n = n + 1.0;
        let new_center: Vec<f64> = self
            .center
            .iter()
            .zip(point.iter())
            .map(|(c, p)| (c * n + p) / new_n)
            .collect();
        if self.members.is_empty() {
            // Legacy cell without member points: when the centroid shifts,
            // the old covering radius must grow by that shift to still
            // cover previously-incorporated variants (an upper bound).
            let shift = euclidean_distance(&self.center, &new_center);
            let d_new = euclidean_distance(&new_center, point);
            self.spread = (self.spread + shift).max(d_new);
        } else {
            // Exact: the farthest incorporated variant from the new center.
            self.members.push(point.to_vec());
            self.spread = self
                .members
                .iter()
                .map(|m| euclidean_distance(&new_center, m))
                .fold(0.0, f64::max);
        }
        self.center = new_center;
        self.variants += 1;
        self.generation += 1;
        self.radius = (base_radius + self.spread) * generalization;
    }

    pub fn matches(&self, sig: &[f64]) -> bool {
        euclidean_distance(&self.center, sig) <= self.radius
    }

    /// View this memory cell as a detector for the recognition pass.
    pub fn to_detector(&self) -> Detector {
        Detector {
            center: self.center.clone(),
            radius: self.radius,
            generation: self.generation,
            family: Some(self.family.clone()),
            origin: DetectorOrigin::Memory,
            age: 0,
        }
    }
}

/// The pool of memory cells across all families.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryPool {
    pub dim: usize,
    pub cells: Vec<MemoryCell>,
}

impl MemoryPool {
    pub fn new(dim: usize) -> Self {
        Self { dim, cells: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    pub fn families(&self) -> Vec<&str> {
        let mut fs: Vec<&str> = self.cells.iter().map(|c| c.family.as_str()).collect();
        fs.sort_unstable();
        fs.dedup();
        fs
    }

    /// All memory cells as detectors, for merging into a recognition pass.
    pub fn detectors(&self) -> Vec<Detector> {
        self.cells.iter().map(|c| c.to_detector()).collect()
    }

    /// Index of the memory cell of `family` nearest to `point`, if any.
    pub fn nearest_family_cell(&self, family: &str, point: &[f64]) -> Option<usize> {
        self.cells
            .iter()
            .enumerate()
            .filter(|(_, c)| c.family == family)
            .min_by(|a, b| {
                euclidean_distance(&a.1.center, point)
                    .partial_cmp(&euclidean_distance(&b.1.center, point))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incorporation_grows_the_covering_ball() {
        let mut cell = MemoryCell::new("fam".into(), vec![0.5, 0.5], 0.05, 1.5);
        let r0 = cell.radius;
        cell.incorporate(&[0.7, 0.5], 0.05, 1.5);
        cell.incorporate(&[0.3, 0.5], 0.05, 1.5);
        assert!(cell.radius > r0, "radius must grow as variants spread out");
        assert_eq!(cell.variants, 3);
        // The center stays near the family centroid.
        assert!((cell.center[0] - 0.5).abs() < 0.1);
    }

    #[test]
    fn spread_is_the_exact_covering_distance() {
        // Variants at 0.4 / 0.5 / 0.6 on one axis: centroid 0.5, so the
        // exact spread is 0.1 — not the sum of every centroid shift.
        let mut cell = MemoryCell::new("fam".into(), vec![0.4, 0.0], 0.05, 1.0);
        cell.incorporate(&[0.6, 0.0], 0.05, 1.0);
        cell.incorporate(&[0.5, 0.0], 0.05, 1.0);
        assert!((cell.center[0] - 0.5).abs() < 1e-9);
        assert!((cell.spread - 0.1).abs() < 1e-9, "spread {}", cell.spread);
        assert!((cell.radius - 0.15).abs() < 1e-9);
        // Every incorporated variant is still covered.
        for m in [[0.4, 0.0], [0.5, 0.0], [0.6, 0.0]] {
            assert!(cell.matches(&m));
        }
    }

    #[test]
    fn legacy_cell_without_members_keeps_the_bound() {
        let mut cell = MemoryCell::new("fam".into(), vec![0.4, 0.0], 0.05, 1.0);
        cell.members.clear(); // as deserialized from an older store
        cell.incorporate(&[0.6, 0.0], 0.05, 1.0);
        assert!(cell.members.is_empty());
        assert!(cell.matches(&[0.4, 0.0]) && cell.matches(&[0.6, 0.0]));
    }

    #[test]
    fn to_detector_carries_family_and_memory_origin() {
        let cell = MemoryCell::new("fam".into(), vec![0.0], 0.1, 1.0);
        let d = cell.to_detector();
        assert_eq!(d.family.as_deref(), Some("fam"));
        assert_eq!(d.origin, DetectorOrigin::Memory);
    }
}
