//! The self-model: a description of the benign-behavior region of
//! antigen signature space.
//!
//! In an Artificial Immune System, "self" is the set of patterns the
//! immune system must learn to tolerate — the body's own cells.
//! agat's computational analogue is the set of **benign** behavioral
//! antigens. Negative selection (Forrest et al., 1994) then generates
//! detectors that cover everything *except* this region.
//!
//! We model self the way the real-valued V-detector algorithm (Ji &
//! Dasgupta, 2004) does: not as a single blob, but as a union of balls
//! — one per self sample, each with a **variable radius** equal to the
//! distance to that sample's k-th nearest self neighbor. Dense regions
//! of self get tight balls; sparse self samples get wider ones. A point
//! is "self" if it falls inside any ball (optionally expanded by a
//! tolerance).
//!
//! Honesty note (see docs/AIS_REBUILD_PLAN.md §7): the quality of this
//! model — and therefore of negative selection's coverage — scales with
//! how representative the benign corpus is. With a small corpus this is
//! a complementary anomaly layer, not a completeness guarantee. The
//! geometry below is faithful regardless of corpus size.

use agat_antigen::{euclidean_distance, Antigen};
use serde::{Deserialize, Serialize};

/// One self sample: its signature vector and the radius of the self
/// ball centered on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfPoint {
    pub signature: Vec<f64>,
    /// Distance to this point's k-th nearest self neighbor. The radius
    /// of the tolerated region around this self sample.
    pub radius: f64,
    /// Provenance: the originating sample id (hex), if known.
    pub sample: Option<String>,
}

/// A model of self as a union of variable-radius balls in signature
/// space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfModel {
    /// Signature dimensionality. Antigens queried against this model
    /// must have been built with the same [`agat_antigen::AntigenConfig`].
    pub dim: usize,
    /// Number of nearest neighbors used to size each self ball.
    pub k: usize,
    pub points: Vec<SelfPoint>,
    /// Mean self-ball radius — a convenient default tolerance scale.
    pub mean_radius: f64,
}

impl SelfModel {
    /// Build a self-model from labelled-benign antigens. Each antigen's
    /// self radius is the distance to its k-th nearest self neighbor
    /// (excluding itself). Identical samples (distance 0) are skipped
    /// when sizing radii so duplicates don't collapse a ball to zero.
    pub fn build<S: AsRef<str>>(antigens: &[(S, &Antigen)], k: usize) -> SelfModel {
        let sigs: Vec<&[f64]> = antigens
            .iter()
            .map(|(_, a)| a.signature.as_slice())
            .collect();
        let dim = sigs.first().map(|s| s.len()).unwrap_or(0);
        let k = k.max(1);

        let mut points = Vec::with_capacity(antigens.len());
        for (i, (id, a)) in antigens.iter().enumerate() {
            // Distances to every other self point.
            let mut dists: Vec<f64> = sigs
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, s)| euclidean_distance(&a.signature, s))
                .filter(|d| *d > 0.0)
                .collect();
            dists.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
            // k-th nearest (index k-1). If we have fewer than k distinct
            // neighbors, fall back to the farthest available, or 0.
            let radius = if dists.is_empty() {
                0.0
            } else {
                dists[(k - 1).min(dists.len() - 1)]
            };
            points.push(SelfPoint {
                signature: a.signature.clone(),
                radius,
                sample: Some(id.as_ref().to_string()),
            });
        }

        let mean_radius = if points.is_empty() {
            0.0
        } else {
            points.iter().map(|p| p.radius).sum::<f64>() / points.len() as f64
        };

        SelfModel {
            dim,
            k,
            points,
            mean_radius,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// Euclidean distance from `sig` to the nearest self *center*
    /// (ignores radii). `None` if the model has no points.
    pub fn nearest_center_distance(&self, sig: &[f64]) -> Option<f64> {
        self.points
            .iter()
            .map(|p| euclidean_distance(sig, &p.signature))
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Signed distance to the self *surface*: the minimum over self
    /// balls of `dist(center, sig) − radius`. Negative ⇒ strictly
    /// inside a self ball; zero ⇒ on a surface; positive ⇒ outside all
    /// balls by that margin. `None` if the model is empty.
    ///
    /// This is the quantity negative selection censors against and that
    /// the danger layer reads as a "distance from normal."
    pub fn surface_distance(&self, sig: &[f64]) -> Option<f64> {
        self.points
            .iter()
            .map(|p| euclidean_distance(sig, &p.signature) - p.radius)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    }

    /// Whether `sig` is considered self. `tolerance` expands every self
    /// ball outward (a self-tolerance threshold ≥ 0 admits points just
    /// outside the balls; the immune literature's "self radius"
    /// slack). With the default `tolerance = 0`, self ⇔ inside a ball.
    pub fn is_self(&self, sig: &[f64], tolerance: f64) -> bool {
        match self.surface_distance(sig) {
            Some(d) => d <= tolerance,
            None => false,
        }
    }

    /// Convenience wrapper that reads the signature off an [`Antigen`].
    pub fn is_self_antigen(&self, antigen: &Antigen, tolerance: f64) -> bool {
        self.is_self(&antigen.signature, tolerance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an antigen straight from a signature vector (bypassing the
    /// feature pipeline) so self-model geometry can be tested directly.
    fn ag(sig: &[f64]) -> Antigen {
        Antigen {
            signature: sig.to_vec(),
            block_tokens: Default::default(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    #[test]
    fn benign_cluster_is_self_decryptor_is_not() {
        // A tight cluster of benign behavioral signatures near (0,0).
        let benign = [
            ag(&[0.10, 0.10]),
            ag(&[0.12, 0.09]),
            ag(&[0.08, 0.11]),
            ag(&[0.11, 0.13]),
            ag(&[0.09, 0.08]),
        ];
        let labelled: Vec<(String, &Antigen)> = benign
            .iter()
            .enumerate()
            .map(|(i, a)| (format!("benign{i}"), a))
            .collect();
        let model = SelfModel::build(&labelled, 2);

        // A point inside the benign cluster is self.
        assert!(model.is_self(&[0.10, 0.105], 0.0));
        // A "decryptor" far away in signature space is non-self.
        let decryptor = [0.9, 0.85];
        assert!(!model.is_self(&decryptor, 0.0));
        // Its surface distance is large and positive.
        assert!(model.surface_distance(&decryptor).unwrap() > 0.5);
        // ...while a benign-like point has a small/negative surface dist.
        assert!(model.surface_distance(&[0.10, 0.105]).unwrap() < 0.1);
    }

    #[test]
    fn tolerance_widens_the_self_region() {
        let benign = [ag(&[0.0, 0.0]), ag(&[0.1, 0.0]), ag(&[0.0, 0.1])];
        let labelled: Vec<(String, &Antigen)> = benign
            .iter()
            .enumerate()
            .map(|(i, a)| (i.to_string(), a))
            .collect();
        let model = SelfModel::build(&labelled, 1);
        let probe = [0.4, 0.0];
        // Outside with zero tolerance...
        assert!(!model.is_self(&probe, 0.0));
        // ...inside once tolerance is generous enough.
        assert!(model.is_self(&probe, 0.5));
    }

    #[test]
    fn serializes_round_trip() {
        let benign = [ag(&[0.1, 0.2]), ag(&[0.2, 0.1])];
        let labelled: Vec<(String, &Antigen)> = benign
            .iter()
            .enumerate()
            .map(|(i, a)| (i.to_string(), a))
            .collect();
        let model = SelfModel::build(&labelled, 1);
        let json = serde_json::to_string(&model).unwrap();
        let back: SelfModel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.points.len(), model.points.len());
        assert_eq!(back.dim, model.dim);
    }
}
