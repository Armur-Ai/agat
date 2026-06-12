//! Recognition — matching an unknown antigen against the repertoire.
//!
//! This is the immune response proper: an unknown sample's antigen is
//! presented to the detector repertoire, and any detector whose
//! recognition ball contains the antigen *binds* it. A binding means
//! the antigen is **non-self** — outside the benign region the
//! repertoire was selected against. If a binding detector has been
//! matured onto a known family (by clonal selection, Stage 5), the
//! binding also **identifies** that family; and if the binder is a
//! long-lived **memory cell**, the response is a fast *secondary*
//! response, the hallmark of immunological memory.
//!
//! Recognition reports the binding affinity (1.0 at a detector's
//! center, 0.0 on its surface) and — for honesty about *why* a sample
//! is non-self — how far the antigen sits from the self surface.

use crate::detectors::{DetectorOrigin, Repertoire};
use crate::self_model::SelfModel;
use agat_antigen::Antigen;

/// The strongest detector that bound the antigen.
#[derive(Debug, Clone)]
pub struct DetectorMatch {
    /// Binding affinity in `[0, 1]` (the antigen is inside the ball, so
    /// non-negative): 1.0 at the center, 0.0 on the surface.
    pub affinity: f64,
    pub family: Option<String>,
    pub generation: u32,
    pub origin: DetectorOrigin,
    /// Index of the detector within the repertoire (for provenance).
    pub detector_index: usize,
}

/// The outcome of presenting an antigen to the repertoire.
#[derive(Debug, Clone)]
pub struct Recognition {
    /// Whether any detector bound the antigen (non-self).
    pub recognized: bool,
    /// Number of detectors that bound.
    pub bound_count: usize,
    /// The highest-affinity binding detector, if any.
    pub best: Option<DetectorMatch>,
    /// The identified family: the family of the highest-affinity binder
    /// that carries a family label. `None` ⇒ recognized as non-self but
    /// not attributed to a known family (pure anomaly).
    pub family: Option<String>,
    /// Whether the family attribution came from a memory cell — i.e. a
    /// fast secondary response.
    pub from_memory: bool,
    /// Signed distance from the self surface (from the self-model):
    /// positive ⇒ outside self by that margin. Context for *why* this
    /// is non-self; `None` when no self-model is supplied.
    pub self_surface_distance: Option<f64>,
}

impl Recognition {
    /// A compact human label for the recognition outcome.
    pub fn verdict(&self) -> &'static str {
        match (self.recognized, &self.family, self.from_memory) {
            (false, _, _) => "self / unrecognized",
            (true, Some(_), true) => "non-self — family (secondary response)",
            (true, Some(_), false) => "non-self — family identified",
            (true, None, _) => "non-self — anomaly (no family)",
        }
    }
}

/// Present `antigen` to `repertoire`, optionally with a `self_model`
/// for anomaly-magnitude context. Memory cells, if any, are expected to
/// live in the same repertoire flagged with [`DetectorOrigin::Memory`]
/// (the CLI merges naive, matured, and memory detectors before calling
/// this), so a single pass handles primary and secondary responses.
pub fn recognize(
    antigen: &Antigen,
    repertoire: &Repertoire,
    self_model: Option<&SelfModel>,
) -> Recognition {
    let sig = &antigen.signature;

    let mut bound_count = 0usize;
    let mut best: Option<DetectorMatch> = None;
    // Best *family-bearing* binder, preferring memory cells, then higher
    // affinity — this drives family attribution and secondary-response
    // detection independently of the single strongest binder.
    let mut best_family: Option<DetectorMatch> = None;

    for (i, d) in repertoire.detectors.iter().enumerate() {
        if !d.matches(sig) {
            continue;
        }
        bound_count += 1;
        let m = DetectorMatch {
            affinity: d.affinity(sig).clamp(0.0, 1.0),
            family: d.family.clone(),
            generation: d.generation,
            origin: d.origin,
            detector_index: i,
        };
        if best.as_ref().map_or(true, |b| m.affinity > b.affinity) {
            best = Some(m.clone());
        }
        if m.family.is_some() && better_family_candidate(&best_family, &m) {
            best_family = Some(m);
        }
    }

    let recognized = bound_count > 0;
    let from_memory = best_family
        .as_ref()
        .map_or(false, |m| m.origin == DetectorOrigin::Memory);
    let family = best_family.as_ref().and_then(|m| m.family.clone());
    let self_surface_distance = self_model.and_then(|sm| sm.surface_distance(sig));

    Recognition {
        recognized,
        bound_count,
        best,
        family,
        from_memory,
        self_surface_distance,
    }
}

/// A family-bearing binder is preferred if we have none yet, or if it is
/// a memory cell and the incumbent is not (secondary response wins), or
/// — within the same memory tier — if it binds with higher affinity.
fn better_family_candidate(incumbent: &Option<DetectorMatch>, cand: &DetectorMatch) -> bool {
    match incumbent {
        None => true,
        Some(inc) => {
            let inc_mem = inc.origin == DetectorOrigin::Memory;
            let cand_mem = cand.origin == DetectorOrigin::Memory;
            match (cand_mem, inc_mem) {
                (true, false) => true,
                (false, true) => false,
                _ => cand.affinity > inc.affinity,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{Detector, DetectorOrigin};

    fn ag(sig: &[f64]) -> Antigen {
        Antigen {
            signature: sig.to_vec(),
            block_tokens: Default::default(),
            cfg_fingerprint: None,
            plaintext_fingerprint: None,
        }
    }

    fn detector(center: &[f64], radius: f64, family: Option<&str>, origin: DetectorOrigin) -> Detector {
        let mut d = Detector::new(center.to_vec(), radius, origin);
        d.family = family.map(|s| s.to_string());
        d
    }

    #[test]
    fn binds_and_reports_affinity() {
        let mut rep = Repertoire::new(2);
        rep.detectors
            .push(detector(&[1.0, 1.0], 0.5, None, DetectorOrigin::NegativeSelection));
        let r = recognize(&ag(&[1.0, 1.0]), &rep, None);
        assert!(r.recognized);
        assert_eq!(r.bound_count, 1);
        assert!((r.best.unwrap().affinity - 1.0).abs() < 1e-9); // at center
        assert!(r.family.is_none()); // anomaly, no family
    }

    #[test]
    fn unrecognized_when_far() {
        let mut rep = Repertoire::new(2);
        rep.detectors
            .push(detector(&[1.0, 1.0], 0.3, None, DetectorOrigin::NegativeSelection));
        let r = recognize(&ag(&[0.0, 0.0]), &rep, None);
        assert!(!r.recognized);
        assert_eq!(r.verdict(), "self / unrecognized");
    }

    #[test]
    fn family_attribution_prefers_memory_cell() {
        // A naive binder, a matured clone with family "alpha", and a
        // memory cell also for "alpha" — all bind. Family must come from
        // the memory cell, and from_memory must be true.
        let mut rep = Repertoire::new(2);
        rep.detectors
            .push(detector(&[0.0, 0.0], 1.0, None, DetectorOrigin::NegativeSelection));
        rep.detectors
            .push(detector(&[0.0, 0.0], 0.9, Some("alpha"), DetectorOrigin::Clone));
        rep.detectors
            .push(detector(&[0.0, 0.0], 0.8, Some("alpha"), DetectorOrigin::Memory));
        let r = recognize(&ag(&[0.05, 0.0]), &rep, None);
        assert!(r.recognized);
        assert_eq!(r.family.as_deref(), Some("alpha"));
        assert!(r.from_memory);
        assert_eq!(r.verdict(), "non-self — family (secondary response)");
    }

    #[test]
    fn surface_distance_is_reported_with_self_model() {
        let benign = [ag(&[0.1, 0.1]), ag(&[0.12, 0.08])];
        let labelled: Vec<(String, &Antigen)> =
            benign.iter().enumerate().map(|(i, a)| (i.to_string(), a)).collect();
        let sm = SelfModel::build(&labelled, 1);
        let mut rep = Repertoire::new(2);
        rep.detectors
            .push(detector(&[0.9, 0.9], 0.4, None, DetectorOrigin::NegativeSelection));
        let r = recognize(&ag(&[0.9, 0.9]), &rep, Some(&sm));
        assert!(r.recognized);
        assert!(r.self_surface_distance.unwrap() > 0.5);
    }
}
