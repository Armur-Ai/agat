//! Regulation — digital regulatory T-cells (R4 · living self).
//!
//! A healthy immune system does not only learn; it restrains itself. A
//! detector that begins firing on the host's own benign software is *digital
//! autoimmunity*, and left alone it produces a false-positive storm. The
//! [`Regulator`] tracks per-detector "FP pressure" — up when a detector binds a
//! confirmed-benign sample, decayed when it behaves — and retires any detector
//! whose pressure crosses a threshold, **before** it causes an outage.
//!
//! Detectors are addressed by their stable [`Detector::detector_id`], so the
//! regulator survives (de)serialization and model merges. Everything is
//! deterministic.

use crate::detectors::Repertoire;
use std::collections::HashMap;

/// Tuning for the regulatory layer.
#[derive(Debug, Clone)]
pub struct RegConfig {
    /// Retire a detector once its FP pressure reaches this.
    pub fp_threshold: f64,
    /// Pressure added each time a detector fires on confirmed-benign input.
    pub fp_weight: f64,
    /// Multiplicative decay applied when a detector behaves (did not misfire).
    pub reward_decay: f64,
}

impl Default for RegConfig {
    fn default() -> Self {
        Self {
            fp_threshold: 3.0,
            fp_weight: 1.0,
            reward_decay: 0.5,
        }
    }
}

/// Accumulates FP pressure per detector and retires chronic offenders.
#[derive(Debug, Clone, Default)]
pub struct Regulator {
    pressure: HashMap<String, f64>,
}

impl Regulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation of `detector_id`: it either misfired on a
    /// confirmed-benign sample (pressure up) or behaved (pressure decays).
    pub fn observe(&mut self, detector_id: &str, fired_on_benign: bool, cfg: &RegConfig) {
        let p = self.pressure.entry(detector_id.to_string()).or_insert(0.0);
        if fired_on_benign {
            *p += cfg.fp_weight;
        } else {
            *p *= cfg.reward_decay;
        }
    }

    /// Current FP pressure for a detector (0 if never observed).
    pub fn pressure_of(&self, detector_id: &str) -> f64 {
        self.pressure.get(detector_id).copied().unwrap_or(0.0)
    }

    /// Retire every detector whose pressure has reached the threshold. Returns
    /// the retired detector ids (sorted, for determinism) and drops them from
    /// both the repertoire and the pressure map.
    pub fn sweep(&mut self, repertoire: &mut Repertoire, cfg: &RegConfig) -> Vec<String> {
        let mut retired: Vec<String> = self
            .pressure
            .iter()
            .filter(|(_, &p)| p >= cfg.fp_threshold)
            .map(|(id, _)| id.clone())
            .collect();
        retired.sort();
        if retired.is_empty() {
            return retired;
        }
        let retired_set: std::collections::HashSet<&String> = retired.iter().collect();
        repertoire
            .detectors
            .retain(|d| !retired_set.contains(&d.detector_id()));
        for id in &retired {
            self.pressure.remove(id);
        }
        retired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{Detector, DetectorOrigin};

    #[test]
    fn pressure_accumulates_and_decays() {
        let mut reg = Regulator::new();
        let cfg = RegConfig::default();
        reg.observe("d1", true, &cfg);
        reg.observe("d1", true, &cfg);
        assert_eq!(reg.pressure_of("d1"), 2.0);
        reg.observe("d1", false, &cfg); // behaved → halves
        assert_eq!(reg.pressure_of("d1"), 1.0);
    }

    #[test]
    fn sweep_retires_an_autoreactive_detector() {
        let mut rep = Repertoire::new(2);
        let good = Detector::new(vec![0.9, 0.9], 0.2, DetectorOrigin::NegativeSelection);
        let bad = Detector::new(vec![0.1, 0.1], 0.2, DetectorOrigin::NegativeSelection);
        rep.detectors.push(good.clone());
        rep.detectors.push(bad.clone());

        let mut reg = Regulator::new();
        let cfg = RegConfig::default();
        // The bad detector keeps firing on benign input.
        for _ in 0..3 {
            reg.observe(&bad.detector_id(), true, &cfg);
        }
        reg.observe(&good.detector_id(), true, &cfg); // one blip, under threshold

        let retired = reg.sweep(&mut rep, &cfg);
        assert_eq!(retired, vec![bad.detector_id()]);
        assert_eq!(rep.len(), 1, "only the autoreactive detector is retired");
        assert_eq!(rep.detectors[0].detector_id(), good.detector_id());
    }
}
