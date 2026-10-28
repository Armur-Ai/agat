//! Adaptive inflammation — local, bounded danger signaling (R5).
//!
//! Danger assessment ([`crate::danger`]) is stateless per sample. This module
//! makes it *locally* adaptive: a strong danger reading in some neighborhood of
//! antigen space releases a "cytokine" that transiently raises sensitivity for
//! *related* samples (tightens the danger gate), then decays back to baseline.
//! The system becomes more paranoid exactly where it is being probed.
//!
//! The dangerous half of the metaphor is a real cytokine storm, which kills the
//! host — so the bounds here are the point, not an afterthought:
//!
//! - every modulation is clamped to `max_gain` (sensitivity can never run away);
//! - the total field heat is capped at `global_cap` (no fleet-wide escalation);
//! - heat decays with a configurable half-life (self-limiting).
//!
//! It is **opt-in and identity-preserving**: with an empty/zero field,
//! [`Cytokines::modulate`] returns the base config unchanged, so the default
//! scan path stays byte-for-byte deterministic and air-gapped.

use crate::danger::DangerConfig;
use std::collections::HashMap;

/// Hard bounds and dynamics for the inflammatory field.
#[derive(Debug, Clone)]
pub struct InflamConfig {
    /// Maximum fractional tightening of the danger gate (0.0–1.0).
    pub max_gain: f64,
    /// Scans over which heat halves (decay half-life).
    pub half_life_scans: f64,
    /// Maximum strength accepted from a single `emit` (rate limit).
    pub emit_limit: f64,
    /// Cap on the *sum* of all neighborhood heat — the anti-DoS bound.
    pub global_cap: f64,
}

impl Default for InflamConfig {
    fn default() -> Self {
        Self {
            max_gain: 0.4,
            half_life_scans: 50.0,
            emit_limit: 0.5,
            global_cap: 2.0,
        }
    }
}

/// The inflammatory field: heat per neighborhood of antigen space.
#[derive(Debug, Clone, Default)]
pub struct Cytokines {
    field: HashMap<String, f64>,
}

/// Coarse bucket key for a signature, so "related" samples share a
/// neighborhood. Quantized to a coarse grid and hashed to a short, stable key.
pub fn neighborhood_key(sig: &[f64]) -> String {
    // FNV-1a over coarsely-quantized coordinates (grid = 0.1).
    let mut h: u64 = 0xcbf29ce484222325;
    for &x in sig {
        let q = (x * 10.0).round() as i64;
        for b in q.to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
    }
    format!("{:08x}", h as u32)
}

impl Cytokines {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current heat for a neighborhood (0 if none).
    pub fn heat(&self, key: &str) -> f64 {
        self.field.get(key).copied().unwrap_or(0.0)
    }

    /// Total field heat — bounded by `global_cap`.
    pub fn total_heat(&self) -> f64 {
        self.field.values().sum()
    }

    /// Release a cytokine into a neighborhood. Strength is rate-limited to
    /// `emit_limit`, per-neighborhood heat is clamped to `max_gain`, and the
    /// total field is clamped to `global_cap` — so no probing campaign can
    /// drive sensitivity past these bounds.
    pub fn emit(&mut self, key: &str, strength: f64, cfg: &InflamConfig) {
        let strength = strength.clamp(0.0, cfg.emit_limit);
        let entry = self.field.entry(key.to_string()).or_insert(0.0);
        *entry = (*entry + strength).min(cfg.max_gain);
        // Enforce the global cap: if the total exceeds it, trim this key.
        let total = self.total_heat();
        if total > cfg.global_cap {
            let over = total - cfg.global_cap;
            if let Some(v) = self.field.get_mut(key) {
                *v = (*v - over).max(0.0);
            }
        }
    }

    /// Decay the whole field toward baseline over `scans` scans.
    pub fn decay(&mut self, scans: f64, cfg: &InflamConfig) {
        if scans <= 0.0 {
            return;
        }
        let factor = 0.5_f64.powf(scans / cfg.half_life_scans.max(1e-9));
        for v in self.field.values_mut() {
            *v *= factor;
        }
        self.field.retain(|_, v| *v > 1e-6);
    }

    /// Return a locally-tightened [`DangerConfig`] for a sample in `key`'s
    /// neighborhood. With zero heat the base config is returned unchanged
    /// (identity), so the default path is unaffected.
    pub fn modulate(&self, base: &DangerConfig, key: &str, cfg: &InflamConfig) -> DangerConfig {
        let heat = self.heat(key).clamp(0.0, cfg.max_gain);
        if heat <= 0.0 {
            return *base;
        }
        let mut c = *base;
        // Tighten the gate: lower the "dangerous" bar and the migration
        // threshold proportionally to heat, clamped by max_gain.
        c.dangerous_at = base.dangerous_at * (1.0 - heat);
        c.migration_threshold = (base.migration_threshold * (1.0 - heat)).max(0.0);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_field_is_identity() {
        let cyto = Cytokines::new();
        let base = DangerConfig::default();
        let m = cyto.modulate(&base, "whatever", &InflamConfig::default());
        assert_eq!(m.dangerous_at, base.dangerous_at);
        assert_eq!(m.migration_threshold, base.migration_threshold);
    }

    #[test]
    fn emit_tightens_locally_within_bounds() {
        let cfg = InflamConfig::default();
        let base = DangerConfig::default();
        let mut cyto = Cytokines::new();
        let k = neighborhood_key(&[0.5, 0.5, 0.5]);
        cyto.emit(&k, 0.3, &cfg);
        let m = cyto.modulate(&base, &k, &cfg);
        assert!(
            m.dangerous_at < base.dangerous_at,
            "local gate must tighten"
        );
        // Never beyond max_gain worth of tightening.
        assert!(m.dangerous_at >= base.dangerous_at * (1.0 - cfg.max_gain) - 1e-9);
    }

    #[test]
    fn bounds_hold_under_a_flood() {
        // The anti-DoS property: no amount of emitting can exceed the bounds.
        let cfg = InflamConfig::default();
        let mut cyto = Cytokines::new();
        for i in 0..1000 {
            let k = neighborhood_key(&[(i % 7) as f64 * 0.1, 0.2]);
            cyto.emit(&k, 10.0, &cfg); // way over emit_limit each time
        }
        assert!(
            cyto.total_heat() <= cfg.global_cap + 1e-9,
            "global cap must hold"
        );
        for v in cyto.field.values() {
            assert!(*v <= cfg.max_gain + 1e-9, "per-neighborhood cap must hold");
        }
    }

    #[test]
    fn decay_returns_to_baseline() {
        let cfg = InflamConfig::default();
        let mut cyto = Cytokines::new();
        let k = neighborhood_key(&[0.1, 0.9]);
        cyto.emit(&k, 0.4, &cfg);
        assert!(cyto.heat(&k) > 0.0);
        cyto.decay(1000.0, &cfg); // many half-lives
        assert_eq!(cyto.heat(&k), 0.0, "heat must self-limit back to baseline");
    }
}
