//! The danger layer — DCA-style signal fusion.
//!
//! Greensmith, Aickelin & Cayzer, *Introducing Dendritic Cells as a
//! Novel Immune-Inspired Algorithm for Anomaly Detection*, ICARIS 2005.
//!
//! Danger theory's insight is that the immune system does not attack
//! everything that is non-self — it attacks things that are non-self
//! *and dangerous*. Dendritic cells sense the context around an antigen
//! via three signal classes and fuse them into a maturation decision:
//!
//! - **PAMP** — pathogen-associated molecular patterns: definitive
//!   evidence of a pathogen.
//! - **Danger signals** — markers of damage/stress, suggestive but not
//!   definitive.
//! - **Safe signals** — markers of healthy, normal context.
//!
//! agat maps its *real* harm signals onto these classes and applies the
//! DCA weighted-transform to produce a danger score. The point is to
//! cut false positives: a sample that is non-self but carries no harm
//! signals (the recognition layer flagged it as merely unusual) gets a
//! low danger score, while a decryptor-with-key + W^X + LLM-artifact
//! sample gets a high one.
//!
//! Honest scope (docs/AIS_REBUILD_PLAN.md §7, weakest-analogy #1):
//! canonical DCA processes a *temporal stream* of antigen with a
//! population of cells maturing over time. agat is a per-sample static
//! analyzer, so we apply the DCA signal-categorization and fusion math
//! over each sample's *internal* signal set. The math is faithful; the
//! biological setup is looser. We call this "DCA-style signal fusion,"
//! not "a running dendritic-cell population."

use agat_ai::artifacts::ArtifactCategory;
use agat_ai::AiFeatures;
use agat_poly::PolyFeatures;
use agat_static::StaticFeatures;
use serde::{Deserialize, Serialize};

/// Which DCA signal class a contribution belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalClass {
    Pamp,
    Danger,
    Safe,
}

/// One named signal contribution, kept for explainability in the report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContribution {
    pub name: String,
    pub class: SignalClass,
    pub value: f64,
}

/// The three fused input signals (each in `[0, 1]`) plus their itemized
/// contributors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerSignals {
    pub pamp: f64,
    pub danger: f64,
    pub safe: f64,
    pub contributors: Vec<SignalContribution>,
}

/// Discrete danger context for a sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DangerContext {
    /// Signals too weak to judge.
    Inconclusive,
    Safe,
    Ambiguous,
    Dangerous,
}

impl DangerContext {
    pub fn label(self) -> &'static str {
        match self {
            DangerContext::Inconclusive => "inconclusive",
            DangerContext::Safe => "safe",
            DangerContext::Ambiguous => "ambiguous",
            DangerContext::Dangerous => "dangerous",
        }
    }
}

/// The DCA weight transform and decision thresholds. Defaults follow the
/// canonical DCA weighting (PAMP and danger drive maturity; safe drives
/// the semi-mature, tolerogenic context).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DangerConfig {
    // Costimulation (signal strength / confidence) weights.
    pub csm_pamp: f64,
    pub csm_danger: f64,
    pub csm_safe: f64,
    // Mature (anomalous) context weights.
    pub mat_pamp: f64,
    pub mat_danger: f64,
    // Semi-mature (tolerogenic) context weight.
    pub semi_safe: f64,
    /// Minimum costimulation below which we report "inconclusive".
    pub migration_threshold: f64,
    /// Danger score ≥ this ⇒ Dangerous.
    pub dangerous_at: f64,
    /// Danger score < this ⇒ Safe.
    pub safe_below: f64,
}

impl Default for DangerConfig {
    fn default() -> Self {
        Self {
            csm_pamp: 2.0,
            csm_danger: 1.0,
            csm_safe: 2.0,
            mat_pamp: 2.0,
            mat_danger: 1.0,
            semi_safe: 2.0,
            migration_threshold: 0.10,
            dangerous_at: 0.50,
            safe_below: 0.33,
        }
    }
}

/// The fused danger assessment for one sample.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerAssessment {
    pub signals: DangerSignals,
    /// Costimulation — overall signal strength / confidence.
    pub csm: f64,
    /// Semi-mature (tolerogenic) accumulation.
    pub semi: f64,
    /// Mature (anomalous) accumulation.
    pub mat: f64,
    /// Danger score in `[0, 1]` — the per-antigen MCAV analogue
    /// (fraction of the maturation pressure that is "mature").
    pub danger_score: f64,
    pub context: DangerContext,
}

/// Apply the DCA weighted transform to fused signals.
pub fn assess(signals: &DangerSignals, cfg: &DangerConfig) -> DangerAssessment {
    let (p, d, s) = (signals.pamp, signals.danger, signals.safe);
    let csm = cfg.csm_pamp * p + cfg.csm_danger * d + cfg.csm_safe * s;
    let mat = cfg.mat_pamp * p + cfg.mat_danger * d;
    let semi = cfg.semi_safe * s;

    let danger_score = if mat + semi <= 0.0 {
        0.0
    } else {
        (mat / (mat + semi)).clamp(0.0, 1.0)
    };

    // Normalize csm against its theoretical maximum so the migration
    // threshold is interpretable in [0, 1].
    let csm_max = cfg.csm_pamp + cfg.csm_danger + cfg.csm_safe;
    let csm_norm = if csm_max > 0.0 { csm / csm_max } else { 0.0 };

    let context = if csm_norm < cfg.migration_threshold {
        DangerContext::Inconclusive
    } else if danger_score >= cfg.dangerous_at {
        DangerContext::Dangerous
    } else if danger_score < cfg.safe_below {
        DangerContext::Safe
    } else {
        DangerContext::Ambiguous
    };

    DangerAssessment {
        signals: signals.clone(),
        csm: csm_norm,
        semi,
        mat,
        danger_score,
        context,
    }
}

/// Import substrings that signal code-injection / self-modification /
/// anti-analysis capability — classic danger markers.
/// Section/segment names left behind by common runtime packers. These are
/// rare in ordinary software and a strong PAMP: a packed executable is a
/// definitive "self-decrypting payload" marker. Matched case-insensitively
/// as a prefix of the section name.
const PACKER_SECTIONS: &[&str] = &[
    "upx0", "upx1", "upx2", "upx!", ".aspack", ".adata", ".nsp0", ".nsp1", "fsg!", ".mpress1",
    ".mpress2", ".boom", ".petite", ".pec", "pebundle", ".themida", ".vmp0", ".vmp1", ".enigma",
    ".packed", ".yoda",
];

const SUSPICIOUS_IMPORTS: &[&str] = &[
    "virtualalloc",
    "virtualprotect",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "setwindowshookex",
    "mprotect",
    "ptrace",
    "memfd_create",
    "dlopen",
    "execve",
    "mmap",
];

/// Extract the three DCA signal classes from agat's real behavioral
/// features. `self_surface_distance` (from the recognition/self-model
/// layer) supplies a strong safe/danger cue: inside self ⇒ safe; far
/// outside ⇒ danger.
pub fn signals_from_features(
    static_features: Option<&StaticFeatures>,
    poly: Option<&PolyFeatures>,
    ai: Option<&AiFeatures>,
    self_surface_distance: Option<f64>,
) -> DangerSignals {
    let mut contributors = Vec::new();
    let mut pamp = 0.0_f64;
    let mut danger = 0.0_f64;
    let mut safe = 0.0_f64;

    let mut add = |name: &str, class: SignalClass, value: f64| {
        if value <= 0.0 {
            return;
        }
        match class {
            SignalClass::Pamp => pamp += value,
            SignalClass::Danger => danger += value,
            SignalClass::Safe => safe += value,
        }
        contributors.push(SignalContribution {
            name: name.to_string(),
            class,
            value,
        });
    };

    // --- PAMP: definitive pathogen-associated patterns -------------
    if let Some(p) = poly {
        // A decryptor loop whose key we recovered is about as
        // definitive a self-decrypting-payload signature as agat has.
        if p.recovered.is_some() {
            add("decryptor_with_recovered_key", SignalClass::Pamp, 0.7);
        }
    }
    if let Some(a) = ai {
        for hit in &a.artifacts {
            let v = match hit.category {
                ArtifactCategory::RefusalString => 0.5,
                ArtifactCategory::ChatMlMarker => 0.6,
                ArtifactCategory::RoleMarker => 0.4,
                ArtifactCategory::ModelMagic => 0.5,
                ArtifactCategory::TokenizerFragment => 0.3,
                ArtifactCategory::SystemPrompt => 0.3,
                ArtifactCategory::ApiEndpoint => 0.2,
            };
            add("llm_artifact", SignalClass::Pamp, v);
        }
    }

    // --- Danger: damage/stress markers -----------------------------
    if let Some(sf) = static_features {
        let n_high = sf.entropy.high_entropy_regions.len();
        if n_high > 0 {
            add(
                "high_entropy_region",
                SignalClass::Danger,
                (0.25 * n_high as f64).min(0.5),
            );
        }
        if sf.entropy.overall > 7.0 {
            add("very_high_overall_entropy", SignalClass::Danger, 0.3);
        }
        // W^X violations: a writable+executable section.
        let wx = sf
            .parsed
            .sections
            .iter()
            .any(|s| s.characteristics.writable && s.characteristics.executable);
        if wx {
            add("writable_executable_section", SignalClass::Danger, 0.4);
        }
        // Known packer section names — a strong self-decrypting-payload tell.
        let packed = sf.parsed.sections.iter().any(|sec| {
            let n = sec.name.to_ascii_lowercase();
            PACKER_SECTIONS.iter().any(|p| n.starts_with(p))
        });
        if packed {
            add("packer_section_name", SignalClass::Pamp, 0.6);
        }
        let suspicious = sf.parsed.imports.iter().any(|imp| {
            let n = imp.name.to_ascii_lowercase();
            SUSPICIOUS_IMPORTS.iter().any(|s| n.contains(s))
        });
        if suspicious {
            add("suspicious_import", SignalClass::Danger, 0.4);
        }
    }
    if let Some(p) = poly {
        if p.confidence > 0.0 {
            add(
                "polymorphic_confidence",
                SignalClass::Danger,
                p.confidence * 0.4,
            );
        }
    }
    if let Some(a) = ai {
        let idioms = a.stylometry.llm_idiom_hits.len();
        if idioms >= 3 {
            add("dense_llm_idioms", SignalClass::Danger, 0.2);
        }
    }
    if let Some(d) = self_surface_distance {
        if d > 0.0 {
            // Distance from the benign region — saturating contribution.
            add(
                "far_from_self",
                SignalClass::Danger,
                (d / (d + 0.5)).min(0.5),
            );
        }
    }

    // --- Safe: healthy/normal context ------------------------------
    if let Some(sf) = static_features {
        if sf.entropy.overall < 5.0 {
            add("low_overall_entropy", SignalClass::Safe, 0.4);
        }
        let no_suspicious = !sf.parsed.imports.iter().any(|imp| {
            let n = imp.name.to_ascii_lowercase();
            SUSPICIOUS_IMPORTS.iter().any(|s| n.contains(s))
        });
        if no_suspicious && !sf.parsed.imports.is_empty() {
            add("benign_import_profile", SignalClass::Safe, 0.3);
        }
    }
    if let Some(a) = ai {
        if a.artifacts.is_empty() && a.stylometry.llm_idiom_hits.is_empty() {
            add("no_ai_artifacts", SignalClass::Safe, 0.2);
        }
    }
    if let Some(d) = self_surface_distance {
        if d <= 0.0 {
            // Inside the benign region — a strong safe signal.
            add("inside_self_region", SignalClass::Safe, 0.6);
        }
    }

    DangerSignals {
        pamp: pamp.clamp(0.0, 1.0),
        danger: danger.clamp(0.0, 1.0),
        safe: safe.clamp(0.0, 1.0),
        contributors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_static::parse::{ParsedBinary, Section, SectionCharacteristics};

    fn section(name: &str) -> Section {
        Section {
            name: name.to_string(),
            virtual_address: 0,
            virtual_size: 0,
            file_offset: 0,
            file_size: 0,
            characteristics: SectionCharacteristics {
                readable: true,
                writable: false,
                executable: false,
            },
            entropy: 0.0,
            sha256: String::new(),
        }
    }

    fn sf_with_sections(names: &[&str]) -> agat_static::StaticFeatures {
        use agat_static::entropy::EntropyCurve;
        use agat_static::features::StringSummary;
        use agat_static::hashes::Hashes;
        agat_static::StaticFeatures {
            size: 0,
            parsed: ParsedBinary {
                format: agat_static::parse::BinaryFormat::Pe,
                arch: agat_static::parse::Arch::X86_64,
                bits: 64,
                entry_point: 0,
                sections: names.iter().map(|n| section(n)).collect(),
                imports: vec![],
                exports: vec![],
            },
            hashes: Hashes {
                sha256: String::new(),
                md5: String::new(),
                imphash: None,
            },
            entropy: EntropyCurve {
                window_size: 0,
                step: 0,
                overall: 0.0,
                points: vec![],
                high_entropy_regions: vec![],
            },
            strings: StringSummary {
                min_len: 4,
                ascii_count: 0,
                utf16le_count: 0,
                samples: vec![],
            },
        }
    }

    #[test]
    fn packer_section_names_raise_a_pamp() {
        let packed = sf_with_sections(&["UPX0", "UPX1", ".rsrc"]);
        let sig = signals_from_features(Some(&packed), None, None, None);
        assert!(sig
            .contributors
            .iter()
            .any(|c| c.name == "packer_section_name" && c.class == SignalClass::Pamp));
        // Ordinary section names do not.
        let normal = sf_with_sections(&[".text", ".data", ".rdata", ".rsrc", ".reloc"]);
        let sig = signals_from_features(Some(&normal), None, None, None);
        assert!(!sig
            .contributors
            .iter()
            .any(|c| c.name == "packer_section_name"));
    }

    fn signals(p: f64, d: f64, s: f64) -> DangerSignals {
        DangerSignals {
            pamp: p,
            danger: d,
            safe: s,
            contributors: vec![],
        }
    }

    #[test]
    fn dangerous_signals_mature() {
        let a = assess(&signals(0.9, 0.8, 0.1), &DangerConfig::default());
        assert_eq!(a.context, DangerContext::Dangerous);
        assert!(a.danger_score > 0.5);
    }

    #[test]
    fn safe_signals_stay_tolerogenic() {
        let a = assess(&signals(0.0, 0.1, 0.9), &DangerConfig::default());
        assert_eq!(a.context, DangerContext::Safe);
        assert!(a.danger_score < 0.33);
    }

    #[test]
    fn non_self_but_harmless_is_not_dangerous() {
        // The false-positive-reduction property: a sample with no harm
        // signals at all (recognition may call it non-self, but there is
        // nothing dangerous about it) must not read as dangerous.
        let a = assess(&signals(0.0, 0.0, 0.2), &DangerConfig::default());
        assert!(a.danger_score < 0.33);
        assert_ne!(a.context, DangerContext::Dangerous);
    }

    #[test]
    fn weak_signals_are_inconclusive() {
        let a = assess(&signals(0.0, 0.0, 0.0), &DangerConfig::default());
        assert_eq!(a.context, DangerContext::Inconclusive);
    }

    #[test]
    fn self_distance_drives_safe_vs_danger() {
        // Inside self ⇒ a safe signal dominates; far outside ⇒ danger.
        let inside = signals_from_features(None, None, None, Some(-0.2));
        assert!(inside.safe > 0.0 && inside.danger == 0.0);

        let outside = signals_from_features(None, None, None, Some(2.0));
        assert!(outside.danger > 0.0 && outside.safe == 0.0);

        // And the fused assessment orders them correctly.
        let di = assess(&inside, &DangerConfig::default()).danger_score;
        let dout = assess(&outside, &DangerConfig::default()).danger_score;
        assert!(dout > di);
    }

    #[test]
    fn poly_recovery_raises_pamp() {
        use agat_poly::PolyFeatures;
        // A polymorphic sample with confidence but no recovery: danger,
        // no PAMP.
        let no_rec = PolyFeatures {
            confidence: 0.8,
            signals: vec![],
            detected_pattern: None,
            recovered: None,
        };
        let s1 = signals_from_features(None, Some(&no_rec), None, None);
        assert_eq!(s1.pamp, 0.0);
        assert!(s1.danger > 0.0);
    }
}
