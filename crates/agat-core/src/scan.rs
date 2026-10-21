//! The scan result contract — agat's stable, machine-readable verdict.
//!
//! Every analyzer and immune mechanism in agat produces rich internal
//! state, but an operator (or a CI pipeline, a SIEM, another tool) needs
//! **one** thing back: *what is this sample, and what should I do about
//! it?* [`ScanResult`] is that answer in a single serializable object.
//!
//! This type is deliberately defined in `agat-core`, with no dependency
//! on the immune or analyzer crates, so it is a **contract** rather than
//! a view onto internal types. Internal representations (the
//! `Recognition`, `DangerAssessment`, `Antigen`) can evolve freely; the
//! assembly from those into a `ScanResult` lives in `agat-engine`, and
//! the shape promised to the outside world is pinned here by
//! [`SCAN_SCHEMA_VERSION`].
//!
//! Honesty note: agat reports **two independent axes** — recognition
//! (is this non-self?) and danger (does it carry harm signals?) — and
//! fuses them into a [`Severity`] only as advice. Both axes are always
//! present in the result so a consumer can apply its own policy.

use serde::{Deserialize, Serialize};

/// The schema identifier embedded in every [`ScanResult`]. Bump the
/// version suffix on any breaking change to the serialized shape so
/// consumers can detect and gate on it.
pub const SCAN_SCHEMA_VERSION: &str = "agat.scan/v1";

/// The fused, actionable severity for a scanned sample.
///
/// This is agat's *recommendation*, derived from the two independent
/// axes (recognition and danger) carried in the same [`ScanResult`].
/// A consumer that disagrees with the fusion policy can ignore this and
/// act on the raw axes directly.
///
/// Variants are ordered by severity (`Clean < Review < Suspicious <
/// Malicious`), so `max()` over a batch yields the worst verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Within self / unrecognized, no notable danger — no action.
    Clean,
    /// A single axis is mild: non-self but low danger (likely
    /// benign-but-unusual), or within-self yet carrying danger signals.
    /// Worth a human glance, not an alarm.
    Review,
    /// Non-self with ambiguous danger — the two axes neither clearly
    /// agree nor clearly clear it. Triage.
    Suspicious,
    /// Recognition and danger agree: non-self *and* dangerous.
    /// Investigate now.
    Malicious,
}

impl Severity {
    /// A stable lower-case label for logs and machine output.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Clean => "clean",
            Severity::Review => "review",
            Severity::Suspicious => "suspicious",
            Severity::Malicious => "malicious",
        }
    }

    /// Process exit code for the operator CLI, chosen so scripts can
    /// branch on outcome: `0` nothing to do, `2` needs a human, `3`
    /// confirmed non-self + dangerous. (`1` is reserved for a tool
    /// error, per Unix convention, and is never returned for a verdict.)
    pub fn exit_code(self) -> i32 {
        match self {
            Severity::Clean => 0,
            Severity::Review | Severity::Suspicious => 2,
            Severity::Malicious => 3,
        }
    }

    /// Whether this severity warrants surfacing the sample to an
    /// operator at all (everything but [`Severity::Clean`]).
    pub fn is_actionable(self) -> bool {
        !matches!(self, Severity::Clean)
    }
}

/// Which sample this result is about.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRef {
    /// Full content id (hex).
    pub id: String,
    /// Short, human-friendly id prefix.
    pub short: String,
    /// Original file name or path, if the scan knew one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// A compact view of the antigen presented to the immune system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntigenSummary {
    /// Dimensionality of the behavioral signature.
    pub dim: usize,
    /// Number of canonical basic blocks tokenized.
    pub blocks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cfg_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_fingerprint: Option<String>,
}

/// The recognition axis: is this non-self, and whose family is it?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognitionSummary {
    /// Whether any detector bound the antigen (non-self).
    pub recognized: bool,
    /// Compact human label for the recognition outcome.
    pub verdict: String,
    /// Identified family, if a family-bearing detector bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Binding affinity in `[0, 1]` of the strongest binder.
    pub affinity: f64,
    /// How many detectors bound.
    pub bound_detectors: usize,
    /// Whether the family attribution came from a memory cell (a fast
    /// secondary response).
    pub secondary_response: bool,
    /// Signed distance from the self surface: positive ⇒ outside self.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_surface_distance: Option<f64>,
    /// How many families the memory pool knew at scan time.
    pub known_families: usize,
}

/// One DCA signal contribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSummary {
    /// Signal class: `pamp`, `danger`, or `safe`.
    pub class: String,
    pub name: String,
    pub value: f64,
}

/// The danger axis: DCA-style fusion of real harm signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerSummary {
    /// Fused danger score in `[0, 1]`.
    pub score: f64,
    /// Discrete context label: `inconclusive` / `safe` / `ambiguous` /
    /// `dangerous`.
    pub context: String,
    /// Aggregate PAMP, danger, and safe signal strengths.
    pub pamp: f64,
    pub danger: f64,
    pub safe: f64,
    /// Individual contributing signals, strongest first.
    pub signals: Vec<SignalSummary>,
}

/// The fused verdict: agat's one-line recommendation plus the inputs it
/// was fused from (kept alongside so a consumer never has to re-derive).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    /// The actionable severity.
    pub severity: Severity,
    /// One-line human explanation of *why* this severity.
    pub summary: String,
    /// Set when an operator policy (an allowlist or denylist entry)
    /// overrode the fused verdict: `"allowlist"` or `"denylist"`. The
    /// recognition and danger axes are still reported unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

/// The complete, machine-readable outcome of scanning one sample.
///
/// Serialize this to JSON for pipelines; render [`verdict`](Self::verdict)
/// and the two axes for a human.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Schema identifier; always [`SCAN_SCHEMA_VERSION`] when written by
    /// this build.
    pub schema_version: String,
    /// The agat version that produced this result.
    pub agat_version: String,
    /// RFC 3339 timestamp of the scan.
    pub scanned_at: String,
    pub sample: SampleRef,
    pub antigen: AntigenSummary,
    pub recognition: RecognitionSummary,
    pub danger: DangerSummary,
    pub verdict: Verdict,
}

impl ScanResult {
    /// Convenience accessor for the fused severity.
    pub fn severity(&self) -> Severity {
        self.verdict.severity
    }

    /// Fuse the two axes into a [`Verdict`]. This is the single place
    /// agat's recommendation policy lives, so the CLI, JSON output, and
    /// any future API all agree.
    ///
    /// `recognized` is the recognition axis; `danger_dangerous` and
    /// `danger_ambiguous` describe the danger context.
    pub fn fuse(recognized: bool, danger_dangerous: bool, danger_ambiguous: bool) -> Verdict {
        let (severity, summary) = match (recognized, danger_dangerous, danger_ambiguous) {
            (true, true, _) => (
                Severity::Malicious,
                "non-self and dangerous — recognition and danger agree; investigate".to_string(),
            ),
            (true, false, true) => (
                Severity::Suspicious,
                "non-self with ambiguous danger — worth a look".to_string(),
            ),
            (true, false, false) => (
                Severity::Review,
                "non-self but low danger — likely benign-but-unusual (false-positive guard)"
                    .to_string(),
            ),
            (false, true, _) => (
                Severity::Review,
                "within self yet dangerous signals present — anomaly worth review".to_string(),
            ),
            (false, false, _) => (
                Severity::Clean,
                "within self / unrecognized — no action".to_string(),
            ),
        };
        Verdict {
            severity,
            summary,
            policy: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fusion_covers_every_axis_combination() {
        // non-self + dangerous ⇒ the one "act now" verdict.
        assert_eq!(
            ScanResult::fuse(true, true, false).severity,
            Severity::Malicious
        );
        // non-self + ambiguous ⇒ triage.
        assert_eq!(
            ScanResult::fuse(true, false, true).severity,
            Severity::Suspicious
        );
        // non-self + clear ⇒ false-positive guard.
        assert_eq!(
            ScanResult::fuse(true, false, false).severity,
            Severity::Review
        );
        // within self but dangerous ⇒ review the anomaly.
        assert_eq!(
            ScanResult::fuse(false, true, false).severity,
            Severity::Review
        );
        // within self, nothing notable ⇒ clean.
        assert_eq!(
            ScanResult::fuse(false, false, false).severity,
            Severity::Clean
        );
    }

    #[test]
    fn exit_codes_are_scriptable_and_distinct() {
        assert_eq!(Severity::Clean.exit_code(), 0);
        assert_eq!(Severity::Review.exit_code(), 2);
        assert_eq!(Severity::Suspicious.exit_code(), 2);
        assert_eq!(Severity::Malicious.exit_code(), 3);
        // 1 is reserved for tool errors and must never be a verdict code.
        for s in [
            Severity::Clean,
            Severity::Review,
            Severity::Suspicious,
            Severity::Malicious,
        ] {
            assert_ne!(s.exit_code(), 1);
        }
    }

    #[test]
    fn severity_orders_from_clean_to_malicious() {
        assert!(Severity::Clean < Severity::Review);
        assert!(Severity::Review < Severity::Suspicious);
        assert!(Severity::Suspicious < Severity::Malicious);
    }

    #[test]
    fn only_clean_is_non_actionable() {
        assert!(!Severity::Clean.is_actionable());
        assert!(Severity::Review.is_actionable());
        assert!(Severity::Suspicious.is_actionable());
        assert!(Severity::Malicious.is_actionable());
    }

    #[test]
    fn severity_roundtrips_through_json_as_snake_case() {
        let j = serde_json::to_string(&Severity::Malicious).unwrap();
        assert_eq!(j, "\"malicious\"");
        let back: Severity = serde_json::from_str(&j).unwrap();
        assert_eq!(back, Severity::Malicious);
    }
}
