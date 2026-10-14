//! SARIF output for agat scan results.
//!
//! SARIF (Static Analysis Results Interchange Format, OASIS 2.1.0) is the
//! lingua franca for security findings: GitHub code scanning, Azure
//! DevOps, and most SARIF viewers ingest it directly. Emitting it is what
//! lets `agat scan --sarif` drop into an existing pipeline without any
//! glue.
//!
//! One [`ScanResult`] becomes at most one SARIF `result`. Clean samples
//! produce no finding (nothing to report), so a SARIF log over a
//! directory lists exactly the samples that warrant attention.

use agat_core::{ScanResult, Severity};
use serde_json::{json, Value};

/// Map a verdict severity to a SARIF result level.
fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Malicious => "error",
        Severity::Suspicious | Severity::Review => "warning",
        Severity::Clean => "note",
    }
}

/// Build a SARIF 2.1.0 log from a batch of scan results. Clean results
/// are omitted (no finding); the tool driver advertises the rules agat
/// can report so viewers render stable rule metadata.
pub fn to_sarif(results: &[ScanResult]) -> Value {
    let rules = json!([
        {
            "id": "agat/non-self-dangerous",
            "name": "NonSelfDangerous",
            "shortDescription": { "text": "Non-self and dangerous" },
            "fullDescription": {
                "text": "The sample is recognized as non-self (outside the benign \
                         self-model) and carries danger signals; recognition and \
                         danger agree."
            },
            "defaultConfiguration": { "level": "error" }
        },
        {
            "id": "agat/suspicious",
            "name": "Suspicious",
            "shortDescription": { "text": "Non-self with ambiguous danger" },
            "defaultConfiguration": { "level": "warning" }
        },
        {
            "id": "agat/review",
            "name": "Review",
            "shortDescription": { "text": "Anomaly worth review" },
            "defaultConfiguration": { "level": "warning" }
        }
    ]);

    let mut sarif_results = Vec::new();
    for r in results {
        if r.severity() == Severity::Clean {
            continue;
        }
        let rule_id = match r.severity() {
            Severity::Malicious => "agat/non-self-dangerous",
            Severity::Suspicious => "agat/suspicious",
            Severity::Review => "agat/review",
            Severity::Clean => unreachable!(),
        };
        let uri = r.sample.name.clone().unwrap_or_else(|| r.sample.short.clone());
        let family = r
            .recognition
            .family
            .as_deref()
            .map(|f| format!(" (family: {f})"))
            .unwrap_or_default();
        let message = format!(
            "{}{} — {} [affinity {:.3}, danger {:.3}]",
            r.verdict.summary,
            family,
            r.recognition.verdict,
            r.recognition.affinity,
            r.danger.score
        );
        sarif_results.push(json!({
            "ruleId": rule_id,
            "level": sarif_level(r.severity()),
            "message": { "text": message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": uri }
                }
            }],
            "partialFingerprints": {
                "agatSampleId": r.sample.id
            },
            "properties": {
                "severity": r.severity().label(),
                "recognized": r.recognition.recognized,
                "family": r.recognition.family,
                "affinity": r.recognition.affinity,
                "dangerScore": r.danger.score,
                "dangerContext": r.danger.context,
                "schemaVersion": r.schema_version
            }
        }));
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agat",
                    "informationUri": "https://github.com/Armur-Ai/agat",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_core::{
        AntigenSummary, DangerSummary, RecognitionSummary, SampleRef, ScanResult, Verdict,
        SCAN_SCHEMA_VERSION,
    };

    fn result(sev: Severity, name: &str) -> ScanResult {
        ScanResult {
            schema_version: SCAN_SCHEMA_VERSION.to_string(),
            agat_version: "test".into(),
            scanned_at: "2026-01-01T00:00:00Z".into(),
            sample: SampleRef { id: "abc123".into(), short: "abc123".into(), name: Some(name.into()) },
            antigen: AntigenSummary { dim: 4, blocks: 1, cfg_fingerprint: None, plaintext_fingerprint: None },
            recognition: RecognitionSummary {
                recognized: sev != Severity::Clean,
                verdict: "test".into(),
                family: Some("metamorph".into()),
                affinity: 0.9,
                bound_detectors: 1,
                secondary_response: true,
                self_surface_distance: Some(0.5),
                known_families: 1,
            },
            danger: DangerSummary {
                score: 0.6,
                context: "dangerous".into(),
                pamp: 0.7,
                danger: 1.0,
                safe: 0.1,
                signals: vec![],
            },
            verdict: Verdict { severity: sev, summary: "s".into() },
        }
    }

    #[test]
    fn clean_results_produce_no_findings() {
        let log = to_sarif(&[result(Severity::Clean, "a.bin")]);
        assert_eq!(log["runs"][0]["results"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn malicious_maps_to_error_with_location_and_fingerprint() {
        let log = to_sarif(&[result(Severity::Malicious, "/path/to/evil.bin")]);
        let res = &log["runs"][0]["results"][0];
        assert_eq!(res["level"], "error");
        assert_eq!(res["ruleId"], "agat/non-self-dangerous");
        assert_eq!(
            res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "/path/to/evil.bin"
        );
        assert_eq!(res["partialFingerprints"]["agatSampleId"], "abc123");
        assert_eq!(log["version"], "2.1.0");
        assert_eq!(log["runs"][0]["tool"]["driver"]["name"], "agat");
    }

    #[test]
    fn mixed_batch_reports_only_the_actionable() {
        let log = to_sarif(&[
            result(Severity::Clean, "ok.bin"),
            result(Severity::Malicious, "bad.bin"),
            result(Severity::Review, "weird.bin"),
        ]);
        assert_eq!(log["runs"][0]["results"].as_array().unwrap().len(), 2);
    }
}
