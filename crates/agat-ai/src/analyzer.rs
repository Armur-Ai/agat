//! [`agat_core::Analyzer`] implementation for AI-signal detection.

use crate::artifacts::{scan, ArtifactCategory, ArtifactHit};
use crate::features::{AiFeatures, SignalScores};
use crate::perplexity::{compute as compute_perplexity, score as score_perplexity};
use crate::stylometry::{compute as compute_stylometry, StylometricFeatures};
use agat_core::{AnalysisContext, Analyzer, Error, FeatureBundle, Result, Sample};
use agat_disasm::DisasmFeatures;
use agat_static::StaticFeatures;

const NAME: &str = "ai";
const VERSION: &str = "0.1.0";

pub struct AiAnalyzer;

impl Default for AiAnalyzer {
    fn default() -> Self {
        AiAnalyzer
    }
}

impl Analyzer for AiAnalyzer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }
    fn dependencies(&self) -> &[&'static str] {
        &["static", "disasm"]
    }

    fn analyze(&self, sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle> {
        let sf: StaticFeatures = pull_features(ctx, "static")?;
        let df: DisasmFeatures = pull_features(ctx, "disasm")?;
        let bytes = ctx.load(&sample.id)?;

        let artifacts = scan(&bytes);
        let stylometry = compute_stylometry(&sf, &df);
        let perplexity_result = compute_perplexity(&sf.strings.samples);
        let perplexity_score = perplexity_result
            .as_ref()
            .map(|r| score_perplexity(r.value));

        let artifact_scan_score = score_artifacts(&artifacts);
        let stylometry_score = score_stylometry(&stylometry);
        let combined_score = combine(artifact_scan_score, stylometry_score, perplexity_score);

        let features = AiFeatures {
            artifacts,
            stylometry,
            signal_scores: SignalScores {
                stylometry: stylometry_score,
                artifact_scan: artifact_scan_score,
                perplexity: perplexity_score,
            },
            perplexity_result,
            combined_score,
        };

        Ok(FeatureBundle {
            analyzer: NAME,
            version: VERSION,
            features: serde_json::to_value(&features)?,
            artifacts: vec![],
        })
    }
}

/// Score artifact-scan hits. A few categories carry disproportionate
/// weight: a refusal phrase or ChatML marker in a binary is far more
/// suspicious than e.g. a generic "language model" string.
fn score_artifacts(hits: &[ArtifactHit]) -> f64 {
    let mut score: f64 = 0.0;
    for hit in hits {
        score += match hit.category {
            ArtifactCategory::RefusalString => 0.25,
            ArtifactCategory::ChatMlMarker => 0.30,
            ArtifactCategory::RoleMarker => 0.25,
            ArtifactCategory::TokenizerFragment => 0.20,
            ArtifactCategory::ModelMagic => 0.30,
            ArtifactCategory::SystemPrompt => 0.20,
            ArtifactCategory::ApiEndpoint => 0.15,
        };
    }
    score.min(1.0)
}

/// Score stylometric features. LLM idiom density is the cleanest
/// signal we have at the binary level; long-string count and
/// underscore density are weaker corroborators.
fn score_stylometry(s: &StylometricFeatures) -> f64 {
    let mut score: f64 = 0.0;
    let n_idioms = s.llm_idiom_hits.len();
    if n_idioms >= 1 {
        score += 0.20;
    }
    if n_idioms >= 3 {
        score += 0.20;
    }
    if n_idioms >= 6 {
        score += 0.20;
    }
    if s.long_string_count >= 5 {
        score += 0.15;
    }
    if s.underscore_density > 0.05 {
        score += 0.15;
    }
    score.min(1.0)
}

/// Combine per-signal scores into a final verdict in `[0, 0.95]`.
/// When perplexity is available it gets a meaningful weight;
/// otherwise we fall back to the artifact/stylometry mix from
/// Phase 5. The 0.95 cap is deliberate — heuristics in a
/// constellation never deserve "100%".
fn combine(artifact: f64, stylometry: f64, perplexity: Option<f64>) -> f64 {
    let raw = match perplexity {
        Some(p) => 0.40 * artifact + 0.30 * stylometry + 0.30 * p,
        None => 0.55 * artifact + 0.45 * stylometry,
    };
    raw.min(0.95)
}

fn pull_features<T: serde::de::DeserializeOwned>(ctx: &AnalysisContext, name: &str) -> Result<T> {
    let value = ctx
        .previous_features
        .get(name)
        .ok_or_else(|| Error::Other(format!("ai: required upstream features '{name}' missing")))?;
    serde_json::from_value(value.clone()).map_err(Error::from)
}
