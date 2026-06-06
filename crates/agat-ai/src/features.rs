//! Serializable feature blob emitted by [`crate::AiAnalyzer`].

use crate::artifacts::ArtifactHit;
use crate::perplexity::PerplexityResult;
use crate::stylometry::StylometricFeatures;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalScores {
    /// Stylometric score (signal 1). 0..1.
    pub stylometry: f64,
    /// Artifact-scan score (signal 3). 0..1.
    pub artifact_scan: f64,
    /// Perplexity score (signal 2). `None` when the corpus was too
    /// small or perplexity computation was unavailable.
    pub perplexity: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFeatures {
    pub artifacts: Vec<ArtifactHit>,
    pub stylometry: StylometricFeatures,
    pub signal_scores: SignalScores,
    /// Raw perplexity value + backend + corpus size. `None` when
    /// no result was computed.
    #[serde(default)]
    pub perplexity_result: Option<PerplexityResult>,
    /// Combined verdict in [0, 0.95]. Heuristic ceiling because we
    /// never claim certainty.
    pub combined_score: f64,
}

impl AiFeatures {
    pub fn is_ai_rewritten(&self) -> bool {
        self.combined_score >= 0.5
    }
}
