use crate::{Result, Sample};
use serde_json::Value;

/// Per-run context handed to each [`Analyzer`]. Holds references to
/// shared infrastructure that analyzers may need (the vault for
/// raw-byte access, a store handle in the future, etc.).
pub struct AnalysisContext<'a> {
    pub vault: &'a crate::Vault,
}

/// A binary blob emitted by an analyzer alongside its structured
/// features — e.g. a recovered decrypted payload, a disassembly
/// listing, or a CFG image.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub kind: String,
    pub blob: Vec<u8>,
}

/// What an [`Analyzer`] returns for a single sample.
#[derive(Debug, Clone)]
pub struct FeatureBundle {
    pub analyzer: &'static str,
    pub version: &'static str,
    pub features: Value,
    pub artifacts: Vec<Artifact>,
}

/// Implemented by every analyzer crate. Analyzers are pure functions
/// of a sample plus its context; persistence happens in the pipeline,
/// not inside the analyzer.
pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn dependencies(&self) -> &[&'static str] {
        &[]
    }
    fn analyze(&self, sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle>;
}
