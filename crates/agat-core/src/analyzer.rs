use crate::{Result, Sample};
use serde_json::Value;
use std::collections::HashMap;

/// Per-run context handed to each [`Analyzer`]. Holds references to
/// shared infrastructure analyzers need: the vault for raw-byte
/// access, plus a map of *already-computed* feature bundles from
/// upstream analyzers in the same pipeline run. Phase 3+ analyzers
/// (e.g. `poly` → needs `static` and `disasm`) read from this map
/// instead of re-doing upstream work.
pub struct AnalysisContext<'a> {
    pub vault: &'a crate::Vault,
    pub previous_features: HashMap<String, Value>,
}

impl<'a> AnalysisContext<'a> {
    pub fn new(vault: &'a crate::Vault) -> Self {
        Self {
            vault,
            previous_features: HashMap::new(),
        }
    }
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
