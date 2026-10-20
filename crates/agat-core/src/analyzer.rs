use crate::{Result, Sample, SampleId};
use serde_json::Value;
use std::collections::HashMap;

/// Where an analysis run reads the sample's raw bytes from.
enum ByteSource<'a> {
    /// The encrypted vault (the sample-library workflow).
    Vault(&'a crate::Vault),
    /// Bytes already in memory (stateless one-shot scans — nothing is
    /// written to disk and no vault password is needed).
    Memory(&'a [u8]),
}

/// Per-run context handed to each [`Analyzer`]. Holds the source of the
/// sample's raw bytes (the vault, or an in-memory buffer), plus a map of
/// *already-computed* feature bundles from upstream analyzers in the
/// same pipeline run. Phase 3+ analyzers (e.g. `poly` → needs `static`
/// and `disasm`) read from this map instead of re-doing upstream work.
pub struct AnalysisContext<'a> {
    source: ByteSource<'a>,
    pub previous_features: HashMap<String, Value>,
}

impl<'a> AnalysisContext<'a> {
    /// A context that loads sample bytes from the encrypted vault.
    pub fn new(vault: &'a crate::Vault) -> Self {
        Self {
            source: ByteSource::Vault(vault),
            previous_features: HashMap::new(),
        }
    }

    /// A context over bytes already in memory. Used by stateless scans,
    /// which analyze a file without ingesting it into the vault.
    pub fn in_memory(bytes: &'a [u8]) -> Self {
        Self {
            source: ByteSource::Memory(bytes),
            previous_features: HashMap::new(),
        }
    }

    /// Load the raw bytes of `id` from this context's byte source.
    pub fn load(&self, id: &SampleId) -> Result<Vec<u8>> {
        match self.source {
            ByteSource::Vault(v) => v.load(id),
            ByteSource::Memory(b) => Ok(b.to_vec()),
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
