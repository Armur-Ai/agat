//! Serializable feature blob emitted by [`crate::MetaAnalyzer`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalInstruction {
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaFeatures {
    /// 16-char hex hash of the WL-refined CFG. Empty string when the
    /// sample isn't disassemblable (non-x86 or zero blocks).
    pub cfg_fingerprint: String,
    pub block_count: usize,
    pub edge_count: usize,
    pub instruction_count: usize,
    pub normalized_instruction_count: usize,
    /// Per-block initial labels — useful for debugging why two
    /// variants don't collapse to the same fingerprint.
    pub block_fingerprints: Vec<String>,
    /// First N canonical instructions, in CFG order, for display.
    pub canonical_preview: Vec<CanonicalInstruction>,
}

impl MetaFeatures {
    pub fn has_fingerprint(&self) -> bool {
        !self.cfg_fingerprint.is_empty()
    }
}
