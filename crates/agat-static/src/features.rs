//! The structured feature blob emitted by [`crate::StaticAnalyzer`].

use crate::entropy::EntropyCurve;
use crate::hashes::Hashes;
use crate::parse::ParsedBinary;
use crate::strings::ExtractedString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFeatures {
    pub size: u64,
    pub parsed: ParsedBinary,
    pub hashes: Hashes,
    pub entropy: EntropyCurve,
    pub strings: StringSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringSummary {
    pub min_len: usize,
    pub ascii_count: usize,
    pub utf16le_count: usize,
    /// Truncated sample for display in CLI/TUI (first N strings by
    /// offset). The full list is recoverable by re-running extraction
    /// against the raw bytes.
    pub samples: Vec<ExtractedString>,
}
