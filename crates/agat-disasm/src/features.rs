//! Serializable feature blob emitted by [`crate::DisasmAnalyzer`].

use crate::cfg::{BasicBlock, Edge};
use crate::disasm::DisasmLine;
use agat_static::parse::Arch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisasmFeatures {
    pub arch: Arch,
    /// 32 for x86, 64 for x86_64, 0 if the architecture isn't supported.
    pub bitness: u32,
    pub disassembled_section: Option<String>,
    pub section_base: u64,
    pub disassembled_bytes: u64,
    pub instruction_count: usize,
    pub block_count: usize,
    pub function_estimate: usize,
    /// First N instructions of the listing (sorted by address) for
    /// display in the CLI and TUI.
    pub listing_preview: Vec<DisasmLine>,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<Edge>,
    /// Top-K mnemonic frequencies — used later by the AI-signal layer
    /// for stylometric comparisons across variants.
    pub opcode_histogram: HashMap<String, usize>,
}
