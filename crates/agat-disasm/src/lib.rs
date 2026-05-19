//! Disassembly and CFG construction.
//!
//! Phase 2 of the agat pipeline. Wraps iced-x86 for x86/x64
//! disassembly and adds:
//!
//! - linear sweep over executable byte regions
//! - recursive descent from entry point, exports, and direct
//!   branch/call targets
//! - leader-based basic-block construction
//! - intra-procedural control-flow graph with typed edges
//!
//! For non-x86 architectures this crate returns an empty
//! [`DisasmFeatures`] with `bitness = 0` rather than failing — the
//! analyzer must work on unknown samples too.

pub mod analyzer;
pub mod cfg;
pub mod disasm;
pub mod features;

pub use analyzer::DisasmAnalyzer;
pub use cfg::{BasicBlock, BlockTerminator, Edge, EdgeKind};
pub use disasm::{DisasmLine, FlowKind};
pub use features::DisasmFeatures;
