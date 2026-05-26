//! Metamorphic-engine detection.
//!
//! Phase 4 of the agat pipeline. Builds a canonical form of each
//! disassembled function, then fingerprints the resulting normalized
//! CFG via Weisfeiler-Lehman hashing. Two samples with the same
//! fingerprint are members of the same metamorphic family.
//!
//! What this crate normalizes in Phase 4 v1:
//!
//! - NOP-like instructions (`nop`, `xchg reg,reg` same register)
//! - Register names, canonicalized into family slots (`R0`, `R1`, …)
//!   by first-appearance order, with `rsp`/`rbp` preserved because
//!   they have semantic roles
//! - Immediate values (collapsed to `IMM`) and memory displacements
//!
//! What it doesn't do yet (deferred to Phase 4.5+):
//!
//! - Folding semantically-equivalent instruction sequences
//!   (`xor reg,reg` ≡ `mov reg,0`, push/pop pairs that cancel, etc.)
//! - Reordering independent instructions into a canonical
//!   data-dependence order
//! - Algorithm-level normalization (the *next* tier — AI rewriters
//!   change algorithms, not just register names)

pub mod analyzer;
pub mod features;
pub mod normalize;
pub mod wl_hash;

pub use analyzer::MetaAnalyzer;
pub use features::{CanonicalInstruction, MetaFeatures};
