//! Polymorphic engine detection and decryptor recovery.
//!
//! Phase 3 of the agat pipeline. Looks for the canonical decryptor
//! stub shape — a low-entropy preamble followed by a high-entropy
//! body, with a tight in-place byte-rewriting loop driving the
//! transition — and, where possible, recovers the plaintext payload
//! by reapplying the inverse operation with a statically-extracted
//! key.
//!
//! What this crate handles in Phase 3 v1:
//!
//! - Single-byte XOR loops with an immediate key
//! - Single-byte ADD / SUB loops with an immediate key
//! - Entropy-boundary heuristic to locate stub-vs-payload split
//! - Backward-jump-in-prelude as a corroborating signal
//!
//! What it doesn't yet handle (deferred):
//!
//! - Register-key XOR loops where the key is loaded into a register
//!   and used by a `xor [mem], reg` form
//! - Multi-byte rotating-key XOR
//! - Multi-stage decryptors / key-derivation routines
//! - Full CPU emulation via unicorn (the "obvious upgrade" path)

pub mod analyzer;
pub mod detect;
pub mod features;
pub mod recover;

pub use analyzer::PolyAnalyzer;
pub use detect::{DecryptorPattern, Operation, Signal};
pub use features::PolyFeatures;
pub use recover::RecoveredPayload;
