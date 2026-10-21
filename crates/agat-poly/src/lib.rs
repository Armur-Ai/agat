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
//! - Key-less recovery (`solve`): register-held and multi-byte repeating
//!   XOR/ADD/SUB keys solved from the ciphertext itself
//!
//! What it doesn't yet handle (deferred):
//!
//! - Multi-stage decryptors / key-derivation routines
//! - Non-repeating keystreams (RC4, LCG-derived keys, …)
//! - Full CPU emulation via unicorn (the "obvious upgrade" path)

pub mod analyzer;
pub mod detect;
pub mod features;
pub mod recover;
pub mod solve;

pub use analyzer::PolyAnalyzer;
pub use detect::{DecryptorPattern, Operation, Signal};
pub use features::PolyFeatures;
pub use recover::{KeySource, RecoveredPayload};
