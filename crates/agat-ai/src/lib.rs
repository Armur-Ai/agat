//! AI-signal detectors for LLM-rewritten malware variants.
//!
//! Phase 5 of the agat pipeline. Implements three of the five signal
//! vectors called out in the design doc:
//!
//! 1. **Stylometry** — compute features from the binary's strings
//!    and disassembly that tend to differ between human-compiled
//!    code and LLM-generated code (verbose identifiers, long
//!    descriptive comments, opcode-distribution entropy, etc.).
//! 3. **Artifact scan** — byte- and substring-pattern matching for
//!    AI-tells: refusal phrases, role markers, ChatML tokens, model
//!    magic bytes, API endpoints, system-prompt residue, BPE
//!    fragments.
//!
//! Signal 4 (cross-variant semantic divergence) is computed by the
//! CLI's `agat divergence` command, since it's inherently a
//! many-sample analysis rather than a per-sample feature. Signal 2
//! (perplexity via llama.cpp) is Phase 6.
//!
//! The verdict is a weighted sum of signal scores, capped at 0.95 —
//! we never claim 100% on heuristics.

pub mod analyzer;
pub mod artifacts;
pub mod features;
pub mod perplexity;
pub mod stylometry;

pub use analyzer::AiAnalyzer;
pub use artifacts::{ArtifactCategory, ArtifactHit};
pub use features::{AiFeatures, SignalScores};
pub use perplexity::{PerplexityBackend, PerplexityResult};
pub use stylometry::StylometricFeatures;
