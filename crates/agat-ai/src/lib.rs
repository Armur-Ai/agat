//! AI-signal detectors.
//!
//! Phase 5-6. Implements the five-vector detection methodology
//! defined in the design doc:
//!
//! 1. Stylometric AST features over decompiled pseudo-C
//! 2. Perplexity scoring (llama.cpp sidecar)
//! 3. Prompt / model artifact YARA scan
//! 4. Cross-variant semantic divergence
//! 5. Generator family fingerprint (stretch)
