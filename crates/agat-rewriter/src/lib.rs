//! Companion research tool — AI-driven behavior-preserving payload rewriter.
//!
//! Phase 7. Produces AI-rewritten variants of benign or research-known
//! payloads via a local llama.cpp invocation, **solely to provide
//! samples for agat to analyze**. Scope is intentionally narrow:
//! behavior-preserving stylistic rewrites only; no evasion, no
//! persistence, no payload functionality. Refuses to operate on
//! inputs flagged by a local AV check (ClamAV) as a guardrail.
//!
//! See the project README's "Ethics & responsible use" section.
