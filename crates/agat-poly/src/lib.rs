//! Polymorphic-engine detection.
//!
//! Phase 3. Will fingerprint known decryptor stubs, score the
//! entropy curve, bound-emulate stubs in unicorn to recover plaintext
//! payloads, and report stub/payload byte ranges plus recovered keys
//! where derivable.
