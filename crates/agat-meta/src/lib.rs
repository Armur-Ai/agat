//! Metamorphic-engine detection.
//!
//! Phase 4. Will canonicalize basic blocks (junk removal, register
//! renaming via data-dependence graph isomorphism, instruction
//! folding, independent-instruction sort) and hash normalized CFGs
//! via Weisfeiler-Lehman for family clustering.
