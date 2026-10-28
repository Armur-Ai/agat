//! Antigen presentation for agat's Artificial Immune System.
//!
//! Stage 1 of the immune pipeline. This crate is the bridge between
//! agat's existing behavioral analysis (static, disasm, poly, meta, ai)
//! and the immune core (`agat-immune`). It projects the per-analyzer
//! feature bundles into a single **antigen**: a mutation-invariant
//! behavioral signature plus the affinity metric every downstream
//! immune mechanism operates in.
//!
//! Why this layer exists, stated honestly: negative selection
//! (Forrest et al., 1994), clonal selection (de Castro & Von Zuben,
//! 2002), and the dendritic-cell algorithm (Greensmith & Aickelin,
//! 2005) all require a **metric space**. agat's existing fingerprints
//! are hashes — match is all-or-nothing, with no graded affinity. The
//! antigen turns the real behavioral features into a genuine metric in
//! which **variants of one family are close and different families are
//! far**, which is precisely what lets recognition generalize to
//! variants it has never seen.
//!
//! See [`antigen`] for the representation and [`affinity`] for the
//! metric.

pub mod affinity;
pub mod antigen;
pub mod mutate;
pub mod opcode;

pub use affinity::{
    affinity, cosine_similarity, distance, euclidean_distance, jaccard, AffinityConfig,
};
pub use antigen::{signature_labels, Antigen, AntigenConfig, AntigenInput, ANTIGEN_LAYOUT_VERSION};
pub use mutate::{mutate, perturb_signature, variant_batch, MutationClass};
pub use opcode::{classify, OPCODE_CLASSES, OPCODE_CLASS_COUNT};

#[cfg(test)]
mod tests {
    //! Stage-1 acceptance test: family variants are closer in antigen
    //! space than cross-family samples. This is the property the entire
    //! immune pipeline rests on — if it doesn't hold, nothing
    //! downstream can generalize.

    use super::*;
    use agat_disasm::{DisasmFeatures, Edge, EdgeKind};
    use agat_meta::MetaFeatures;
    use agat_static::parse::Arch;
    use std::collections::HashMap;

    /// Build a DisasmFeatures with a given opcode mix and CFG shape.
    /// `edges` placeholder edges are synthesized so `cfg_shape` (which
    /// reads `edges.len()`) sees the intended count.
    fn disasm(opcodes: &[(&str, usize)], blocks: usize, edges: usize) -> DisasmFeatures {
        let mut hist = HashMap::new();
        let mut instr = 0;
        for (m, c) in opcodes {
            hist.insert((*m).to_string(), *c);
            instr += *c;
        }
        DisasmFeatures {
            arch: Arch::X86_64,
            bitness: 64,
            disassembled_section: None,
            section_base: 0,
            disassembled_bytes: 0,
            instruction_count: instr,
            block_count: blocks,
            function_estimate: 1,
            listing_preview: vec![],
            blocks: vec![],
            edges: (0..edges)
                .map(|i| Edge {
                    from: i,
                    to: i + 1,
                    kind: EdgeKind::Fallthrough,
                })
                .collect(),
            opcode_histogram: hist,
        }
    }

    fn meta(block_fps: &[&str]) -> MetaFeatures {
        MetaFeatures {
            cfg_fingerprint: format!("cfg-{}", block_fps.join("-")),
            block_count: block_fps.len(),
            edge_count: block_fps.len().saturating_sub(1),
            instruction_count: 0,
            normalized_instruction_count: 0,
            block_fingerprints: block_fps.iter().map(|s| s.to_string()).collect(),
            canonical_preview: vec![],
        }
    }

    fn antigen(df: &DisasmFeatures, mf: &MetaFeatures) -> Antigen {
        Antigen::build(
            &AntigenInput {
                disasm: Some(df),
                meta: Some(mf),
                ..Default::default()
            },
            &AntigenConfig::default(),
        )
    }

    #[test]
    fn family_variants_are_closer_than_cross_family() {
        // Family A: a byte-wise XOR decryptor. Two metamorphic variants
        // share opcode mix and most canonical blocks (register renaming
        // changes neither), differing only in one block / a stray op.
        let a1 = antigen(
            &disasm(
                &[("mov", 4), ("xor", 3), ("inc", 2), ("cmp", 1), ("jne", 1)],
                3,
                3,
            ),
            &meta(&["b_load", "b_xor", "b_loop"]),
        );
        let a2 = antigen(
            &disasm(
                &[("mov", 5), ("xor", 3), ("inc", 2), ("cmp", 1), ("jne", 1)],
                3,
                3,
            ),
            &meta(&["b_load", "b_xor", "b_loop2"]), // one block differs
        );

        // Family B: an add/rotate cipher with a different control-flow
        // shape and disjoint canonical blocks.
        let b1 = antigen(
            &disasm(
                &[("add", 5), ("rol", 4), ("push", 3), ("call", 2), ("ret", 1)],
                6,
                8,
            ),
            &meta(&["c_init", "c_round", "c_perm", "c_mix", "c_out"]),
        );

        let intra = affinity(&a1, &a2, &AffinityConfig::default());
        let inter_ab = affinity(&a1, &b1, &AffinityConfig::default());
        let inter_ab2 = affinity(&a2, &b1, &AffinityConfig::default());

        assert!(
            intra > inter_ab && intra > inter_ab2,
            "intra-family affinity {intra:.3} must exceed inter-family ({inter_ab:.3}, {inter_ab2:.3})"
        );
        // And the margin should be substantial, not marginal.
        assert!(
            intra - inter_ab > 0.2,
            "expected a clear margin; got intra {intra:.3} vs inter {inter_ab:.3}"
        );
    }

    #[test]
    fn identical_features_have_affinity_one() {
        let df = disasm(&[("mov", 3), ("xor", 2), ("jne", 1)], 2, 2);
        let mf = meta(&["x", "y"]);
        let a = antigen(&df, &mf);
        let b = antigen(&df, &mf);
        let aff = affinity(&a, &b, &AffinityConfig::default());
        assert!(
            (aff - 1.0).abs() < 1e-9,
            "identical antigens should have affinity 1, got {aff}"
        );
    }

    #[test]
    fn signature_length_matches_schema() {
        let cfg = AntigenConfig::default();
        let a = antigen(&disasm(&[("mov", 1)], 1, 0), &meta(&["z"]));
        assert_eq!(a.dim(), signature_labels(&cfg).len());
    }

    #[test]
    fn empty_inputs_do_not_panic() {
        let a = Antigen::build(&AntigenInput::default(), &AntigenConfig::default());
        assert_eq!(a.dim(), signature_labels(&AntigenConfig::default()).len());
        assert!(a.block_tokens.is_empty());
        // Two empty antigens: cosine of zero vectors is defined as 0.
        let b = Antigen::build(&AntigenInput::default(), &AntigenConfig::default());
        assert_eq!(affinity(&a, &b, &AffinityConfig::default()), 0.0);
    }
}
