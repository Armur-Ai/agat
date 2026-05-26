//! [`agat_core::Analyzer`] implementation for metamorphic analysis.

use crate::features::MetaFeatures;
use crate::normalize::{canonicalize_block_with, RegisterRenamer};
use crate::wl_hash::{hash_block, wl_hash};
use agat_core::{AnalysisContext, Analyzer, Error, FeatureBundle, Result, Sample};
use agat_disasm::{DisasmFeatures, DisasmLine};

const NAME: &str = "meta";
const VERSION: &str = "0.1.0";

pub struct MetaAnalyzer {
    pub preview_size: usize,
}

impl Default for MetaAnalyzer {
    fn default() -> Self {
        Self { preview_size: 64 }
    }
}

impl Analyzer for MetaAnalyzer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }
    fn dependencies(&self) -> &[&'static str] {
        &["disasm"]
    }

    fn analyze(&self, _sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle> {
        let df: DisasmFeatures = pull_features(ctx, "disasm")?;

        if df.bitness == 0 || df.blocks.is_empty() {
            return Ok(empty_bundle());
        }

        // Walk every instruction in the listing once, in address order.
        // For each block, collect the instructions whose addresses lie
        // in [block.start, block.end]. We treat the whole sample as a
        // single "function" so the register renamer is consistent
        // across blocks.
        let mut block_lines: Vec<Vec<&DisasmLine>> = vec![Vec::new(); df.blocks.len()];
        for line in &df.listing_preview {
            for (i, block) in df.blocks.iter().enumerate() {
                if line.address >= block.start && line.address <= block.end {
                    block_lines[i].push(line);
                    break;
                }
            }
        }

        let mut renamer = RegisterRenamer::new();
        let mut canonical_blocks = Vec::with_capacity(df.blocks.len());
        for lines in &block_lines {
            canonical_blocks.push(canonicalize_block_with(lines, &mut renamer));
        }

        let block_fingerprints: Vec<String> = canonical_blocks.iter().map(|b| hash_block(b)).collect();
        let edges: Vec<(usize, usize)> = df.edges.iter().map(|e| (e.from, e.to)).collect();
        let cfg_fingerprint = wl_hash(&canonical_blocks, &edges);

        let normalized_instruction_count: usize =
            canonical_blocks.iter().map(|b| b.len()).sum();
        let canonical_preview = canonical_blocks
            .iter()
            .flatten()
            .take(self.preview_size)
            .cloned()
            .collect();

        let features = MetaFeatures {
            cfg_fingerprint,
            block_count: df.blocks.len(),
            edge_count: df.edges.len(),
            instruction_count: df.instruction_count,
            normalized_instruction_count,
            block_fingerprints,
            canonical_preview,
        };

        Ok(FeatureBundle {
            analyzer: NAME,
            version: VERSION,
            features: serde_json::to_value(&features)?,
            artifacts: vec![],
        })
    }
}

fn empty_bundle() -> FeatureBundle {
    let features = MetaFeatures {
        cfg_fingerprint: String::new(),
        block_count: 0,
        edge_count: 0,
        instruction_count: 0,
        normalized_instruction_count: 0,
        block_fingerprints: vec![],
        canonical_preview: vec![],
    };
    FeatureBundle {
        analyzer: NAME,
        version: VERSION,
        features: serde_json::to_value(&features).unwrap_or(serde_json::Value::Null),
        artifacts: vec![],
    }
}

fn pull_features<T: serde::de::DeserializeOwned>(
    ctx: &AnalysisContext,
    name: &str,
) -> Result<T> {
    let value = ctx
        .previous_features
        .get(name)
        .ok_or_else(|| Error::Other(format!("meta: required upstream features '{name}' missing")))?;
    serde_json::from_value(value.clone()).map_err(Error::from)
}
