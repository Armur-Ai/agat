//! [`agat_core::Analyzer`] implementation for x86/x64 disassembly.

use crate::cfg::{build_cfg, EdgeKind};
use crate::disasm::{recursive_descent, DisasmLine};
use crate::features::DisasmFeatures;
use agat_core::{AnalysisContext, Analyzer, FeatureBundle, Result, Sample};
use agat_static::parse::{parse, Arch, Section};
use std::collections::{HashMap, HashSet};

const NAME: &str = "disasm";
const VERSION: &str = "0.1.0";

pub struct DisasmAnalyzer {
    pub max_instructions: usize,
    pub listing_preview_size: usize,
    pub histogram_top_k: usize,
}

impl Default for DisasmAnalyzer {
    fn default() -> Self {
        Self {
            max_instructions: 50_000,
            listing_preview_size: 256,
            histogram_top_k: 32,
        }
    }
}

impl Analyzer for DisasmAnalyzer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }
    fn dependencies(&self) -> &[&'static str] {
        &["static"]
    }

    fn analyze(&self, sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle> {
        let bytes = ctx.vault.load(&sample.id)?;
        let parsed = parse(&bytes);

        let bitness = match parsed.arch {
            Arch::X86 => 32,
            Arch::X86_64 => 64,
            _ => 0,
        };
        if bitness == 0 {
            return Ok(empty_bundle(parsed.arch));
        }

        let (section_name, section_base, section_bytes) =
            pick_executable_section(&parsed.sections, &bytes, parsed.entry_point);

        if section_bytes.is_empty() {
            return Ok(empty_bundle(parsed.arch));
        }

        let mut roots = Vec::new();
        let end_addr = section_base + section_bytes.len() as u64;
        if parsed.entry_point >= section_base && parsed.entry_point < end_addr {
            roots.push(parsed.entry_point);
        }
        for exp in &parsed.exports {
            if exp.address >= section_base && exp.address < end_addr {
                roots.push(exp.address);
            }
        }
        if roots.is_empty() {
            roots.push(section_base);
        }

        let lines = recursive_descent(
            &section_bytes,
            section_base,
            bitness,
            &roots,
            self.max_instructions,
        );
        let (blocks, edges) = build_cfg(&lines);

        let opcode_histogram = top_k_mnemonics(&lines, self.histogram_top_k);
        let function_estimate = estimate_functions(&blocks, &edges);
        let listing_preview: Vec<DisasmLine> = lines
            .iter()
            .take(self.listing_preview_size)
            .cloned()
            .collect();

        let features = DisasmFeatures {
            arch: parsed.arch,
            bitness,
            disassembled_section: section_name,
            section_base,
            disassembled_bytes: section_bytes.len() as u64,
            instruction_count: lines.len(),
            block_count: blocks.len(),
            function_estimate,
            listing_preview,
            blocks,
            edges,
            opcode_histogram,
        };

        Ok(FeatureBundle {
            analyzer: NAME,
            version: VERSION,
            features: serde_json::to_value(&features)?,
            artifacts: vec![],
        })
    }
}

fn empty_bundle(arch: Arch) -> FeatureBundle {
    let features = DisasmFeatures {
        arch,
        bitness: 0,
        disassembled_section: None,
        section_base: 0,
        disassembled_bytes: 0,
        instruction_count: 0,
        block_count: 0,
        function_estimate: 0,
        listing_preview: vec![],
        blocks: vec![],
        edges: vec![],
        opcode_histogram: HashMap::new(),
    };
    FeatureBundle {
        analyzer: NAME,
        version: VERSION,
        features: serde_json::to_value(&features).unwrap_or(serde_json::Value::Null),
        artifacts: vec![],
    }
}

fn pick_executable_section(
    sections: &[Section],
    bytes: &[u8],
    entry: u64,
) -> (Option<String>, u64, Vec<u8>) {
    // First preference: the executable section containing the entry point.
    let containing = sections.iter().find(|s| {
        s.characteristics.executable
            && entry >= s.virtual_address
            && entry < s.virtual_address + s.virtual_size
    });
    if let Some(s) = containing {
        if let Some(blob) = section_bytes(s, bytes) {
            return (Some(s.name.clone()), s.virtual_address, blob);
        }
    }
    // Fallback: first executable section with usable bytes.
    for s in sections.iter().filter(|s| s.characteristics.executable) {
        if let Some(blob) = section_bytes(s, bytes) {
            return (Some(s.name.clone()), s.virtual_address, blob);
        }
    }
    (None, 0, Vec::new())
}

fn section_bytes(s: &Section, bytes: &[u8]) -> Option<Vec<u8>> {
    let off = s.file_offset as usize;
    if off >= bytes.len() || s.file_size == 0 {
        return None;
    }
    let end = (off + s.file_size as usize).min(bytes.len());
    Some(bytes[off..end].to_vec())
}

fn top_k_mnemonics(lines: &[DisasmLine], k: usize) -> HashMap<String, usize> {
    let mut hist: HashMap<String, usize> = HashMap::new();
    for l in lines {
        *hist.entry(l.mnemonic.clone()).or_insert(0) += 1;
    }
    let mut v: Vec<(String, usize)> = hist.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1));
    v.truncate(k);
    v.into_iter().collect()
}

fn estimate_functions(blocks: &[crate::cfg::BasicBlock], edges: &[crate::cfg::Edge]) -> usize {
    if blocks.is_empty() {
        return 0;
    }
    let call_targets: HashSet<usize> = edges
        .iter()
        .filter(|e| e.kind == EdgeKind::Call)
        .map(|e| e.to)
        .collect();
    // The entry block is always at least one function.
    call_targets.len() + 1
}
