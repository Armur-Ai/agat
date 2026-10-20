//! [`agat_core::Analyzer`] implementation for static analysis.

use crate::features::{StaticFeatures, StringSummary};
use crate::{entropy, hashes, parse, strings};
use agat_core::{AnalysisContext, Analyzer, FeatureBundle, Result, Sample};

const NAME: &str = "static";
const VERSION: &str = "0.1.0";

pub struct StaticAnalyzer {
    pub window_size: usize,
    pub window_step: usize,
    pub min_string_len: usize,
    pub max_strings_in_summary: usize,
}

impl Default for StaticAnalyzer {
    fn default() -> Self {
        Self {
            window_size: 256,
            window_step: 256,
            min_string_len: 6,
            max_strings_in_summary: 256,
        }
    }
}

impl Analyzer for StaticAnalyzer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }

    fn analyze(&self, sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle> {
        let bytes = ctx.load(&sample.id)?;

        let parsed = parse::parse(&bytes);
        let hashes = hashes::compute_hashes(&bytes, &parsed);
        let entropy = entropy::entropy_curve(&bytes, self.window_size, self.window_step);
        let all_strings = strings::extract_strings(&bytes, self.min_string_len);
        let ascii_count = all_strings
            .iter()
            .filter(|s| s.encoding == strings::StringEncoding::Ascii)
            .count();
        let utf16le_count = all_strings
            .iter()
            .filter(|s| s.encoding == strings::StringEncoding::Utf16Le)
            .count();
        let samples = all_strings
            .into_iter()
            .take(self.max_strings_in_summary)
            .collect();

        let features = StaticFeatures {
            size: bytes.len() as u64,
            parsed,
            hashes,
            entropy,
            strings: StringSummary {
                min_len: self.min_string_len,
                ascii_count,
                utf16le_count,
                samples,
            },
        };

        Ok(FeatureBundle {
            analyzer: NAME,
            version: VERSION,
            features: serde_json::to_value(&features)?,
            artifacts: vec![],
        })
    }
}
