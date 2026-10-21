//! [`agat_core::Analyzer`] implementation for polymorphic detection.

use crate::detect::Signal;
use crate::detect::{collect_signals, confidence, strongest_pattern};
use crate::features::PolyFeatures;
use crate::recover::{try_recover, try_solve};
use agat_core::{AnalysisContext, Analyzer, Error, FeatureBundle, Result, Sample};
use agat_disasm::DisasmFeatures;
use agat_static::StaticFeatures;

const NAME: &str = "poly";
// 0.2.0: key-less recovery for register-held / multi-byte keys, and
// ADD/SUB decryptors run forward.
const VERSION: &str = "0.2.0";

pub struct PolyAnalyzer;

impl Default for PolyAnalyzer {
    fn default() -> Self {
        PolyAnalyzer
    }
}

impl Analyzer for PolyAnalyzer {
    fn name(&self) -> &'static str {
        NAME
    }
    fn version(&self) -> &'static str {
        VERSION
    }
    fn dependencies(&self) -> &[&'static str] {
        &["static", "disasm"]
    }

    fn analyze(&self, sample: &Sample, ctx: &AnalysisContext) -> Result<FeatureBundle> {
        let sf: StaticFeatures = pull_features(ctx, "static")?;
        let df: DisasmFeatures = pull_features(ctx, "disasm")?;
        let bytes = ctx.load(&sample.id)?;

        let signals = collect_signals(&sf, &df);
        let confidence = confidence(&signals);
        let detected_pattern = strongest_pattern(&signals);
        // An immediate key first; if there is none, or it recovers no
        // strings, solve for the key under the decryptor loop's operation.
        let recovered = detected_pattern
            .and_then(|p| try_recover(p, &sf, &bytes))
            .filter(|r| !r.recovered_strings.is_empty())
            .or_else(|| {
                signals.iter().find_map(|s| match s {
                    Signal::DecryptorLoop { op, .. } => try_solve(*op, &sf, &bytes),
                    _ => None,
                })
            });

        let features = PolyFeatures {
            confidence,
            signals,
            detected_pattern,
            recovered,
        };

        Ok(FeatureBundle {
            analyzer: NAME,
            version: VERSION,
            features: serde_json::to_value(&features)?,
            artifacts: vec![],
        })
    }
}

fn pull_features<T: serde::de::DeserializeOwned>(ctx: &AnalysisContext, name: &str) -> Result<T> {
    let value = ctx.previous_features.get(name).ok_or_else(|| {
        Error::Other(format!("poly: required upstream features '{name}' missing"))
    })?;
    serde_json::from_value(value.clone()).map_err(Error::from)
}
