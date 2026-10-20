//! Operator configuration: `config.toml` in the agat home (or `--config`).
//!
//! Everything here is optional; a missing file means built-in defaults.
//! Command-line flags override the file. Example:
//!
//! ```toml
//! [scan]
//! output = "json"        # text | json | sarif
//! fail_on = "suspicious" # review | suspicious | malicious | never
//!
//! [danger]
//! dangerous_at = 0.5     # danger score >= this => dangerous
//! safe_below = 0.33      # danger score <  this => safe
//!
//! [allowlist]
//! sha256 = ["<64 hex>"]  # always reported clean
//!
//! [denylist]
//! sha256 = ["<64 hex>"]  # always reported malicious (wins over allowlist)
//! ```

use agat_core::Severity;
use agat_engine::ScanPolicy;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Output format for the `recognize` and `scan` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Human-readable, multi-axis report (the default).
    Text,
    /// `ScanResult` JSON (a single object, or an array for a batch).
    Json,
    /// SARIF 2.1.0 log — one finding per non-clean sample.
    Sarif,
}

/// The lowest severity that makes `scan`/`recognize` exit non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Review,
    Suspicious,
    Malicious,
    /// Always exit 0 on a completed scan (report-only mode).
    Never,
}

impl FailOn {
    /// The process exit code for a (worst) severity under this threshold:
    /// the severity's own code if it meets the threshold, else `0`.
    pub fn exit_code(self, worst: Severity) -> i32 {
        let threshold = match self {
            FailOn::Review => Severity::Review,
            FailOn::Suspicious => Severity::Suspicious,
            FailOn::Malicious => Severity::Malicious,
            FailOn::Never => return 0,
        };
        if worst >= threshold {
            worst.exit_code()
        } else {
            0
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub scan: ScanSection,
    pub danger: DangerSection,
    pub allowlist: HashList,
    pub denylist: HashList,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanSection {
    pub output: Option<OutputFormat>,
    pub fail_on: Option<FailOn>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DangerSection {
    pub dangerous_at: Option<f64>,
    pub safe_below: Option<f64>,
    pub migration_threshold: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HashList {
    pub sha256: Vec<String>,
}

impl Config {
    /// Load `explicit` if given (it must exist), else `<home>/config.toml`
    /// if present, else the defaults.
    pub fn load(explicit: Option<&Path>, home: &Path) -> Result<Self> {
        let default_path = home.join("config.toml");
        let path = match explicit {
            Some(p) => p,
            None if default_path.is_file() => default_path.as_path(),
            None => return Ok(Self::default()),
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.policy()?; // validate eagerly so a bad file fails at startup
        Ok(cfg)
    }

    /// The scan-time policy this config describes.
    pub fn policy(&self) -> Result<ScanPolicy> {
        let mut danger = agat_immune::DangerConfig::default();
        if let Some(v) = self.danger.dangerous_at {
            danger.dangerous_at = unit("danger.dangerous_at", v)?;
        }
        if let Some(v) = self.danger.safe_below {
            danger.safe_below = unit("danger.safe_below", v)?;
        }
        if let Some(v) = self.danger.migration_threshold {
            danger.migration_threshold = unit("danger.migration_threshold", v)?;
        }
        if danger.safe_below > danger.dangerous_at {
            bail!(
                "danger.safe_below ({}) must not exceed danger.dangerous_at ({})",
                danger.safe_below,
                danger.dangerous_at
            );
        }
        Ok(ScanPolicy {
            danger,
            allow_sha256: hashes("allowlist", &self.allowlist.sha256)?,
            deny_sha256: hashes("denylist", &self.denylist.sha256)?,
        })
    }
}

fn unit(key: &str, v: f64) -> Result<f64> {
    if !(0.0..=1.0).contains(&v) {
        bail!("{key} must be in [0, 1], got {v}");
    }
    Ok(v)
}

fn hashes(list: &str, raw: &[String]) -> Result<std::collections::HashSet<String>> {
    raw.iter()
        .map(|h| {
            let h = h.trim().to_ascii_lowercase();
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{list}.sha256 entry '{h}' is not a 64-character hex SHA-256");
            }
            Ok(h)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "AB00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn empty_config_is_all_defaults() {
        let cfg = Config::parse("").unwrap();
        assert!(cfg.scan.output.is_none());
        assert!(cfg.scan.fail_on.is_none());
        let p = cfg.policy().unwrap();
        assert_eq!(p.danger, agat_immune::DangerConfig::default());
        assert!(p.allow_sha256.is_empty() && p.deny_sha256.is_empty());
    }

    #[test]
    fn full_config_parses_and_normalizes_hashes() {
        let cfg = Config::parse(&format!(
            "[scan]\noutput = \"sarif\"\nfail_on = \"malicious\"\n\
             [danger]\ndangerous_at = 0.6\nsafe_below = 0.2\n\
             [allowlist]\nsha256 = [\"{H}\"]\n"
        ))
        .unwrap();
        assert_eq!(cfg.scan.output, Some(OutputFormat::Sarif));
        assert_eq!(cfg.scan.fail_on, Some(FailOn::Malicious));
        let p = cfg.policy().unwrap();
        assert_eq!(p.danger.dangerous_at, 0.6);
        assert_eq!(p.danger.safe_below, 0.2);
        assert!(p.allow_sha256.contains(&H.to_ascii_lowercase()));
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::parse("[scan]\nfail_on = \"sometimes\"").is_err());
        assert!(Config::parse("[danger]\ndangerous_at = 1.5").is_err());
        assert!(Config::parse("[danger]\ndangerous_at = 0.2\nsafe_below = 0.4").is_err());
        assert!(Config::parse("[denylist]\nsha256 = [\"nothex\"]").is_err());
        assert!(Config::parse("[typo]\nx = 1").is_err());
    }

    #[test]
    fn fail_on_gates_the_exit_code() {
        assert_eq!(FailOn::Review.exit_code(Severity::Review), 2);
        assert_eq!(FailOn::Suspicious.exit_code(Severity::Review), 0);
        assert_eq!(FailOn::Suspicious.exit_code(Severity::Malicious), 3);
        assert_eq!(FailOn::Malicious.exit_code(Severity::Suspicious), 0);
        assert_eq!(FailOn::Never.exit_code(Severity::Malicious), 0);
        assert_eq!(FailOn::Review.exit_code(Severity::Clean), 0);
    }
}
