//! Core types, traits, and the encrypted sample vault for agat.
//!
//! Every analyzer crate depends on this one. It defines the universal
//! vocabulary used across the workspace:
//!
//! - [`Sample`], [`SampleId`], [`SampleKind`], [`SampleMetadata`]
//! - The [`Analyzer`] trait and the [`FeatureBundle`] / [`Artifact`] types
//!   it returns
//! - The encrypted on-disk [`Vault`] that holds binary samples
//! - The crate-wide [`Error`] and [`Result`] types

pub mod analyzer;
pub mod error;
pub mod sample;
pub mod scan;
pub mod vault;

pub use analyzer::{AnalysisContext, Analyzer, Artifact, FeatureBundle};
pub use error::{Error, Result};
pub use sample::{Sample, SampleId, SampleKind, SampleMetadata};
pub use scan::{
    AntigenSummary, DangerSummary, RecognitionSummary, SampleRef, ScanResult, Severity,
    SignalSummary, Verdict, SCAN_SCHEMA_VERSION,
};
pub use vault::Vault;
