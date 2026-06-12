//! agat's Artificial Immune System core.
//!
//! This crate implements the computational logic of three immune
//! mechanisms over the mutation-invariant antigen produced by
//! `agat-antigen`:
//!
//! - **Negative selection** — Forrest, Perelson, Allen & Cherukuri,
//!   *Self-Nonself Discrimination in a Computer*, IEEE S&P 1994; in its
//!   real-valued V-detector form, Ji & Dasgupta, GECCO 2004.
//! - **Clonal selection / affinity maturation** — de Castro & Von
//!   Zuben, *Learning and Optimization Using the Clonal Selection
//!   Principle (CLONALG)*, IEEE TEC 2002.
//! - **Danger theory / dendritic cells** — Greensmith, Aickelin &
//!   Cayzer, *Introducing Dendritic Cells as a Novel Immune-Inspired
//!   Algorithm for Anomaly Detection*, ICARIS 2005.
//!
//! This is **bio-inspired computing**: agat implements the algorithms'
//! logic over real behavioral data. It is not a biological simulation.
//!
//! Stage 2 adds [`self_model`]; later stages add negative selection,
//! recognition, clonal selection, and the danger layer as sibling
//! modules.

pub mod clonal;
pub mod danger;
pub mod detectors;
pub mod memory;
pub mod negative_selection;
pub mod recognition;
pub mod self_model;

pub use clonal::{mature, ClonalConfig, Maturation};
pub use danger::{
    assess as assess_danger, signals_from_features, DangerAssessment, DangerConfig, DangerContext,
    DangerSignals, SignalClass,
};
pub use detectors::{Detector, DetectorOrigin, Repertoire};
pub use memory::{MemoryCell, MemoryPool};
pub use negative_selection::{generate as generate_repertoire, NsaConfig};
pub use recognition::{recognize, DetectorMatch, Recognition};
pub use self_model::{SelfModel, SelfPoint};
