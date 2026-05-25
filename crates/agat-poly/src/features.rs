//! Serializable polymorphic-analysis feature blob.

use crate::detect::{DecryptorPattern, Signal};
use crate::recover::RecoveredPayload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolyFeatures {
    pub confidence: f64,
    pub signals: Vec<Signal>,
    pub detected_pattern: Option<DecryptorPattern>,
    pub recovered: Option<RecoveredPayload>,
}

impl PolyFeatures {
    pub fn is_polymorphic(&self) -> bool {
        self.confidence >= 0.5
    }
}
