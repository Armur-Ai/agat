//! Byte- and substring-pattern matching for AI-related artifacts.
//!
//! The rule set is a curated list of distinctive patterns that show
//! up around LLM-generated or LLM-assisted code: refusal phrases the
//! model couldn't quite suppress, ChatML control tokens, model magic
//! bytes (in case a sample bundles its own quantized weights), API
//! endpoints, BPE tokenizer fragments. Production rule sets would
//! grow this list significantly; the Phase 5 set is enough to make
//! the demo light up convincingly.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArtifactCategory {
    RefusalString,
    RoleMarker,
    ChatMlMarker,
    ModelMagic,
    TokenizerFragment,
    ApiEndpoint,
    SystemPrompt,
}

impl ArtifactCategory {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactCategory::RefusalString => "refusal",
            ArtifactCategory::RoleMarker => "role marker",
            ArtifactCategory::ChatMlMarker => "ChatML",
            ArtifactCategory::ModelMagic => "model magic",
            ArtifactCategory::TokenizerFragment => "tokenizer",
            ArtifactCategory::ApiEndpoint => "API endpoint",
            ArtifactCategory::SystemPrompt => "system prompt",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    name: &'static str,
    category: ArtifactCategory,
    needle: &'static [u8],
}

const RULES: &[Rule] = &[
    Rule {
        name: "as_an_ai",
        category: ArtifactCategory::RefusalString,
        needle: b"As an AI",
    },
    Rule {
        name: "i_cannot_help",
        category: ArtifactCategory::RefusalString,
        needle: b"I cannot help with",
    },
    Rule {
        name: "i_am_sorry_but",
        category: ArtifactCategory::RefusalString,
        needle: b"I'm sorry, but",
    },
    Rule {
        name: "claude_identity",
        category: ArtifactCategory::RefusalString,
        needle: b"I'm Claude",
    },
    Rule {
        name: "gpt_identity",
        category: ArtifactCategory::RefusalString,
        needle: b"I'm ChatGPT",
    },
    Rule {
        name: "language_model",
        category: ArtifactCategory::RefusalString,
        needle: b"language model",
    },
    Rule {
        name: "role_user",
        category: ArtifactCategory::RoleMarker,
        needle: b"\"role\":\"user\"",
    },
    Rule {
        name: "role_assistant",
        category: ArtifactCategory::RoleMarker,
        needle: b"\"role\":\"assistant\"",
    },
    Rule {
        name: "role_system",
        category: ArtifactCategory::RoleMarker,
        needle: b"\"role\":\"system\"",
    },
    Rule {
        name: "chatml_im_start",
        category: ArtifactCategory::ChatMlMarker,
        needle: b"<|im_start|>",
    },
    Rule {
        name: "chatml_im_end",
        category: ArtifactCategory::ChatMlMarker,
        needle: b"<|im_end|>",
    },
    Rule {
        name: "chatml_bos",
        category: ArtifactCategory::TokenizerFragment,
        needle: b"<|begin_of_text|>",
    },
    Rule {
        name: "chatml_eos",
        category: ArtifactCategory::TokenizerFragment,
        needle: b"<|end_of_text|>",
    },
    Rule {
        name: "endoftext",
        category: ArtifactCategory::TokenizerFragment,
        needle: b"<|endoftext|>",
    },
    Rule {
        name: "gguf_magic",
        category: ArtifactCategory::ModelMagic,
        needle: b"GGUF",
    },
    Rule {
        name: "safetensors",
        category: ArtifactCategory::ModelMagic,
        needle: b"safetensors",
    },
    Rule {
        name: "openai_endpoint",
        category: ArtifactCategory::ApiEndpoint,
        needle: b"api.openai.com",
    },
    Rule {
        name: "anthropic_endpoint",
        category: ArtifactCategory::ApiEndpoint,
        needle: b"api.anthropic.com",
    },
    Rule {
        name: "cohere_endpoint",
        category: ArtifactCategory::ApiEndpoint,
        needle: b"api.cohere.ai",
    },
    Rule {
        name: "helpful_assistant",
        category: ArtifactCategory::SystemPrompt,
        needle: b"You are a helpful assistant",
    },
    Rule {
        name: "ai_assistant",
        category: ArtifactCategory::SystemPrompt,
        needle: b"You are an AI assistant",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHit {
    pub rule_name: String,
    pub category: ArtifactCategory,
    pub offset: u64,
}

/// Scan `bytes` against the rule set. Each rule fires at most once
/// (at its first occurrence); we don't need every offset for the
/// signal — presence is enough.
pub fn scan(bytes: &[u8]) -> Vec<ArtifactHit> {
    let mut out = Vec::new();
    for rule in RULES {
        if let Some(off) = find_needle(bytes, rule.needle) {
            out.push(ArtifactHit {
                rule_name: rule.name.to_string(),
                category: rule.category,
                offset: off as u64,
            });
        }
    }
    out
}

/// Linear-scan needle search. Good enough for our binary sizes;
/// trades memchr-style optimization for portability.
fn find_needle(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_refusal_string() {
        let data = b"\x00\x00As an AI, I cannot help with that.\x00";
        let hits = scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "as_an_ai"));
        assert!(hits.iter().any(|h| h.rule_name == "i_cannot_help"));
    }

    #[test]
    fn finds_chatml_markers() {
        let data = b"<|im_start|>system\nbe helpful<|im_end|>";
        let hits = scan(data);
        assert!(hits.iter().any(|h| h.rule_name == "chatml_im_start"));
        assert!(hits.iter().any(|h| h.rule_name == "chatml_im_end"));
    }

    #[test]
    fn no_hits_on_random_bytes() {
        let data = [0u8; 4096];
        assert!(scan(&data).is_empty());
    }
}
