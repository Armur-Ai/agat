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
    /// The pattern. For `ci` rules this must be written lower-case.
    needle: &'static [u8],
    /// Case-insensitive match. Used for natural-language tells (refusals,
    /// system prompts), whose casing varies; structural tokens, magic
    /// bytes and endpoints stay exact to avoid false positives.
    ci: bool,
}

const RULES: &[Rule] = &[
    // --- refusals / model identity (case-insensitive) ---------------
    r(
        "as_an_ai",
        ArtifactCategory::RefusalString,
        b"as an ai",
        true,
    ),
    r(
        "as_a_large_lm",
        ArtifactCategory::RefusalString,
        b"as a large language model",
        true,
    ),
    r(
        "i_cannot_help",
        ArtifactCategory::RefusalString,
        b"i cannot help with",
        true,
    ),
    r(
        "i_cant_assist",
        ArtifactCategory::RefusalString,
        b"i can't assist with",
        true,
    ),
    r(
        "cannot_assist",
        ArtifactCategory::RefusalString,
        b"cannot assist with that",
        true,
    ),
    r(
        "i_am_sorry_but",
        ArtifactCategory::RefusalString,
        b"i'm sorry, but",
        true,
    ),
    r(
        "i_apologize_but",
        ArtifactCategory::RefusalString,
        b"i apologize, but",
        true,
    ),
    r(
        "i_must_decline",
        ArtifactCategory::RefusalString,
        b"i must decline",
        true,
    ),
    r(
        "against_guidelines",
        ArtifactCategory::RefusalString,
        b"against my guidelines",
        true,
    ),
    r(
        "not_able_to_provide",
        ArtifactCategory::RefusalString,
        b"not able to provide",
        true,
    ),
    r(
        "claude_identity",
        ArtifactCategory::RefusalString,
        b"i'm claude",
        true,
    ),
    r(
        "gpt_identity",
        ArtifactCategory::RefusalString,
        b"i'm chatgpt",
        true,
    ),
    r(
        "im_an_ai",
        ArtifactCategory::RefusalString,
        b"i'm an ai",
        true,
    ),
    r(
        "language_model",
        ArtifactCategory::RefusalString,
        b"language model, i",
        true,
    ),
    r(
        "knowledge_cutoff",
        ArtifactCategory::RefusalString,
        b"knowledge cutoff",
        true,
    ),
    // --- chat role markers (exact: structured JSON) -----------------
    r(
        "role_user",
        ArtifactCategory::RoleMarker,
        b"\"role\":\"user\"",
        false,
    ),
    r(
        "role_assistant",
        ArtifactCategory::RoleMarker,
        b"\"role\":\"assistant\"",
        false,
    ),
    r(
        "role_system",
        ArtifactCategory::RoleMarker,
        b"\"role\":\"system\"",
        false,
    ),
    // --- ChatML / prompt-template control tokens (exact) ------------
    r(
        "chatml_im_start",
        ArtifactCategory::ChatMlMarker,
        b"<|im_start|>",
        false,
    ),
    r(
        "chatml_im_end",
        ArtifactCategory::ChatMlMarker,
        b"<|im_end|>",
        false,
    ),
    r(
        "llama3_eot",
        ArtifactCategory::ChatMlMarker,
        b"<|eot_id|>",
        false,
    ),
    r(
        "llama3_start_header",
        ArtifactCategory::ChatMlMarker,
        b"<|start_header_id|>",
        false,
    ),
    r(
        "llama3_end_header",
        ArtifactCategory::ChatMlMarker,
        b"<|end_header_id|>",
        false,
    ),
    r(
        "mistral_inst",
        ArtifactCategory::ChatMlMarker,
        b"[/INST]",
        false,
    ),
    r(
        "gemma_turn",
        ArtifactCategory::ChatMlMarker,
        b"<start_of_turn>",
        false,
    ),
    r(
        "alpaca_instruction",
        ArtifactCategory::ChatMlMarker,
        b"### Instruction:",
        false,
    ),
    r(
        "alpaca_response",
        ArtifactCategory::ChatMlMarker,
        b"### Response:",
        false,
    ),
    r(
        "vicuna_user",
        ArtifactCategory::ChatMlMarker,
        b"<|user|>",
        false,
    ),
    r(
        "vicuna_assistant",
        ArtifactCategory::ChatMlMarker,
        b"<|assistant|>",
        false,
    ),
    // --- tokenizer special tokens (exact) ---------------------------
    r(
        "chatml_bos",
        ArtifactCategory::TokenizerFragment,
        b"<|begin_of_text|>",
        false,
    ),
    r(
        "chatml_eos",
        ArtifactCategory::TokenizerFragment,
        b"<|end_of_text|>",
        false,
    ),
    r(
        "endoftext",
        ArtifactCategory::TokenizerFragment,
        b"<|endoftext|>",
        false,
    ),
    r(
        "fim_prefix",
        ArtifactCategory::TokenizerFragment,
        b"<|fim_prefix|>",
        false,
    ),
    r(
        "pad_token",
        ArtifactCategory::TokenizerFragment,
        b"<|pad|>",
        false,
    ),
    r(
        "fim_middle",
        ArtifactCategory::TokenizerFragment,
        b"<fim_middle>",
        false,
    ),
    r(
        "fim_suffix",
        ArtifactCategory::TokenizerFragment,
        b"<fim_suffix>",
        false,
    ),
    r(
        "reserved_special",
        ArtifactCategory::TokenizerFragment,
        b"<|reserved_special_token_",
        false,
    ),
    // --- model magic / weight formats (exact) -----------------------
    r("gguf_magic", ArtifactCategory::ModelMagic, b"GGUF", false),
    r(
        "ggml_magic",
        ArtifactCategory::ModelMagic,
        b"ggml\x00\x00\x00",
        false,
    ),
    r(
        "safetensors",
        ArtifactCategory::ModelMagic,
        b"safetensors",
        false,
    ),
    // --- inference endpoints (exact; already lower-case) ------------
    r(
        "openai_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.openai.com",
        false,
    ),
    r(
        "anthropic_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.anthropic.com",
        false,
    ),
    r(
        "cohere_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.cohere.ai",
        false,
    ),
    r(
        "mistral_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.mistral.ai",
        false,
    ),
    r(
        "google_genai_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"generativelanguage.googleapis.com",
        false,
    ),
    r(
        "groq_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.groq.com",
        false,
    ),
    r(
        "openrouter_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"openrouter.ai",
        false,
    ),
    r(
        "ollama_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"/api/generate",
        false,
    ),
    r(
        "deepseek_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.deepseek.com",
        false,
    ),
    r(
        "xai_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.x.ai",
        false,
    ),
    r(
        "together_endpoint",
        ArtifactCategory::ApiEndpoint,
        b"api.together.xyz",
        false,
    ),
    // --- system prompts (case-insensitive) --------------------------
    r(
        "helpful_assistant",
        ArtifactCategory::SystemPrompt,
        b"you are a helpful assistant",
        true,
    ),
    r(
        "ai_assistant",
        ArtifactCategory::SystemPrompt,
        b"you are an ai assistant",
        true,
    ),
    r(
        "coding_assistant",
        ArtifactCategory::SystemPrompt,
        b"you are a coding assistant",
        true,
    ),
    r(
        "you_are_an_expert",
        ArtifactCategory::SystemPrompt,
        b"you are an expert",
        true,
    ),
];

const fn r(
    name: &'static str,
    category: ArtifactCategory,
    needle: &'static [u8],
    ci: bool,
) -> Rule {
    Rule {
        name,
        category,
        needle,
        ci,
    }
}

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
    // Lower-case copy built once, only if any case-insensitive rule could
    // match (i.e. there are printable ASCII letters to fold).
    let lowered: Option<Vec<u8>> = if bytes.iter().any(|b| b.is_ascii_uppercase()) {
        Some(bytes.iter().map(|b| b.to_ascii_lowercase()).collect())
    } else {
        None
    };
    let mut out = Vec::new();
    for rule in RULES {
        let hay: &[u8] = if rule.ci {
            lowered.as_deref().unwrap_or(bytes)
        } else {
            bytes
        };
        if let Some(off) = find_needle(hay, rule.needle) {
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
    fn refusals_match_case_insensitively() {
        // Mixed/upper case still fires the lower-case refusal rule.
        assert!(scan(b"AS AN AI language model, I decline")
            .iter()
            .any(|h| h.rule_name == "as_an_ai"));
        assert!(scan(b"I Apologize, But I cannot")
            .iter()
            .any(|h| h.rule_name == "i_apologize_but"));
    }

    #[test]
    fn structural_tokens_stay_exact() {
        // ChatML tokens and endpoints are case-sensitive: an upper-case
        // variant must not match (real tokens are always lower-case).
        assert!(scan(b"<|IM_START|>")
            .iter()
            .all(|h| h.rule_name != "chatml_im_start"));
        assert!(scan(b"<|im_start|>")
            .iter()
            .any(|h| h.rule_name == "chatml_im_start"));
        assert!(scan(b"modern <|eot_id|> marker")
            .iter()
            .any(|h| h.rule_name == "llama3_eot"));
    }

    #[test]
    fn no_hits_on_random_bytes() {
        let data = [0u8; 4096];
        assert!(scan(&data).is_empty());
    }
}
