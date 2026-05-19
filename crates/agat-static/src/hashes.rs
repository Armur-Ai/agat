//! Whole-file and structural hashes: SHA-256, MD5, imphash.

use crate::parse::{BinaryFormat, ParsedBinary};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub sha256: String,
    pub md5: String,
    /// Mandiant-style import hash. Only meaningful for PE files with
    /// imports; `None` everywhere else.
    pub imphash: Option<String>,
}

pub fn compute_hashes(bytes: &[u8], parsed: &ParsedBinary) -> Hashes {
    let sha256 = hex::encode(Sha256::digest(bytes));
    let md5 = hex::encode(Md5::digest(bytes));
    let imphash = compute_imphash(parsed);
    Hashes {
        sha256,
        md5,
        imphash,
    }
}

fn compute_imphash(parsed: &ParsedBinary) -> Option<String> {
    if parsed.format != BinaryFormat::Pe || parsed.imports.is_empty() {
        return None;
    }
    let tokens: Vec<String> = parsed
        .imports
        .iter()
        .map(|imp| {
            let dll = imp.library.to_ascii_lowercase();
            let dll = strip_dll_extension(&dll);
            let name = if imp.name.is_empty() {
                match imp.ordinal {
                    Some(n) => format!("ord{n}"),
                    None => "ord0".to_string(),
                }
            } else {
                imp.name.to_ascii_lowercase()
            };
            format!("{dll}.{name}")
        })
        .collect();
    let joined = tokens.join(",");
    Some(hex::encode(Md5::digest(joined.as_bytes())))
}

fn strip_dll_extension(s: &str) -> &str {
    for ext in [".dll", ".sys", ".ocx", ".exe"] {
        if let Some(stripped) = s.strip_suffix(ext) {
            return stripped;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{Arch, Import};

    #[test]
    fn sha256_md5_roundtrip() {
        let parsed = ParsedBinary {
            format: BinaryFormat::Unknown,
            arch: Arch::Other,
            bits: 0,
            entry_point: 0,
            sections: vec![],
            imports: vec![],
            exports: vec![],
        };
        let h = compute_hashes(b"abc", &parsed);
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert!(h.imphash.is_none());
    }

    #[test]
    fn imphash_is_md5_of_normalized_tokens() {
        let parsed = ParsedBinary {
            format: BinaryFormat::Pe,
            arch: Arch::X86_64,
            bits: 64,
            entry_point: 0,
            sections: vec![],
            imports: vec![
                Import {
                    library: "KERNEL32.dll".to_string(),
                    name: "LoadLibraryA".to_string(),
                    ordinal: None,
                },
                Import {
                    library: "user32.DLL".to_string(),
                    name: "MessageBoxA".to_string(),
                    ordinal: None,
                },
            ],
            exports: vec![],
        };
        let h = compute_hashes(b"", &parsed);
        // md5("kernel32.loadlibrarya,user32.messageboxa") = c4f...
        let imphash = h.imphash.expect("PE with imports should have imphash");
        let expected = hex::encode(Md5::digest(
            b"kernel32.loadlibrarya,user32.messageboxa",
        ));
        assert_eq!(imphash, expected);
    }
}
