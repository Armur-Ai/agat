//! ASCII and UTF-16LE printable string extraction.
//!
//! No allocator games or SIMD — this is the boring linear-scan version
//! that's plenty fast for samples under a few hundred MB.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringEncoding {
    Ascii,
    Utf16Le,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: StringEncoding,
    pub value: String,
}

/// Extract all ASCII and UTF-16LE strings of length ≥ `min_len`,
/// sorted by file offset.
pub fn extract_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = extract_ascii(bytes, min_len);
    out.extend(extract_utf16le(bytes, min_len));
    out.sort_by_key(|s| s.offset);
    out
}

pub fn extract_ascii(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                out.push(ExtractedString {
                    offset: s as u64,
                    encoding: StringEncoding::Ascii,
                    value: String::from_utf8_lossy(&bytes[s..i]).into_owned(),
                });
            }
        }
    }
    if let Some(s) = start {
        if bytes.len() - s >= min_len {
            out.push(ExtractedString {
                offset: s as u64,
                encoding: StringEncoding::Ascii,
                value: String::from_utf8_lossy(&bytes[s..]).into_owned(),
            });
        }
    }
    out
}

pub fn extract_utf16le(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let start = i;
        let mut chars: Vec<u8> = Vec::new();
        while i + 1 < bytes.len() {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if hi == 0 && (0x20..=0x7E).contains(&lo) {
                chars.push(lo);
                i += 2;
            } else {
                break;
            }
        }
        if chars.len() >= min_len {
            out.push(ExtractedString {
                offset: start as u64,
                encoding: StringEncoding::Utf16Le,
                value: String::from_utf8_lossy(&chars).into_owned(),
            });
        }
        if i == start {
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_string() {
        let bytes = b"\x00\x00hello world\x00\x00";
        let s = extract_ascii(bytes, 4);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, "hello world");
        assert_eq!(s[0].offset, 2);
    }

    #[test]
    fn respects_min_length() {
        let bytes = b"\x00hi\x00hello\x00";
        let s = extract_ascii(bytes, 4);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, "hello");
    }

    #[test]
    fn finds_utf16le_string() {
        let mut bytes = vec![0u8; 4];
        for &c in b"kernel32" {
            bytes.push(c);
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0u8; 4]);
        let s = extract_utf16le(&bytes, 4);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, "kernel32");
    }
}
