use crate::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// SHA-256 of the sample contents. The canonical identifier for a sample.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleId(pub [u8; 32]);

impl SampleId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&digest);
        SampleId(id)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::Other(format!(
                "expected 32-byte sample id, got {} bytes",
                bytes.len()
            )));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(SampleId(id))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Truncated 12-character hex prefix for display in tables and the TUI.
    pub fn short(&self) -> String {
        self.to_hex()[..12].to_string()
    }
}

impl fmt::Display for SampleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for SampleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SampleId({})", self.short())
    }
}

impl Serialize for SampleId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SampleId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SampleId::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Coarse classification of a sample's container format. Detected
/// from magic bytes; finer-grained details (architecture variants,
/// machine flags, etc.) belong to `agat-static`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SampleKind {
    Pe32,
    Pe64,
    Elf32,
    Elf64,
    MachO32,
    MachO64,
    /// Universal ("fat") Mach-O: several architecture slices in one file.
    MachOFat,
    Shellcode,
    Unknown,
}

impl SampleKind {
    pub fn detect(bytes: &[u8]) -> Self {
        if bytes.len() < 4 {
            return SampleKind::Unknown;
        }
        if bytes.starts_with(b"\x7FELF") && bytes.len() >= 5 {
            return match bytes[4] {
                1 => SampleKind::Elf32,
                2 => SampleKind::Elf64,
                _ => SampleKind::Unknown,
            };
        }
        if bytes.starts_with(b"MZ") && bytes.len() >= 0x40 {
            let pe_off =
                u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
            if bytes.len() >= pe_off + 6 && &bytes[pe_off..pe_off + 4] == b"PE\0\0" {
                let machine = u16::from_le_bytes([bytes[pe_off + 4], bytes[pe_off + 5]]);
                return match machine {
                    0x014C => SampleKind::Pe32,
                    0x8664 => SampleKind::Pe64,
                    _ => SampleKind::Unknown,
                };
            }
        }
        match bytes[..4] {
            // MH_MAGIC / MH_CIGAM (32-bit), MH_MAGIC_64 / MH_CIGAM_64.
            [0xCE, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCE] => return SampleKind::MachO32,
            [0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCF] => return SampleKind::MachO64,
            // FAT_MAGIC is also the Java class-file magic; a fat header's
            // next field is a small slice count, a class file's is a
            // version number (≥ 45).
            [0xCA, 0xFE, 0xBA, 0xBE] if bytes.len() >= 8 => {
                let n = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                if (1..=16).contains(&n) {
                    return SampleKind::MachOFat;
                }
            }
            _ => {}
        }
        SampleKind::Unknown
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SampleKind::Pe32 => "Pe32",
            SampleKind::Pe64 => "Pe64",
            SampleKind::Elf32 => "Elf32",
            SampleKind::Elf64 => "Elf64",
            SampleKind::MachO32 => "MachO32",
            SampleKind::MachO64 => "MachO64",
            SampleKind::MachOFat => "MachOFat",
            SampleKind::Shellcode => "Shellcode",
            SampleKind::Unknown => "Unknown",
        }
    }

    pub fn from_str_lenient(s: &str) -> Self {
        match s {
            "Pe32" => SampleKind::Pe32,
            "Pe64" => SampleKind::Pe64,
            "Elf32" => SampleKind::Elf32,
            "Elf64" => SampleKind::Elf64,
            "MachO32" => SampleKind::MachO32,
            "MachO64" => SampleKind::MachO64,
            "MachOFat" => SampleKind::MachOFat,
            "Shellcode" => SampleKind::Shellcode,
            _ => SampleKind::Unknown,
        }
    }
}

impl fmt::Display for SampleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// User-supplied metadata attached to a sample at ingest time, plus
/// anything the pipeline derives later.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SampleMetadata {
    pub original_filename: Option<String>,
    pub family: Option<String>,
    pub variant_of: Option<String>,
    pub source: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Sample {
    pub id: SampleId,
    pub kind: SampleKind,
    pub size: u64,
    pub metadata: SampleMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_round_trip() {
        let id = SampleId::from_bytes(b"abc");
        // Known SHA-256 of "abc"
        assert_eq!(
            id.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let back = SampleId::from_hex(&id.to_hex()).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn detect_pe64() {
        let mut buf = vec![0u8; 0x100];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C] = 0x80;
        buf[0x80] = b'P';
        buf[0x81] = b'E';
        buf[0x82] = 0;
        buf[0x83] = 0;
        buf[0x84] = 0x64;
        buf[0x85] = 0x86;
        assert_eq!(SampleKind::detect(&buf), SampleKind::Pe64);
    }

    #[test]
    fn detect_elf64() {
        let buf = [0x7F, b'E', b'L', b'F', 2, 0, 0, 0];
        assert_eq!(SampleKind::detect(&buf), SampleKind::Elf64);
    }

    #[test]
    fn detect_macho_thin_fat_and_not_java() {
        let mut thin = vec![0u8; 32];
        thin[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]);
        assert_eq!(SampleKind::detect(&thin), SampleKind::MachO64);
        thin[..4].copy_from_slice(&[0xCE, 0xFA, 0xED, 0xFE]);
        assert_eq!(SampleKind::detect(&thin), SampleKind::MachO32);

        let mut fat = vec![0u8; 32];
        fat[..8].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]);
        assert_eq!(SampleKind::detect(&fat), SampleKind::MachOFat);

        // A Java class file (major version 52 = Java 8) shares the magic.
        let java = [0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52];
        assert_eq!(SampleKind::detect(&java), SampleKind::Unknown);

        for k in [
            SampleKind::MachO32,
            SampleKind::MachO64,
            SampleKind::MachOFat,
        ] {
            assert_eq!(SampleKind::from_str_lenient(k.as_str()), k);
        }
    }

    #[test]
    fn detect_unknown() {
        assert_eq!(SampleKind::detect(b"hello world"), SampleKind::Unknown);
    }
}
