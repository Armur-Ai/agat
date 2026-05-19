//! goblin-backed PE/ELF parsing into a serializable normalized form.

use crate::entropy::shannon_entropy;
use goblin::Object;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    Pe,
    Elf,
    Mach,
    Archive,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    PowerPc,
    Other,
}

impl fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BinaryFormat::Pe => "PE",
            BinaryFormat::Elf => "ELF",
            BinaryFormat::Mach => "Mach-O",
            BinaryFormat::Archive => "Archive",
            BinaryFormat::Unknown => "Unknown",
        })
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Aarch64 => "aarch64",
            Arch::Mips => "mips",
            Arch::PowerPc => "ppc",
            Arch::Other => "other",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SectionCharacteristics {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub characteristics: SectionCharacteristics,
    pub entropy: f64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Import {
    pub library: String,
    pub name: String,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedBinary {
    pub format: BinaryFormat,
    pub arch: Arch,
    pub bits: u8,
    pub entry_point: u64,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}

/// Always returns *some* `ParsedBinary`. If the file isn't a
/// recognized format (or goblin chokes on it), the result has
/// `format: Unknown` and empty section/import/export lists. Static
/// analysis still works against the raw bytes.
pub fn parse(bytes: &[u8]) -> ParsedBinary {
    match Object::parse(bytes) {
        Ok(Object::PE(pe)) => parse_pe(&pe, bytes),
        Ok(Object::Elf(elf)) => parse_elf(&elf, bytes),
        Ok(Object::Mach(_)) => unknown(BinaryFormat::Mach),
        Ok(Object::Archive(_)) => unknown(BinaryFormat::Archive),
        _ => unknown(BinaryFormat::Unknown),
    }
}

fn unknown(format: BinaryFormat) -> ParsedBinary {
    ParsedBinary {
        format,
        arch: Arch::Other,
        bits: 0,
        entry_point: 0,
        sections: vec![],
        imports: vec![],
        exports: vec![],
    }
}

fn parse_pe(pe: &goblin::pe::PE, bytes: &[u8]) -> ParsedBinary {
    let arch = match pe.header.coff_header.machine {
        0x014C => Arch::X86,
        0x8664 => Arch::X86_64,
        0x01C0 | 0x01C4 => Arch::Arm,
        0xAA64 => Arch::Aarch64,
        _ => Arch::Other,
    };
    let bits = if pe.is_64 { 64 } else { 32 };

    let mut sections = Vec::new();
    for sect in &pe.sections {
        let name = sect.name().unwrap_or("?").to_string();
        let file_offset = sect.pointer_to_raw_data as u64;
        let file_size = sect.size_of_raw_data as u64;
        let virtual_address = sect.virtual_address as u64;
        let virtual_size = sect.virtual_size as u64;
        let ch = sect.characteristics;
        let characteristics = SectionCharacteristics {
            executable: ch & 0x2000_0000 != 0,
            readable: ch & 0x4000_0000 != 0,
            writable: ch & 0x8000_0000 != 0,
        };
        let (entropy, sha256) = section_blob(bytes, file_offset, file_size);
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            file_offset,
            file_size,
            characteristics,
            entropy,
            sha256,
        });
    }

    let imports = pe
        .imports
        .iter()
        .map(|imp| Import {
            library: imp.dll.to_string(),
            name: imp.name.to_string(),
            ordinal: if imp.ordinal == 0 {
                None
            } else {
                Some(imp.ordinal)
            },
        })
        .collect();

    let exports = pe
        .exports
        .iter()
        .filter_map(|e| {
            Some(Export {
                name: e.name?.to_string(),
                address: e.rva as u64,
            })
        })
        .collect();

    ParsedBinary {
        format: BinaryFormat::Pe,
        arch,
        bits,
        entry_point: pe.entry as u64,
        sections,
        imports,
        exports,
    }
}

fn parse_elf(elf: &goblin::elf::Elf, bytes: &[u8]) -> ParsedBinary {
    let arch = match elf.header.e_machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        8 | 10 => Arch::Mips,
        20 => Arch::PowerPc,
        _ => Arch::Other,
    };
    let bits = if elf.is_64 { 64 } else { 32 };

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(sh.sh_name)
            .unwrap_or("?")
            .to_string();
        let file_offset = sh.sh_offset;
        let file_size = sh.sh_size;
        let virtual_address = sh.sh_addr;
        let virtual_size = sh.sh_size;
        let flags = sh.sh_flags;
        let characteristics = SectionCharacteristics {
            writable: flags & 0x1 != 0,
            readable: flags & 0x2 != 0,
            executable: flags & 0x4 != 0,
        };
        // SHT_NOBITS (.bss) has no file data; skip the entropy/hash.
        let is_nobits = sh.sh_type == 8;
        let (entropy, sha256) = if is_nobits {
            (0.0, String::new())
        } else {
            section_blob(bytes, file_offset, file_size)
        };
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            file_offset,
            file_size,
            characteristics,
            entropy,
            sha256,
        });
    }

    let mut imports = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.is_import() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    imports.push(Import {
                        library: String::new(),
                        name: name.to_string(),
                        ordinal: None,
                    });
                }
            }
        }
    }

    let mut exports = Vec::new();
    for sym in elf.dynsyms.iter() {
        if !sym.is_import() && sym.st_bind() == 1 {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    exports.push(Export {
                        name: name.to_string(),
                        address: sym.st_value,
                    });
                }
            }
        }
    }

    ParsedBinary {
        format: BinaryFormat::Elf,
        arch,
        bits,
        entry_point: elf.entry,
        sections,
        imports,
        exports,
    }
}

fn section_blob(bytes: &[u8], file_offset: u64, file_size: u64) -> (f64, String) {
    if file_size == 0 || (file_offset as usize) >= bytes.len() {
        return (0.0, String::new());
    }
    let end = ((file_offset + file_size) as usize).min(bytes.len());
    let data = &bytes[file_offset as usize..end];
    (shannon_entropy(data), hex::encode(Sha256::digest(data)))
}
