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
        Ok(Object::Mach(mach)) => parse_mach(mach, bytes),
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

const CPU_TYPE_X86: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;

/// Mach-O, thin or universal. For a universal ("fat") binary the x86-64
/// slice is analyzed when present (that's what agat can disassemble),
/// otherwise the first slice. Section offsets are rebased onto the whole
/// file, because every analyzer reads the file's full bytes.
fn parse_mach(mach: goblin::mach::Mach, bytes: &[u8]) -> ParsedBinary {
    use goblin::mach::{Mach, MachO};
    match mach {
        Mach::Binary(macho) => parse_macho(&macho, bytes, 0),
        Mach::Fat(fat) => {
            let arches = match fat.arches() {
                Ok(a) => a,
                Err(_) => return unknown(BinaryFormat::Mach),
            };
            let pick = arches
                .iter()
                .find(|a| a.cputype == CPU_TYPE_X86_64)
                .or_else(|| arches.first());
            // Parse the slice as its own byte range: goblin resolves a
            // slice's symbol-table offsets against whatever buffer it is
            // given, so parsing in place (MachO::parse(bytes, offset))
            // reads the symbol table from the wrong place.
            match pick.and_then(|a| {
                let start = a.offset as usize;
                let end = start.checked_add(a.size as usize)?.min(bytes.len());
                MachO::parse(bytes.get(start..end)?, 0)
                    .ok()
                    .map(|m| (m, a.offset as u64))
            }) {
                Some((macho, base)) => parse_macho(&macho, bytes, base),
                None => unknown(BinaryFormat::Mach),
            }
        }
    }
}

fn parse_macho(macho: &goblin::mach::MachO, bytes: &[u8], base: u64) -> ParsedBinary {
    let arch = match macho.header.cputype {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM => Arch::Arm,
        CPU_TYPE_ARM64 => Arch::Aarch64,
        _ => Arch::Other,
    };
    let bits = if macho.is_64 { 64 } else { 32 };

    // S_ZEROFILL / S_GB_ZEROFILL / S_THREAD_LOCAL_ZEROFILL: no file data.
    const ZEROFILL_TYPES: [u32; 3] = [0x1, 0xc, 0x12];
    const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
    const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

    let mut sections = Vec::new();
    for segment in macho.segments.iter() {
        let seg_name = segment.name().unwrap_or("?").to_string();
        let Ok(secs) = segment.sections() else {
            continue;
        };
        for (sec, _) in secs {
            let sec_name = sec.name().unwrap_or("?");
            let zerofill = ZEROFILL_TYPES.contains(&(sec.flags & 0xff));
            let has_code = sec.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
            let characteristics = SectionCharacteristics {
                readable: segment.initprot & 0x1 != 0,
                writable: segment.initprot & 0x2 != 0,
                executable: segment.initprot & 0x4 != 0 && has_code,
            };
            let (file_offset, file_size) = if zerofill || sec.offset == 0 {
                (0, 0)
            } else {
                (base + sec.offset as u64, sec.size)
            };
            let (entropy, sha256) = section_blob(bytes, file_offset, file_size);
            sections.push(Section {
                name: format!("{seg_name},{sec_name}"),
                virtual_address: sec.addr,
                virtual_size: sec.size,
                file_offset,
                file_size,
                characteristics,
                entropy,
                sha256,
            });
        }
    }

    let mut imports: Vec<Import> = macho
        .imports()
        .unwrap_or_default()
        .into_iter()
        .map(|i| Import {
            library: i.dylib.to_string(),
            name: i.name.trim_start_matches('_').to_string(),
            ordinal: None,
        })
        .collect();
    if imports.is_empty() {
        // Binaries linked with chained fixups (LC_DYLD_CHAINED_FIXUPS,
        // the default on current macOS) carry no dyld bind opcodes for
        // goblin to decode; their imports are the symbol table's
        // undefined external symbols.
        if let Some(symbols) = &macho.symbols {
            for (name, nlist) in symbols.iter().flatten() {
                if nlist.is_undefined() && nlist.is_global() && !name.is_empty() {
                    imports.push(Import {
                        library: String::new(),
                        name: name.trim_start_matches('_').to_string(),
                        ordinal: None,
                    });
                }
            }
        }
    }
    let exports = macho
        .exports()
        .unwrap_or_default()
        .into_iter()
        .map(|e| Export {
            name: e.name.trim_start_matches('_').to_string(),
            address: e.offset,
        })
        .collect();

    ParsedBinary {
        format: BinaryFormat::Mach,
        arch,
        bits,
        entry_point: macho.entry,
        sections,
        imports,
        exports,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn name16(s: &str) -> [u8; 16] {
        let mut n = [0u8; 16];
        n[..s.len()].copy_from_slice(s.as_bytes());
        n
    }

    fn put(out: &mut Vec<u8>, at: usize, data: &[u8]) {
        if out.len() < at + data.len() {
            out.resize(at + data.len(), 0);
        }
        out[at..at + data.len()].copy_from_slice(data);
    }

    #[allow(clippy::too_many_arguments)]
    fn segment(
        seg: &str,
        sect: &str,
        vmaddr: u64,
        fileoff: u64,
        filesize: u64,
        prot: u32,
        sect_addr: u64,
        sect_off: u32,
        sect_size: u64,
        sect_flags: u32,
    ) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
        c.extend_from_slice(&(72u32 + 80).to_le_bytes());
        c.extend_from_slice(&name16(seg));
        c.extend_from_slice(&vmaddr.to_le_bytes());
        c.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
        c.extend_from_slice(&fileoff.to_le_bytes());
        c.extend_from_slice(&filesize.to_le_bytes());
        c.extend_from_slice(&7u32.to_le_bytes()); // maxprot
        c.extend_from_slice(&prot.to_le_bytes()); // initprot
        c.extend_from_slice(&1u32.to_le_bytes()); // nsects
        c.extend_from_slice(&0u32.to_le_bytes()); // flags
        c.extend_from_slice(&name16(sect));
        c.extend_from_slice(&name16(seg));
        c.extend_from_slice(&sect_addr.to_le_bytes());
        c.extend_from_slice(&sect_size.to_le_bytes());
        c.extend_from_slice(&sect_off.to_le_bytes());
        c.extend_from_slice(&[0u8; 12]); // align, reloff, nreloc
        c.extend_from_slice(&sect_flags.to_le_bytes());
        c.extend_from_slice(&[0u8; 12]); // reserved1..3
        c
    }

    /// A minimal x86-64 Mach-O executable: __TEXT,__text (code) at file
    /// offset 0x200, __DATA,__data at 0x400, and an LC_MAIN entry point.
    fn thin_macho() -> Vec<u8> {
        let code = [0x48, 0x31, 0xc0, 0xc3]; // xor rax, rax; ret
        let data = b"hello from __data";
        let text = segment(
            "__TEXT",
            "__text",
            0x1_0000_0000,
            0,
            0x400,
            5,
            0x1_0000_0200,
            0x200,
            code.len() as u64,
            0x8000_0400,
        );
        let dseg = segment(
            "__DATA",
            "__data",
            0x1_0000_1000,
            0x400,
            data.len() as u64,
            3,
            0x1_0000_1000,
            0x400,
            data.len() as u64,
            0,
        );
        let mut main = Vec::new();
        main.extend_from_slice(&0x8000_0028u32.to_le_bytes()); // LC_MAIN
        main.extend_from_slice(&24u32.to_le_bytes());
        main.extend_from_slice(&0x200u64.to_le_bytes()); // entryoff
        main.extend_from_slice(&0u64.to_le_bytes()); // stacksize

        let mut header = Vec::new();
        header.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        header.extend_from_slice(&0x0100_0007u32.to_le_bytes()); // x86_64
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        header.extend_from_slice(&3u32.to_le_bytes()); // ncmds
        header.extend_from_slice(&((text.len() + dseg.len() + main.len()) as u32).to_le_bytes());
        header.extend_from_slice(&[0u8; 8]); // flags, reserved

        let mut out = Vec::new();
        put(&mut out, 0, &header);
        put(&mut out, 32, &text);
        put(&mut out, 32 + text.len(), &dseg);
        put(&mut out, 32 + text.len() + dseg.len(), &main);
        put(&mut out, 0x200, &code);
        put(&mut out, 0x400, data);
        out
    }

    /// Universal binary: an arm64 decoy slice first, the x86-64 slice at 0x1000.
    fn fat_macho(thin: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
        hdr.extend_from_slice(&2u32.to_be_bytes());
        for (cpu, off, size) in [
            (0x0100_000Cu32, 0x3000u32, 32u32),
            (0x0100_0007, 0x1000, thin.len() as u32),
        ] {
            for v in [cpu, 0, off, size, 12] {
                hdr.extend_from_slice(&v.to_be_bytes());
            }
        }
        put(&mut out, 0, &hdr);
        put(&mut out, 0x1000, thin);
        put(&mut out, 0x3000, &0xfeed_facfu32.to_le_bytes());
        out.resize(0x3000 + 32, 0);
        out
    }

    #[test]
    fn parses_thin_macho_sections_entry_and_permissions() {
        let p = parse(&thin_macho());
        assert_eq!(p.format, BinaryFormat::Mach);
        assert_eq!(p.arch, Arch::X86_64);
        assert_eq!(p.bits, 64);
        assert_eq!(p.entry_point, 0x1_0000_0200);
        let text = p
            .sections
            .iter()
            .find(|s| s.name == "__TEXT,__text")
            .expect("__text");
        assert!(text.characteristics.executable && !text.characteristics.writable);
        assert_eq!((text.file_offset, text.file_size), (0x200, 4));
        let data = p
            .sections
            .iter()
            .find(|s| s.name == "__DATA,__data")
            .expect("__data");
        assert!(!data.characteristics.executable && data.characteristics.writable);
        assert_eq!(data.file_offset, 0x400);
    }

    #[test]
    fn universal_binary_picks_x86_64_and_rebases_offsets() {
        let thin = thin_macho();
        let fat = fat_macho(&thin);
        let p = parse(&fat);
        assert_eq!(
            p.arch,
            Arch::X86_64,
            "x86-64 slice chosen over the arm64 decoy"
        );
        let text = p
            .sections
            .iter()
            .find(|s| s.name == "__TEXT,__text")
            .unwrap();
        assert_eq!(
            text.file_offset,
            0x1000 + 0x200,
            "offset rebased onto the whole file"
        );
        assert_eq!(
            &fat[text.file_offset as usize..][..4],
            &[0x48, 0x31, 0xc0, 0xc3]
        );
    }
}
