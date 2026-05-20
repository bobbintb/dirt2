use crate::error::ShfsError;
use elf::endian::AnyEndian;
use elf::ElfBytes;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use log::{debug, trace};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const SHFS_BINARY_PATH: &str = "/usr/libexec/unraid/shfs";

/// A struct to hold information about the shfs binary analysis.
struct ShfsAnalysis<'a> {
    elf: ElfBytes<'a, AnyEndian>,
    text_section: elf::section::SectionHeader,
    loadable_segments: Vec<elf::segment::ProgramHeader>,
}

impl<'a> ShfsAnalysis<'a> {
    /// Creates a new analysis instance for the shfs binary.
    fn new(file_bytes: &'a [u8]) -> Result<Self, ShfsError> {
        let elf = ElfBytes::<AnyEndian>::minimal_parse(file_bytes)
            .map_err(ShfsError::ElfParseError)?;

        let text_section = elf
            .section_header_by_name(".text")?
            .ok_or(ShfsError::ExecSegmentNotFound)?;

        let loadable_segments = elf
            .segments()
            .ok_or(ShfsError::ExecSegmentNotFound)?
            .iter()
            .filter(|phdr| phdr.p_type == elf::abi::PT_LOAD)
            .collect();

        Ok(Self {
            elf,
            text_section,
            loadable_segments,
        })
    }

    /// Converts a virtual address to a file offset.
    fn vaddr_to_offset(&self, vaddr: u64) -> Result<u64, ShfsError> {
        for phdr in &self.loadable_segments {
            if vaddr >= phdr.p_vaddr && vaddr < phdr.p_vaddr + phdr.p_memsz {
                return Ok(phdr.p_offset + (vaddr - phdr.p_vaddr));
            }
        }
        Err(ShfsError::AddressNotLoadable { addr: vaddr })
    }

    /// Finds the virtual address of a function's string identifier.
    fn find_string_vaddr(&self, func_name: &str) -> Result<u64, ShfsError> {
        let rodata = self.elf.section_header_by_name(".rodata")?.ok_or(
            ShfsError::StringNotFound {
                name: func_name.to_string(),
            },
        )?;

        let (data, _) = self.elf.section_data(&rodata)?;
        let cstr_name = std::ffi::CString::new(func_name).unwrap();

        let string_relative_offset = data
            .windows(cstr_name.as_bytes_with_nul().len())
            .position(|window| window == cstr_name.as_bytes_with_nul())
            .map(|pos| pos as u64)
            .ok_or_else(|| ShfsError::StringNotFound {
                name: func_name.to_string(),
            })?;

        Ok(rodata.sh_addr + string_relative_offset)
    }

    /// Finds the first reference to a virtual address in the .text section.
    fn find_string_ref_vaddr(&self, string_vaddr: u64) -> Result<u64, ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        let mut decoder = Decoder::new(64, text_data, DecoderOptions::AMD);
        decoder.set_ip(self.text_section.sh_addr);

        for instruction in decoder {
            if instruction.is_invalid() {
                continue;
            }

            // Case 1: IP-relative memory operand. This is the most common case in x64.
            if instruction.is_ip_rel_memory_operand() {
                if instruction.ip_rel_memory_address() == string_vaddr {
                    debug!("Found IP-relative reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                    return Ok(instruction.ip());
                }
            }

            // Case 2: Absolute memory operand or immediate operand.
            for i in 0..instruction.op_count() {
                let op_kind = instruction.op_kind(i);

                // Check for an absolute memory address (no base/index registers).
                if op_kind == iced_x86::OpKind::Memory &&
                   instruction.memory_base() == iced_x86::Register::None &&
                   instruction.memory_index() == iced_x86::Register::None {
                    if instruction.memory_displacement64() == string_vaddr {
                        debug!("Found absolute memory reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                }

                // Check for an immediate value matching the address.
                match op_kind {
                    iced_x86::OpKind::Immediate64 if instruction.immediate64() == string_vaddr => {
                        debug!("Found immediate reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                    iced_x86::OpKind::Immediate32 if instruction.immediate32() as u64 == string_vaddr => {
                        debug!("Found immediate reference to {:#x} at {:#x}", string_vaddr, instruction.ip());
                        return Ok(instruction.ip());
                    }
                    _ => {}
                }
            }
        }

        Err(ShfsError::StringRefNotFound { name: format!("{:#x}", string_vaddr) })
    }

    /// Logs the first N instructions of a function.
    fn log_function_instructions(
        &self,
        func_name: &str,
        func_vaddr: u64,
        count: usize,
    ) -> Result<(), ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        if func_vaddr < self.text_section.sh_addr
            || func_vaddr >= self.text_section.sh_addr + self.text_section.sh_size
        {
            return Err(ShfsError::AddressNotLoadable { addr: func_vaddr });
        }

        let start_index = (func_vaddr - self.text_section.sh_addr) as usize;
        let data_to_decode = &text_data[start_index..];

        let mut decoder = Decoder::new(64, data_to_decode, DecoderOptions::AMD);
        decoder.set_ip(func_vaddr);

        let mut formatter = IntelFormatter::new();
        let mut instruction = iced_x86::Instruction::default();

        for _ in 0..count {
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut instruction);

            let mut output = String::new();
            formatter.format(&instruction, &mut output);

            let instr_len = instruction.len();
            let instr_offset = (instruction.ip() - self.text_section.sh_addr) as usize;
            let instr_bytes = &text_data[instr_offset..instr_offset + instr_len];
            let hex_bytes = instr_bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join(" ");

            debug!(
                "{}: {:#018x} {:<20} {}",
                func_name,
                instruction.ip(),
                hex_bytes,
                output
            );
        }

        Ok(())
    }

    /// Searches backwards from a reference address to find the function prologue.
    fn find_function_prologue_vaddr(&self, ref_vaddr: u64) -> Result<u64, ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        // Virtual address to index in the .text section's data.
        let ref_index = (ref_vaddr - self.text_section.sh_addr) as usize;

        // Common x86_64 function prologue patterns.
        let prologue_patterns: &[&[u8]] = &[
            &[0x55, 0x48, 0x89, 0xe5],             // push rbp; mov rbp, rsp
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5], // endbr64; push rbp; mov rbp, rsp
            &[0xf3, 0x0f, 0x1e, 0xfa],             // endbr64
            &[0x41, 0x56, 0x41, 0x54, 0x55, 0x53], // push r14; push r12; push rbp; push rbx
            &[0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54], // push r15..r12
            &[0x55, 0x41, 0x57, 0x41, 0x56],       // push rbp; push r15; push r14
        ];

        // Search backwards from the string reference for a known prologue pattern.
        // We limit the search distance to avoid overshooting into unrelated functions.
        const MAX_SEARCH_DISTANCE: usize = 8192;
        let start_search = ref_index.saturating_sub(MAX_SEARCH_DISTANCE);

        for i in (start_search..ref_index).rev() {
            for pattern in prologue_patterns {
                if text_data[i..].starts_with(pattern) {
                    let prologue_vaddr = self.text_section.sh_addr + i as u64;
                    debug!(
                        "Found function prologue for ref {:#x} at {:#x} using pattern {:?}",
                        ref_vaddr, prologue_vaddr, pattern
                    );
                    return Ok(prologue_vaddr);
                }
            }

            // Secondary heuristic: check for function padding (nop or int3) following a 'ret' (0xc3)
            // if we are at least 16 bytes away from the reference point.
            if ref_index - i > 16 && i > 0 && i + 1 < text_data.len() {
                let prev_byte = text_data[i - 1];
                let curr_byte = text_data[i];
                if prev_byte == 0xc3 && (curr_byte == 0x90 || curr_byte == 0xcc || curr_byte == 0x0f) {
                    // 0x0f 0x1f is part of a multi-byte NOP.
                    // We found a likely function boundary.
                    let prologue_vaddr = self.text_section.sh_addr + i as u64;
                    debug!(
                        "Found likely function boundary for ref {:#x} at {:#x} via padding heuristic",
                        ref_vaddr, prologue_vaddr
                    );
                    return Ok(prologue_vaddr);
                }
            }
        }

        Err(ShfsError::PrologueNotFound {
            name: format!("{:#x}", ref_vaddr),
        })
    }
}

/// Finds the file offsets for a list of function names in the shfs binary.
pub fn get_function_offsets(
    functions: &[&str],
) -> Result<HashMap<String, u64>, ShfsError> {
    debug!("Starting analysis of binary: {}", SHFS_BINARY_PATH);
    let binary_path = Path::new(SHFS_BINARY_PATH);
    if !binary_path.exists() {
        return Err(ShfsError::BinaryNotFound {
            path: SHFS_BINARY_PATH.to_string(),
        });
    }

    let file_bytes = fs::read(binary_path).map_err(|e| ShfsError::ReadError {
        path: SHFS_BINARY_PATH.to_string(),
        source: e,
    })?;

    let analysis = ShfsAnalysis::new(&file_bytes)?;
    let mut offsets = HashMap::new();

    for &func_name in functions {
        debug!("Searching for function: {}", func_name);

        let string_vaddr = analysis.find_string_vaddr(func_name)?;
        debug!("String virtual address: {:#x}", string_vaddr);

        let ref_vaddr = analysis.find_string_ref_vaddr(string_vaddr)?;
        trace!("Found reference to string at vaddr: {:#x}", ref_vaddr);

        let func_vaddr = analysis.find_function_prologue_vaddr(ref_vaddr)?;
        debug!("Function start virtual address: {:#x}", func_vaddr);

        analysis.log_function_instructions(func_name, func_vaddr, 10)?;

        let func_offset = analysis.vaddr_to_offset(func_vaddr)?;
        debug!("Function file offset: {:#x}", func_offset);

        offsets.insert(func_name.to_string(), func_offset);
    }

    Ok(offsets)
}
