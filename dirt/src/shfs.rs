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
        let rodata = self
            .elf
            .section_header_by_name(".rodata")?
            .ok_or_else(|| ShfsError::SectionNotFound {
                name: ".rodata".to_string(),
            })?;

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

    /// Searches backwards from a reference address to find the function prologue.
    fn find_function_prologue_vaddr(&self, ref_vaddr: u64) -> Result<u64, ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        let ref_offset_in_text = (ref_vaddr - self.text_section.sh_addr) as usize;

        // Search backwards for common prologue patterns or padding.
        // We limit the search distance to 4096 bytes.
        let search_start = ref_offset_in_text.saturating_sub(4096);
        let data_to_search = &text_data[search_start..ref_offset_in_text];

        for i in (0..data_to_search.len()).rev() {
            let current_vaddr = self.text_section.sh_addr + search_start as u64 + i as u64;

            // Pattern 1: `endbr64` (f3 0f 1e fa)
            if data_to_search[i..].starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
                debug!("Found endbr64 at {:#x}", current_vaddr);
                return Ok(current_vaddr);
            }

            // Pattern 2: `push rbp; mov rbp, rsp` (55 48 89 e5)
            if data_to_search[i..].starts_with(&[0x55, 0x48, 0x89, 0xe5]) {
                debug!("Found push rbp; mov rbp, rsp at {:#x}", current_vaddr);
                return Ok(current_vaddr);
            }

            // Pattern 3: `push rbp` followed by something that isn't `mov rbp, rsp`
            // and preceded by padding (ret + nop/int3).
            if data_to_search[i] == 0x55 && i > 0 {
                let prev_byte = data_to_search[i - 1];
                if prev_byte == 0x90 || prev_byte == 0xcc || prev_byte == 0xc3 {
                    debug!("Found possible push rbp at {:#x} after padding", current_vaddr);
                    return Ok(current_vaddr);
                }
            }

            // Pattern 4: Register push sequence (push r14; push r12; push rbp; push rbx)
            if data_to_search[i..].starts_with(&[0x41, 0x56, 0x41, 0x54, 0x55, 0x53]) {
                debug!("Found register push sequence at {:#x}", current_vaddr);
                return Ok(current_vaddr);
            }

            // Pattern 5: Any instruction after padding (ret followed by nops or int3)
            if i > 0 && (data_to_search[i - 1] == 0x90 || data_to_search[i - 1] == 0xcc) {
                // If current byte is not padding, but previous was, we might be at function start.
                if data_to_search[i] != 0x90 && data_to_search[i] != 0xcc {
                    // Check if we have a sequence of nops/int3 and then a ret/jmp before that.
                    let mut j = i - 1;
                    while j > 0 && (data_to_search[j] == 0x90 || data_to_search[j] == 0xcc) {
                        j -= 1;
                    }
                    if data_to_search[j] == 0xc3 || data_to_search[j] == 0xc2 {
                        debug!("Found function start after padding at {:#x}", current_vaddr);
                        return Ok(current_vaddr);
                    }
                }
            }
        }

        Err(ShfsError::PrologueNotFound {
            name: format!("{:#x}", ref_vaddr),
        })
    }

    /// Verifies and logs the instructions at a function's starting virtual address.
    fn verify_function(&self, func_name: &str, vaddr: u64) -> Result<(), ShfsError> {
        let (text_data, _) = self
            .elf
            .section_data(&self.text_section)
            .map_err(ShfsError::ElfParseError)?;

        let offset_in_text = (vaddr - self.text_section.sh_addr) as usize;
        let data_to_decode = &text_data[offset_in_text..];

        let mut decoder = Decoder::new(64, data_to_decode, DecoderOptions::AMD);
        decoder.set_ip(vaddr);

        let mut formatter = IntelFormatter::new();
        let mut output = String::new();

        debug!("Verification of function: {}", func_name);
        for instruction in decoder.into_iter().take(10) {
            output.clear();
            formatter.format(&instruction, &mut output);

            let start_index = (instruction.ip() - vaddr) as usize;
            let instr_bytes = &data_to_decode[start_index..start_index + instruction.len()];

            let mut hex_bytes = String::new();
            for b in instr_bytes {
                hex_bytes.push_str(&format!("{:02x} ", b));
            }

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

        analysis.verify_function(func_name, func_vaddr)?;

        let func_offset = analysis.vaddr_to_offset(func_vaddr)?;
        debug!("Function file offset: {:#x}", func_offset);

        offsets.insert(func_name.to_string(), func_offset);
    }

    Ok(offsets)
}
