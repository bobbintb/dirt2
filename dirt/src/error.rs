use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShfsError {
    #[error("binary not found at path: {path}")]
    BinaryNotFound { path: String },

    #[error("error reading file at {path}")]
    ReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("error parsing ELF file")]
    ElfParseError(#[from] elf::ParseError),

    #[error("executable segment not found in ELF file")]
    ExecSegmentNotFound,

    #[error("section '{name}' not found in ELF file")]
    SectionNotFound { name: String },

    #[error("address {addr:#x} is not in a loadable segment")]
    AddressNotLoadable { addr: u64 },

    #[error("string '{name}' not found in binary")]
    StringNotFound { name: String },

    #[error("reference to string '{name}' not found in .text section")]
    StringRefNotFound { name: String },

    #[error("function prologue for reference '{name}' not found")]
    PrologueNotFound { name: String },
}