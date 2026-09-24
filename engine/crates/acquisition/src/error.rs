use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcquisitionError {
    #[error("Evidence source does not exist: {path}")]
    SourceNotFound { path: PathBuf },

    #[error("Evidence source is not a regular file or readable device: {path}")]
    InvalidSourceType { path: PathBuf },

    #[error("Permission denied opening evidence source strictly read-only: {path}: {source}")]
    PermissionDenied {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("CRITICAL FORENSIC INTEGRITY VIOLATION: Write operation attempted on read-only evidence handle for {path}")]
    WriteForbidden { path: PathBuf },

    #[error("Failed to read from evidence source {path} at offset {offset}: {source}")]
    ReadError {
        path: PathBuf,
        offset: u64,
        source: std::io::Error,
    },

    #[error("Invalid block size: {0}. Block size must be greater than 0.")]
    InvalidBlockSize(usize),

    #[error("Output directory error for {path}: {source}")]
    OutputDirectoryError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Failed to serialize or write acquisition manifest to {path}: {source}")]
    ManifestWriteError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AcquisitionError>;
