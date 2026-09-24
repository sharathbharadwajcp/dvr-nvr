use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Failed to parse YAML grammar file {path}: {source}")]
    GrammarParseError {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("Grammar I/O error for {path}: {source}")]
    GrammarIoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("No matching grammar detected in directory {grammars_dir} for evidence source {evidence_path}")]
    DetectionFailed {
        evidence_path: PathBuf,
        grammars_dir: PathBuf,
    },

    #[error("Invalid magic signature rule in grammar {grammar_id}: neither ascii nor hex specified")]
    InvalidMagicRule { grammar_id: String },

    #[error("Block slice size ({actual} bytes) smaller than expected structure header size ({expected} bytes)")]
    BlockTooSmall { actual: usize, expected: usize },

    #[error("Evidence manifest not found or invalid at {path}: {source}")]
    ManifestError {
        path: PathBuf,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Database error at {path}: {source}")]
    DatabaseError {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("Acquisition engine error: {0}")]
    Acquisition(#[from] acquisition::AcquisitionError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ParserError>;
