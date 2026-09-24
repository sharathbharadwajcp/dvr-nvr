use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, IdentificationError>;

#[derive(Error, Debug)]
pub enum IdentificationError {
    #[error("Evidence image path not found: {0}")]
    ImageNotFound(PathBuf),

    #[error("Grammars directory not found: {0}")]
    GrammarsDirNotFound(PathBuf),

    #[error("I/O error reading evidence source at {path}: {source}")]
    IoError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("Grammar error during identification: {0}")]
    ParserError(#[from] parser::error::ParserError),

    #[error("Identification error: {0}")]
    Other(String),
}
