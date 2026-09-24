use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SandboxError>;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Plugin file not found: {0}")]
    PluginNotFound(PathBuf),

    #[error("Failed to load/compile WASM module: {0}")]
    CompilationError(String),

    #[error("Missing required WASM export: {0}")]
    MissingExport(&'static str),

    #[error("Execution timeout exceeded ({0}ms)")]
    ExecutionTimeout(u64),

    #[error("Memory ceiling exceeded (limit: {0} bytes)")]
    MemoryLimitExceeded(usize),

    #[error("WASM execution trap: {0}")]
    ExecutionTrap(String),

    #[error("Sandbox error: {0}")]
    Other(String),
}
