use crate::block_stream::AcquisitionResult;
use crate::error::{AcquisitionError, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Forensic manifest documenting the acquisition of an evidence source.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcquisitionManifest {
    /// Case identifier assigned by the investigator.
    pub case_name: String,

    /// Absolute canonical path to the evidence source.
    pub source_path: String,

    /// Total size in bytes of the acquired evidence.
    pub total_bytes: u64,

    /// SHA-256 cryptographic digest of the entire evidence image.
    pub whole_image_sha256: String,

    /// MD5 cryptographic digest of the entire evidence image.
    pub whole_image_md5: String,

    /// Fixed block size (in bytes) used during acquisition.
    pub block_size: usize,

    /// Total number of acquired blocks.
    pub block_count: usize,

    /// Per-block BLAKE3 hashes (block 0 through N-1).
    pub block_hashes: Vec<String>,

    /// Per-block MD5 hashes (block 0 through N-1).
    pub block_hashes_md5: Vec<String>,

    /// ISO-8601 UTC timestamp marking completion of acquisition.
    pub acquisition_timestamp: String,

    /// Device / model identification results, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identification: Option<serde_json::Value>,
}

impl AcquisitionManifest {
    /// Builds a new manifest from the case name, source path, and acquisition result.
    pub fn new(
        case_name: impl Into<String>,
        source_path: &Path,
        result: AcquisitionResult,
    ) -> Self {
        Self {
            case_name: case_name.into(),
            source_path: source_path.to_string_lossy().into_owned(),
            total_bytes: result.total_bytes,
            whole_image_sha256: result.whole_image_sha256,
            whole_image_md5: result.whole_image_md5,
            block_size: result.block_size,
            block_count: result.block_count,
            block_hashes: result.block_hashes,
            block_hashes_md5: result.block_hashes_md5,
            acquisition_timestamp: Utc::now().to_rfc3339(),
            identification: None,
        }
    }

    /// Writes this manifest as pretty-printed JSON to `<output_dir>/manifest.json`.
    pub fn write_to_directory<P: AsRef<Path>>(&self, output_dir: P) -> Result<PathBuf> {
        let dir = output_dir.as_ref();
        create_dir_all(dir).map_err(|e| AcquisitionError::OutputDirectoryError {
            path: dir.to_path_buf(),
            source: e,
        })?;

        let manifest_path = dir.join("manifest.json");
        let mut file = File::create(&manifest_path).map_err(|e| {
            AcquisitionError::ManifestWriteError {
                path: manifest_path.clone(),
                source: e,
            }
        })?;

        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AcquisitionError::ManifestWriteError {
                path: manifest_path.clone(),
                source: std::io::Error::new(std::io::ErrorKind::Other, e),
            }
        })?;

        file.write_all(json.as_bytes()).map_err(|e| {
            AcquisitionError::ManifestWriteError {
                path: manifest_path.clone(),
                source: e,
            }
        })?;

        Ok(manifest_path)
    }
}
