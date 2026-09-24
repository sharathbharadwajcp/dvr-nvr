pub mod block_stream;
pub mod error;
pub mod manifest;
pub mod source;

pub use block_stream::{
    stream_and_hash, AcquiredBlock, AcquisitionResult, StreamOptions, DEFAULT_BLOCK_SIZE,
};
pub use error::{AcquisitionError, Result};
pub use manifest::AcquisitionManifest;
pub use source::ReadOnlySource;

use std::path::{Path, PathBuf};

/// High-level function to acquire an evidence source strictly read-only,
/// compute whole-image SHA-256 and per-block BLAKE3 hashes, and write manifest.json.
pub fn acquire_evidence<P: AsRef<Path>, O: AsRef<Path>>(
    source_path: P,
    case_name: &str,
    output_dir: O,
    block_size: Option<usize>,
) -> Result<(AcquisitionManifest, PathBuf)> {
    acquire_evidence_with_options(source_path, case_name, output_dir, block_size, None)
}

/// High-level function to acquire an evidence source with optional pre-computed device identification.
pub fn acquire_evidence_with_options<P: AsRef<Path>, O: AsRef<Path>>(
    source_path: P,
    case_name: &str,
    output_dir: O,
    block_size: Option<usize>,
    identification: Option<serde_json::Value>,
) -> Result<(AcquisitionManifest, PathBuf)> {
    let path = source_path.as_ref();
    let source = ReadOnlySource::open(path)?;

    let options = StreamOptions {
        block_size: block_size.unwrap_or(DEFAULT_BLOCK_SIZE),
        ..Default::default()
    };

    let result = stream_and_hash(source, options)?;
    let mut manifest = AcquisitionManifest::new(case_name, path, result);
    manifest.identification = identification;
    let manifest_path = manifest.write_to_directory(output_dir.as_ref())?;

    Ok((manifest, manifest_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::Md5;
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use tempfile::tempdir;

    #[test]
    fn test_hashing_correctness_known_vectors() {
        let test_data = b"Digital Video Forensics Platform - SIH 2025 - Team Cyber 4";

        // Expected SHA-256
        let expected_sha256 = hex::encode(Sha256::digest(test_data));

        // Expected BLAKE3
        let expected_blake3 = blake3::hash(test_data).to_hex().to_string();

        // Expected MD5
        let expected_md5 = hex::encode(Md5::digest(test_data));

        let dir = tempdir().unwrap();
        let file_path = dir.path().join("evidence.raw");
        fs::write(&file_path, test_data).unwrap();

        let source = ReadOnlySource::open(&file_path).unwrap();
        let result = stream_and_hash(
            source,
            StreamOptions {
                block_size: test_data.len(),
                batch_size: 1,
            },
        )
        .unwrap();

        assert_eq!(result.total_bytes, test_data.len() as u64);
        assert_eq!(result.block_count, 1);
        assert_eq!(result.whole_image_sha256, expected_sha256);
        assert_eq!(result.whole_image_md5, expected_md5);
        assert_eq!(result.block_hashes[0], expected_blake3);
        assert_eq!(result.block_hashes_md5[0], expected_md5);
    }

    #[test]
    fn test_acquisition_byte_identical_to_reference_read() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("sample_dvr.img");

        // Generate non-trivial deterministic test image: 10,000 bytes with pattern
        let mut sample_bytes = Vec::with_capacity(10_000);
        for i in 0..10_000 {
            sample_bytes.push((i % 256) as u8);
        }
        fs::write(&file_path, &sample_bytes).unwrap();

        // 1. Standard reference read
        let reference_data = fs::read(&file_path).unwrap();
        let ref_sha256 = hex::encode(Sha256::digest(&reference_data));
        let ref_md5 = hex::encode(Md5::digest(&reference_data));

        // 2. Perform acquisition streaming with 4096-byte blocks
        let out_dir = dir.path().join("case_output");
        let (manifest, manifest_path) =
            acquire_evidence(&file_path, "TEST-CASE-BYTE-ID", &out_dir, Some(4096)).unwrap();

        assert_eq!(manifest.total_bytes, reference_data.len() as u64);
        assert_eq!(manifest.whole_image_sha256, ref_sha256);
        assert_eq!(manifest.whole_image_md5, ref_md5);
        // 10,000 / 4096 = 2 full blocks (4096 each) + 1 partial block (1808) -> 3 blocks
        assert_eq!(manifest.block_count, 3);
        assert_eq!(manifest.block_hashes.len(), 3);
        assert_eq!(manifest.block_hashes_md5.len(), 3);

        // Verify per-block hashes match reference blocks
        let block0_ref = blake3::hash(&reference_data[0..4096])
            .to_hex()
            .to_string();
        let block1_ref = blake3::hash(&reference_data[4096..8192])
            .to_hex()
            .to_string();
        let block2_ref = blake3::hash(&reference_data[8192..10000])
            .to_hex()
            .to_string();

        let block0_md5 = hex::encode(Md5::digest(&reference_data[0..4096]));
        let block1_md5 = hex::encode(Md5::digest(&reference_data[4096..8192]));
        let block2_md5 = hex::encode(Md5::digest(&reference_data[8192..10000]));

        assert_eq!(manifest.block_hashes[0], block0_ref);
        assert_eq!(manifest.block_hashes[1], block1_ref);
        assert_eq!(manifest.block_hashes[2], block2_ref);

        assert_eq!(manifest.block_hashes_md5[0], block0_md5);
        assert_eq!(manifest.block_hashes_md5[1], block1_md5);
        assert_eq!(manifest.block_hashes_md5[2], block2_md5);

        // Verify manifest file exists and contains valid JSON
        assert!(manifest_path.exists());
        let manifest_content = fs::read_to_string(&manifest_path).unwrap();
        let parsed: AcquisitionManifest = serde_json::from_str(&manifest_content).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn test_strict_read_only_and_write_failure() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("readonly_source.img");
        fs::write(&file_path, b"Strict Read-Only Evidence Data").unwrap();

        // ReadOnlySource opens strictly read-only
        let source = ReadOnlySource::open(&file_path).unwrap();
        assert_eq!(source.len(), 30);

        // Verify no write method is exposed on ReadOnlySource (compile-time guarantee)
        // and verify that attempting to open with write permission on a write-protected file fails.
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file_path, perms).unwrap();

        // Attempting to open the write-protected file in write mode must fail
        let write_attempt = OpenOptions::new().write(true).open(&file_path);
        assert!(
            write_attempt.is_err(),
            "Writing to read-only evidence file must be denied by OS"
        );

        // But ReadOnlySource::open still succeeds strictly read-only
        let ro_reopen = ReadOnlySource::open(&file_path);
        assert!(ro_reopen.is_ok());

        // Restore write perms so tempdir cleanup succeeds
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_readonly(false);
        let _ = fs::set_permissions(&file_path, perms);
    }

    #[test]
    fn test_source_not_found_fails_loudly() {
        let missing_path = PathBuf::from("C:/nonexistent/dvr_disk_never_existed.img");
        let result = ReadOnlySource::open(&missing_path);

        assert!(result.is_err());
        match result.err().unwrap() {
            AcquisitionError::SourceNotFound { path } => {
                assert_eq!(path, missing_path);
            }
            other => panic!("Expected SourceNotFound error, got: {:?}", other),
        }
    }

    #[test]
    fn test_empty_file_handling() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("empty.raw");
        File::create(&file_path).unwrap();

        let out_dir = dir.path().join("empty_case");
        let (manifest, _) = acquire_evidence(&file_path, "CASE-EMPTY", &out_dir, Some(4096)).unwrap();

        assert_eq!(manifest.total_bytes, 0);
        assert_eq!(manifest.block_count, 0);
        assert_eq!(manifest.block_hashes.len(), 0);
        assert_eq!(
            manifest.whole_image_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
