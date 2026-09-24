use crate::db::CaseDatabase;
use crate::error::{ParserError, Result};
use acquisition::{AcquisitionManifest, ReadOnlySource};
use chrono::Utc;
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockIntegrityDiscrepancy {
    pub block_index: usize,
    pub byte_offset: u64,
    pub expected_hash: String,
    pub actual_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DbRecordDiscrepancy {
    pub block_index: usize,
    pub byte_offset: u64,
    pub issue: String,
}

/// Comprehensive cryptographic audit report for evidence integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub case_name: String,
    pub evidence_path: String,
    pub whole_image_sha256_match: bool,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub whole_image_md5_match: bool,
    pub expected_md5: String,
    pub actual_md5: String,
    pub total_blocks: usize,
    pub matched_blocks: usize,
    pub block_discrepancies: Vec<BlockIntegrityDiscrepancy>,
    pub db_checked: bool,
    pub db_record_discrepancies: Vec<DbRecordDiscrepancy>,
    pub is_pristine: bool,
    pub audit_timestamp: String,
}

/// Audits evidence disk image integrity against acquisition manifest and SQLite database.
pub fn verify_case_integrity<P: AsRef<Path>, D: AsRef<Path>>(
    case_dir: P,
    custom_db_path: Option<D>,
) -> Result<IntegrityReport> {
    let c_dir = case_dir.as_ref();
    let manifest_path = c_dir.join("manifest.json");

    if !manifest_path.exists() {
        return Err(ParserError::ManifestError {
            path: manifest_path,
            source: "Acquisition manifest.json not found in case directory".into(),
        });
    }

    let manifest_file = File::open(&manifest_path).map_err(|e| ParserError::ManifestError {
        path: manifest_path.clone(),
        source: Box::new(e),
    })?;
    let manifest: AcquisitionManifest =
        serde_json::from_reader(manifest_file).map_err(|e| ParserError::ManifestError {
            path: manifest_path.clone(),
            source: Box::new(e),
        })?;

    // Robust path resolution
    let mut evidence_path = PathBuf::from(&manifest.source_path);
    if !evidence_path.exists() {
        let file_name = Path::new(&manifest.source_path).file_name();
        let candidate_paths = vec![
            c_dir.join(&manifest.source_path),
            c_dir.parent().map(|p| p.join(&manifest.source_path)).unwrap_or_default(),
            file_name.map(|f| c_dir.join(f)).unwrap_or_default(),
            file_name.and_then(|f| c_dir.parent().map(|p| p.join(f))).unwrap_or_default(),
        ];

        let mut found = None;
        for cand in candidate_paths {
            if cand.exists() {
                found = Some(cand);
                break;
            }
        }

        if let Some(f) = found {
            evidence_path = f;
        } else {
            return Err(ParserError::Acquisition(
                acquisition::AcquisitionError::SourceNotFound {
                    path: evidence_path,
                },
            ));
        }
    }

    let mut source = ReadOnlySource::open(&evidence_path)?;
    let block_size = manifest.block_size;
    let mut buffer = vec![0u8; block_size];

    let mut sha256_hasher = Sha256::new();
    let mut md5_hasher = Md5::new();

    let mut block_index = 0;
    let mut current_offset = 0u64;
    let mut block_discrepancies = Vec::new();
    let mut actual_block_hashes = Vec::with_capacity(manifest.block_count);

    while block_index < manifest.block_count {
        let mut read_bytes = 0;
        while read_bytes < block_size {
            let n = source.read(&mut buffer[read_bytes..])?;
            if n == 0 {
                break;
            }
            read_bytes += n;
        }

        if read_bytes == 0 {
            break;
        }

        let slice = &buffer[..read_bytes];
        sha256_hasher.update(slice);
        md5_hasher.update(slice);

        let actual_hash = blake3::hash(slice).to_hex().to_string();
        actual_block_hashes.push(actual_hash.clone());

        if block_index < manifest.block_hashes.len() {
            let expected_hash = &manifest.block_hashes[block_index];
            if &actual_hash != expected_hash {
                block_discrepancies.push(BlockIntegrityDiscrepancy {
                    block_index,
                    byte_offset: current_offset,
                    expected_hash: expected_hash.clone(),
                    actual_hash,
                });
            }
        }

        current_offset += read_bytes as u64;
        block_index += 1;
    }

    let actual_sha256 = hex::encode(sha256_hasher.finalize());
    let actual_md5 = hex::encode(md5_hasher.finalize());

    let sha256_match = actual_sha256.eq_ignore_ascii_case(&manifest.whole_image_sha256);
    let md5_match = actual_md5.eq_ignore_ascii_case(&manifest.whole_image_md5);

    let matched_blocks = manifest.block_count.saturating_sub(block_discrepancies.len());

    // Check Case Database records if database exists
    let db_path = match custom_db_path {
        Some(p) => Some(p.as_ref().to_path_buf()),
        None => {
            let def_p = c_dir.join("case.db");
            if def_p.exists() {
                Some(def_p)
            } else {
                None
            }
        }
    };

    let mut db_checked = false;
    let mut db_discrepancies = Vec::new();

    if let Some(ref db_file) = db_path {
        if db_file.exists() {
            db_checked = true;
            if let Ok(db) = CaseDatabase::open(db_file) {
                // Check if extracted records match the actual evidence disk blocks
                if let Ok(records) = db.query_all_records() {
                    for r in &records {
                        if r.block_index < actual_block_hashes.len() {
                            let disk_hash = &actual_block_hashes[r.block_index];
                            if &r.blake3_hash != disk_hash {
                                db_discrepancies.push(DbRecordDiscrepancy {
                                    block_index: r.block_index,
                                    byte_offset: r.byte_offset,
                                    issue: format!(
                                        "DB recorded BLAKE3 {} does not match current evidence disk block BLAKE3 {}",
                                        r.blake3_hash, disk_hash
                                    ),
                                });
                            }
                        } else {
                            db_discrepancies.push(DbRecordDiscrepancy {
                                block_index: r.block_index,
                                byte_offset: r.byte_offset,
                                issue: "DB record refers to a block index beyond current evidence size".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    let is_pristine = sha256_match
        && md5_match
        && block_discrepancies.is_empty()
        && db_discrepancies.is_empty();

    let report = IntegrityReport {
        case_name: manifest.case_name,
        evidence_path: evidence_path.to_string_lossy().to_string(),
        whole_image_sha256_match: sha256_match,
        expected_sha256: manifest.whole_image_sha256,
        actual_sha256,
        whole_image_md5_match: md5_match,
        expected_md5: manifest.whole_image_md5,
        actual_md5,
        total_blocks: manifest.block_count,
        matched_blocks,
        block_discrepancies,
        db_checked,
        db_record_discrepancies: db_discrepancies,
        is_pristine,
        audit_timestamp: Utc::now().to_rfc3339(),
    };

    // If database is available, record audit log
    if let Some(ref db_file) = db_path {
        if db_file.exists() {
            if let Ok(mut db) = CaseDatabase::open(db_file) {
                let _ = db.log_verification_audit(&report);
            }
        }
    }

    Ok(report)
}
