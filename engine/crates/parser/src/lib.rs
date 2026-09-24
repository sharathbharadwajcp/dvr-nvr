pub mod ast;
pub mod db;
pub mod demux;
pub mod detect;
pub mod error;
pub mod interpreter;
pub mod verify;

pub use ast::GrammarFile;
pub use db::{AnalyticsDbDetection, CaseDatabase, CorrelatedDbEvent, RecordFilter};
pub use demux::{demux_records, DemuxedStream};
pub use recovery::CarvedFrame;
pub use detect::detect_grammar;
pub use error::{ParserError, Result};
pub use interpreter::{ExtractedRecord, GrammarInterpreter};
pub use verify::{
    verify_case_integrity, BlockIntegrityDiscrepancy, DbRecordDiscrepancy, IntegrityReport,
};

use acquisition::{AcquisitionManifest, ReadOnlySource};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct ParseSummary {
    pub grammar_id: String,
    pub grammar_name: String,
    pub validation_tier: u8,
    pub total_blocks: usize,
    pub valid_video_frames: usize,
    pub scrambled_blocks: usize,
    pub descrambled_blocks: usize,
    pub corrupted_blocks: usize,
    pub channel_streams: HashMap<u32, DemuxedStream>,
    pub db_path: PathBuf,
}

/// End-to-end parsing pipeline:
/// 1. Reads case acquisition manifest.
/// 2. Auto-detects matching declarative grammar.
/// 3. Reads blocks strictly read-only, hashes them before parsing.
/// 4. Interprets AST to extract structured block records.
/// 5. Descrambles scrambled blocks via sandboxed WASM plugin if available.
/// 6. Demuxes multi-channel streams.
/// 7. Commits records to SQLite WAL database.
pub fn parse_case<P: AsRef<Path>, G: AsRef<Path>>(
    case_dir: P,
    grammars_dir: G,
    custom_db_path: Option<PathBuf>,
) -> Result<ParseSummary> {
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

    // Determine evidence image path: robust resolution across relative and parent paths
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

    // Auto-detect grammar
    let (grammar, grammar_file_path) = detect_grammar(&evidence_path, grammars_dir.as_ref())?;
    println!("[*] Detected grammar: {} (Tier {}) from {}", grammar.grammar.name, grammar.grammar.tier, grammar_file_path.display());

    // Initialize sandboxed descrambler if specified in grammar
    let mut descrambler = None;
    if let Some(ref plugin_name) = grammar.grammar.descramble_plugin {
        let candidate_paths = [
            grammars_dir.as_ref().parent().map(|p| p.join("plugins").join(format!("{}.wasm", plugin_name))),
            Some(c_dir.join("plugins").join(format!("{}.wasm", plugin_name))),
            Some(PathBuf::from("plugins").join(format!("{}.wasm", plugin_name))),
            Some(PathBuf::from("../plugins").join(format!("{}.wasm", plugin_name))),
            Some(PathBuf::from("../../plugins").join(format!("{}.wasm", plugin_name))),
        ];

        let mut found_path = None;
        for opt_p in candidate_paths.into_iter().flatten() {
            if opt_p.exists() {
                found_path = Some(opt_p);
                break;
            }
        }

        if let Some(p) = found_path {
            println!("[*] Loading sandboxed descrambler plugin from {}", p.display());
            match sandbox::PluginHost::new() {
                Ok(host) => match host.load_plugin(&p, None) {
                    Ok(plugin) => {
                        descrambler = Some(plugin);
                        println!("[+] Sandboxed descrambler plugin loaded successfully.");
                    }
                    Err(e) => {
                        eprintln!("[!] Warning: Failed to load plugin {}: {}", p.display(), e);
                    }
                },
                Err(e) => {
                    eprintln!("[!] Warning: Failed to initialize WASM sandbox host: {}", e);
                }
            }
        } else {
            eprintln!("[!] Warning: Plugin '{}' specified in grammar but wasm binary not found.", plugin_name);
        }
    }

    let interpreter = GrammarInterpreter::new(&grammar);

    // Open strictly read-only
    let mut source = ReadOnlySource::open(&evidence_path)?;
    let block_size = manifest.block_size;
    let mut buffer = vec![0u8; block_size];

    let mut records = Vec::with_capacity(manifest.block_count);
    let mut block_index = 0;
    let mut current_offset = 0u64;

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

        let block_slice = &buffer[..read_bytes];

        // Hash before parsing
        let computed_hash = blake3::hash(block_slice).to_hex().to_string();

        let mut record = interpreter.interpret_block(
            block_index,
            current_offset,
            block_slice,
            &computed_hash,
        )?;

        // If block is scrambled and plugin is available, run sandboxed descrambler
        if record.is_scrambled {
            if let Some(ref plugin) = descrambler {
                let payload_offset_in_block = (record.payload_offset.saturating_sub(record.byte_offset)) as usize;
                let payload_end = payload_offset_in_block + record.payload_len;
                if payload_end <= block_slice.len() {
                    let scrambled_payload = &block_slice[payload_offset_in_block..payload_end];
                    match plugin.descramble(scrambled_payload) {
                        Ok(descrambled_bytes) => {
                            let descrambled_hash = blake3::hash(&descrambled_bytes).to_hex().to_string();
                            record.descrambled = true;
                            record.descrambled_blake3_hash = Some(descrambled_hash);
                        }
                        Err(e) => {
                            eprintln!(
                                "[!] Warning: Descrambler failed on block {}: {}",
                                block_index, e
                            );
                        }
                    }
                }
            }
        }

        records.push(record);

        current_offset += read_bytes as u64;
        block_index += 1;
    }

    // Demux multi-channel streams
    let channel_streams = demux_records(&records);

    // Store in SQLite database (WAL mode)
    let db_path = custom_db_path.unwrap_or_else(|| c_dir.join("case.db"));
    let mut db = CaseDatabase::open(&db_path)?;

    db.store_case_extraction(
        &manifest.case_name,
        &evidence_path.to_string_lossy(),
        &manifest.whole_image_sha256,
        &manifest.whole_image_md5,
        manifest.block_size,
        manifest.block_count,
        &grammar.grammar.id,
        grammar.grammar.tier,
        &manifest.acquisition_timestamp,
        &records,
    )?;

    let valid_video_frames = records.iter().filter(|r| r.block_type == "video_frame").count();
    let scrambled_blocks = records.iter().filter(|r| r.is_scrambled).count();
    let descrambled_blocks = records.iter().filter(|r| r.descrambled).count();
    let corrupted_blocks = records.iter().filter(|r| r.is_corrupted).count();

    Ok(ParseSummary {
        grammar_id: grammar.grammar.id,
        grammar_name: grammar.grammar.name,
        validation_tier: grammar.grammar.tier,
        total_blocks: records.len(),
        valid_video_frames,
        scrambled_blocks,
        descrambled_blocks,
        corrupted_blocks,
        channel_streams,
        db_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_parser_matches_synthetic_ground_truth() {
        // Resolve project paths (crates/parser -> crates -> engine -> dvr-forensics)
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let grammar_path = project_root.join("grammars").join("synthetic-v1.yaml");
        let image_path = project_root.join("samples").join("synthetic_disk.img");
        let truth_path = project_root.join("samples").join("synthetic_disk.truth.json");

        assert!(grammar_path.exists(), "Grammar file must exist: {:?}", grammar_path);
        assert!(image_path.exists(), "Synthetic disk image must exist: {:?}", image_path);
        assert!(truth_path.exists(), "Ground truth file must exist: {:?}", truth_path);

        // Load grammar and ground truth
        let grammar = GrammarFile::load_from_file(&grammar_path).unwrap();
        let truth_content = fs::read_to_string(&truth_path).unwrap();
        let truth: Value = serde_json::from_str(&truth_content).unwrap();

        let truth_blocks = truth["blocks"].as_array().expect("Ground truth must contain blocks array");
        assert_eq!(truth_blocks.len(), 64, "Ground truth must contain 64 blocks");

        // Execute parsing against image blocks
        let mut source = ReadOnlySource::open(&image_path).unwrap();
        let interpreter = GrammarInterpreter::new(&grammar);

        let mut buffer = vec![0u8; 4096];
        let mut parsed_records = Vec::new();

        for b in 0..64 {
            let offset = (b * 4096) as u64;
            source.read_exact(&mut buffer).unwrap();
            let blake3_hash = blake3::hash(&buffer).to_hex().to_string();

            let record = interpreter.interpret_block(b, offset, &buffer, &blake3_hash).unwrap();
            parsed_records.push(record);
        }

        // =====================================================================
        // RIGOROUS GROUND TRUTH DIFF VALIDATION
        // =====================================================================
        // Block 0: Superblock
        assert_eq!(parsed_records[0].block_type, "superblock");
        assert_eq!(parsed_records[0].channel_id, 0);

        // Block 1: Partition Table
        assert_eq!(parsed_records[1].block_type, "partition_table");
        assert_eq!(parsed_records[1].channel_id, 0);

        // Blocks 2..63: Video blocks
        for b in 2..64 {
            let rec = &parsed_records[b];
            let truth_b = &truth_blocks[b];

            let truth_offset = truth_b["offset"].as_u64().unwrap();
            let truth_corrupted = truth_b["is_corrupted"].as_bool().unwrap();
            let truth_scrambled = truth_b["is_scrambled"].as_bool().unwrap();

            assert_eq!(rec.byte_offset, truth_offset, "Block {} offset mismatch", b);

            if truth_corrupted {
                // Ground truth declares corrupted header (blocks 22..23)
                assert!(
                    rec.is_corrupted,
                    "Block {} was marked corrupted in ground truth but not recognized as corrupted by parser",
                    b
                );
                assert_eq!(
                    rec.block_type,
                    "unallocated_or_corrupted",
                    "Block {} should be flagged unallocated_or_corrupted",
                    b
                );
            } else {
                // Non-corrupted blocks must match ground truth exactly on every single field
                let truth_channel = truth_b["channel_id"].as_u64().unwrap() as u32;
                let truth_timestamp = truth_b["timestamp"].as_u64().unwrap();
                let truth_seq = truth_b["sequence_num"].as_u64().unwrap() as u32;
                let truth_payload_len = truth_b["payload_len"].as_u64().unwrap() as usize;

                assert_eq!(rec.block_type, "video_frame", "Block {} expected video_frame", b);
                assert_eq!(rec.channel_id, truth_channel, "Block {} channel mismatch", b);
                assert_eq!(rec.timestamp, truth_timestamp, "Block {} timestamp mismatch", b);
                assert!(
                    !rec.normalized_timestamp.is_empty(),
                    "Normalized timestamp must not be empty"
                );
                assert!(
                    rec.normalized_timestamp.ends_with('Z'),
                    "Normalized timestamp must be canonical UTC with Z suffix"
                );
                assert_eq!(rec.sequence_num, truth_seq, "Block {} sequence mismatch", b);
                assert_eq!(rec.payload_len, truth_payload_len, "Block {} payload_len mismatch", b);
                assert_eq!(rec.is_scrambled, truth_scrambled, "Block {} is_scrambled mismatch", b);
                assert_eq!(rec.is_corrupted, false, "Block {} should not be corrupted", b);
            }
        }

        // Test Demuxer functionality
        let demuxed = demux_records(&parsed_records);
        assert!(demuxed.contains_key(&1), "Must contain channel 1");
        assert!(demuxed.contains_key(&2), "Must contain channel 2");

        let ch1 = &demuxed[&1];
        let ch2 = &demuxed[&2];
        assert!(ch1.total_blocks > 0);
        assert!(ch2.total_blocks > 0);

        println!("Ground truth diff test passed 100%! All 64 blocks match ground truth exactly.");
    }

    #[test]
    fn test_all_grammars_compile() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let grammars_dir = project_root.join("grammars");
        assert!(grammars_dir.exists(), "Grammars dir must exist");

        let entries = fs::read_dir(&grammars_dir).unwrap();
        let mut count = 0;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
                if path.file_name().and_then(|s| s.to_str()) == Some("vendor_registry.yaml") {
                    continue;
                }
                let grammar = GrammarFile::load_from_file(&path).unwrap_or_else(|e| {
                    panic!("Failed to load/compile grammar {}: {:?}", path.display(), e)
                });
                assert!(!grammar.grammar.id.is_empty());
                assert!(grammar.grammar.tier >= 1 && grammar.grammar.tier <= 3);
                count += 1;
            }
        }

        assert!(count >= 2, "Expected at least 2 grammar files, found {}", count);
        println!("Successfully loaded and compiled {} grammar files!", count);
    }

    #[test]
    fn test_timestamp_normalization_non_utc() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let dahua_grammar_path = project_root.join("grammars").join("dahua-v1.yaml");
        let grammar = GrammarFile::load_from_file(&dahua_grammar_path).unwrap();
        let interpreter = GrammarInterpreter::new(&grammar);

        // Construct a synthetic Dahua block matching DHAV header structure
        // Magic 'DHAV' at offset 0
        // Frame type at offset 4 (u16)
        // Channel ID at offset 6 (u16) -> 1
        // Frame number at offset 8 (u32) -> 42
        // Payload length at offset 12 (u32) -> 1024
        // Date packed at offset 16 (u32) -> 2024-03-15 16:30:45 in UTC+8
        //   Year: 2024 - 2000 = 24
        //   Month: 3
        //   Day: 15
        //   Hour: 16
        //   Minute: 30
        //   Second: 45
        let raw_packed: u32 = (24 << 26) | (3 << 22) | (15 << 17) | (16 << 12) | (30 << 6) | 45;

        let mut block = vec![0u8; 4096];
        block[0..4].copy_from_slice(b"DHAV");
        block[4..6].copy_from_slice(&0xFC00u16.to_le_bytes()); // keyframe
        block[6..8].copy_from_slice(&1u16.to_le_bytes()); // channel 1
        block[8..12].copy_from_slice(&42u32.to_le_bytes()); // frame 42
        block[12..16].copy_from_slice(&1024u32.to_le_bytes()); // payload len 1024
        block[16..20].copy_from_slice(&raw_packed.to_le_bytes()); // packed timestamp
        block[20..24].copy_from_slice(&0u32.to_le_bytes()); // timestamp ticks

        let blake3_hash = blake3::hash(&block).to_hex().to_string();
        let record = interpreter.interpret_block(0, 0, &block, &blake3_hash).unwrap();

        assert_eq!(record.block_type, "video_frame");
        assert_eq!(record.channel_id, 1);
        assert_eq!(record.sequence_num, 42);
        assert_eq!(record.payload_len, 1024);
        assert_eq!(record.timestamp, raw_packed as u64);

        // 16:30:45 in UTC+8 normalized to canonical UTC ISO 8601 should be 08:30:45Z
        assert_eq!(
            record.normalized_timestamp,
            "2024-03-15T08:30:45Z",
            "Non-UTC Dahua packed timestamp must be normalized to canonical UTC ISO 8601"
        );
    }

    #[test]
    fn test_parse_case_with_descrambler() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let case_dir = project_root.join("samples").join("case_ident_06");
        let grammars_dir = project_root.join("grammars");
        let truth_path = project_root.join("samples").join("synthetic_disk.truth.json");

        let truth_content = fs::read_to_string(&truth_path).unwrap();
        let truth: Value = serde_json::from_str(&truth_content).unwrap();
        let truth_blocks = truth["blocks"].as_array().expect("Ground truth must contain blocks");

        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("test_case.db");

        let summary = parse_case(&case_dir, &grammars_dir, Some(db_path.clone())).unwrap();

        assert_eq!(summary.total_blocks, 64);
        assert_eq!(summary.scrambled_blocks, 4, "Should detect 4 scrambled blocks (10..13)");
        assert_eq!(summary.descrambled_blocks, 4, "Should successfully descramble all 4 blocks via WASM");

        // Validate database records and hash fidelity against original pre-scrambled payloads
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT block_index, descrambled, descrambled_blake3_hash FROM extracted_records WHERE is_scrambled = 1 ORDER BY block_index ASC;")
            .unwrap();

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? == 1,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .unwrap();

        let mut checked_count = 0;
        for r in rows {
            let (b_idx, descrambled, descrambled_hash) = r.unwrap();
            assert!(descrambled, "Block {} must be marked descrambled in SQLite", b_idx);
            let expected_orig_hash = truth_blocks[b_idx]["original_payload_blake3"].as_str().unwrap();
            assert_eq!(
                descrambled_hash.as_deref(),
                Some(expected_orig_hash),
                "Block {} descrambled BLAKE3 hash must exactly match pre-scramble ground truth payload hash",
                b_idx
            );
            checked_count += 1;
        }

        assert_eq!(checked_count, 4, "Must verify all 4 descrambled blocks");
        println!("[OK] Successfully verified 4/4 scrambled blocks descrambled with 100% hash fidelity!");
    }

    #[test]
    fn test_case_integrity_verification_pristine() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let case_dir = project_root.join("samples").join("case_ident_06");

        let report = verify_case_integrity(&case_dir, None::<&Path>).unwrap();

        assert!(report.is_pristine, "Untampered case must be pristine");
        assert!(report.whole_image_sha256_match, "SHA-256 must match manifest");
        assert!(report.whole_image_md5_match, "MD5 must match manifest");
        assert_eq!(report.total_blocks, 64);
        assert_eq!(report.matched_blocks, 64);
        assert!(report.block_discrepancies.is_empty(), "Expected 0 block discrepancies");
        assert!(report.db_record_discrepancies.is_empty(), "Expected 0 DB discrepancies");
    }

    #[test]
    fn test_case_integrity_verification_detects_tampering() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let orig_case_dir = project_root.join("samples").join("case_ident_06");
        let orig_image_path = project_root.join("samples").join("synthetic_disk.img");

        let temp_dir = tempfile::tempdir().unwrap();
        let tampered_case_dir = temp_dir.path().join("case_tampered");
        std::fs::create_dir_all(&tampered_case_dir).unwrap();

        let tampered_image_path = temp_dir.path().join("tampered_disk.img");
        std::fs::copy(&orig_image_path, &tampered_image_path).unwrap();

        // Deliberately tamper with evidence: flip 1 single byte in Block 15 (offset: 15 * 4096 + 100)
        let tamper_offset = (15 * 4096) + 100;
        {
            use std::io::Seek;
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).open(&tampered_image_path).unwrap();
            f.seek(std::io::SeekFrom::Start(tamper_offset)).unwrap();
            f.write_all(&[0xDE]).unwrap();
        }

        // Copy manifest and point to tampered image
        let manifest_content = std::fs::read_to_string(orig_case_dir.join("manifest.json")).unwrap();
        let mut manifest_val: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
        manifest_val["source_path"] = serde_json::Value::String(tampered_image_path.to_str().unwrap().to_string());
        std::fs::write(tampered_case_dir.join("manifest.json"), serde_json::to_string_pretty(&manifest_val).unwrap()).unwrap();

        // Also copy case.db if it exists
        if orig_case_dir.join("case.db").exists() {
            let _ = std::fs::copy(orig_case_dir.join("case.db"), tampered_case_dir.join("case.db"));
        }

        let report = verify_case_integrity(&tampered_case_dir, None::<&Path>).unwrap();

        assert!(!report.is_pristine, "Tampered case must NOT be pristine");
        assert!(!report.whole_image_sha256_match, "Whole-image SHA-256 must detect tampering");
        assert!(!report.whole_image_md5_match, "Whole-image MD5 must detect tampering");
        assert_eq!(report.block_discrepancies.len(), 1, "Must isolate exactly 1 tampered block");

        let disc = &report.block_discrepancies[0];
        assert_eq!(disc.block_index, 15, "Tampered block index must be exactly 15");
        assert_eq!(disc.byte_offset, 15 * 4096, "Tampered block byte offset must be 15 * 4096");
        println!("[OK] Successfully detected tampering in Block 15 at byte offset {}", disc.byte_offset);
    }

    #[test]
    fn test_deep_carving_corrupted_blocks_and_db_storage() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let image_path = project_root.join("samples").join("synthetic_disk.img");

        // Blocks 22 and 23 have corrupted/zeroed headers in C4FS synthetic disk
        let corrupted_blocks = vec![22, 23];
        let carved = recovery::carve_corrupted_blocks(&image_path, 4096, &corrupted_blocks).unwrap();

        assert!(!carved.is_empty(), "Carver must recover video frames from corrupted blocks 22..23");
        println!("Carved {} raw video frames from corrupted blocks 22..23", carved.len());

        for f in &carved {
            assert!(f.length > 0);
            assert!(f.confidence >= 0.85);
            assert!(!f.blake3_hash.is_empty());
        }

        // Test storing and querying carved records in SQLite
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("carve_test.db");
        let mut db = CaseDatabase::open(&db_path).unwrap();

        // Insert a dummy case and evidence item to satisfy foreign keys
        let (_case_id, evidence_id) = db.store_case_extraction(
            "TEST-CARVE-CASE",
            &image_path.to_string_lossy(),
            "dummy_sha256",
            "dummy_md5",
            4096,
            64,
            "synthetic-v1",
            1,
            "2026-09-20T00:00:00Z",
            &[],
        ).unwrap();

        let stored_count = db.store_carved_records(evidence_id, &carved).unwrap();
        assert_eq!(stored_count, carved.len());

        let queried_carved = db.query_carved_records(Some(evidence_id)).unwrap();
        assert_eq!(queried_carved.len(), carved.len());

        // Test RecordFilter queries
        let filter = RecordFilter {
            corrupted_only: true,
            ..Default::default()
        };
        let queried_records = db.query_records(&filter).unwrap();
        assert_eq!(queried_records.len(), 0); // No extracted records stored in this dummy table
    }

    #[test]
    fn test_cross_camera_correlation_and_db_storage() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let case_dir = project_root.join("samples").join("case_ident_06");
        let db_path = case_dir.join("case.db");
        assert!(db_path.exists(), "Case DB must exist: {:?}", db_path);

        let mut db = CaseDatabase::open(&db_path).unwrap();
        let records = db.query_all_records().unwrap();
        assert_eq!(records.len(), 64);

        let record_inputs: Vec<correlation::RecordInput> = records.iter().map(|r| r.to_correlation_input()).collect();

        // Run correlation with 5s window and 15s blackout gap
        let report = correlation::generate_correlation_report(&record_inputs, 5, 15);

        assert_eq!(report.active_channels, vec![1, 2]);
        assert!(!report.transitions.is_empty(), "Must detect cross-camera transitions between CH 1 and CH 2");
        println!("Identified {} cross-camera transitions!", report.transitions.len());

        let primary_evidence_id = db.get_primary_evidence_id().unwrap().unwrap_or(1);
        let mut db_events = Vec::new();

        for t in &report.transitions {
            db_events.push(CorrelatedDbEvent {
                id: None,
                event_type: "transition".to_string(),
                start_timestamp: t.from_normalized_ts.clone(),
                end_timestamp: t.to_normalized_ts.clone(),
                channels_involved: format!("{},{}", t.from_channel, t.to_channel),
                confidence: t.confidence,
                details_json: serde_json::to_string(t).unwrap_or_default(),
            });
        }

        let stored = db.store_correlated_events(primary_evidence_id, &db_events).unwrap();
        assert_eq!(stored, report.transitions.len());

        let queried = db.query_correlated_events(Some(primary_evidence_id)).unwrap();
        assert!(queried.len() >= report.transitions.len());
        assert_eq!(queried[0].event_type, "transition");
    }

    #[test]
    fn test_ai_video_analytics_and_db_storage() {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let case_dir = project_root.join("samples").join("case_ident_06");
        let db_path = case_dir.join("case.db");
        let image_path = project_root.join("samples").join("synthetic_disk.img");
        assert!(db_path.exists(), "Case DB must exist: {:?}", db_path);
        assert!(image_path.exists(), "Image must exist: {:?}", image_path);

        let mut db = CaseDatabase::open(&db_path).unwrap();
        let records = db.query_all_records().unwrap();
        assert_eq!(records.len(), 64);

        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&image_path).unwrap();

        let mut analyses = Vec::new();
        let mut db_detections = Vec::new();

        for r in &records {
            if r.payload_len == 0 {
                continue;
            }
            f.seek(SeekFrom::Start(r.payload_offset)).unwrap();
            let mut payload = vec![0u8; r.payload_len];
            f.read_exact(&mut payload).unwrap();

            let is_keyframe = (r.flags & 1) != 0;
            let analysis = analytics::analyze_frame(
                r.block_index,
                r.channel_id,
                r.timestamp,
                &r.normalized_timestamp,
                &payload,
                is_keyframe,
            );

            for det in &analysis.entities {
                let bbox_json = serde_json::to_string(&det.bbox).unwrap_or_default();
                let attrs_json = serde_json::to_string(&det.attributes).unwrap_or_default();

                db_detections.push(AnalyticsDbDetection {
                    id: None,
                    block_index: r.block_index,
                    channel_id: r.channel_id,
                    timestamp: r.timestamp,
                    normalized_timestamp: r.normalized_timestamp.clone(),
                    motion_energy: analysis.motion_energy,
                    relevance_score: analysis.relevance_score,
                    entity_class: det.class_label.code().to_string(),
                    confidence: det.confidence,
                    bbox_json,
                    attributes_json: attrs_json,
                });
            }

            analyses.push(analysis);
        }

        assert_eq!(analyses.len(), 64);
        assert!(!db_detections.is_empty(), "Must produce AI entity detections across synthetic video blocks");

        let summary = analytics::summarize_analytics(analyses, 0.50, 10);
        assert_eq!(summary.total_frames_analyzed, 64);
        assert!(summary.high_relevance_frames > 0);
        assert!(!summary.top_leads.is_empty());

        let primary_evidence_id = db.get_primary_evidence_id().unwrap().unwrap_or(1);
        let stored = db.store_analytics_detections(primary_evidence_id, &db_detections).unwrap();
        assert_eq!(stored, db_detections.len());

        let queried = db.query_analytics_detections(Some(primary_evidence_id), 0.50, 0.60, None, Some(10)).unwrap();
        assert!(!queried.is_empty());
        for q in &queried {
            assert!(q.relevance_score >= 0.50);
            assert!(q.confidence >= 0.60);
        }
        println!("[OK] Successfully stored and queried {} AI analytics detections from SQLite!", stored);
    }
}


