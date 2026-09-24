use identify::{identify_device, MIN_CONFIDENCE_THRESHOLD};
use std::path::PathBuf;

fn get_project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn test_identify_synthetic_image() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let image_path = root.join("samples").join("synthetic_disk.img");

    assert!(image_path.exists(), "Synthetic disk image must exist");

    let result = identify_device(&image_path, &grammars_dir).expect("Identification should succeed");

    assert!(result.recognized, "Synthetic disk should be recognized");
    assert_eq!(result.vendor, "Cyber4 Synthetic");
    assert!(result.model.as_deref().unwrap_or("").contains("C4FS"));
    assert_eq!(result.chipset.as_deref(), Some("Synthetic C4-ARM64"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("synthetic-v1"));
    assert_eq!(result.validation_tier, Some(1));
    assert!(
        result.confidence >= 0.95,
        "Expected high confidence (>= 0.95), got {}",
        result.confidence
    );
}

#[test]
fn test_identify_hikvision_literature_sample() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let fixture_path = root.join("samples").join("fixtures").join("hikvision_header.raw");

    assert!(fixture_path.exists(), "Hikvision fixture must exist");

    let result = identify_device(&fixture_path, &grammars_dir).expect("Identification should succeed");

    assert!(result.recognized, "Hikvision sample should be recognized");
    assert_eq!(result.vendor, "Hikvision");
    assert!(result.model.as_deref().unwrap_or("").contains("DS-7000"));
    assert!(result.chipset.as_deref().unwrap_or("").contains("HiSilicon"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("hikvision-v1"));
    assert_eq!(result.validation_tier, Some(2));
    assert!(
        result.confidence >= 0.90,
        "Expected high confidence for 18-byte signature, got {}",
        result.confidence
    );
}

#[test]
fn test_identify_dahua_literature_sample() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let fixture_path = root.join("samples").join("fixtures").join("dahua_header.raw");

    assert!(fixture_path.exists(), "Dahua fixture must exist");

    let result = identify_device(&fixture_path, &grammars_dir).expect("Identification should succeed");

    assert!(result.recognized, "Dahua sample should be recognized");
    assert_eq!(result.vendor, "Dahua");
    assert!(result.model.as_deref().unwrap_or("").contains("DH-DVR"));
    assert!(result.chipset.as_deref().unwrap_or("").contains("HiSilicon"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("dahua-v1"));
    assert_eq!(result.validation_tier, Some(2));
    assert!(
        result.confidence >= 0.90,
        "Expected confidence >= 0.90, got {}",
        result.confidence
    );
}

#[test]
fn test_identify_garbage_unrecognized() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let fixture_path = root.join("samples").join("fixtures").join("garbage_data.raw");

    assert!(fixture_path.exists(), "Garbage fixture must exist");

    let result = identify_device(&fixture_path, &grammars_dir).expect("Identification should run without crash");

    assert!(!result.recognized, "Garbage data must NOT be recognized");
    assert_eq!(result.vendor, "Unknown");
    assert_eq!(result.confidence, 0.0);
    assert!(result.confidence < MIN_CONFIDENCE_THRESHOLD);
    assert_eq!(result.matched_grammar_id, None);
}

#[test]
fn test_identify_registry_only_cpplus() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("cpplus_sample.raw");

    let mut buf = vec![0u8; 4096];
    buf[..6].copy_from_slice(b"CPPLUS");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "CP Plus signature must be recognized from vendor registry");
    assert_eq!(result.vendor, "CP Plus");
    assert_eq!(result.validation_tier, Some(0), "Registry-only format must be Tier 0");
    assert_eq!(result.matched_grammar_id, None, "Must not have active grammar");
    assert!(result.confidence >= 0.90);
    assert!(result.display_summary().contains("Tier 0"));
    println!("[OK] Successfully identified CP Plus as Tier 0 (unimplemented registry OEM)");
}

#[test]
fn test_identify_registry_only_uniview() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("uniview_sample.raw");

    let mut buf = vec![0u8; 4096];
    buf[..7].copy_from_slice(b"UNIVIEW");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized);
    assert_eq!(result.vendor, "Uniview");
    assert_eq!(result.validation_tier, Some(0));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified Uniview as Tier 0");
}

#[test]
fn test_identify_registry_only_matrix() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("matrix_sample.raw");

    let mut buf = vec![0u8; 4096];
    buf[..7].copy_from_slice(b"SATATYA");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized);
    assert_eq!(result.vendor, "Matrix");
    assert_eq!(result.validation_tier, Some(0));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified Matrix Satatya as Tier 0");
}

#[test]
fn test_identify_registry_only_godrej() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("godrej_sample.raw");

    let mut buf = vec![0u8; 4096];
    buf[..6].copy_from_slice(b"GODREJ");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized);
    assert_eq!(result.vendor, "Godrej");
    assert_eq!(result.validation_tier, Some(0));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified Godrej SeeThru as Tier 0");
}

#[test]
fn test_identify_registry_only_tplink() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("tplink_sample.raw");

    let mut buf = vec![0u8; 4096];
    buf[..8].copy_from_slice(b"VIGI_NVR");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized);
    assert_eq!(result.vendor, "TP-Link");
    assert_eq!(result.validation_tier, Some(0));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified TP-Link VIGI as Tier 0");
}

#[test]
fn test_identify_mp4_video_container() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("cctv_export.mp4");

    let mut buf = vec![0u8; 4096];
    // MP4 header: length 0x20, 'ftyp', 'isom'
    buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x20]);
    buf[4..8].copy_from_slice(b"ftyp");
    buf[8..12].copy_from_slice(b"isom");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "MP4 video container must be recognized");
    assert!(result.vendor.contains("MP4") || result.vendor.contains("CCTV"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("cctv-mp4"));
    assert_eq!(result.validation_tier, Some(3));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified MP4 video container");
}

#[test]
fn test_identify_hikvision_mp4_container() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("hikvision_export.mp4");

    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x20]);
    buf[4..8].copy_from_slice(b"ftyp");
    buf[8..12].copy_from_slice(b"hikv");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "Hikvision MP4 container must be recognized");
    assert_eq!(result.vendor, "Hikvision");
    assert_eq!(result.matched_grammar_id.as_deref(), Some("hikvision-mp4"));
    assert_eq!(result.validation_tier, Some(2));
    assert!(result.confidence >= 0.90);
    println!("[OK] Successfully identified Hikvision MP4 container export");
}

#[test]
fn test_identify_avi_video_container() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("cctv_footage.avi");

    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(b"RIFF");
    buf[4..8].copy_from_slice(&[0x00, 0x10, 0x00, 0x00]);
    buf[8..12].copy_from_slice(b"AVI ");
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "AVI video container must be recognized");
    assert!(result.vendor.contains("AVI"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("cctv-avi"));
    assert_eq!(result.validation_tier, Some(3));
    println!("[OK] Successfully identified AVI video container");
}

#[test]
fn test_identify_mkv_video_container() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("cctv_clip.mkv");

    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "MKV video container must be recognized");
    assert!(result.vendor.contains("Matroska") || result.vendor.contains("MKV"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("cctv-mkv"));
    println!("[OK] Successfully identified MKV video container");
}

#[test]
fn test_identify_raw_h264_stream() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("stream.h264");

    let mut buf = vec![0u8; 4096];
    // Annex B start code + SPS (0x67)
    buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    buf[4] = 0x67; // SPS
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "Raw H.264 stream must be recognized");
    assert!(result.vendor.contains("H.264"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("h264-stream"));
    println!("[OK] Successfully identified raw H.264 video stream");
}

#[test]
fn test_identify_raw_h265_stream() {
    let root = get_project_root();
    let grammars_dir = root.join("grammars");
    let temp = tempfile::tempdir().unwrap();
    let sample_path = temp.path().join("stream.h265");

    let mut buf = vec![0u8; 4096];
    // Annex B start code + HEVC VPS (0x40 0x01)
    buf[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    buf[4] = 0x40; // VPS
    buf[5] = 0x01;
    std::fs::write(&sample_path, &buf).unwrap();

    let result = identify_device(&sample_path, &grammars_dir).expect("Identification should succeed");
    assert!(result.recognized, "Raw H.265 stream must be recognized");
    assert!(result.vendor.contains("H.265"));
    assert_eq!(result.matched_grammar_id.as_deref(), Some("h265-stream"));
    println!("[OK] Successfully identified raw H.265 video stream");
}
