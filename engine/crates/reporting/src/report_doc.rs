use crate::certificate::ExaminerDetails;
use crate::export::ExportSummary;
use crate::timeline::{DiscontinuityAlert, TimelineEntry};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Complete structural model of a digital video forensics examination report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveForensicReport {
    pub case_name: String,
    pub generated_at: String,
    pub examiner: ExaminerDetails,
    pub evidence_source_path: String,
    pub image_size_bytes: u64,
    pub block_size: usize,
    pub block_count: usize,
    pub md5_hash: String,
    pub sha256_hash: String,
    pub blake3_hash: String,
    pub is_pristine: bool,
    pub identified_format: String,
    pub identified_chipset: String,
    pub confidence: f64,
    pub validation_tier: u8,
    pub validation_tier_disclosure: String,
    pub extracted_records_count: usize,
    pub carved_frames_count: usize,
    pub transitions_count: usize,
    pub analytics_leads_count: usize,
    pub discontinuities: Vec<DiscontinuityAlert>,
    pub export_summary: Option<ExportSummary>,
    pub timeline: Vec<TimelineEntry>,
}

/// Generates human-readable Markdown and structured JSON forensic reports.
pub fn write_report_documents<P: AsRef<Path>>(
    report: &ComprehensiveForensicReport,
    output_dir: P,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let out_dir = output_dir.as_ref();
    std::fs::create_dir_all(out_dir)?;

    let json_path = out_dir.join("forensic_report.json");
    let json_str = serde_json::to_string_pretty(report)?;
    let mut json_file = File::create(&json_path)?;
    json_file.write_all(json_str.as_bytes())?;

    let md_path = out_dir.join("forensic_report.md");
    let mut md_file = File::create(&md_path)?;

    writeln!(md_file, "# Forensic Examination & Technical Intelligence Report")?;
    writeln!(md_file, "### Under Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023")?;
    writeln!(md_file, "> **DRAFT — REQUIRING FORMAL LEGAL REVIEW**\n")?;

    writeln!(md_file, "## 1. Case & Examiner Particulars")?;
    writeln!(md_file, "| Parameter | Details |")?;
    writeln!(md_file, "| :--- | :--- |")?;
    writeln!(md_file, "| **Case Name / ID** | `{}` |", report.case_name)?;
    writeln!(md_file, "| **Date of Examination** | `{}` |", report.generated_at)?;
    writeln!(md_file, "| **Forensic Examiner** | {} |", report.examiner.name)?;
    writeln!(md_file, "| **Designation** | {} |", report.examiner.designation)?;
    writeln!(md_file, "| **Law Enforcement / Agency** | {} |", report.examiner.agency)?;
    writeln!(md_file, "| **Badge / ID** | `{}` |", report.examiner.badge_number)?;
    writeln!(md_file, "| **Laboratory** | {} |\n", report.examiner.laboratory)?;

    writeln!(md_file, "## 2. Evidence Storage Media & Hardware Identification")?;
    writeln!(md_file, "| Property | Value |")?;
    writeln!(md_file, "| :--- | :--- |")?;
    writeln!(md_file, "| **Evidence File** | `{}` |", report.evidence_source_path)?;
    writeln!(md_file, "| **File Size** | {} bytes |", report.image_size_bytes)?;
    writeln!(md_file, "| **Block Geometry** | {} blocks × {} bytes |", report.block_count, report.block_size)?;
    writeln!(md_file, "| **Identified Format** | **{}** |", report.identified_format)?;
    writeln!(md_file, "| **SoC / Chipset Architecture** | {} |", report.identified_chipset)?;
    writeln!(md_file, "| **Detection Confidence** | **{:.1}%** |", report.confidence * 100.0)?;
    writeln!(md_file, "| **Grammar Validation Tier** | **Tier {}** |", report.validation_tier)?;
    writeln!(md_file, "| **Tier Disclosure** | {} |\n", report.validation_tier_disclosure)?;

    writeln!(md_file, "## 3. Cryptographic Hash Integrity Verification")?;
    writeln!(md_file, "| Algorithm | Computed Whole-Image Hash Value |")?;
    writeln!(md_file, "| :--- | :--- |")?;
    writeln!(md_file, "| **MD5 (RFC 1321)** | `{}` |", report.md5_hash)?;
    writeln!(md_file, "| **SHA-256 (FIPS 180-4)** | `{}` |", report.sha256_hash)?;
    writeln!(md_file, "| **BLAKE3 (Cryptographic)** | `{}` |", report.blake3_hash)?;
    writeln!(md_file, "\n**Integrity Status**: {}\n",
        if report.is_pristine { "[OK] PRISTINE / UNTAMPERED" } else { "[!] TAMPERED / MODIFIED" }
    )?;

    writeln!(md_file, "## 4. Extraction, Recovery & Analytics Summary")?;
    writeln!(md_file, "- **Demuxed Video Records**: {}", report.extracted_records_count)?;
    writeln!(md_file, "- **Carved Video Fragments**: {}", report.carved_frames_count)?;
    writeln!(md_file, "- **Cross-Camera Correlated Events**: {}", report.transitions_count)?;
    writeln!(md_file, "- **Prioritized AI Video Analytics Leads**: {}", report.analytics_leads_count)?;
    writeln!(md_file, "- **Timeline Discontinuities / Anomalies**: {}\n", report.discontinuities.len())?;

    if !report.discontinuities.is_empty() {
        writeln!(md_file, "### Potential Tampering / Discontinuity Alerts")?;
        writeln!(md_file, "| Severity | Duration | Interval (UTC) | Description |")?;
        writeln!(md_file, "| :--- | :--- | :--- | :--- |")?;
        for d in &report.discontinuities {
            writeln!(md_file, "| **{}** | {}s | `{}` -> `{}` | {} |",
                d.severity, d.duration_secs, d.start_timestamp, d.end_timestamp, d.description)?;
        }
        writeln!(md_file)?;
    }

    if let Some(ref exp) = report.export_summary {
        writeln!(md_file, "### Exported Media Clips")?;
        writeln!(md_file, "- **Raw H.264 Streams**: {} clips exported to `{}`", exp.raw_h264_exported, exp.output_dir.display())?;
        if exp.ffmpeg_available {
            writeln!(md_file, "- **MP4 Transcoded Containers**: {} clips containerized", exp.mp4_transcoded)?;
        } else {
            writeln!(md_file, "- **Containerization Notice**: `ffmpeg` not detected in PATH. Raw H.264 bitstreams preserved for playback.")?;
        }
        writeln!(md_file)?;
    }

    writeln!(md_file, "## 5. Reconstructed Chronological Timeline (Top Highlights)")?;
    writeln!(md_file, "| Timestamp (UTC) | Channel | Type | Summary |")?;
    writeln!(md_file, "| :--- | :--- | :--- | :--- |")?;
    for entry in report.timeline.iter().take(50) {
        writeln!(
            md_file,
            "| `{}` | {} | {} | {} |",
            entry.normalized_timestamp,
            entry.channel_id.map(|c| format!("CH {:02}", c)).unwrap_or_else(|| "N/A".to_string()),
            entry.entry_type,
            entry.summary
        )?;
    }
    if report.timeline.len() > 50 {
        writeln!(md_file, "\n*(... {} additional timeline entries available in `forensic_report.json`)*", report.timeline.len() - 50)?;
    }

    writeln!(md_file, "\n---\n*Report generated by DVR/NVR Digital Video Forensics Platform (`dvrft v0.1.0`), Team Cyber 4.*")?;

    Ok((md_path, json_path))
}
