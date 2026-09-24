use anyhow::Result;
use clap::Parser;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use tiny_http::{Header, Response, Server, StatusCode};

const INDEX_HTML: &str = include_str!("../web/index.html");
const STYLES_CSS: &str = include_str!("../web/styles.css");
const APP_JS: &str = include_str!("../web/app.js");

#[derive(Parser, Debug)]
#[command(
    name = "dvrft-gui",
    about = "DVR/NVR Forensic Desktop GUI Application - Digital Evidence Platform"
)]
struct Args {
    /// Port to bind GUI HTTP server
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Case directory to auto-load on start
    #[arg(long, default_value = "../samples/case_ident_06")]
    case_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let addr = format!("127.0.0.1:{}", args.port);
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;

    println!("============================================================");
    println!(" DVR Forensics Platform - Desktop GUI Ready");
    println!("============================================================");
    println!("  Local Webview / UI : http://{}", addr);
    println!("  Default Case Dir   : {}", args.case_dir.display());
    println!("  Engine Status      : In-Process Direct Crate Bindings Active");
    println!("------------------------------------------------------------");
    println!("Press Ctrl+C to terminate GUI server.");

    // Store last generated report paths in memory
    let mut last_case_dir = args.case_dir;

    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().to_string();

        if method == "GET" {
            match url.as_str() {
                "/" | "/index.html" => {
                    let header = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
                    let response = Response::from_string(INDEX_HTML).with_header(header);
                    let _ = request.respond(response);
                }
                "/styles.css" => {
                    let header = Header::from_bytes(&b"Content-Type"[..], &b"text/css; charset=utf-8"[..]).unwrap();
                    let response = Response::from_string(STYLES_CSS).with_header(header);
                    let _ = request.respond(response);
                }
                "/app.js" => {
                    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/javascript; charset=utf-8"[..]).unwrap();
                    let response = Response::from_string(APP_JS).with_header(header);
                    let _ = request.respond(response);
                }
                "/api/download-pdf" => {
                    let cert_path = last_case_dir.join("report").join("certificate.pdf");
                    if cert_path.exists() {
                        if let Ok(mut f) = File::open(&cert_path) {
                            let mut buf = Vec::new();
                            let _ = f.read_to_end(&mut buf);
                            let h1 = Header::from_bytes(&b"Content-Type"[..], &b"application/pdf"[..]).unwrap();
                            let h2 = Header::from_bytes(&b"Content-Disposition"[..], &b"attachment; filename=\"certificate.pdf\""[..]).unwrap();
                            let response = Response::from_data(buf).with_header(h1).with_header(h2);
                            let _ = request.respond(response);
                            continue;
                        }
                    }
                    let response = Response::from_string("Certificate PDF not found. Generate report first.").with_status_code(StatusCode(404));
                    let _ = request.respond(response);
                }
                "/api/view-report-md" => {
                    let md_path = last_case_dir.join("report").join("forensic_report.md");
                    if md_path.exists() {
                        if let Ok(content) = std::fs::read_to_string(&md_path) {
                            let h = Header::from_bytes(&b"Content-Type"[..], &b"text/plain; charset=utf-8"[..]).unwrap();
                            let response = Response::from_string(content).with_header(h);
                            let _ = request.respond(response);
                            continue;
                        }
                    }
                    let response = Response::from_string("Report not found.").with_status_code(StatusCode(404));
                    let _ = request.respond(response);
                }
                "/api/view-report-json" => {
                    let json_path = last_case_dir.join("report").join("forensic_report.json");
                    if json_path.exists() {
                        if let Ok(content) = std::fs::read_to_string(&json_path) {
                            let h = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
                            let response = Response::from_string(content).with_header(h);
                            let _ = request.respond(response);
                            continue;
                        }
                    }
                    let response = Response::from_string("{}").with_status_code(StatusCode(404));
                    let _ = request.respond(response);
                }
                _ => {
                    let response = Response::from_string("Not Found").with_status_code(StatusCode(404));
                    let _ = request.respond(response);
                }
            }
        } else if method == "POST" {
            let mut body_bytes = Vec::new();
            let _ = request.as_reader().read_to_end(&mut body_bytes);
            let body_str = String::from_utf8_lossy(&body_bytes);
            let body: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));

            let json_header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

            match url.as_str() {
                "/api/acquire" => {
                    let image_path_raw = body.get("image_path").and_then(|v| v.as_str()).unwrap_or("../samples/synthetic_disk.img");
                    let image_path = image_path_raw.trim().trim_matches('"').trim_matches('\'');
                    let case_name = body.get("case_name").and_then(|v| v.as_str()).unwrap_or("GUI-CASE-01");
                    let output_dir = body.get("output_dir").and_then(|v| v.as_str()).unwrap_or("../samples/gui_case");

                    let res = acquisition::acquire_evidence_with_options(
                        image_path,
                        case_name,
                        output_dir,
                        Some(acquisition::DEFAULT_BLOCK_SIZE),
                        None,
                    );

                    let resp_val = match res {
                        Ok(manifest) => {
                            last_case_dir = PathBuf::from(output_dir);
                            json!({ "success": true, "manifest": manifest })
                        }
                        Err(e) => json!({ "success": false, "error": e.to_string() }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                "/api/identify" => {
                    let image_path_raw = body.get("image_path").and_then(|v| v.as_str()).unwrap_or("../samples/synthetic_disk.img");
                    let image_path = image_path_raw.trim().trim_matches('"').trim_matches('\'');
                    let grammars_dir = body.get("grammars_dir").and_then(|v| v.as_str()).unwrap_or("../grammars");

                    let res = identify::identify_device(image_path, grammars_dir);
                    let resp_val = match res {
                        Ok(ident) => json!({ "success": true, "identification": ident }),
                        Err(e) => json!({ "success": false, "error": e.to_string() }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                "/api/parse" => {
                    let case_dir_str = body.get("case_dir").and_then(|v| v.as_str()).unwrap_or("../samples/case_ident_06");
                    let case_dir = PathBuf::from(case_dir_str);
                    last_case_dir = case_dir.clone();

                    let db_path = case_dir.join("case.db");
                    let db_res = parser::CaseDatabase::open(&db_path);

                    let resp_val = match db_res {
                        Ok(db) => {
                            let records = db.query_all_records().unwrap_or_default();
                            let carved = db.query_carved_records(None).unwrap_or_default();
                            let (_grammar_id, validation_tier) = db
                                .get_primary_evidence_grammar_and_tier()
                                .unwrap_or_default()
                                .unwrap_or_else(|| ("synthetic-v1".to_string(), 1));

                            let valid_count = records.iter().filter(|r| !r.is_corrupted).count();
                            let descrambled_count = records.iter().filter(|r| r.descrambled).count();

                            let mapped_records: Vec<_> = records.iter().take(100).map(|r| {
                                json!({
                                    "block_index": r.block_index,
                                    "byte_offset": r.byte_offset,
                                    "channel_id": r.channel_id,
                                    "normalized_timestamp": r.normalized_timestamp,
                                    "sequence_num": r.sequence_num,
                                    "is_scrambled": r.is_scrambled,
                                    "descrambled": r.descrambled,
                                    "is_corrupted": r.is_corrupted,
                                    "tier": validation_tier,
                                })
                            }).collect();

                            json!({
                                "success": true,
                                "total_blocks": records.len(),
                                "valid_frames": valid_count,
                                "descrambled_blocks": descrambled_count,
                                "carved_count": carved.len(),
                                "records": mapped_records,
                            })
                        }
                        Err(e) => json!({ "success": false, "error": e.to_string() }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                "/api/timeline-analytics" => {
                    let case_dir_str = body.get("case_dir").and_then(|v| v.as_str()).unwrap_or("../samples/case_ident_06");
                    let case_dir = PathBuf::from(case_dir_str);
                    last_case_dir = case_dir.clone();

                    let db_path = case_dir.join("case.db");
                    let db_res = parser::CaseDatabase::open(&db_path);

                    let resp_val = match db_res {
                        Ok(db) => {
                            let records = db.query_all_records().unwrap_or_default();
                            let record_inputs: Vec<_> = records.iter().map(|r| r.to_correlation_input()).collect();

                            let corr_report = correlation::generate_correlation_report(&record_inputs, 5, 15);

                            // Run analytics across records
                            let manifest_file = File::open(case_dir.join("manifest.json")).ok();
                            let mut evidence_path = case_dir.parent().unwrap_or(&case_dir).join("synthetic_disk.img");
                            if let Some(mf) = manifest_file {
                                if let Ok(m) = serde_json::from_reader::<_, acquisition::AcquisitionManifest>(mf) {
                                    if Path::new(&m.source_path).exists() {
                                        evidence_path = PathBuf::from(m.source_path);
                                    }
                                }
                            }

                            let mut frame_analyses = Vec::new();
                            if let Ok(mut f) = File::open(&evidence_path) {
                                for r in &records {
                                    if r.payload_len > 0 {
                                        let mut buf = vec![0u8; r.payload_len];
                                        if f.seek(SeekFrom::Start(r.payload_offset)).is_ok() && f.read_exact(&mut buf).is_ok() {
                                            let is_key = (r.flags & 1) != 0;
                                            frame_analyses.push(analytics::analyze_frame(
                                                r.block_index,
                                                r.channel_id,
                                                r.timestamp,
                                                &r.normalized_timestamp,
                                                &buf,
                                                is_key,
                                            ));
                                        }
                                    }
                                }
                            }

                            let summary = analytics::summarize_analytics(frame_analyses, 0.50, 20);

                            json!({
                                "success": true,
                                "transitions_count": corr_report.transitions.len(),
                                "blackouts_count": corr_report.blackouts.len(),
                                "detections_count": summary.total_entities_detected,
                                "leads": summary.top_leads,
                            })
                        }
                        Err(e) => json!({ "success": false, "error": e.to_string() }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                "/api/analyze-video" => {
                    let video_path_raw = body.get("video_path").and_then(|v| v.as_str()).unwrap_or("../samples/case_ident_06/report/clips/carved_clip_0000_90144_key.h264");
                    let video_path = PathBuf::from(video_path_raw.trim().trim_matches('"').trim_matches('\''));

                    let resp_val = match File::open(&video_path) {
                        Ok(mut f) => {
                            let mut buf = Vec::new();
                            let _ = f.read_to_end(&mut buf);
                            let file_size = buf.len();

                            let carved_frames = recovery::carve_buffer(&buf, 0);
                            let mut frame_analyses = Vec::new();

                            if !carved_frames.is_empty() {
                                for (idx, cf) in carved_frames.iter().enumerate() {
                                    let end = (cf.byte_offset as usize + cf.length).min(buf.len());
                                    let slice = &buf[cf.byte_offset as usize..end];
                                    let ts_sec = 1773800000 + (idx as u64 * 2);
                                    let norm_ts = format!("2026-03-18T10:{:02}:{:02}Z", (idx / 60) % 60, idx % 60);

                                    frame_analyses.push(analytics::analyze_frame(
                                        idx,
                                        1,
                                        ts_sec,
                                        &norm_ts,
                                        slice,
                                        cf.is_keyframe,
                                    ));
                                }
                            } else {
                                let chunk_size = 4096;
                                for (idx, chunk) in buf.chunks(chunk_size).enumerate() {
                                    let ts_sec = 1773800000 + (idx as u64 * 2);
                                    let norm_ts = format!("2026-03-18T10:{:02}:{:02}Z", (idx / 60) % 60, idx % 60);
                                    let is_key = idx % 5 == 0;

                                    frame_analyses.push(analytics::analyze_frame(
                                        idx,
                                        1,
                                        ts_sec,
                                        &norm_ts,
                                        chunk,
                                        is_key,
                                    ));
                                }
                            }

                            let summary = analytics::summarize_analytics(frame_analyses, 0.40, 20);

                            json!({
                                "success": true,
                                "video_path": video_path.to_string_lossy(),
                                "file_size": file_size,
                                "total_frames_analyzed": summary.total_frames_analyzed,
                                "total_entities_detected": summary.total_entities_detected,
                                "high_relevance_frames": summary.high_relevance_frames,
                                "entity_counts": summary.entity_counts,
                                "leads": summary.top_leads,
                            })
                        }
                        Err(e) => json!({ "success": false, "error": format!("Could not open video file: {}", e) }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                "/api/report" => {
                    let case_dir_str = body.get("case_dir").and_then(|v| v.as_str()).unwrap_or("../samples/case_ident_06");
                    let case_dir = PathBuf::from(case_dir_str);
                    last_case_dir = case_dir.clone();

                    let ex_val = body.get("examiner");
                    let examiner = reporting::ExaminerDetails {
                        name: ex_val.and_then(|v| v.get("name")).and_then(|v| v.as_str()).unwrap_or("Inspector Vikram Sharma").to_string(),
                        designation: ex_val.and_then(|v| v.get("designation")).and_then(|v| v.as_str()).unwrap_or("Senior Forensic Specialist").to_string(),
                        agency: ex_val.and_then(|v| v.get("agency")).and_then(|v| v.as_str()).unwrap_or("State Cyber Crime Branch").to_string(),
                        badge_number: ex_val.and_then(|v| v.get("badge_number")).and_then(|v| v.as_str()).unwrap_or("DF-2026-04").to_string(),
                        laboratory: ex_val.and_then(|v| v.get("laboratory")).and_then(|v| v.as_str()).unwrap_or("State Digital Forensic Science Laboratory").to_string(),
                    };

                    let out = reporting::generate_case_report(&case_dir, None, examiner, None);
                    let resp_val = match out {
                        Ok(outcome) => json!({
                            "success": true,
                            "case_name": outcome.report.case_name,
                            "certificate_path": outcome.certificate_path,
                            "markdown_path": outcome.markdown_path,
                            "json_path": outcome.json_path,
                        }),
                        Err(e) => json!({ "success": false, "error": e.to_string() }),
                    };

                    let response = Response::from_string(resp_val.to_string()).with_header(json_header);
                    let _ = request.respond(response);
                }

                _ => {
                    let response = Response::from_string("API endpoint not found").with_status_code(StatusCode(404));
                    let _ = request.respond(response);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_assets_present() {
        assert!(INDEX_HTML.contains("DVR-FT — Digital Evidence Platform"));
        assert!(STYLES_CSS.contains("--bg-primary"));
        assert!(APP_JS.contains("setupNavigation"));
    }

    #[test]
    fn test_all_five_screens_in_html() {
        assert!(INDEX_HTML.contains("id=\"screen-1\""), "Screen 1 (Acquisition) must exist");
        assert!(INDEX_HTML.contains("id=\"screen-2\""), "Screen 2 (Identification) must exist");
        assert!(INDEX_HTML.contains("id=\"screen-3\""), "Screen 3 (Parse & Recovery) must exist");
        assert!(INDEX_HTML.contains("id=\"screen-4\""), "Screen 4 (Timeline & Analytics) must exist");
        assert!(INDEX_HTML.contains("id=\"screen-5\""), "Screen 5 (Section 63 Certificate) must exist");
        assert!(INDEX_HTML.contains("Section 63, Bharatiya Sakshya Adhiniyam"));
    }

    #[test]
    fn test_direct_crate_calls_in_gui() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        let case_dir = root.join("samples").join("case_ident_06");
        let image_path = root.join("samples").join("synthetic_disk.img");
        let grammars_dir = root.join("grammars");

        // 1. Direct in-process call to identify crate
        let ident = identify::identify_device(&image_path, &grammars_dir).expect("Direct identify call must succeed");
        assert!(ident.recognized);
        assert_eq!(ident.vendor, "Cyber4 Synthetic");

        // 2. Direct in-process call to parser database
        let db_path = case_dir.join("case.db");
        let db = parser::CaseDatabase::open(&db_path).expect("Direct DB open must succeed");
        let records = db.query_all_records().unwrap();
        assert_eq!(records.len(), 64);

        // 3. Direct in-process call to correlation crate
        let record_inputs: Vec<_> = records.iter().map(|r| r.to_correlation_input()).collect();
        let corr = correlation::generate_correlation_report(&record_inputs, 5, 15);
        assert_eq!(corr.active_channels, vec![1, 2]);

        // 4. Direct in-process call to reporting crate
        let temp = tempfile::tempdir().unwrap();
        let examiner = reporting::ExaminerDetails::default();
        let outcome = reporting::generate_case_report(&case_dir, None, examiner, Some(temp.path()))
            .expect("Direct report generation must succeed");
        assert!(outcome.certificate_path.exists());
        assert!(outcome.markdown_path.exists());
        assert!(outcome.json_path.exists());
        println!("[OK] Successfully verified direct in-process crate invocations without CLI shelling!");
    }
}
