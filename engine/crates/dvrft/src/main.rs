use acquisition::{acquire_evidence_with_options, DEFAULT_BLOCK_SIZE};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use parser::{parse_case, verify_case_integrity, CaseDatabase, RecordFilter};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "dvrft",
    author = "Team Cyber 4",
    version = "0.1.0",
    about = "Digital Video Forensics Platform for CCTV/DVR/NVR Systems (SIH 2025)",
    long_about = "Forensic acquisition, declarative grammar AST parsing, demuxing, integrity verification, and deep carving tool for proprietary CCTV/DVR/NVR storage formats."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Strictly read-only forensic acquisition with whole-image SHA-256 and per-block BLAKE3 hashing
    Acquire(AcquireArgs),

    /// Auto-detect format grammar, parse structured block headers, demux channels, and record to SQLite
    Parse(ParseArgs),

    /// Pre-acquisition device, model, and SoC identification with confidence scoring
    Identify(IdentifyArgs),

    /// Verify forensic integrity against acquisition manifest and database
    Verify(VerifyArgs),

    /// Deep carve video frames from unallocated or corrupted blocks
    Carve(CarveArgs),

    /// Query and inspect forensic timeline records in the SQLite case database
    Query(QueryArgs),

    /// Multi-camera spatial-temporal event fusion, transition tracking, and blackout anomaly detection
    Correlate(CorrelateArgs),

    /// AI-powered video analytics, visual motion estimation, entity classification, and relevance ranking
    Analyze(AnalyzeArgs),

    /// Generate court-admissible forensic report and Section 63 BSA 2023 legal certificate
    Report(ReportArgs),
}

#[derive(Args, Debug)]
struct AcquireArgs {
    /// Path to raw disk image or block device
    #[arg(value_name = "IMAGE_PATH")]
    image_path: PathBuf,

    /// Case identifier for chain-of-custody
    #[arg(short, long, value_name = "CASE_NAME")]
    case: String,

    /// Destination directory for case records and manifest.json
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,

    /// Block size in bytes (default: 4096)
    #[arg(long, default_value_t = DEFAULT_BLOCK_SIZE)]
    block_size: usize,

    /// Directory containing .yaml format grammars for identification (default: ../grammars)
    #[arg(long, default_value = "../grammars")]
    grammars_dir: PathBuf,
}

#[derive(Args, Debug)]
struct ParseArgs {
    /// Directory containing acquisition manifest.json and evidence reference
    #[arg(value_name = "CASE_DIR")]
    case_dir: PathBuf,

    /// Directory containing .yaml format grammars (default: ../grammars)
    #[arg(long, default_value = "../grammars")]
    grammars_dir: PathBuf,

    /// Custom path for SQLite case database (default: <CASE_DIR>/case.db)
    #[arg(long)]
    db: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct IdentifyArgs {
    /// Path to raw disk image or block device
    #[arg(value_name = "IMAGE_PATH")]
    image_path: PathBuf,

    /// Directory containing .yaml format grammars (default: ../grammars)
    #[arg(long, default_value = "../grammars")]
    grammars_dir: PathBuf,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Directory containing acquisition manifest.json and case.db
    #[arg(value_name = "CASE_DIR")]
    case_dir: PathBuf,

    /// Custom path for SQLite case database (default: <CASE_DIR>/case.db)
    #[arg(long)]
    db: Option<PathBuf>,

    /// Output audit report as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct CarveArgs {
    /// Directory containing acquisition manifest.json and case.db
    #[arg(value_name = "CASE_DIR")]
    case_dir: PathBuf,

    /// Custom path for SQLite case database (default: <CASE_DIR>/case.db)
    #[arg(long)]
    db: Option<PathBuf>,

    /// Optional directory to export extracted raw video frames
    #[arg(short, long, value_name = "OUT_DIR")]
    out_dir: Option<PathBuf>,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct QueryArgs {
    /// Path to SQLite case database (e.g. case.db)
    #[arg(value_name = "CASE_DB")]
    db: PathBuf,

    /// Filter by camera channel ID
    #[arg(short, long)]
    channel: Option<u32>,

    /// Filter by start timestamp (epoch seconds)
    #[arg(long)]
    start: Option<u64>,

    /// Filter by end timestamp (epoch seconds)
    #[arg(long)]
    end: Option<u64>,

    /// Filter only keyframes (I-frames)
    #[arg(short, long)]
    keyframes: bool,

    /// Filter only scrambled blocks
    #[arg(long)]
    scrambled: bool,

    /// Filter only descrambled blocks
    #[arg(long)]
    descrambled: bool,

    /// Filter only corrupted blocks
    #[arg(long)]
    corrupted: bool,

    /// Query carved frames instead of standard timeline records
    #[arg(long)]
    carved: bool,

    /// Limit number of records returned (default: 50)
    #[arg(short, long, default_value_t = 50)]
    limit: usize,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct CorrelateArgs {
    /// Path to SQLite case database (e.g. case.db)
    #[arg(value_name = "CASE_DB")]
    db: PathBuf,

    /// Maximum time window in seconds for cross-camera activity transitions (default: 10)
    #[arg(short, long, default_value_t = 10)]
    window: i64,

    /// Minimum duration in seconds to trigger a global blackout anomaly (default: 15)
    #[arg(short, long, default_value_t = 15)]
    blackout_gap: i64,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// Directory containing acquisition manifest.json and case.db
    #[arg(value_name = "CASE_DIR")]
    case_dir: PathBuf,

    /// Custom path for SQLite case database (default: <CASE_DIR>/case.db)
    #[arg(long)]
    db: Option<PathBuf>,

    /// Minimum forensic relevance score to flag as investigative lead [0.0 - 1.0] (default: 0.50)
    #[arg(long, default_value_t = 0.50)]
    min_relevance: f64,

    /// Filter by minimum entity detection confidence [0.0 - 1.0] (default: 0.60)
    #[arg(long, default_value_t = 0.60)]
    min_confidence: f64,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct ReportArgs {
    /// Directory containing acquisition manifest.json and case.db
    #[arg(value_name = "CASE_DIR")]
    case_dir: PathBuf,

    /// Name of certifying forensic examiner
    #[arg(short, long, default_value = "Forensic Examiner")]
    examiner: String,

    /// Designation or rank of examiner
    #[arg(long, default_value = "Senior Digital Forensics Specialist")]
    designation: String,

    /// Law enforcement department or agency
    #[arg(long, default_value = "State Cyber Police / Forensic Science Laboratory")]
    agency: String,

    /// Official badge, registration, or ID number
    #[arg(long, default_value = "DF-2026-04")]
    badge: String,

    /// Official digital forensics laboratory
    #[arg(long, default_value = "Central Cyber Forensics Division")]
    lab: String,

    /// Custom path for SQLite case database (default: <CASE_DIR>/case.db)
    #[arg(long)]
    db: Option<PathBuf>,

    /// Custom output directory for reports, certificate, and clips (default: <CASE_DIR>/report)
    #[arg(short, long, value_name = "OUT_DIR")]
    out_dir: Option<PathBuf>,

    /// Output report summary as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Acquire(args) => run_acquire(args),
        Commands::Parse(args) => run_parse(args),
        Commands::Identify(args) => run_identify(args),
        Commands::Verify(args) => run_verify(args),
        Commands::Carve(args) => run_carve(args),
        Commands::Query(args) => run_query(args),
        Commands::Correlate(args) => run_correlate(args),
        Commands::Analyze(args) => run_analyze(args),
        Commands::Report(args) => run_report(args),
    }
}

fn run_identify(args: IdentifyArgs) -> Result<()> {
    let ident = identify::identify_device(&args.image_path, &args.grammars_dir)
        .with_context(|| format!("Failed identifying device for image: {}", args.image_path.display()))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&ident)?);
    } else {
        println!("============================================================");
        println!(" DVR Forensics Platform (Team Cyber 4) - Device Identification");
        println!("============================================================");
        println!("Evidence Path      : {}", args.image_path.display());
        println!("Grammars Dir       : {}", args.grammars_dir.display());
        println!("------------------------------------------------------------");
        print!("{}", ident.display_summary());
        println!("------------------------------------------------------------");
    }

    Ok(())
}

fn run_acquire(args: AcquireArgs) -> Result<()> {
    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Acquisition Engine");
    println!("============================================================");
    println!("Evidence Source : {}", args.image_path.display());
    println!("Case Identifier : {}", args.case);
    println!("Output Folder   : {}", args.output.display());
    println!("Block Size      : {} bytes", args.block_size);
    println!("------------------------------------------------------------");

    let start_time = Instant::now();

    let ident_val = if let Ok(ident) = identify::identify_device(&args.image_path, &args.grammars_dir) {
        serde_json::to_value(&ident).ok()
    } else {
        None
    };

    let (manifest, manifest_path) = acquire_evidence_with_options(
        &args.image_path,
        &args.case,
        &args.output,
        Some(args.block_size),
        ident_val,
    )
    .with_context(|| format!("Failed acquiring evidence from {}", args.image_path.display()))?;

    let elapsed = start_time.elapsed();

    println!("\n[+] Acquisition Finished Successfully in {:.2}s", elapsed.as_secs_f64());
    println!("  Total Streamed  : {} bytes ({:.2} MB)", manifest.total_bytes, manifest.total_bytes as f64 / (1024.0 * 1024.0));
    println!("  Blocks Hashed   : {}", manifest.block_count);
    println!("  SHA-256 (Image) : {}", manifest.whole_image_sha256);
    println!("  MD5 (Image)     : {}", manifest.whole_image_md5);
    println!("  Manifest Saved  : {}", manifest_path.display());
    println!("------------------------------------------------------------");
    println!("[OK] Evidence acquired bit-by-bit strictly read-only.");

    Ok(())
}

fn run_parse(args: ParseArgs) -> Result<()> {
    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Grammar Parser");
    println!("============================================================");
    println!("Case Directory: {}", args.case_dir.display());
    println!("Grammars Dir  : {}", args.grammars_dir.display());
    println!("------------------------------------------------------------");

    let start_time = Instant::now();

    let summary = parse_case(&args.case_dir, &args.grammars_dir, args.db)
        .with_context(|| format!("Failed parsing case at {}", args.case_dir.display()))?;

    let elapsed = start_time.elapsed();

    println!("\n[+] Structured Parsing Completed in {:.3}s", elapsed.as_secs_f64());
    println!("  Applied Grammar     : {} (ID: {})", summary.grammar_name, summary.grammar_id);
    println!("  Validation Provenance: TIER {}", summary.validation_tier);
    println!("  Total Blocks Parsed : {}", summary.total_blocks);
    println!("  Valid Video Frames  : {}", summary.valid_video_frames);
    println!("  Scrambled Blocks    : {}", summary.scrambled_blocks);
    println!("  Descrambled (WASM)  : {}", summary.descrambled_blocks);
    println!("  Corrupted / Zeroed  : {}", summary.corrupted_blocks);
    println!("  Channels Demuxed    : {}", summary.channel_streams.len());

    for (ch_id, stream) in &summary.channel_streams {
        println!(
            "    * Channel {:02}: {} frames | Time Range: {} - {} | Gaps: {}",
            ch_id,
            stream.total_blocks,
            stream.min_timestamp,
            stream.max_timestamp,
            stream.sequence_gaps.len()
        );
    }

    println!("  Case Database (WAL) : {}", summary.db_path.display());
    println!("------------------------------------------------------------");
    println!("[OK] Extraction successfully recorded to SQLite.");

    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let report = verify_case_integrity(&args.case_dir, args.db.as_deref())
        .with_context(|| format!("Failed verifying case integrity at {}", args.case_dir.display()))?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Forensic Integrity Audit");
    println!("============================================================");
    println!("Case Identifier : {}", report.case_name);
    println!("Evidence Path   : {}", report.evidence_path);
    println!("Audit Timestamp : {}", report.audit_timestamp);
    println!("------------------------------------------------------------");
    println!(
        "Whole Image SHA-256 : {} [{}]",
        report.actual_sha256,
        if report.whole_image_sha256_match { "MATCH" } else { "TAMPERED / MISMATCH" }
    );
    println!(
        "Whole Image MD5     : {} [{}]",
        report.actual_md5,
        if report.whole_image_md5_match { "MATCH" } else { "TAMPERED / MISMATCH" }
    );
    println!(
        "Per-Block BLAKE3    : {} / {} matched ({:.1}%)",
        report.matched_blocks,
        report.total_blocks,
        (report.matched_blocks as f64 / report.total_blocks as f64) * 100.0
    );

    if report.db_checked {
        println!(
            "Case DB Cross-Check : {} discrepancy(ies)",
            report.db_record_discrepancies.len()
        );
    }

    println!("------------------------------------------------------------");
    if report.is_pristine {
        println!("OVERALL STATUS      : [OK] PRISTINE / UNTAMPERED EVIDENCE");
    } else {
        println!("OVERALL STATUS      : [!] INTEGRITY ALERT - EVIDENCE ALTERED");
        for d in &report.block_discrepancies {
            println!(
                "  * Block {:04} (Byte Offset {}): Expected {}... Actual {}...",
                d.block_index,
                d.byte_offset,
                &d.expected_hash[..12],
                &d.actual_hash[..12]
            );
        }
        for d in &report.db_record_discrepancies {
            println!("  * DB Block {:04} (Byte Offset {}): {}", d.block_index, d.byte_offset, d.issue);
        }
    }
    println!("------------------------------------------------------------");

    Ok(())
}

fn run_carve(args: CarveArgs) -> Result<()> {
    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Deep Video Carving");
    println!("============================================================");
    println!("Case Directory: {}", args.case_dir.display());

    let manifest_path = args.case_dir.join("manifest.json");
    if !manifest_path.exists() {
        anyhow::bail!("Manifest not found at {}", manifest_path.display());
    }

    let manifest_file = File::open(&manifest_path)?;
    let manifest: acquisition::AcquisitionManifest = serde_json::from_reader(manifest_file)?;

    // Resolve evidence path
    let mut evidence_path = PathBuf::from(&manifest.source_path);
    if !evidence_path.exists() {
        let file_name = Path::new(&manifest.source_path).file_name();
        let candidate_paths = vec![
            args.case_dir.join(&manifest.source_path),
            args.case_dir.parent().map(|p| p.join(&manifest.source_path)).unwrap_or_default(),
            file_name.map(|f| args.case_dir.join(f)).unwrap_or_default(),
            file_name.and_then(|f| args.case_dir.parent().map(|p| p.join(f))).unwrap_or_default(),
        ];
        for cand in candidate_paths {
            if cand.exists() {
                evidence_path = cand;
                break;
            }
        }
    }

    println!("Evidence Source: {}", evidence_path.display());

    let db_path = args.db.unwrap_or_else(|| args.case_dir.join("case.db"));
    let mut db = CaseDatabase::open(&db_path)?;

    // Query corrupted or unallocated blocks to carve
    let corrupted_records = db.query_records(&RecordFilter {
        corrupted_only: true,
        ..Default::default()
    })?;

    let target_blocks: Vec<usize> = if !corrupted_records.is_empty() {
        corrupted_records.iter().map(|r| r.block_index).collect()
    } else {
        // Fallback: scan whole image in block increments
        (0..manifest.block_count).collect()
    };

    println!("Scanning {} target block(s) for video bitstreams...", target_blocks.len());

    let carved = recovery::carve_corrupted_blocks(&evidence_path, manifest.block_size, &target_blocks)
        .with_context(|| "Failed executing video carving")?;

    let primary_evidence_id = db.get_primary_evidence_id()?.unwrap_or(1);
    let stored_count = db.store_carved_records(primary_evidence_id, &carved)?;

    if let Some(ref out_dir) = args.out_dir {
        std::fs::create_dir_all(out_dir)?;
        let mut f = File::open(&evidence_path)?;
        for (i, frame) in carved.iter().enumerate() {
            use std::io::{Read, Seek, SeekFrom};
            f.seek(SeekFrom::Start(frame.byte_offset))?;
            let mut buf = vec![0u8; frame.length];
            f.read_exact(&mut buf)?;

            let out_file = out_dir.join(format!("carved_frame_{:04}_{}.h264", i, if frame.is_keyframe { "key" } else { "slice" }));
            let mut out = File::create(out_file)?;
            out.write_all(&buf)?;
        }
        println!("[+] Exported {} raw frame bitstreams to {}", carved.len(), out_dir.display());
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&carved)?);
    } else {
        println!("\n[+] Deep Carving Completed");
        println!("  Carved Video Frames : {}", carved.len());
        println!("  Keyframes (I-frames): {}", carved.iter().filter(|f| f.is_keyframe).count());
        println!("  Non-IDR Slices      : {}", carved.iter().filter(|f| !f.is_keyframe).count());
        println!("  Recorded in DB      : {} entries in `carved_records`", stored_count);
        println!("------------------------------------------------------------");
    }

    Ok(())
}

fn run_query(args: QueryArgs) -> Result<()> {
    let db = CaseDatabase::open(&args.db)
        .with_context(|| format!("Failed opening SQLite database at {}", args.db.display()))?;

    if args.carved {
        let carved = db.query_carved_records(None)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&carved)?);
        } else {
            println!("============================================================");
            println!(" DVR Forensics Platform (Team Cyber 4) - Carved Records Query");
            println!("============================================================");
            println!("Database: {}", args.db.display());
            println!("Total Carved Frames Found: {}", carved.len());
            println!("------------------------------------------------------------");
            println!("{:<10} {:<10} {:<32} {:<10} {:<12}", "OFFSET", "LENGTH", "NAL TYPE", "KEYFRAME", "CONFIDENCE");
            println!("{:-<78}", "");
            for f in carved.iter().take(args.limit) {
                println!(
                    "{:<10} {:<10} {:<32} {:<10} {:<12.1}%",
                    f.byte_offset,
                    f.length,
                    f.nal_type,
                    if f.is_keyframe { "YES" } else { "NO" },
                    f.confidence * 100.0
                );
            }
            if carved.len() > args.limit {
                println!("... ({} more records truncated, increase --limit)", carved.len() - args.limit);
            }
        }
        return Ok(());
    }

    let filter = RecordFilter {
        channel_id: args.channel,
        start_timestamp: args.start,
        end_timestamp: args.end,
        keyframes_only: args.keyframes,
        scrambled_only: args.scrambled,
        descrambled_only: args.descrambled,
        corrupted_only: args.corrupted,
        limit: Some(args.limit),
        offset: None,
    };

    let records = db.query_records(&filter)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else {
        println!("============================================================");
        println!(" DVR Forensics Platform (Team Cyber 4) - Case Database Query");
        println!("============================================================");
        println!("Database: {}", args.db.display());
        println!("Matching Records Found: {}", records.len());
        println!("------------------------------------------------------------");
        println!("{:<6} {:<10} {:<4} {:<22} {:<6} {:<12} {:<12}", "BLOCK", "OFFSET", "CH", "TIMESTAMP (UTC)", "SEQ", "SCRAMBLED", "STATUS");
        println!("{:-<78}", "");
        for r in &records {
            let status = if r.is_corrupted {
                "CORRUPTED"
            } else if r.descrambled {
                "DESCRAMBLED"
            } else if r.is_scrambled {
                "SCRAMBLED"
            } else {
                "VALID"
            };

            println!(
                "{:<6} {:<10} {:<4} {:<22} {:<6} {:<12} {:<12}",
                r.block_index,
                r.byte_offset,
                r.channel_id,
                r.normalized_timestamp,
                r.sequence_num,
                if r.is_scrambled { "YES" } else { "NO" },
                status
            );
        }
        println!("------------------------------------------------------------");
    }

    Ok(())
}

fn run_correlate(args: CorrelateArgs) -> Result<()> {
    let mut db = CaseDatabase::open(&args.db)
        .with_context(|| format!("Failed opening SQLite database at {}", args.db.display()))?;

    let records = db.query_all_records()?;
    let record_inputs: Vec<correlation::RecordInput> = records.iter().map(|r| r.to_correlation_input()).collect();

    let report = correlation::generate_correlation_report(&record_inputs, args.window, args.blackout_gap);

    // Save detected transitions and anomalies into database
    let primary_evidence_id = db.get_primary_evidence_id()?.unwrap_or(1);
    let mut db_events = Vec::new();

    for t in &report.transitions {
        db_events.push(parser::CorrelatedDbEvent {
            id: None,
            event_type: "transition".to_string(),
            start_timestamp: t.from_normalized_ts.clone(),
            end_timestamp: t.to_normalized_ts.clone(),
            channels_involved: format!("{},{}", t.from_channel, t.to_channel),
            confidence: t.confidence,
            details_json: serde_json::to_string(t).unwrap_or_default(),
        });
    }

    for b in &report.blackouts {
        db_events.push(parser::CorrelatedDbEvent {
            id: None,
            event_type: "global_blackout".to_string(),
            start_timestamp: b.start_normalized_ts.clone(),
            end_timestamp: b.end_normalized_ts.clone(),
            channels_involved: b.affected_channels.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
            confidence: 0.99,
            details_json: serde_json::to_string(b).unwrap_or_default(),
        });
    }

    let _ = db.store_correlated_events(primary_evidence_id, &db_events);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("============================================================");
        println!(" DVR Forensics Platform (Team Cyber 4) - Cross-Camera Correlation");
        println!("============================================================");
        println!("Database: {}", args.db.display());
        println!("Total Analyzed Records: {}", report.total_records);
        println!("Active Camera Channels: {:?}", report.active_channels);
        println!("Global Time Range     : {} -> {}", report.min_normalized_ts, report.max_normalized_ts);
        println!("------------------------------------------------------------");

        println!("[+] Cross-Camera Transitions Identified (Window: <= {}s): {}", args.window, report.transitions.len());
        if !report.transitions.is_empty() {
            println!("{:<14} {:<24} {:<24} {:<8} {:<10}", "CAMERA ROUTE", "DEPARTURE (UTC)", "ARRIVAL (UTC)", "DELTA", "CONFIDENCE");
            println!("{:-<84}", "");
            for t in report.transitions.iter().take(20) {
                println!(
                    "CH {:02} -> CH {:02}   {:<24} {:<24} {:<8} {:<10.1}%",
                    t.from_channel,
                    t.to_channel,
                    t.from_normalized_ts,
                    t.to_normalized_ts,
                    format!("+{}s", t.delta_secs),
                    t.confidence * 100.0
                );
            }
            if report.transitions.len() > 20 {
                println!("... ({} more transitions truncated)", report.transitions.len() - 20);
            }
        }

        println!("\n[+] Global Anomalies & Blackouts Detected (Gap: >= {}s): {}", args.blackout_gap, report.blackouts.len());
        if !report.blackouts.is_empty() {
            for (idx, b) in report.blackouts.iter().enumerate() {
                println!(
                    "  [{}] Severity: {} | Duration: {}s | Interval: {} -> {}",
                    idx + 1,
                    b.severity,
                    b.duration_secs,
                    b.start_normalized_ts,
                    b.end_normalized_ts
                );
                println!("      Channels: {:?} | {}", b.affected_channels, b.description);
            }
        } else {
            println!("  [OK] Continuous recording verified. No simultaneous multi-camera blackouts detected.");
        }
        println!("------------------------------------------------------------");
    }

    Ok(())
}

fn run_analyze(args: AnalyzeArgs) -> Result<()> {
    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - AI Video Analytics");
    println!("============================================================");
    println!("Case Directory: {}", args.case_dir.display());

    let manifest_path = args.case_dir.join("manifest.json");
    if !manifest_path.exists() {
        anyhow::bail!("Manifest not found at {}", manifest_path.display());
    }

    let manifest_file = File::open(&manifest_path)?;
    let manifest: acquisition::AcquisitionManifest = serde_json::from_reader(manifest_file)?;

    // Resolve evidence path
    let mut evidence_path = PathBuf::from(&manifest.source_path);
    if !evidence_path.exists() {
        let file_name = Path::new(&manifest.source_path).file_name();
        let candidate_paths = vec![
            args.case_dir.join(&manifest.source_path),
            args.case_dir.parent().map(|p| p.join(&manifest.source_path)).unwrap_or_default(),
            file_name.map(|f| args.case_dir.join(f)).unwrap_or_default(),
            file_name.and_then(|f| args.case_dir.parent().map(|p| p.join(f))).unwrap_or_default(),
        ];
        for cand in candidate_paths {
            if cand.exists() {
                evidence_path = cand;
                break;
            }
        }
    }

    println!("Evidence Source: {}", evidence_path.display());

    let db_path = args.db.unwrap_or_else(|| args.case_dir.join("case.db"));
    let mut db = CaseDatabase::open(&db_path)?;

    let records = db.query_all_records()?;
    let primary_evidence_id = db.get_primary_evidence_id()?.unwrap_or(1);

    println!("Analyzing {} video records for motion, entities, and forensic relevance...", records.len());

    use std::io::{Read, Seek, SeekFrom};
    let mut evidence_file = File::open(&evidence_path)
        .with_context(|| format!("Failed opening evidence file at {}", evidence_path.display()))?;

    let mut frame_analyses = Vec::new();
    let mut db_detections = Vec::new();

    for record in &records {
        if record.payload_len == 0 {
            continue;
        }

        let mut payload = vec![0u8; record.payload_len];
        if evidence_file.seek(SeekFrom::Start(record.payload_offset)).is_ok()
            && evidence_file.read_exact(&mut payload).is_ok()
        {
            let is_keyframe = (record.flags & 1) != 0;
            let analysis = analytics::analyze_frame(
                record.block_index,
                record.channel_id,
                record.timestamp,
                &record.normalized_timestamp,
                &payload,
                is_keyframe,
            );

            for det in &analysis.entities {
                let bbox_json = serde_json::to_string(&det.bbox).unwrap_or_default();
                let attrs_json = serde_json::to_string(&det.attributes).unwrap_or_default();

                db_detections.push(parser::AnalyticsDbDetection {
                    id: None,
                    block_index: record.block_index,
                    channel_id: record.channel_id,
                    timestamp: record.timestamp,
                    normalized_timestamp: record.normalized_timestamp.clone(),
                    motion_energy: analysis.motion_energy,
                    relevance_score: analysis.relevance_score,
                    entity_class: det.class_label.code().to_string(),
                    confidence: det.confidence,
                    bbox_json,
                    attributes_json: attrs_json,
                });
            }

            frame_analyses.push(analysis);
        }
    }

    // Persist detections to SQLite
    let stored_count = db.store_analytics_detections(primary_evidence_id, &db_detections)?;
    let summary = analytics::summarize_analytics(frame_analyses, args.min_relevance, 20);

    if args.json {
        let output = serde_json::json!({
            "summary": summary,
            "leads": summary.top_leads,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\n[+] AI Video Analytics Completed");
        println!("  Frames Analyzed       : {}", summary.total_frames_analyzed);
        println!("  Total Detections      : {}", summary.total_entities_detected);
        println!("  High Relevance Frames : {}", summary.high_relevance_frames);
        println!("  Class Breakdown       : Persons: {}, Vehicles: {}, Faces: {}, Motion Clusters: {}",
            summary.entity_counts.get("person").unwrap_or(&0),
            summary.entity_counts.get("vehicle").unwrap_or(&0),
            summary.entity_counts.get("face").unwrap_or(&0),
            summary.entity_counts.get("motion_cluster").unwrap_or(&0),
        );
        println!("  Detections Stored in DB: {} entries in `analytics_detections`", stored_count);
        println!("------------------------------------------------------------");

        println!("[+] Prioritized Investigative Leads (Relevance >= {:.2}): {}", args.min_relevance, summary.top_leads.len());
        if !summary.top_leads.is_empty() {
            println!("{:<6} {:<4} {:<24} {:<10} {:<12} {:<20}", "BLOCK", "CH", "TIMESTAMP (UTC)", "MOTION", "RELEVANCE", "DETECTIONS");
            println!("{:-<94}", "");
            for lead in &summary.top_leads {
                let det_str = lead.entities.iter()
                    .map(|d| format!("{} ({:.0}%)", d.class_label.code(), d.confidence * 100.0))
                    .collect::<Vec<_>>()
                    .join(", ");

                println!(
                    "{:<6} {:<4} {:<24} {:<10.4} {:<12.4} {:<20}",
                    lead.block_index,
                    lead.channel_id,
                    lead.normalized_timestamp,
                    lead.motion_energy,
                    lead.relevance_score,
                    if det_str.is_empty() { "Motion Only".to_string() } else { det_str }
                );
            }
        } else {
            println!("  [OK] No high-priority anomalies detected above threshold {:.2}.", args.min_relevance);
        }
        println!("------------------------------------------------------------");
    }

    Ok(())
}

fn run_report(args: ReportArgs) -> Result<()> {
    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Forensic Report & Cert");
    println!("============================================================");
    println!("Case Directory: {}", args.case_dir.display());

    let examiner = reporting::ExaminerDetails {
        name: args.examiner,
        designation: args.designation,
        agency: args.agency,
        badge_number: args.badge,
        laboratory: args.lab,
    };

    let outcome = reporting::generate_case_report(
        &args.case_dir,
        args.db.as_deref(),
        examiner,
        args.out_dir.as_deref(),
    )?;

    if args.json {
        let out_json = serde_json::json!({
            "report": outcome.report,
            "certificate_pdf": outcome.certificate_path,
            "forensic_report_md": outcome.markdown_path,
            "forensic_report_json": outcome.json_path,
            "export_summary": outcome.export_summary,
        });
        println!("{}", serde_json::to_string_pretty(&out_json)?);
    } else {
        println!("\n[+] Forensic Examination Report Generated Successfully");
        println!("  Case Identifier       : {}", outcome.report.case_name);
        println!("  Identified Format     : {} ({:.1}% confidence)", outcome.report.identified_format, outcome.report.confidence * 100.0);
        println!("  Validation Tier       : Tier {} ({})", outcome.report.validation_tier, outcome.report.validation_tier_disclosure);
        println!("  Triple Hashes (Pristine):");
        println!("    * MD5    : {}", outcome.report.md5_hash);
        println!("    * SHA-256: {}", outcome.report.sha256_hash);
        println!("    * BLAKE3 : {}", outcome.report.blake3_hash);
        println!("  Extracted Records     : {}", outcome.report.extracted_records_count);
        println!("  Carved Video Frames   : {}", outcome.report.carved_frames_count);
        println!("  Correlated Events     : {}", outcome.report.transitions_count);
        println!("  AI Analytics Leads    : {}", outcome.report.analytics_leads_count);
        println!("  Timeline Gaps/Alerts  : {}", outcome.report.discontinuities.len());
        println!("------------------------------------------------------------");
        println!("[+] Generated Deliverables:");
        println!("  * Legal Certificate PDF : {}", outcome.certificate_path.display());
        println!("    (Formulated under Section 63, Bharatiya Sakshya Adhiniyam, 2023)");
        println!("  * Full Forensic Report  : {}", outcome.markdown_path.display());
        println!("  * Structural JSON Data  : {}", outcome.json_path.display());
        println!("  * Video Clips Export    : {} raw .h264, {} .mp4 in {}",
            outcome.export_summary.raw_h264_exported,
            outcome.export_summary.mp4_transcoded,
            outcome.export_summary.output_dir.display()
        );
        if !outcome.export_summary.ffmpeg_available {
            println!("    [Notice] ffmpeg not detected in PATH; raw H.264 streams preserved.");
        }
        println!("------------------------------------------------------------");
    }

    Ok(())
}
