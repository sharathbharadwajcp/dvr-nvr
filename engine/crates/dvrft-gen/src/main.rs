use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

pub const BLOCK_SIZE: usize = 4096;
pub const HEADER_SIZE: usize = 32;
pub const PAYLOAD_SIZE: usize = BLOCK_SIZE - HEADER_SIZE; // 4064 bytes

pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"C4DVR\x00\x01\x00";
pub const PARTITION_MAGIC: &[u8; 4] = b"C4PT";
pub const VIDEO_BLOCK_MAGIC: &[u8; 4] = b"C4VF";

pub const XOR_SCRAMBLE_KEY: [u8; 4] = [0xD4, 0xA8, 0x7E, 0x31];

// Flag bits
pub const FLAG_KEYFRAME: u16 = 0x0001;
pub const FLAG_SCRAMBLED: u16 = 0x0002;
pub const FLAG_CORRUPTED: u16 = 0x0004;

#[derive(Parser, Debug)]
#[command(
    name = "dvrft-gen",
    author = "Team Cyber 4",
    version = "0.1.0",
    about = "Generates synthetic vendor-like DVR disk images and ground-truth metadata"
)]
struct Args {
    /// Output raw disk image path
    #[arg(short, long, default_value = "../samples/synthetic_disk.img")]
    output: PathBuf,

    /// Output ground-truth JSON path
    #[arg(short, long, default_value = "../samples/synthetic_disk.truth.json")]
    truth: PathBuf,

    /// Total number of 4096-byte blocks to generate (min 32)
    #[arg(short, long, default_value_t = 64)]
    blocks: usize,

    /// Base Unix timestamp for video streams
    #[arg(long, default_value_t = 1773800000)]
    base_timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroundTruth {
    format_tier: String,
    specification_file: String,
    image_metadata: ImageMetadata,
    channels: Vec<ChannelMetadata>,
    blocks: Vec<BlockGroundTruth>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImageMetadata {
    filename: String,
    total_bytes: u64,
    block_size: usize,
    total_blocks: usize,
    whole_image_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChannelMetadata {
    channel_id: u32,
    channel_name: String,
    start_block: u32,
    block_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockGroundTruth {
    block_index: usize,
    offset: u64,
    channel_id: u32,
    timestamp: u64,
    sequence_num: u32,
    payload_len: usize,
    is_scrambled: bool,
    xor_key: Option<String>,
    is_corrupted: bool,
    corruption_type: Option<String>,
    original_payload_blake3: String,
    disk_block_blake3: String,
}

fn compute_header_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Generates deterministic pseudo-random payload bytes seeded by channel and sequence.
fn generate_deterministic_payload(channel_id: u32, seq: u32, is_keyframe: bool) -> Vec<u8> {
    let mut payload = vec![0u8; PAYLOAD_SIZE];

    // Video NAL start code simulation:
    // 00 00 00 01 followed by NAL type (0x67 for SPS/I-frame, 0x41 for non-IDR/P-frame)
    payload[0] = 0x00;
    payload[1] = 0x00;
    payload[2] = 0x00;
    payload[3] = 0x01;
    payload[4] = if is_keyframe { 0x67 } else { 0x41 };

    // Linear Congruential PRNG seed
    let seq_term = (seq as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let mut state: u64 = ((channel_id as u64) << 32) ^ seq_term;

    for i in 5..PAYLOAD_SIZE {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        payload[i] = ((state >> 33) & 0xFF) as u8;
    }

    payload
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.blocks < 32 {
        anyhow::bail!("Minimum block count is 32 to host filesystem, partitions, and test regions.");
    }

    println!("============================================================");
    println!(" DVR Forensics Platform (Team Cyber 4) - Synthetic Disk Gen");
    println!("============================================================");
    println!("Output Image : {}", args.output.display());
    println!("Output Truth : {}", args.truth.display());
    println!("Total Blocks : {} ({} bytes)", args.blocks, args.blocks * BLOCK_SIZE);
    println!("Specification: docs/synthetic-format-spec.md (TIER 1)");
    println!("------------------------------------------------------------");

    let total_bytes = args.blocks * BLOCK_SIZE;
    let mut disk_data = Vec::with_capacity(total_bytes);
    let mut truth_blocks = Vec::with_capacity(args.blocks);

    // =========================================================================
    // Block 0: Superblock
    // =========================================================================
    let mut block0 = vec![0u8; BLOCK_SIZE];
    block0[0..8].copy_from_slice(SUPERBLOCK_MAGIC);
    block0[8..12].copy_from_slice(&1u32.to_le_bytes()); // version = 1
    block0[12..16].copy_from_slice(&(BLOCK_SIZE as u32).to_le_bytes()); // block_size = 4096
    block0[16..20].copy_from_slice(&(args.blocks as u32).to_le_bytes()); // total_blocks
    block0[20..28].copy_from_slice(&(BLOCK_SIZE as u64).to_le_bytes()); // partition_table_offset = 4096
    block0[28..32].copy_from_slice(&2u32.to_le_bytes()); // partition_count = 2
    block0[32..40].copy_from_slice(&args.base_timestamp.to_le_bytes()); // created_timestamp
    block0[40..44].copy_from_slice(&0u32.to_le_bytes()); // flags = 0
    disk_data.extend_from_slice(&block0);

    truth_blocks.push(BlockGroundTruth {
        block_index: 0,
        offset: 0,
        channel_id: 0,
        timestamp: args.base_timestamp,
        sequence_num: 0,
        payload_len: 0,
        is_scrambled: false,
        xor_key: None,
        is_corrupted: false,
        corruption_type: None,
        original_payload_blake3: "".to_string(),
        disk_block_blake3: blake3::hash(&block0).to_hex().to_string(),
    });

    // =========================================================================
    // Block 1: Partition Table
    // =========================================================================
    let mut block1 = vec![0u8; BLOCK_SIZE];
    block1[0..4].copy_from_slice(PARTITION_MAGIC);
    block1[4..8].copy_from_slice(&2u32.to_le_bytes()); // 2 active entries

    // Entry 0: Channel 1 (Channel A)
    let p1_offset = 16;
    block1[p1_offset..p1_offset + 4].copy_from_slice(&1u32.to_le_bytes());
    block1[p1_offset + 4..p1_offset + 12].copy_from_slice(b"CH_01_A\x00");
    block1[p1_offset + 12..p1_offset + 16].copy_from_slice(&2u32.to_le_bytes()); // start block = 2
    let stream_blocks = ((args.blocks - 2) / 2) as u32;
    block1[p1_offset + 16..p1_offset + 20].copy_from_slice(&stream_blocks.to_le_bytes());
    block1[p1_offset + 20..p1_offset + 24].copy_from_slice(&1u32.to_le_bytes()); // Active

    // Entry 1: Channel 2 (Channel B)
    let p2_offset = 48;
    block1[p2_offset..p2_offset + 4].copy_from_slice(&2u32.to_le_bytes());
    block1[p2_offset + 4..p2_offset + 12].copy_from_slice(b"CH_02_B\x00");
    block1[p2_offset + 12..p2_offset + 16].copy_from_slice(&2u32.to_le_bytes());
    block1[p2_offset + 16..p2_offset + 20].copy_from_slice(&stream_blocks.to_le_bytes());
    block1[p2_offset + 20..p2_offset + 24].copy_from_slice(&1u32.to_le_bytes());

    disk_data.extend_from_slice(&block1);

    truth_blocks.push(BlockGroundTruth {
        block_index: 1,
        offset: BLOCK_SIZE as u64,
        channel_id: 0,
        timestamp: args.base_timestamp,
        sequence_num: 0,
        payload_len: 0,
        is_scrambled: false,
        xor_key: None,
        is_corrupted: false,
        corruption_type: None,
        original_payload_blake3: "".to_string(),
        disk_block_blake3: blake3::hash(&block1).to_hex().to_string(),
    });

    // =========================================================================
    // Blocks 2..N: Interleaved Video Streams (Channel A & Channel B)
    // =========================================================================
    let mut seq_ch1: u32 = 0;
    let mut seq_ch2: u32 = 0;

    for b in 2..args.blocks {
        let block_offset = (b * BLOCK_SIZE) as u64;

        // Alternate channels: even blocks = Channel 1 (A), odd blocks = Channel 2 (B)
        let (channel_id, seq) = if b % 2 == 0 {
            seq_ch1 += 1;
            (1u32, seq_ch1)
        } else {
            seq_ch2 += 1;
            (2u32, seq_ch2)
        };

        let timestamp = args.base_timestamp + (b as u64 * 2);
        let is_keyframe = (seq % 10) == 1;

        // Check if this block falls into special test regions:
        // 1. Scrambled region: blocks 10..14
        let is_scrambled = (10..=13).contains(&b);

        // 2. Corrupted header region: blocks 22..23
        let is_corrupted = (22..=23).contains(&b);

        let mut flags: u16 = 0;
        if is_keyframe {
            flags |= FLAG_KEYFRAME;
        }
        if is_scrambled {
            flags |= FLAG_SCRAMBLED;
        }
        if is_corrupted {
            flags |= FLAG_CORRUPTED;
        }

        // Generate original deterministic video payload
        let original_payload = generate_deterministic_payload(channel_id, seq, is_keyframe);
        let original_payload_hash = blake3::hash(&original_payload).to_hex().to_string();

        let mut payload = original_payload.clone();

        // Apply XOR scrambling if flagged
        if is_scrambled {
            for (idx, byte) in payload.iter_mut().enumerate() {
                *byte ^= XOR_SCRAMBLE_KEY[idx % XOR_SCRAMBLE_KEY.len()];
            }
        }

        let mut block = vec![0u8; BLOCK_SIZE];

        // Construct 32-byte header
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(VIDEO_BLOCK_MAGIC);
        header[4..8].copy_from_slice(&channel_id.to_le_bytes());
        header[8..16].copy_from_slice(&timestamp.to_le_bytes());
        header[16..20].copy_from_slice(&seq.to_le_bytes());
        header[20..24].copy_from_slice(&(PAYLOAD_SIZE as u32).to_le_bytes());
        header[24..26].copy_from_slice(&flags.to_le_bytes());

        let crc = compute_header_crc(&header[0..26]);
        header[26..28].copy_from_slice(&crc.to_le_bytes());
        // header[28..32] is reserved (0x00)

        // Apply corruption if designated: zero out header completely
        if is_corrupted {
            header = [0u8; HEADER_SIZE];
        }

        block[0..HEADER_SIZE].copy_from_slice(&header);
        block[HEADER_SIZE..BLOCK_SIZE].copy_from_slice(&payload);

        let disk_hash = blake3::hash(&block).to_hex().to_string();
        disk_data.extend_from_slice(&block);

        truth_blocks.push(BlockGroundTruth {
            block_index: b,
            offset: block_offset,
            channel_id,
            timestamp,
            sequence_num: seq,
            payload_len: PAYLOAD_SIZE,
            is_scrambled,
            xor_key: if is_scrambled {
                Some(hex::encode(XOR_SCRAMBLE_KEY).to_uppercase())
            } else {
                None
            },
            is_corrupted,
            corruption_type: if is_corrupted {
                Some("zeroed_header_unallocated_test".to_string())
            } else {
                None
            },
            original_payload_blake3: original_payload_hash,
            disk_block_blake3: disk_hash,
        });
    }

    // Compute whole image SHA-256
    let whole_image_sha256 = hex::encode(Sha256::digest(&disk_data));

    // Ensure output directories exist
    if let Some(parent) = args.output.parent() {
        create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    if let Some(parent) = args.truth.parent() {
        create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    // Write raw disk image
    let mut out_file = File::create(&args.output)
        .with_context(|| format!("Failed to create output disk image: {}", args.output.display()))?;
    out_file
        .write_all(&disk_data)
        .with_context(|| format!("Failed to write disk data to {}", args.output.display()))?;

    // Build GroundTruth structure
    let truth = GroundTruth {
        format_tier: "TIER 1 (Synthetic Ground Truth)".to_string(),
        specification_file: "docs/synthetic-format-spec.md".to_string(),
        image_metadata: ImageMetadata {
            filename: args
                .output
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            total_bytes: disk_data.len() as u64,
            block_size: BLOCK_SIZE,
            total_blocks: args.blocks,
            whole_image_sha256: whole_image_sha256.clone(),
        },
        channels: vec![
            ChannelMetadata {
                channel_id: 1,
                channel_name: "CH_01_A".to_string(),
                start_block: 2,
                block_count: stream_blocks,
            },
            ChannelMetadata {
                channel_id: 2,
                channel_name: "CH_02_B".to_string(),
                start_block: 2,
                block_count: stream_blocks,
            },
        ],
        blocks: truth_blocks,
    };

    let truth_json = serde_json::to_string_pretty(&truth)
        .context("Failed to serialize ground-truth JSON")?;
    let mut truth_file = File::create(&args.truth)
        .with_context(|| format!("Failed to create ground-truth file: {}", args.truth.display()))?;
    truth_file
        .write_all(truth_json.as_bytes())
        .with_context(|| format!("Failed to write ground-truth to {}", args.truth.display()))?;

    println!("[+] Synthetic Disk Image successfully generated!");
    println!("  Image Path          : {}", args.output.display());
    println!("  Ground Truth Path   : {}", args.truth.display());
    println!("  Image SHA-256       : {}", whole_image_sha256);
    println!("  Scrambled Region    : Blocks 10..13 (Key: 0xD4A87E31)");
    println!("  Corrupted Headers   : Blocks 22..23 (Zeroed header, intact video payload)");
    println!("------------------------------------------------------------");
    println!("[OK] Ready for grammar AST parsing, WASM descrambler, and carving tests.");

    Ok(())
}
