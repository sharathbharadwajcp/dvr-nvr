use crate::error::{AcquisitionError, Result};
use crate::source::ReadOnlySource;
use md5::Md5;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::io::Read;

/// Default block size for forensic acquisition (4 KiB).
pub const DEFAULT_BLOCK_SIZE: usize = 4096;

/// Number of blocks processed in a parallel hashing batch.
/// 64 * 4 KiB = 256 KiB batch in flight, ensuring strictly bounded RAM usage.
pub const DEFAULT_BATCH_BLOCKS: usize = 64;

/// Detailed record of an individual acquired block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredBlock {
    pub index: usize,
    pub offset: u64,
    pub size: usize,
    pub blake3_hash: String,
    pub md5_hash: String,
}

/// Aggregated result of streaming acquisition.
#[derive(Debug, Clone)]
pub struct AcquisitionResult {
    pub total_bytes: u64,
    pub block_size: usize,
    pub block_count: usize,
    pub whole_image_sha256: String,
    pub whole_image_md5: String,
    pub block_hashes: Vec<String>,
    pub block_hashes_md5: Vec<String>,
}

/// Options to configure the streaming acquisition process.
#[derive(Debug, Clone)]
pub struct StreamOptions {
    pub block_size: usize,
    pub batch_size: usize,
}

impl Default for StreamOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            batch_size: DEFAULT_BATCH_BLOCKS,
        }
    }
}

/// Streams an evidence source in fixed-size blocks, computing a sequential SHA-256
/// of the whole image and parallel BLAKE3 hashes for every block.
///
/// Multi-threaded I/O & computation guarantees:
/// 1. Only a small, bounded batch of blocks resides in memory at any point.
/// 2. SHA-256 digest is updated in strict streaming order.
/// 3. BLAKE3 hashing is parallelized over worker threads using Rayon.
/// 4. Every block's hash is recorded before downstream usage.
pub fn stream_and_hash(
    mut source: ReadOnlySource,
    options: StreamOptions,
) -> Result<AcquisitionResult> {
    if options.block_size == 0 {
        return Err(AcquisitionError::InvalidBlockSize(0));
    }

    let block_size = options.block_size;
    let batch_size = if options.batch_size == 0 {
        DEFAULT_BATCH_BLOCKS
    } else {
        options.batch_size
    };

    let mut sha256_hasher = Sha256::new();
    let mut md5_hasher = Md5::new();
    let mut all_block_hashes = Vec::new();
    let mut all_block_hashes_md5 = Vec::new();

    let mut total_bytes: u64 = 0;
    let mut current_offset: u64 = 0;

    // Allocate reusable buffer for a batch: batch_size * block_size
    let batch_capacity = batch_size * block_size;
    let mut raw_buffer = vec![0u8; batch_capacity];

    loop {
        // Read up to batch_capacity bytes from the strictly read-only source
        let mut bytes_in_batch = 0;
        while bytes_in_batch < batch_capacity {
            let n = source
                .read(&mut raw_buffer[bytes_in_batch..])
                .map_err(|e| AcquisitionError::ReadError {
                    path: source.path().to_path_buf(),
                    offset: current_offset + bytes_in_batch as u64,
                    source: e,
                })?;

            if n == 0 {
                // End of file / stream reached
                break;
            }
            bytes_in_batch += n;
        }

        if bytes_in_batch == 0 {
            // EOF reached without reading further data
            break;
        }

        // Slice batch into individual blocks
        let valid_data = &raw_buffer[..bytes_in_batch];
        let chunks: Vec<&[u8]> = valid_data.chunks(block_size).collect();

        // 1. Update whole-image SHA-256 and MD5 in strict sequential order
        for chunk in &chunks {
            sha256_hasher.update(chunk);
            md5_hasher.update(chunk);
        }

        // 2. Parallel BLAKE3 and MD5 computation across Rayon worker threads
        let batch_hashes: Vec<(String, String)> = chunks
            .par_iter()
            .map(|chunk| {
                let b3 = blake3::hash(chunk).to_hex().to_string();
                let md5_val = hex::encode(Md5::digest(chunk));
                (b3, md5_val)
            })
            .collect();

        for (b3, m5) in batch_hashes {
            all_block_hashes.push(b3);
            all_block_hashes_md5.push(m5);
        }

        total_bytes += bytes_in_batch as u64;
        current_offset += bytes_in_batch as u64;
        let _ = chunks.len();

        if bytes_in_batch < batch_capacity {
            // Reached EOF on partial batch
            break;
        }
    }

    let whole_image_sha256 = hex::encode(sha256_hasher.finalize());
    let whole_image_md5 = hex::encode(md5_hasher.finalize());

    Ok(AcquisitionResult {
        total_bytes,
        block_size,
        block_count: all_block_hashes.len(),
        whole_image_sha256,
        whole_image_md5,
        block_hashes: all_block_hashes,
        block_hashes_md5: all_block_hashes_md5,
    })
}
