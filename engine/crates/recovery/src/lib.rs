use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("I/O error during carving: {0}")]
    Io(#[from] std::io::Error),
    #[error("Corrupted range invalid: start {start}, length {len}")]
    InvalidRange { start: u64, len: u64 },
}

pub type Result<T> = std::result::Result<T, RecoveryError>;

/// Represents a carved video frame or NAL unit recovered from raw unallocated or corrupted space.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CarvedFrame {
    /// Byte offset within the target evidence image
    pub byte_offset: u64,
    /// Length in bytes of the carved frame payload
    pub length: usize,
    /// Classified NAL unit or frame type
    pub nal_type: String,
    /// Whether the frame is an intra / keyframe (e.g., SPS / PPS / IDR)
    pub is_keyframe: bool,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// BLAKE3 cryptographic hash of carved frame bytes
    pub blake3_hash: String,
}

/// NAL unit classifications supported by the forensic carver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalClassification {
    H264SpsKeyframe,
    H264Pps,
    H264IdrKeyframe,
    H264NonIdrSlice,
    H264Sei,
    H264Aud,
    H265Vps,
    H265Sps,
    H265Pps,
    H265IdrKeyframe,
    H265NonIdrSlice,
    UnknownNal(u8),
}

impl NalClassification {
    pub fn description(&self) -> &'static str {
        match self {
            Self::H264SpsKeyframe => "H.264 SPS / Keyframe Preamble",
            Self::H264Pps => "H.264 PPS",
            Self::H264IdrKeyframe => "H.264 IDR Keyframe (I-Frame)",
            Self::H264NonIdrSlice => "H.264 Non-IDR Slice (P/B-Frame)",
            Self::H264Sei => "H.264 SEI",
            Self::H264Aud => "H.264 AUD",
            Self::H265Vps => "H.265 VPS",
            Self::H265Sps => "H.265 SPS",
            Self::H265Pps => "H.265 PPS",
            Self::H265IdrKeyframe => "H.265 IDR Keyframe",
            Self::H265NonIdrSlice => "H.265 Non-IDR Slice",
            Self::UnknownNal(_) => "Generic / Unknown NAL Unit",
        }
    }

    pub fn is_keyframe(&self) -> bool {
        matches!(
            self,
            Self::H264SpsKeyframe
                | Self::H264IdrKeyframe
                | Self::H265Vps
                | Self::H265Sps
                | Self::H265IdrKeyframe
        )
    }

    pub fn default_confidence(&self) -> f64 {
        match self {
            Self::H264SpsKeyframe | Self::H264IdrKeyframe => 0.95,
            Self::H264Pps | Self::H264Sei | Self::H264Aud => 0.90,
            Self::H264NonIdrSlice => 0.85,
            Self::H265Vps | Self::H265Sps | Self::H265IdrKeyframe => 0.95,
            Self::H265Pps => 0.90,
            Self::H265NonIdrSlice => 0.85,
            Self::UnknownNal(_) => 0.50,
        }
    }
}

/// Classifies a NAL unit byte.
pub fn classify_nal_header(header_byte: u8) -> NalClassification {
    let nal_type_h264 = header_byte & 0x1F;
    let forbidden_zero_bit = (header_byte & 0x80) != 0;

    if !forbidden_zero_bit {
        match nal_type_h264 {
            1 => return NalClassification::H264NonIdrSlice,
            5 => return NalClassification::H264IdrKeyframe,
            6 => return NalClassification::H264Sei,
            7 => return NalClassification::H264SpsKeyframe,
            8 => return NalClassification::H264Pps,
            9 => return NalClassification::H264Aud,
            _ => {}
        }
    }

    NalClassification::UnknownNal(header_byte)
}

/// Deep video frame carver. Scans raw byte buffers for NAL unit start codes
/// (`00 00 00 01` or `00 00 01`) and reconstructs individual video frames.
pub fn carve_buffer(data: &[u8], base_offset: u64) -> Vec<CarvedFrame> {
    let mut frames = Vec::new();
    let len = data.len();
    if len < 5 {
        return frames;
    }

    // Locate all start code candidate indices
    let mut start_indices = Vec::new();
    let mut i = 0;
    while i + 4 <= len {
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            if data[i + 2] == 0x00 && data[i + 3] == 0x01 {
                start_indices.push((i, 4));
                i += 4;
                continue;
            } else if data[i + 2] == 0x01 {
                start_indices.push((i, 3));
                i += 3;
                continue;
            }
        }
        i += 1;
    }

    if start_indices.is_empty() {
        return frames;
    }

    for idx in 0..start_indices.len() {
        let (start_pos, prefix_len) = start_indices[idx];
        let end_pos = if idx + 1 < start_indices.len() {
            start_indices[idx + 1].0
        } else {
            len
        };

        if end_pos <= start_pos + prefix_len {
            continue;
        }

        let header_byte = data[start_pos + prefix_len];
        let classification = classify_nal_header(header_byte);

        let frame_slice = &data[start_pos..end_pos];
        let frame_hash = blake3::hash(frame_slice).to_hex().to_string();

        frames.push(CarvedFrame {
            byte_offset: base_offset + start_pos as u64,
            length: frame_slice.len(),
            nal_type: classification.description().to_string(),
            is_keyframe: classification.is_keyframe(),
            confidence: classification.default_confidence(),
            blake3_hash: frame_hash,
        });
    }

    frames
}

/// Carves video frames from designated block indices of an evidence image.
pub fn carve_corrupted_blocks<P: AsRef<Path>>(
    image_path: P,
    block_size: usize,
    block_indices: &[usize],
) -> Result<Vec<CarvedFrame>> {
    let mut file = File::open(image_path)?;
    let mut buffer = vec![0u8; block_size];
    let mut all_carved = Vec::new();

    for &b_idx in block_indices {
        let offset = (b_idx * block_size) as u64;
        file.seek(SeekFrom::Start(offset))?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            continue;
        }

        let carved = carve_buffer(&buffer[..read], offset);
        all_carved.extend(carved);
    }

    Ok(all_carved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_carve_h264_stream_in_buffer() {
        // Build synthetic buffer containing 1 SPS keyframe and 2 P-frames
        let mut buffer = vec![0xFFu8; 100]; // 100 bytes of noise
        let sps_offset = buffer.len();
        buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1E]); // SPS
        buffer.extend_from_slice(&[0xAA; 50]);

        let p1_offset = buffer.len();
        buffer.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x41, 0x9A]); // P-frame
        buffer.extend_from_slice(&[0xBB; 40]);

        let p2_offset = buffer.len();
        buffer.extend_from_slice(&[0x00, 0x00, 0x01, 0x41, 0x9B]); // 3-byte prefix P-frame
        buffer.extend_from_slice(&[0xCC; 30]);

        let carved = carve_buffer(&buffer, 1000);
        assert_eq!(carved.len(), 3);

        assert_eq!(carved[0].byte_offset, 1000 + sps_offset as u64);
        assert!(carved[0].is_keyframe);
        assert_eq!(carved[0].nal_type, "H.264 SPS / Keyframe Preamble");

        assert_eq!(carved[1].byte_offset, 1000 + p1_offset as u64);
        assert!(!carved[1].is_keyframe);
        assert_eq!(carved[1].nal_type, "H.264 Non-IDR Slice (P/B-Frame)");

        assert_eq!(carved[2].byte_offset, 1000 + p2_offset as u64);
        assert!(!carved[2].is_keyframe);
        assert_eq!(carved[2].nal_type, "H.264 Non-IDR Slice (P/B-Frame)");
    }
}
