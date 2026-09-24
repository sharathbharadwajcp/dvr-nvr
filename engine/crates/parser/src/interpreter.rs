use crate::ast::{FieldDef, GrammarFile, VideoBlockDef};
use crate::error::{ParserError, Result};
use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedRecord {
    pub block_index: usize,
    pub byte_offset: u64,
    pub channel_id: u32,
    pub timestamp: u64,
    pub normalized_timestamp: String,
    pub sequence_num: u32,
    pub payload_offset: u64,
    pub payload_len: usize,
    pub flags: u16,
    pub is_scrambled: bool,
    pub is_corrupted: bool,
    pub block_type: String,
    pub blake3_hash: String,
    #[serde(default)]
    pub descrambled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descrambled_blake3_hash: Option<String>,
}

impl ExtractedRecord {
    pub fn to_correlation_input(&self) -> correlation::RecordInput {
        correlation::RecordInput {
            block_index: self.block_index,
            byte_offset: self.byte_offset,
            channel_id: self.channel_id,
            timestamp: self.timestamp,
            normalized_timestamp: self.normalized_timestamp.clone(),
            sequence_num: self.sequence_num,
            is_keyframe: (self.flags & 1) != 0,
            is_scrambled: self.is_scrambled,
            descrambled: self.descrambled,
            is_corrupted: self.is_corrupted,
        }
    }
}

pub struct GrammarInterpreter<'a> {
    grammar: &'a GrammarFile,
}

impl<'a> GrammarInterpreter<'a> {
    pub fn new(grammar: &'a GrammarFile) -> Self {
        Self { grammar }
    }

    /// Interprets a single acquired block using the compiled grammar.
    pub fn interpret_block(
        &self,
        block_index: usize,
        byte_offset: u64,
        block_bytes: &[u8],
        blake3_hash: &str,
    ) -> Result<ExtractedRecord> {
        let video_def = &self.grammar.structures.video_block;

        if block_bytes.len() < video_def.header.size {
            return Err(ParserError::BlockTooSmall {
                actual: block_bytes.len(),
                expected: video_def.header.size,
            });
        }

        // Check video block magic bytes
        let magic_bytes = video_def.header.magic.expected_bytes()?;
        let magic_offset = video_def.header.magic.offset;
        let magic_len = magic_bytes.len();

        let has_video_magic = block_bytes.len() >= magic_offset + magic_len
            && &block_bytes[magic_offset..magic_offset + magic_len] == magic_bytes.as_slice();

        if !has_video_magic {
            // Check if this block matches superblock or partition table
            if let Some(ref sb) = self.grammar.structures.superblock {
                if let Some(ref sb_magic) = sb.magic {
                    if let Ok(expected) = sb_magic.expected_bytes() {
                        let off = sb_magic.offset;
                        if block_bytes.len() >= off + expected.len()
                            && &block_bytes[off..off + expected.len()] == expected.as_slice()
                        {
                            return Ok(ExtractedRecord {
                                block_index,
                                byte_offset,
                                channel_id: 0,
                                timestamp: 0,
                                sequence_num: 0,
                                payload_offset: byte_offset,
                                payload_len: block_bytes.len(),
                                flags: 0,
                                is_scrambled: false,
                                is_corrupted: false,
                                block_type: "superblock".to_string(),
                                blake3_hash: blake3_hash.to_string(),
                                normalized_timestamp: "1970-01-01T00:00:00Z".to_string(),
                                descrambled: false,
                                descrambled_blake3_hash: None,
                            });
                        }
                    }
                }
            }

            if let Some(ref pt) = self.grammar.structures.partition_table {
                if let Some(ref pt_magic) = pt.magic {
                    if let Ok(expected) = pt_magic.expected_bytes() {
                        let off = pt_magic.offset;
                        if block_bytes.len() >= off + expected.len()
                            && &block_bytes[off..off + expected.len()] == expected.as_slice()
                        {
                            return Ok(ExtractedRecord {
                                block_index,
                                byte_offset,
                                channel_id: 0,
                                timestamp: 0,
                                sequence_num: 0,
                                payload_offset: byte_offset,
                                payload_len: block_bytes.len(),
                                flags: 0,
                                is_scrambled: false,
                                is_corrupted: false,
                                block_type: "partition_table".to_string(),
                                blake3_hash: blake3_hash.to_string(),
                                normalized_timestamp: "1970-01-01T00:00:00Z".to_string(),
                                descrambled: false,
                                descrambled_blake3_hash: None,
                            });
                        }
                    }
                }
            }

            // Neither valid video magic nor superblock/partition table -> unallocated or corrupted
            return Ok(ExtractedRecord {
                block_index,
                byte_offset,
                channel_id: 0,
                timestamp: 0,
                sequence_num: 0,
                payload_offset: byte_offset + video_def.payload.offset as u64,
                payload_len: video_def.payload.default_length,
                flags: 0,
                is_scrambled: false,
                is_corrupted: true,
                block_type: "unallocated_or_corrupted".to_string(),
                blake3_hash: blake3_hash.to_string(),
                normalized_timestamp: "1970-01-01T00:00:00Z".to_string(),
                descrambled: false,
                descrambled_blake3_hash: None,
            });
        }

        // Parse structured video block fields
        self.parse_video_block(block_index, byte_offset, block_bytes, blake3_hash, video_def)
    }

    fn parse_video_block(
        &self,
        block_index: usize,
        byte_offset: u64,
        block_bytes: &[u8],
        blake3_hash: &str,
        video_def: &VideoBlockDef,
    ) -> Result<ExtractedRecord> {
        let mut channel_id: u32 = 0;
        let mut timestamp: u64 = 0;
        let mut normalized_timestamp = "1970-01-01T00:00:00Z".to_string();
        let mut sequence_num: u32 = 0;
        let mut payload_len: usize = video_def.payload.default_length;
        let mut flags: u16 = 0;
        let mut is_scrambled = false;
        let mut is_corrupted = false;

        for field in &video_def.header.fields {
            let val = read_field_value(block_bytes, field)?;

            match field.role.as_deref() {
                Some("channel_id") => {
                    channel_id = val as u32;
                }
                Some("timestamp") => {
                    timestamp = val;
                    normalized_timestamp = normalize_timestamp(
                        val,
                        field.encoding.as_deref(),
                        field.timezone.as_deref(),
                    );
                }
                Some("sequence_num") => {
                    sequence_num = val as u32;
                }
                Some("payload_length") => {
                    if val > 0 && (val as usize) <= block_bytes.len() {
                        payload_len = val as usize;
                    }
                }
                Some("flags") => {
                    flags = val as u16;
                    if let Some(ref masks) = field.flag_masks {
                        if let Some(&scramble_mask) = masks.get("scrambled") {
                            is_scrambled = (flags as u32 & scramble_mask) != 0;
                        }
                        if let Some(&corrupt_mask) = masks.get("corrupted") {
                            is_corrupted = (flags as u32 & corrupt_mask) != 0;
                        }
                    } else {
                        is_scrambled = (flags & 0x0002) != 0;
                        is_corrupted = (flags & 0x0004) != 0;
                    }
                }
                _ => {}
            }
        }

        let payload_offset = byte_offset + video_def.payload.offset as u64;

        Ok(ExtractedRecord {
            block_index,
            byte_offset,
            channel_id,
            timestamp,
            normalized_timestamp,
            sequence_num,
            payload_offset,
            payload_len,
            flags,
            is_scrambled,
            is_corrupted,
            block_type: "video_frame".to_string(),
            blake3_hash: blake3_hash.to_string(),
            descrambled: false,
            descrambled_blake3_hash: None,
        })
    }
}

/// Parses an optional timezone string into a `FixedOffset`.
/// Supports:
/// - "UTC", "Z", or empty -> +00:00
/// - "+08:00", "-05:00"
/// - "+0800", "-0500"
/// - "+08", "-05"
pub fn parse_timezone_offset(tz_str: Option<&str>) -> FixedOffset {
    let s = match tz_str {
        Some(s) if !s.trim().is_empty() => s.trim(),
        _ => return FixedOffset::east_opt(0).unwrap(),
    };
    if s.eq_ignore_ascii_case("UTC") || s.eq_ignore_ascii_case("Z") {
        return FixedOffset::east_opt(0).unwrap();
    }

    let sign = if s.starts_with('-') { -1 } else { 1 };
    let clean = s.trim_start_matches('+').trim_start_matches('-');
    let parts: Vec<&str> = clean.split(':').collect();
    let (hours, mins) = if parts.len() == 2 {
        (
            parts[0].parse::<i32>().unwrap_or(0),
            parts[1].parse::<i32>().unwrap_or(0),
        )
    } else if clean.len() == 4 {
        (
            clean[0..2].parse::<i32>().unwrap_or(0),
            clean[2..4].parse::<i32>().unwrap_or(0),
        )
    } else {
        (clean.parse::<i32>().unwrap_or(0), 0)
    };

    let total_secs = sign * (hours * 3600 + mins * 60);
    FixedOffset::east_opt(total_secs).unwrap_or_else(|| FixedOffset::east_opt(0).unwrap())
}

/// Normalizes a raw timestamp value into canonical UTC ISO 8601 (RFC 3339 with 'Z' suffix).
pub fn normalize_timestamp(
    raw_val: u64,
    encoding: Option<&str>,
    timezone: Option<&str>,
) -> String {
    if raw_val == 0 {
        return "1970-01-01T00:00:00Z".to_string();
    }

    let enc = encoding.unwrap_or("unix_seconds");
    let tz_offset = parse_timezone_offset(timezone);

    match enc {
        "dahua_packed" | "dhav_packed" => {
            // Dahua 32-bit packed timestamp:
            // Year: bits 26..31 (offset from year 2000)
            // Month: bits 22..25 (1-12)
            // Day: bits 17..21 (1-31)
            // Hour: bits 12..16 (0-23)
            // Minute: bits 6..11 (0-59)
            // Second: bits 0..5 (0-59)
            let year = (((raw_val >> 26) & 0x3F) as i32) + 2000;
            let month = ((raw_val >> 22) & 0x0F) as u32;
            let day = ((raw_val >> 17) & 0x1F) as u32;
            let hour = ((raw_val >> 12) & 0x1F) as u32;
            let minute = ((raw_val >> 6) & 0x3F) as u32;
            let second = (raw_val & 0x3F) as u32;

            if let Some(naive_date) = NaiveDate::from_ymd_opt(year, month, day) {
                if let Some(naive_dt) = naive_date.and_hms_opt(hour, minute, second) {
                    if let Some(local_dt) = tz_offset.from_local_datetime(&naive_dt).single() {
                        let utc_dt: DateTime<Utc> = local_dt.with_timezone(&Utc);
                        return utc_dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    }
                }
            }

            DateTime::from_timestamp(raw_val as i64, 0)
                .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
        }
        "unix_millis" => {
            let secs = (raw_val / 1000) as i64;
            let nsecs = ((raw_val % 1000) * 1_000_000) as u32;
            if tz_offset.local_minus_utc() == 0 {
                DateTime::from_timestamp(secs, nsecs)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
            } else {
                if let Some(utc_dt) = DateTime::from_timestamp(secs, nsecs) {
                    let naive_dt = utc_dt.naive_utc();
                    if let Some(local_dt) = tz_offset.from_local_datetime(&naive_dt).single() {
                        let utc_dt: DateTime<Utc> = local_dt.with_timezone(&Utc);
                        return utc_dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    }
                }
                "1970-01-01T00:00:00Z".to_string()
            }
        }
        "unix_seconds" | _ => {
            let secs = raw_val as i64;
            if tz_offset.local_minus_utc() == 0 {
                DateTime::from_timestamp(secs, 0)
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
            } else {
                if let Some(utc_dt) = DateTime::from_timestamp(secs, 0) {
                    let naive_dt = utc_dt.naive_utc();
                    if let Some(local_dt) = tz_offset.from_local_datetime(&naive_dt).single() {
                        let utc_dt: DateTime<Utc> = local_dt.with_timezone(&Utc);
                        return utc_dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                    }
                }
                "1970-01-01T00:00:00Z".to_string()
            }
        }
    }
}

fn read_field_value(data: &[u8], field: &FieldDef) -> Result<u64> {
    let offset = field.offset;
    let is_little = field.endian.as_deref() != Some("big");

    match field.field_type.as_str() {
        "u8" => {
            if offset >= data.len() {
                return Ok(0);
            }
            Ok(data[offset] as u64)
        }
        "u16" => {
            if offset + 2 > data.len() {
                return Ok(0);
            }
            let slice: [u8; 2] = [data[offset], data[offset + 1]];
            let val = if is_little {
                u16::from_le_bytes(slice)
            } else {
                u16::from_be_bytes(slice)
            };
            Ok(val as u64)
        }
        "u32" => {
            if offset + 4 > data.len() {
                return Ok(0);
            }
            let slice: [u8; 4] = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            let val = if is_little {
                u32::from_le_bytes(slice)
            } else {
                u32::from_be_bytes(slice)
            };
            Ok(val as u64)
        }
        "u64" => {
            if offset + 8 > data.len() {
                return Ok(0);
            }
            let slice: [u8; 8] = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ];
            let val = if is_little {
                u64::from_le_bytes(slice)
            } else {
                u64::from_be_bytes(slice)
            };
            Ok(val)
        }
        _ => Ok(0),
    }
}
