use crate::interpreter::ExtractedRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DemuxedStream {
    pub channel_id: u32,
    pub total_blocks: usize,
    pub min_timestamp: u64,
    pub max_timestamp: u64,
    pub sequence_gaps: Vec<u32>,
    pub records: Vec<ExtractedRecord>,
}

/// Demuxes an interleaved list of extracted records into separate streams per camera channel.
pub fn demux_records(records: &[ExtractedRecord]) -> HashMap<u32, DemuxedStream> {
    let mut channel_buckets: HashMap<u32, Vec<ExtractedRecord>> = HashMap::new();

    for record in records {
        if record.channel_id > 0 {
            channel_buckets
                .entry(record.channel_id)
                .or_default()
                .push(record.clone());
        }
    }

    let mut demuxed = HashMap::new();

    for (channel_id, mut ch_records) in channel_buckets {
        // Sort by monotonic sequence number (or timestamp)
        ch_records.sort_by_key(|r| (r.sequence_num, r.timestamp));

        let total_blocks = ch_records.len();
        let min_timestamp = ch_records.iter().map(|r| r.timestamp).min().unwrap_or(0);
        let max_timestamp = ch_records.iter().map(|r| r.timestamp).max().unwrap_or(0);

        // Detect missing sequence numbers
        let mut sequence_gaps = Vec::new();
        let mut last_seq = None;
        for r in &ch_records {
            if let Some(prev) = last_seq {
                if r.sequence_num > prev + 1 {
                    for missing in (prev + 1)..r.sequence_num {
                        sequence_gaps.push(missing);
                    }
                }
            }
            last_seq = Some(r.sequence_num);
        }

        demuxed.insert(
            channel_id,
            DemuxedStream {
                channel_id,
                total_blocks,
                min_timestamp,
                max_timestamp,
                sequence_gaps,
                records: ch_records,
            },
        );
    }

    demuxed
}
