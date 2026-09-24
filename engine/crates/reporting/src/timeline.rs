use serde::{Deserialize, Serialize};

/// Represents a single chronological entry in the reconstructed forensic timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEntry {
    pub timestamp: u64,
    pub normalized_timestamp: String,
    pub channel_id: Option<u32>,
    pub entry_type: String,
    pub summary: String,
    pub details_json: String,
    pub flagged: bool,
}

/// Alert indicating an unexplained recording interruption, non-monotonicity, or suspected blackout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiscontinuityAlert {
    pub start_timestamp: String,
    pub end_timestamp: String,
    pub duration_secs: i64,
    pub affected_channels: Vec<u32>,
    pub severity: String,
    pub description: String,
}

/// Reconstructs a unified timeline from extracted records, carved frames, correlation events, and AI leads.
pub fn reconstruct_timeline(
    records: &[parser::ExtractedRecord],
    carved: &[parser::CarvedFrame],
    events: &[parser::CorrelatedDbEvent],
    analytics: &[parser::AnalyticsDbDetection],
    max_expected_gap_secs: u64,
) -> (Vec<TimelineEntry>, Vec<DiscontinuityAlert>) {
    let mut timeline: Vec<TimelineEntry> = Vec::new();
    let mut alerts: Vec<DiscontinuityAlert> = Vec::new();

    // 1. Regular parsed video records
    for r in records {
        let is_keyframe = (r.flags & 1) != 0;
        let mut flags_desc = Vec::new();
        if is_keyframe {
            flags_desc.push("I-FRAME");
        }
        if r.is_scrambled {
            flags_desc.push(if r.descrambled { "DESCRAMBLED" } else { "SCRAMBLED" });
        }
        if r.is_corrupted {
            flags_desc.push("CORRUPTED");
        }

        let summary = format!(
            "Block {:04} | CH {:02} | Seq: {} | {}",
            r.block_index,
            r.channel_id,
            r.sequence_num,
            if flags_desc.is_empty() { "NORMAL".to_string() } else { flags_desc.join(" | ") }
        );

        let details = serde_json::json!({
            "block_index": r.block_index,
            "byte_offset": r.byte_offset,
            "payload_len": r.payload_len,
            "blake3_hash": r.blake3_hash,
            "descrambled": r.descrambled,
            "is_corrupted": r.is_corrupted,
        });

        timeline.push(TimelineEntry {
            timestamp: r.timestamp,
            normalized_timestamp: r.normalized_timestamp.clone(),
            channel_id: Some(r.channel_id),
            entry_type: "video_frame".to_string(),
            summary,
            details_json: details.to_string(),
            flagged: r.is_corrupted || (r.is_scrambled && !r.descrambled),
        });
    }

    // 2. Carved unallocated / damaged records
    for c in carved {
        timeline.push(TimelineEntry {
            timestamp: 0,
            normalized_timestamp: "CARVED_UNINDEXED".to_string(),
            channel_id: None,
            entry_type: "carved_frame".to_string(),
            summary: format!(
                "Carved Video Frame at Offset {} ({} bytes, NAL: {}, Keyframe: {})",
                c.byte_offset,
                c.length,
                c.nal_type,
                if c.is_keyframe { "YES" } else { "NO" }
            ),
            details_json: serde_json::to_string(c).unwrap_or_default(),
            flagged: true,
        });
    }

    // 3. Correlated cross-camera events & anomalies
    for e in events {
        timeline.push(TimelineEntry {
            timestamp: 0,
            normalized_timestamp: e.start_timestamp.clone(),
            channel_id: None,
            entry_type: format!("correlated_{}", e.event_type),
            summary: format!(
                "Correlated Event [{}]: CH [{}] (Conf: {:.1}%)",
                e.event_type.to_uppercase(),
                e.channels_involved,
                e.confidence * 100.0
            ),
            details_json: e.details_json.clone(),
            flagged: e.event_type.contains("blackout") || e.confidence >= 0.90,
        });
    }

    // 4. AI Analytics detections (filter top relevance)
    for a in analytics {
        if a.relevance_score >= 0.50 {
            timeline.push(TimelineEntry {
                timestamp: a.timestamp,
                normalized_timestamp: a.normalized_timestamp.clone(),
                channel_id: Some(a.channel_id),
                entry_type: "analytics_lead".to_string(),
                summary: format!(
                    "AI Detection: {} ({:.0}%) | Motion: {:.2} | Relevance: {:.2}",
                    a.entity_class.to_uppercase(),
                    a.confidence * 100.0,
                    a.motion_energy,
                    a.relevance_score
                ),
                details_json: serde_json::to_string(a).unwrap_or_default(),
                flagged: a.relevance_score >= 0.75,
            });
        }
    }

    // Sort timeline chronologically (by normalized timestamp string or timestamp)
    timeline.sort_by(|a, b| {
        let ts_a = if a.timestamp > 0 { a.timestamp } else { u64::MAX };
        let ts_b = if b.timestamp > 0 { b.timestamp } else { u64::MAX };
        match ts_a.cmp(&ts_b) {
            std::cmp::Ordering::Equal => a.normalized_timestamp.cmp(&b.normalized_timestamp),
            other => other,
        }
    });

    // Detect timeline gaps and discontinuities across valid extracted timestamps
    let mut valid_records: Vec<&parser::ExtractedRecord> = records.iter().filter(|r| r.timestamp > 0).collect();
    valid_records.sort_by_key(|r| r.timestamp);

    for window in valid_records.windows(2) {
        let prev = window[0];
        let curr = window[1];

        if curr.timestamp > prev.timestamp {
            let delta = curr.timestamp - prev.timestamp;
            if delta > max_expected_gap_secs {
                let severity = if delta > 60 {
                    "CRITICAL"
                } else if delta > 30 {
                    "HIGH"
                } else {
                    "MEDIUM"
                };

                alerts.push(DiscontinuityAlert {
                    start_timestamp: prev.normalized_timestamp.clone(),
                    end_timestamp: curr.normalized_timestamp.clone(),
                    duration_secs: delta as i64,
                    affected_channels: vec![prev.channel_id, curr.channel_id],
                    severity: severity.to_string(),
                    description: format!(
                        "Recording gap of {}s detected between {} and {} (CH {} -> CH {})",
                        delta, prev.normalized_timestamp, curr.normalized_timestamp, prev.channel_id, curr.channel_id
                    ),
                });
            }
        }
    }

    (timeline, alerts)
}
