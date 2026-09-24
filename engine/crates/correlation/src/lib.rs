use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Input record specification for cross-camera correlation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordInput {
    pub block_index: usize,
    pub byte_offset: u64,
    pub channel_id: u32,
    pub timestamp: u64,
    pub normalized_timestamp: String,
    pub sequence_num: u32,
    pub is_keyframe: bool,
    pub is_scrambled: bool,
    pub descrambled: bool,
    pub is_corrupted: bool,
}

/// A unified chronological timeline entry across all camera channels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEvent {
    pub sequence_order: usize,
    pub block_index: usize,
    pub byte_offset: u64,
    pub channel_id: u32,
    pub timestamp: u64,
    pub normalized_timestamp: String,
    pub sequence_num: u32,
    pub is_keyframe: bool,
    pub is_scrambled: bool,
    pub descrambled: bool,
    pub is_corrupted: bool,
}

/// Identified transition of activity between two distinct camera channels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrossCameraTransition {
    pub from_channel: u32,
    pub to_channel: u32,
    pub from_timestamp: u64,
    pub to_timestamp: u64,
    pub from_normalized_ts: String,
    pub to_normalized_ts: String,
    pub delta_secs: i64,
    pub from_block_index: usize,
    pub to_block_index: usize,
    pub confidence: f64,
}

/// Synchronous recording blackout or gap across all active camera channels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalBlackoutAnomaly {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub start_normalized_ts: String,
    pub end_normalized_ts: String,
    pub duration_secs: i64,
    pub affected_channels: Vec<u32>,
    pub severity: String,
    pub description: String,
}

/// Comprehensive cross-camera spatial-temporal correlation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    pub total_records: usize,
    pub active_channels: Vec<u32>,
    pub min_timestamp: u64,
    pub max_timestamp: u64,
    pub min_normalized_ts: String,
    pub max_normalized_ts: String,
    pub timeline_events: Vec<TimelineEvent>,
    pub transitions: Vec<CrossCameraTransition>,
    pub blackouts: Vec<GlobalBlackoutAnomaly>,
}

/// Merges records from all camera channels into a unified, chronologically monotonic timeline.
pub fn merge_timeline(records: &[RecordInput]) -> Vec<TimelineEvent> {
    let mut sorted = records.to_vec();
    sorted.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.channel_id.cmp(&b.channel_id))
            .then_with(|| a.sequence_num.cmp(&b.sequence_num))
            .then_with(|| a.block_index.cmp(&b.block_index))
    });

    sorted
        .into_iter()
        .enumerate()
        .map(|(idx, r)| TimelineEvent {
            sequence_order: idx + 1,
            block_index: r.block_index,
            byte_offset: r.byte_offset,
            channel_id: r.channel_id,
            timestamp: r.timestamp,
            normalized_timestamp: r.normalized_timestamp,
            sequence_num: r.sequence_num,
            is_keyframe: r.is_keyframe,
            is_scrambled: r.is_scrambled,
            descrambled: r.descrambled,
            is_corrupted: r.is_corrupted,
        })
        .collect()
}

/// Detects inter-camera transitions within a temporal proximity window (`max_window_secs`).
pub fn detect_transitions(
    timeline: &[TimelineEvent],
    max_window_secs: i64,
) -> Vec<CrossCameraTransition> {
    let mut transitions = Vec::new();
    if timeline.len() < 2 || max_window_secs <= 0 {
        return transitions;
    }

    // Only consider non-corrupted video frame events
    let valid_events: Vec<&TimelineEvent> = timeline
        .iter()
        .filter(|e| !e.is_corrupted && e.channel_id > 0)
        .collect();

    for i in 0..valid_events.len() {
        let from_event = valid_events[i];

        // Look ahead for events on different channels within max_window_secs
        for j in (i + 1)..valid_events.len() {
            let to_event = valid_events[j];

            if to_event.timestamp < from_event.timestamp {
                continue;
            }

            let delta = (to_event.timestamp - from_event.timestamp) as i64;
            if delta > max_window_secs {
                break; // Events are chronologically sorted
            }

            if from_event.channel_id != to_event.channel_id && delta > 0 {
                // Compute calibrated confidence: closer time delta -> higher confidence
                let time_factor = 1.0 - (delta as f64 / (max_window_secs as f64 + 1.0)) * 0.4;
                let keyframe_boost = if from_event.is_keyframe && to_event.is_keyframe {
                    0.10
                } else if from_event.is_keyframe || to_event.is_keyframe {
                    0.05
                } else {
                    0.0
                };
                let confidence = (time_factor + keyframe_boost).clamp(0.50, 0.99);

                transitions.push(CrossCameraTransition {
                    from_channel: from_event.channel_id,
                    to_channel: to_event.channel_id,
                    from_timestamp: from_event.timestamp,
                    to_timestamp: to_event.timestamp,
                    from_normalized_ts: from_event.normalized_timestamp.clone(),
                    to_normalized_ts: to_event.normalized_timestamp.clone(),
                    delta_secs: delta,
                    from_block_index: from_event.block_index,
                    to_block_index: to_event.block_index,
                    confidence,
                });
            }
        }
    }

    // Deduplicate transitions with identical from/to channel and timestamps
    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    for t in transitions {
        let key = (t.from_channel, t.to_channel, t.from_timestamp, t.to_timestamp);
        if seen.insert(key) {
            deduped.push(t);
        }
    }

    deduped
}

/// Detects simultaneous gaps across all camera channels exceeding `min_gap_secs`.
pub fn detect_global_blackouts(
    records: &[RecordInput],
    min_gap_secs: i64,
) -> Vec<GlobalBlackoutAnomaly> {
    let mut blackouts = Vec::new();
    if records.is_empty() || min_gap_secs <= 0 {
        return blackouts;
    }

    // Group valid timestamps per channel
    let mut channel_times: BTreeMap<u32, Vec<(u64, String)>> = BTreeMap::new();
    for r in records {
        if r.channel_id > 0 && !r.is_corrupted {
            channel_times
                .entry(r.channel_id)
                .or_default()
                .push((r.timestamp, r.normalized_timestamp.clone()));
        }
    }

    let all_channels: Vec<u32> = channel_times.keys().copied().collect();
    if all_channels.is_empty() {
        return blackouts;
    }

    // Sort timestamps for each channel
    for times in channel_times.values_mut() {
        times.sort_by_key(|t| t.0);
    }

    // Compute gaps for each channel
    // A blackout occurs when ALL active channels experience a gap concurrently.
    // For each channel's gap, check if all other channels also have no recordings in that interval.
    let primary_channel = all_channels[0];
    let primary_times = &channel_times[&primary_channel];

    for i in 0..primary_times.len().saturating_sub(1) {
        let t_start = primary_times[i].0;
        let t_end = primary_times[i + 1].0;
        let gap = (t_end - t_start) as i64;

        if gap >= min_gap_secs {
            // Check if all other channels have NO recordings strictly between t_start and t_end
            let mut all_blackout = true;
            for &other_ch in &all_channels {
                if other_ch == primary_channel {
                    continue;
                }
                let other_ts = &channel_times[&other_ch];
                let has_recording_in_gap = other_ts
                    .iter()
                    .any(|(t, _)| *t > t_start + 1 && *t < t_end - 1);
                if has_recording_in_gap {
                    all_blackout = false;
                    break;
                }
            }

            if all_blackout {
                blackouts.push(GlobalBlackoutAnomaly {
                    start_timestamp: t_start,
                    end_timestamp: t_end,
                    start_normalized_ts: primary_times[i].1.clone(),
                    end_normalized_ts: primary_times[i + 1].1.clone(),
                    duration_secs: gap,
                    affected_channels: all_channels.clone(),
                    severity: if gap >= 60 { "CRITICAL".to_string() } else { "HIGH".to_string() },
                    description: format!(
                        "Synchronous recording outage across all {} camera channel(s) lasting {} seconds",
                        all_channels.len(),
                        gap
                    ),
                });
            }
        }
    }

    blackouts
}

/// Generates a comprehensive multi-camera correlation report.
pub fn generate_correlation_report(
    records: &[RecordInput],
    window_secs: i64,
    blackout_gap_secs: i64,
) -> CorrelationReport {
    let timeline = merge_timeline(records);
    let transitions = detect_transitions(&timeline, window_secs);
    let blackouts = detect_global_blackouts(records, blackout_gap_secs);

    let active_channels: Vec<u32> = records
        .iter()
        .filter(|r| r.channel_id > 0)
        .map(|r| r.channel_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let (min_ts, min_norm_ts) = timeline
        .first()
        .map(|e| (e.timestamp, e.normalized_timestamp.clone()))
        .unwrap_or((0, "1970-01-01T00:00:00Z".to_string()));

    let (max_ts, max_norm_ts) = timeline
        .last()
        .map(|e| (e.timestamp, e.normalized_timestamp.clone()))
        .unwrap_or((0, "1970-01-01T00:00:00Z".to_string()));

    CorrelationReport {
        total_records: records.len(),
        active_channels,
        min_timestamp: min_ts,
        max_timestamp: max_ts,
        min_normalized_ts: min_norm_ts,
        max_normalized_ts: max_norm_ts,
        timeline_events: timeline,
        transitions,
        blackouts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_timeline_monotonic_order() {
        let records = vec![
            RecordInput {
                block_index: 2,
                byte_offset: 8192,
                channel_id: 1,
                timestamp: 100,
                normalized_timestamp: "2026-03-18T00:01:40Z".to_string(),
                sequence_num: 1,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            RecordInput {
                block_index: 3,
                byte_offset: 12288,
                channel_id: 2,
                timestamp: 102,
                normalized_timestamp: "2026-03-18T00:01:42Z".to_string(),
                sequence_num: 1,
                is_keyframe: false,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            RecordInput {
                block_index: 4,
                byte_offset: 16384,
                channel_id: 1,
                timestamp: 104,
                normalized_timestamp: "2026-03-18T00:01:44Z".to_string(),
                sequence_num: 2,
                is_keyframe: false,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
        ];

        let merged = merge_timeline(&records);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].timestamp, 100);
        assert_eq!(merged[0].channel_id, 1);
        assert_eq!(merged[1].timestamp, 102);
        assert_eq!(merged[1].channel_id, 2);
        assert_eq!(merged[2].timestamp, 104);
        assert_eq!(merged[2].channel_id, 1);
    }

    #[test]
    fn test_detect_cross_camera_transitions() {
        let timeline = vec![
            TimelineEvent {
                sequence_order: 1,
                block_index: 2,
                byte_offset: 8192,
                channel_id: 1,
                timestamp: 100,
                normalized_timestamp: "2026-03-18T00:01:40Z".to_string(),
                sequence_num: 1,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            TimelineEvent {
                sequence_order: 2,
                block_index: 3,
                byte_offset: 12288,
                channel_id: 2,
                timestamp: 104,
                normalized_timestamp: "2026-03-18T00:01:44Z".to_string(),
                sequence_num: 1,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
        ];

        let transitions = detect_transitions(&timeline, 10);
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from_channel, 1);
        assert_eq!(transitions[0].to_channel, 2);
        assert_eq!(transitions[0].delta_secs, 4);
        assert!(transitions[0].confidence > 0.80);
    }

    #[test]
    fn test_detect_global_blackout() {
        let records = vec![
            // Channel 1 at t=100 and t=160 (gap of 60s)
            RecordInput {
                block_index: 2,
                byte_offset: 8192,
                channel_id: 1,
                timestamp: 100,
                normalized_timestamp: "2026-03-18T00:01:40Z".to_string(),
                sequence_num: 1,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            RecordInput {
                block_index: 4,
                byte_offset: 16384,
                channel_id: 1,
                timestamp: 160,
                normalized_timestamp: "2026-03-18T00:02:40Z".to_string(),
                sequence_num: 2,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            // Channel 2 also at t=100 and t=160
            RecordInput {
                block_index: 3,
                byte_offset: 12288,
                channel_id: 2,
                timestamp: 100,
                normalized_timestamp: "2026-03-18T00:01:40Z".to_string(),
                sequence_num: 1,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
            RecordInput {
                block_index: 5,
                byte_offset: 20480,
                channel_id: 2,
                timestamp: 160,
                normalized_timestamp: "2026-03-18T00:02:40Z".to_string(),
                sequence_num: 2,
                is_keyframe: true,
                is_scrambled: false,
                descrambled: false,
                is_corrupted: false,
            },
        ];

        let blackouts = detect_global_blackouts(&records, 30);
        assert_eq!(blackouts.len(), 1);
        assert_eq!(blackouts[0].duration_secs, 60);
        assert_eq!(blackouts[0].affected_channels, vec![1, 2]);
        assert_eq!(blackouts[0].severity, "CRITICAL");
    }
}
