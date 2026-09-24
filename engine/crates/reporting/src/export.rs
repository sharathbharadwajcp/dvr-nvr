use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Summary of exported video artifacts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExportSummary {
    pub raw_h264_exported: usize,
    pub mp4_transcoded: usize,
    pub output_dir: PathBuf,
    pub ffmpeg_available: bool,
}

/// Checks whether `ffmpeg` is installed and reachable in system PATH.
pub fn is_ffmpeg_available() -> bool {
    Command::new("ffmpeg")
        .arg("-version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Exports carved and extracted video frames from evidence image and converts to MP4 if ffmpeg is present.
pub fn export_clips(
    evidence_path: &Path,
    carved_frames: &[parser::CarvedFrame],
    output_dir: &Path,
) -> Result<ExportSummary> {
    let clips_dir = output_dir.join("clips");
    std::fs::create_dir_all(&clips_dir)?;

    let ffmpeg_present = is_ffmpeg_available();
    let mut raw_count = 0;
    let mut mp4_count = 0;

    let mut evidence_file = File::open(evidence_path)?;

    for (i, frame) in carved_frames.iter().enumerate() {
        if frame.length == 0 {
            continue;
        }

        evidence_file.seek(SeekFrom::Start(frame.byte_offset))?;
        let mut buf = vec![0u8; frame.length];
        evidence_file.read_exact(&mut buf)?;

        let frame_kind = if frame.is_keyframe { "key" } else { "slice" };
        let h264_filename = format!("carved_clip_{:04}_{}_{}.h264", i, frame.byte_offset, frame_kind);
        let h264_path = clips_dir.join(&h264_filename);

        let mut out_h264 = File::create(&h264_path)?;
        out_h264.write_all(&buf)?;
        raw_count += 1;

        if ffmpeg_present {
            let mp4_filename = format!("carved_clip_{:04}_{}_{}.mp4", i, frame.byte_offset, frame_kind);
            let mp4_path = clips_dir.join(&mp4_filename);

            // Transcode elementary stream into MP4 container
            let status = Command::new("ffmpeg")
                .arg("-y")
                .arg("-f")
                .arg("h264")
                .arg("-i")
                .arg(&h264_path)
                .arg("-c:v")
                .arg("copy")
                .arg(&mp4_path)
                .output();

            if let Ok(res) = status {
                if res.status.success() {
                    mp4_count += 1;
                }
            }
        }
    }

    Ok(ExportSummary {
        raw_h264_exported: raw_count,
        mp4_transcoded: mp4_count,
        output_dir: clips_dir,
        ffmpeg_available: ffmpeg_present,
    })
}
