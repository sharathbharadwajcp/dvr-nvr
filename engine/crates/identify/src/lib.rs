pub mod error;

pub use error::{IdentificationError, Result};

use acquisition::ReadOnlySource;
use parser::ast::GrammarFile;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Minimum confidence threshold below which a device is classified as unrecognized.
pub const MIN_CONFIDENCE_THRESHOLD: f32 = 0.50;

/// A signature rule defined in vendor_registry.yaml
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistrySignature {
    pub name: String,
    pub magic_ascii: Option<String>,
    pub magic_hex: Option<String>,
    pub offset: usize,
    pub weight: f32,
}

/// A vendor entry documented in vendor_registry.yaml
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegistryVendor {
    pub id: String,
    pub name: String,
    pub full_name: String,
    pub tier: u8,
    pub status: String,
    pub known_chipsets: Vec<String>,
    pub claimed_os_filesystem: String,
    pub public_sdk_available: bool,
    pub third_party_tool_support: String,
    pub sources: Vec<String>,
    pub signatures: Vec<RegistrySignature>,
}

/// The root vendor registry structure
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VendorRegistry {
    pub version: u32,
    pub vendors: Vec<RegistryVendor>,
}

impl VendorRegistry {
    /// Loads vendor_registry.yaml from standard search paths relative to grammars_dir or project root.
    pub fn load_from_paths<P: AsRef<Path>>(grammars_dir: P) -> Option<Self> {
        let g_dir = grammars_dir.as_ref();
        let candidate_paths = vec![
            g_dir.join("vendor_registry.yaml"),
            g_dir.parent().map(|p| p.join("vendor_registry.yaml")).unwrap_or_default(),
            g_dir.parent().map(|p| p.join("engine/vendor_registry.yaml")).unwrap_or_default(),
            g_dir.parent().and_then(|p| p.parent()).map(|p| p.join("engine/vendor_registry.yaml")).unwrap_or_default(),
            g_dir.parent().and_then(|p| p.parent()).map(|p| p.join("grammars/vendor_registry.yaml")).unwrap_or_default(),
        ];

        for cand in candidate_paths {
            if cand.exists() {
                if let Ok(content) = fs::read_to_string(&cand) {
                    if let Ok(registry) = serde_yaml::from_str::<VendorRegistry>(&content) {
                        return Some(registry);
                    }
                }
            }
        }
        None
    }
}

/// Output of the device identification process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceIdentification {
    /// True if the evidence format was conclusively recognized.
    pub recognized: bool,

    /// Detected equipment vendor (e.g. "Hikvision", "Dahua", "Cyber4 Synthetic", or "Unknown").
    pub vendor: String,

    /// Detected model or model series.
    pub model: Option<String>,

    /// Underlying SoC / chipset family (e.g. HiSilicon Hi35xx, Ambarella S2L).
    pub chipset: Option<String>,

    /// Calibrated confidence score (0.00 to 1.00).
    pub confidence: f32,

    /// ID of the matching declarative grammar, if recognized.
    pub matched_grammar_id: Option<String>,

    /// Validation tier of the matching grammar (Tier 1/2/3), or 0 for registry-only.
    pub validation_tier: Option<u8>,

    /// Identifying byte signature that matched.
    pub matched_signature: Option<String>,

    /// Diagnostic and investigative context notes.
    pub details: Vec<String>,
}

impl DeviceIdentification {
    /// Returns an explicit unrecognized/unknown result when confidence is below threshold.
    pub fn unrecognized() -> Self {
        Self {
            recognized: false,
            vendor: "Unknown".to_string(),
            model: None,
            chipset: None,
            confidence: 0.0,
            matched_grammar_id: None,
            validation_tier: None,
            matched_signature: None,
            details: vec![
                "Vendor unknown / format unrecognized (below confidence threshold)".to_string(),
            ],
        }
    }

    /// Formats this identification report for terminal display.
    pub fn display_summary(&self) -> String {
        let mut out = String::new();
        if self.recognized {
            out.push_str(&format!("  Detected Vendor    : {}\n", self.vendor));
            out.push_str(&format!(
                "  Model / Family     : {}\n",
                self.model.as_deref().unwrap_or("Generic OEM Model")
            ));
            out.push_str(&format!(
                "  SoC / Chipset      : {}\n",
                self.chipset.as_deref().unwrap_or("Undetermined")
            ));
            out.push_str(&format!(
                "  Confidence Score   : {:.1}% ({})\n",
                self.confidence * 100.0,
                if self.confidence >= 0.85 {
                    "High"
                } else if self.confidence >= 0.65 {
                    "Moderate"
                } else {
                    "Low"
                }
            ));
            if let Some(ref gid) = self.matched_grammar_id {
                out.push_str(&format!(
                    "  Matched Grammar    : {} (Tier {})\n",
                    gid,
                    self.validation_tier.unwrap_or(0)
                ));
            } else if self.validation_tier == Some(0) {
                out.push_str("  Format Status      : Identified (Format Not Yet Implemented -- Tier 0)\n");
                out.push_str("  Forensic Action    : Refer to docs/vendor-extension-guide.md to author grammar.\n");
            }
            if let Some(ref sig) = self.matched_signature {
                out.push_str(&format!("  Anchor Signature   : {}\n", sig));
            }
        } else {
            out.push_str("  Status             : Vendor Unknown / Format Unrecognized\n");
            out.push_str("  Confidence Score   : 0.0% (No match meets threshold >= 50%)\n");
            out.push_str("  Forensic Action    : Raw carving or vendor extension required.\n");
        }
        out
    }
}

/// Detects standard CCTV video containers, elementary video streams, and standard filesystems.
pub fn detect_video_container_or_stream(probe_slice: &[u8], _file_len: u64) -> Option<DeviceIdentification> {
    if probe_slice.len() < 12 {
        return None;
    }

    // 1. MP4 / ISO Base Media / QuickTime
    // Standard format: [size 4B][ftyp 4B][major_brand 4B]...
    if probe_slice.len() >= 12 && &probe_slice[4..8] == b"ftyp" {
        let brand_bytes = &probe_slice[8..12];
        let brand_str = String::from_utf8_lossy(brand_bytes).trim().to_string();

        if brand_str.eq_ignore_ascii_case("hikv") || probe_slice.windows(4).any(|w| w == b"hikv" || w == b"hik4" || w == b"HIKV" || w == b"HIK4") {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: "Hikvision".to_string(),
                model: Some("Hikvision Surveillance MP4 Export".to_string()),
                chipset: Some("HiSilicon / Embedded CCTV SoC".to_string()),
                confidence: 0.95,
                matched_grammar_id: Some("hikvision-mp4".to_string()),
                validation_tier: Some(2),
                matched_signature: Some(format!("ftyp ({})", brand_str)),
                details: vec![
                    format!("Detected Hikvision-branded MP4 container (Brand: {})", brand_str),
                    "Payload: H.264/H.265 surveillance video with Hikvision box metadata".to_string(),
                ],
            });
        }

        if brand_str.eq_ignore_ascii_case("dhav") || probe_slice.windows(4).any(|w| w == b"dhav" || w == b"DHAV") {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: "Dahua".to_string(),
                model: Some("Dahua Surveillance MP4 Export".to_string()),
                chipset: Some("HiSilicon Hi35xx / Ambarella S2L".to_string()),
                confidence: 0.95,
                matched_grammar_id: Some("dahua-mp4".to_string()),
                validation_tier: Some(2),
                matched_signature: Some(format!("ftyp ({})", brand_str)),
                details: vec![
                    format!("Detected Dahua MP4 container (Brand: {})", brand_str),
                    "Payload: DHAV/H.264 surveillance stream".to_string(),
                ],
            });
        }

        if let Some((oem_vendor, oem_model, oem_chipset, oem_grammar)) = detect_container_oem(probe_slice) {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: oem_vendor.to_string(),
                model: Some(oem_model.to_string()),
                chipset: Some(oem_chipset.to_string()),
                confidence: 0.96,
                matched_grammar_id: Some(oem_grammar.to_string()),
                validation_tier: Some(2),
                matched_signature: Some(format!("ftyp ({}) + OEM ({})", brand_str, oem_vendor)),
                details: vec![
                    format!("Detected {} surveillance video container (Brand: {})", oem_vendor, brand_str),
                    format!("Identified proprietary {} metadata markers embedded inside container boxes.", oem_vendor),
                    "Payload: H.264/H.265 surveillance video stream ready for playback and frame carving.".to_string(),
                ],
            });
        }

        return Some(DeviceIdentification {
            recognized: true,
            vendor: "CCTV Video Container (MP4 / MOV)".to_string(),
            model: Some(format!("ISO Base Media Container (Brand: {})", brand_str)),
            chipset: Some("Universal Surveillance H.264/H.265 Encoders".to_string()),
            confidence: 0.92,
            matched_grammar_id: Some("cctv-mp4".to_string()),
            validation_tier: Some(3),
            matched_signature: Some(format!("ftyp ({})", brand_str)),
            details: vec![
                format!("Identified valid ISO Base Media / QuickTime container (Brand: {})", brand_str),
                "Note: The CCTV DVR exported this recording in standard ISO MP4 format without vendor-specific metadata tags.".to_string(),
                "Proprietary file systems (HBFS for Hikvision, DHFS for CP PLUS/Dahua) exist on the raw hard disk, not inside exported MP4 video files.".to_string(),
                "Compatible with universal CCTV demuxers and forensic NAL bitstream analyzers.".to_string(),
                "To extract frames, verify timestamps, or play the video, proceed to Screen 4 (Carving) or Screen 5 (Playback).".to_string(),
            ],
        });
    }

    // 2. Dahua DAV / DHAV Stream
    let dhav_pos = probe_slice[..probe_slice.len().min(4096)]
        .windows(4)
        .position(|w| w == b"DHAV" || w == b"DAHV");
    if let Some(pos) = dhav_pos {
        let sig = String::from_utf8_lossy(&probe_slice[pos..pos + 4]).to_string();
        return Some(DeviceIdentification {
            recognized: true,
            vendor: "Dahua".to_string(),
            model: Some("DH-DVR / DH-NVR Series (DHFS / DHAV)".to_string()),
            chipset: Some("HiSilicon Hi35xx / Ambarella S2L".to_string()),
            confidence: 0.90,
            matched_grammar_id: Some("dahua-v1".to_string()),
            validation_tier: Some(3),
            matched_signature: Some(if pos == 0 { sig } else { format!("{} (offset 0x{:X})", sig, pos) }),
            details: vec![
                format!("Identified Dahua DHAV proprietary frame container signature at byte {}", pos),
                "Compatible with Dahua DHAV demuxer (Tier 2)".to_string(),
            ],
        });
    }

    // 3. AVI (Audio Video Interleaved) Container
    if probe_slice.len() >= 12 && &probe_slice[0..4] == b"RIFF" && (&probe_slice[8..12] == b"AVI " || &probe_slice[8..12] == b"AVIX") {
        return Some(DeviceIdentification {
            recognized: true,
            vendor: "CCTV Video Container (AVI / RIFF)".to_string(),
            model: Some("Audio Video Interleaved Surveillance Export (.avi)".to_string()),
            chipset: Some("OEM Surveillance Codecs (H.264 / MJPEG / MPEG-4)".to_string()),
            confidence: 0.92,
            matched_grammar_id: Some("cctv-avi".to_string()),
            validation_tier: Some(3),
            matched_signature: Some("RIFF...AVI ".to_string()),
            details: vec![
                "Identified Microsoft RIFF AVI container header".to_string(),
                "Commonly utilized for CCTV exports (Honeywell, CP Plus, generic DVRs)".to_string(),
            ],
        });
    }

    // 4. Matroska / WebM Container (EBML ID: 0x1A 0x45 0xDF 0xA3)
    if probe_slice.len() >= 4 && probe_slice[0..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Some(DeviceIdentification {
            recognized: true,
            vendor: "CCTV Video Container (Matroska / MKV)".to_string(),
            model: Some("EBML Matroska Video Container (.mkv)".to_string()),
            chipset: Some("Surveillance Multi-Track Video Stream".to_string()),
            confidence: 0.92,
            matched_grammar_id: Some("cctv-mkv".to_string()),
            validation_tier: Some(3),
            matched_signature: Some("1A 45 DF A3 (EBML)".to_string()),
            details: vec![
                "Identified Matroska / EBML container header signature".to_string(),
                "Multi-channel surveillance video container".to_string(),
            ],
        });
    }

    // 5. Raw H.264 / AVC or H.265 / HEVC Elementary Stream
    let start_pos = probe_slice[..probe_slice.len().min(4096)]
        .windows(4)
        .position(|w| w == &[0x00, 0x00, 0x00, 0x01])
        .map(|p| (p, 4))
        .or_else(|| {
            probe_slice[..probe_slice.len().min(4096)]
                .windows(3)
                .position(|w| w == &[0x00, 0x00, 0x01])
                .map(|p| (p, 3))
        });

    if let Some((pos, code_len)) = start_pos {
        if probe_slice.len() > pos + code_len {
            let nb = probe_slice[pos + code_len];
            if (nb & 0x80) == 0 {
                let nal_type = nb & 0x1F;
                let hevc_type = (nb >> 1) & 0x3F;

                if (hevc_type == 32 || hevc_type == 33 || hevc_type == 34) && probe_slice.len() > pos + code_len + 1 {
                    return Some(DeviceIdentification {
                        recognized: true,
                        vendor: "Surveillance Video Stream (Raw H.265 / HEVC)".to_string(),
                        model: Some("H.265 / HEVC Elementary Byte Stream".to_string()),
                        chipset: Some("H.265 / HEVC Surveillance Encoder".to_string()),
                        confidence: 0.92,
                        matched_grammar_id: Some("h265-stream".to_string()),
                        validation_tier: Some(3),
                        matched_signature: Some(format!("00 00 00 01 (HEVC Type {})", hevc_type)),
                        details: vec![
                            format!("Identified raw H.265 / HEVC Annex B NAL unit header (Type: {}) at offset 0x{:X}", hevc_type, pos),
                            "Direct elementary bitstream suitable for H.265 carving and frame parsing".to_string(),
                        ],
                    });
                }

                if matches!(nal_type, 1 | 5 | 6 | 7 | 8 | 9) {
                    let type_name = match nal_type {
                        7 => "SPS (Sequence Parameter Set)",
                        8 => "PPS (Picture Parameter Set)",
                        5 => "IDR (Keyframe)",
                        6 => "SEI (Supplemental Enhancement)",
                        9 => "AUD (Access Unit Delimiter)",
                        1 => "Non-IDR Video Slice",
                        _ => "NAL Unit",
                    };
                    return Some(DeviceIdentification {
                        recognized: true,
                        vendor: "Surveillance Video Stream (Raw H.264 / AVC)".to_string(),
                        model: Some("Raw H.264 Elementary Byte Stream (Annex B)".to_string()),
                        chipset: Some("H.264 / AVC Surveillance Encoder".to_string()),
                        confidence: 0.92,
                        matched_grammar_id: Some("h264-stream".to_string()),
                        validation_tier: Some(3),
                        matched_signature: Some(format!("00 00 00 01 0x{:02X} ({})", nb, type_name)),
                        details: vec![
                            format!("Identified raw H.264 Annex B stream starting with {} at offset 0x{:X}", type_name, pos),
                            "Direct elementary bitstream suitable for Screen 3 carving and Screen 4 analytics".to_string(),
                        ],
                    });
                }
            }
        }
    }

    // 6. MPEG-TS (Transport Stream)
    if probe_slice.len() >= 188 * 3 && probe_slice[0] == 0x47 && probe_slice[188] == 0x47 && probe_slice[376] == 0x47 {
        return Some(DeviceIdentification {
            recognized: true,
            vendor: "Surveillance Transport Stream (MPEG-TS)".to_string(),
            model: Some("MPEG-2 Transport Stream (188-byte packets)".to_string()),
            chipset: Some("NVR RTSP / Export Transport Stream".to_string()),
            confidence: 0.88,
            matched_grammar_id: Some("mpegts-stream".to_string()),
            validation_tier: Some(3),
            matched_signature: Some("0x47 (Sync Byte @ 188-byte stride)".to_string()),
            details: vec![
                "Identified MPEG-2 Transport Stream with verified 188-byte sync byte cadence".to_string(),
                "Compatible with TS demuxers and multi-channel extraction".to_string(),
            ],
        });
    }

    // 7. Standard filesystems (investigator loaded external USB / standard disk)
    if probe_slice.len() >= 1082 {
        if &probe_slice[3..7] == b"NTFS" {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: "Standard Filesystem Volume (NTFS)".to_string(),
                model: Some("Windows NT File System (Non-Proprietary DVR / External Drive)".to_string()),
                chipset: Some("PC / Standard Embedded Storage".to_string()),
                confidence: 0.85,
                matched_grammar_id: Some("standard-ntfs".to_string()),
                validation_tier: Some(3),
                matched_signature: Some("NTFS".to_string()),
                details: vec!["Identified NTFS volume boot record".to_string()],
            });
        }
        if probe_slice.len() >= 90 && &probe_slice[82..87] == b"FAT32" {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: "Standard Filesystem Volume (FAT32)".to_string(),
                model: Some("FAT32 Storage Volume (Standard SD Card / USB Backup)".to_string()),
                chipset: Some("Generic Storage Controller".to_string()),
                confidence: 0.85,
                matched_grammar_id: Some("standard-fat32".to_string()),
                validation_tier: Some(3),
                matched_signature: Some("FAT32".to_string()),
                details: vec!["Identified FAT32 volume boot record".to_string()],
            });
        }
        if probe_slice[1080] == 0x53 && probe_slice[1081] == 0xEF {
            return Some(DeviceIdentification {
                recognized: true,
                vendor: "Standard Filesystem Volume (Linux ext4)".to_string(),
                model: Some("Linux ext2/3/4 Standard Superblock".to_string()),
                chipset: Some("Embedded Linux Standard Partition".to_string()),
                confidence: 0.85,
                matched_grammar_id: Some("standard-ext4".to_string()),
                validation_tier: Some(3),
                matched_signature: Some("0x53 0xEF (ext4 magic)".to_string()),
                details: vec!["Identified Linux ext filesystem superblock signature".to_string()],
            });
        }
    }

    // 8. Still Graphic Images (PNG, JPEG, BMP) - CCTV Snapshot / Exported Picture
    if probe_slice.len() >= 8 && probe_slice.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        let (vendor, model, oem_note) = if let Some((oem, model_desc)) = detect_image_metadata_oem(probe_slice) {
            (
                format!("CCTV Snapshot / Export ({})", oem),
                Some(model_desc),
                format!("OEM Identified from embedded metadata: {}", oem),
            )
        } else {
            (
                "Still Graphic Image / CCTV Snapshot (PNG)".to_string(),
                Some("Generic PNG Image (No OEM Tags in Metadata)".to_string()),
                "No OEM brand metadata (Hikvision, CP PLUS, Dahua, etc.) embedded in PNG chunks.".to_string(),
            )
        };

        return Some(DeviceIdentification {
            recognized: true,
            vendor,
            model,
            chipset: Some("Single-Frame Graphic Asset".to_string()),
            confidence: 0.99,
            matched_grammar_id: Some("image-png".to_string()),
            validation_tier: Some(3),
            matched_signature: Some("89 50 4E 47 0D 0A 1A 0A (.PNG)".to_string()),
            details: vec![
                "Identified PNG still image file (CCTV snapshot / picture).".to_string(),
                oem_note,
                "A PNG file is an open W3C bitmap image format (pixel colors), NOT a DVR hard drive filesystem.".to_string(),
                "Proprietary filesystems (e.g. DHFS for CP PLUS/Dahua, HIKVISION for Hikvision) exist on the raw hard disk, not inside exported PNG snapshots.".to_string(),
                "To identify the DVR equipment conclusively, acquire the physical HDD (.img/.raw) or native exported video clip (.dav/.mp4/.h264).".to_string(),
            ],
        });
    }

    if probe_slice.len() >= 3 && probe_slice.starts_with(&[0xFF, 0xD8, 0xFF]) {
        let (vendor, model, oem_note) = if let Some((oem, model_desc)) = detect_image_metadata_oem(probe_slice) {
            (
                format!("CCTV Snapshot / Export ({})", oem),
                Some(model_desc),
                format!("OEM Identified from embedded EXIF metadata: {}", oem),
            )
        } else {
            (
                "Still Graphic Image / CCTV Snapshot (JPEG)".to_string(),
                Some("Generic JPEG Image (No OEM Tags in Metadata)".to_string()),
                "No OEM brand metadata (Hikvision, CP PLUS, Dahua, etc.) embedded in EXIF tags.".to_string(),
            )
        };

        return Some(DeviceIdentification {
            recognized: true,
            vendor,
            model,
            chipset: Some("Single-Frame Graphic Asset".to_string()),
            confidence: 0.99,
            matched_grammar_id: Some("image-jpeg".to_string()),
            validation_tier: Some(3),
            matched_signature: Some("FF D8 FF (JPEG SOI)".to_string()),
            details: vec![
                "Identified JPEG still photo (CCTV snapshot).".to_string(),
                oem_note,
                "A JPEG photo contains compressed pixel data, NOT a DVR hard drive filesystem.".to_string(),
                "To identify the DVR equipment conclusively, acquire the physical HDD (.img/.raw) or native exported video clip (.dav/.mp4/.h264).".to_string(),
            ],
        });
    }

    None
}

/// Scans image header bytes (first 64KB) for ASCII metadata markers of major CCTV OEMs.
fn detect_image_metadata_oem(data: &[u8]) -> Option<(String, String)> {
    let lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    let s = String::from_utf8_lossy(&lower);

    if s.contains("hikvision") || s.contains("hik_") || s.contains("ds-7") || s.contains("ds-8") {
        Some(("Hikvision".to_string(), "Hikvision CCTV Snapshot / Export".to_string()))
    } else if s.contains("cp plus") || s.contains("cpplus") || s.contains("cp-uvr") || s.contains("cp-e") {
        Some(("CP PLUS".to_string(), "CP PLUS CCTV Snapshot / Export".to_string()))
    } else if s.contains("dahua") || s.contains("dhav") || s.contains("dh-") {
        Some(("Dahua Technology".to_string(), "Dahua CCTV Snapshot / Export".to_string()))
    } else if s.contains("uniview") || s.contains("unv") {
        Some(("Uniview (UNV)".to_string(), "Uniview CCTV Snapshot / Export".to_string()))
    } else if s.contains("tiandy") {
        Some(("Tiandy Technologies".to_string(), "Tiandy CCTV Snapshot / Export".to_string()))
    } else if s.contains("hanwha") || s.contains("samsung techwin") || s.contains("wiserec") {
        Some(("Hanwha Techwin (Samsung)".to_string(), "Hanwha CCTV Snapshot / Export".to_string()))
    } else if s.contains("axis") {
        Some(("Axis Communications".to_string(), "Axis Network Camera Snapshot".to_string()))
    } else if s.contains("bosch") {
        Some(("Bosch Security Systems".to_string(), "Bosch CCTV Snapshot".to_string()))
    } else if s.contains("xiongmai") || s.contains("xm_") {
        Some(("Xiongmai (XM)".to_string(), "Xiongmai CCTV Snapshot".to_string()))
    } else {
        None
    }
}

/// Scans container header bytes (first 64KB) for ASCII metadata markers of major CCTV OEMs in video containers (MP4, MKV, AVI).
fn detect_container_oem(probe_slice: &[u8]) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    let lower: Vec<u8> = probe_slice.iter().map(|b| b.to_ascii_lowercase()).collect();
    let s = String::from_utf8_lossy(&lower);

    if s.contains("hikvision") || s.contains("hik_") || s.contains("hik4") || s.contains("ds-7") || s.contains("ds-8") || s.contains("ivms") {
        Some(("Hikvision", "Hikvision Surveillance MP4 Export", "HiSilicon / Embedded CCTV SoC", "hikvision-mp4"))
    } else if s.contains("cp plus") || s.contains("cpplus") || s.contains("cp-uvr") || s.contains("cp-e") || s.contains("gcmob") || s.contains("kvms") {
        Some(("CP PLUS", "CP PLUS Surveillance MP4 Export", "HiSilicon / Custom Embedded SoC", "cctv-mp4"))
    } else if s.contains("dahua") || s.contains("dhav") || s.contains("dh-") || s.contains("smartpss") {
        Some(("Dahua", "Dahua Surveillance MP4 Export", "HiSilicon Hi35xx / Ambarella S2L", "dahua-mp4"))
    } else if s.contains("uniview") || s.contains("unv") {
        Some(("Uniview (UNV)", "Uniview Surveillance MP4 Export", "Grain Media / HiSilicon SoC", "cctv-mp4"))
    } else if s.contains("tiandy") {
        Some(("Tiandy", "Tiandy Surveillance MP4 Export", "Embedded Surveillance SoC", "cctv-mp4"))
    } else if s.contains("hanwha") || s.contains("samsung") || s.contains("wiserec") {
        Some(("Hanwha Techwin (Samsung)", "Hanwha Surveillance MP4 Export", "Wisenet SoC", "cctv-mp4"))
    } else if s.contains("xiongmai") || s.contains("xm_") || s.contains("dvr_") {
        Some(("Xiongmai (XM)", "Xiongmai Surveillance MP4 Export", "HiSilicon / Xiongmai SoC", "cctv-mp4"))
    } else if s.contains("axis") {
        Some(("Axis Communications", "Axis Surveillance MP4 Export", "ARTPEC SoC", "cctv-mp4"))
    } else if s.contains("bosch") {
        Some(("Bosch Security", "Bosch Surveillance MP4 Export", "Bosch Embedded Media Engine", "cctv-mp4"))
    } else {
        None
    }
}

/// Identifies the device vendor, model, chipset family, and confidence score for a raw evidence image or video.
///
/// Multi-step identification methodology:
/// 1. Opens source strictly read-only (zero write syscall risk).
/// 2. Iterates across all declarative format grammars in `grammars_dir` (Tiers 1, 2, 3).
/// 3. Cross-checks `vendor_registry.yaml` for unimplemented OEMs (Tier 0).
/// 4. Checks standard CCTV video containers (MP4, AVI, MKV, TS) and elementary streams (H.264, H.265).
/// 5. Computes calibrated confidence score without false guessing.
pub fn identify_device<P: AsRef<Path>, G: AsRef<Path>>(
    image_path: P,
    grammars_dir: G,
) -> Result<DeviceIdentification> {
    let img_p = image_path.as_ref();
    let g_dir_candidate = grammars_dir.as_ref();

    if !img_p.exists() {
        return Err(IdentificationError::ImageNotFound(img_p.to_path_buf()));
    }

    // Resolve grammars directory with fallbacks
    let g_dir_buf: PathBuf = if g_dir_candidate.exists() {
        g_dir_candidate.to_path_buf()
    } else {
        let candidates = [
            PathBuf::from("../grammars"),
            PathBuf::from("grammars"),
            PathBuf::from("../../grammars"),
            PathBuf::from("scratch/dvr-forensics/grammars"),
            PathBuf::from("C:/Users/HP/.gemini/antigravity/scratch/dvr-forensics/grammars"),
        ];
        candidates
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| g_dir_candidate.to_path_buf())
    };
    let g_dir = &g_dir_buf;

    // Open strictly read-only
    let mut source = ReadOnlySource::open(img_p).map_err(|e| IdentificationError::IoError {
        path: img_p.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
    })?;

    let file_len = source.len();
    if file_len == 0 {
        return Ok(DeviceIdentification::unrecognized());
    }

    // Read up to first 64 KiB of headers into memory for signature testing
    let probe_size = (file_len as usize).min(65536);
    let mut probe_buffer = vec![0u8; probe_size];
    let n_read = source
        .read(&mut probe_buffer)
        .map_err(|e| IdentificationError::IoError {
            path: img_p.to_path_buf(),
            source: e,
        })?;
    let probe_slice = &probe_buffer[..n_read];

    let mut candidate_matches: Vec<DeviceIdentification> = Vec::new();

    // 1. Check declarative format grammars in grammars_dir if exists
    if g_dir.exists() {
        if let Ok(entries) = fs::read_dir(g_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) != Some("yaml") {
                    continue;
                }

                // Skip registry file when reading grammars
                if p.file_name().and_then(|f| f.to_str()) == Some("vendor_registry.yaml") {
                    continue;
                }

                let grammar = match GrammarFile::load_from_file(&p) {
                    Ok(g) => g,
                    Err(_) => continue,
                };

                let mut matched_rules_count = 0;
                let mut max_rule_weight = 0.0f32;
                let mut matched_sig_str = None;

                for rule in &grammar.detection.rules {
                    let expected_bytes = match rule.expected_bytes() {
                        Ok(b) => b,
                        Err(_) => continue,
                    };

                    let rule_end = rule.offset + expected_bytes.len();
                    if probe_slice.len() >= rule_end {
                        if &probe_slice[rule.offset..rule_end] == expected_bytes.as_slice() {
                            matched_rules_count += 1;
                            let weight = rule.weight.unwrap_or(0.80);
                            if weight > max_rule_weight {
                                max_rule_weight = weight;
                                matched_sig_str = rule
                                    .magic_ascii
                                    .clone()
                                    .or_else(|| rule.magic_hex.clone());
                            }
                        }
                    }
                }

                if matched_rules_count > 0 {
                    let multi_rule_bonus = ((matched_rules_count - 1) as f32 * 0.04).min(0.08);
                    let mut confidence = (max_rule_weight + multi_rule_bonus).min(0.99);

                    if let Some(ref sb) = grammar.structures.superblock {
                        if let Some(ref sb_magic) = sb.magic {
                            if let Ok(sb_bytes) = sb_magic.expected_bytes() {
                                let off = sb_magic.offset;
                                if probe_slice.len() >= off + sb_bytes.len()
                                    && &probe_slice[off..off + sb_bytes.len()] == sb_bytes.as_slice()
                                {
                                    confidence = (confidence + 0.02).min(0.99);
                                }
                            }
                        }
                    }

                    let vendor = grammar
                        .grammar
                        .vendor
                        .unwrap_or_else(|| grammar.grammar.name.clone());
                    let model = grammar.grammar.model;
                    let chipset = grammar.grammar.chipset;

                    candidate_matches.push(DeviceIdentification {
                        recognized: true,
                        vendor,
                        model,
                        chipset,
                        confidence,
                        matched_grammar_id: Some(grammar.grammar.id),
                        validation_tier: Some(grammar.grammar.tier),
                        matched_signature: matched_sig_str,
                        details: vec![format!(
                            "Matched {} detection rule(s) in grammar '{}'",
                            matched_rules_count, grammar.grammar.name
                        )],
                    });
                }
            }
        }
    }


    // 2. Check vendor_registry.yaml for known signatures of unimplemented OEMs (Tier 0)
    if let Some(registry) = VendorRegistry::load_from_paths(g_dir) {
        for vendor in &registry.vendors {
            for sig in &vendor.signatures {
                let expected_bytes: Option<Vec<u8>> = if let Some(ref asc) = sig.magic_ascii {
                    Some(asc.as_bytes().to_vec())
                } else if let Some(ref hex_str) = sig.magic_hex {
                    hex::decode(hex_str.replace(' ', "")).ok()
                } else {
                    None
                };

                if let Some(expected) = expected_bytes {
                    let rule_end = sig.offset + expected.len();
                    if probe_slice.len() >= rule_end
                        && &probe_slice[sig.offset..rule_end] == expected.as_slice()
                    {
                        candidate_matches.push(DeviceIdentification {
                            recognized: true,
                            vendor: vendor.name.clone(),
                            model: Some(format!("{} (Format Unimplemented)", vendor.full_name)),
                            chipset: vendor.known_chipsets.first().cloned(),
                            confidence: sig.weight,
                            matched_grammar_id: None,
                            validation_tier: Some(0), // Tier 0: Registry-Only
                            matched_signature: sig.magic_ascii.clone().or_else(|| sig.magic_hex.clone()),
                            details: vec![
                                format!(
                                    "Identified vendor '{}', format not yet implemented (Tier 0: Registry-Only)",
                                    vendor.name
                                ),
                                format!("Claimed Architecture: {}", vendor.claimed_os_filesystem),
                                format!("Known Chipsets: {}", vendor.known_chipsets.join(", ")),
                                format!("Third-party Support: {}", vendor.third_party_tool_support),
                                "Action Required: Refer to docs/vendor-extension-guide.md to author a grammar definition.".to_string(),
                            ],
                        });
                        break;
                    }
                }
            }
        }
    }

    // 3. Check standard CCTV video containers, streams, and filesystems
    if let Some(video_ident) = detect_video_container_or_stream(probe_slice, file_len) {
        candidate_matches.push(video_ident);
    }

    // Sort candidate matches: prioritize active declarative grammars (Tier 1 & 2) first, then registry Tier 0, then container Tier 3
    candidate_matches.sort_by(|a, b| {
        let a_tier_priority = match a.validation_tier {
            Some(1) => 0.20,
            Some(2) => 0.15,
            Some(0) => 0.08,
            _ => 0.0,
        };
        let b_tier_priority = match b.validation_tier {
            Some(1) => 0.20,
            Some(2) => 0.15,
            Some(0) => 0.08,
            _ => 0.0,
        };
        let a_score = a.confidence + a_tier_priority;
        let b_score = b.confidence + b_tier_priority;
        b_score.partial_cmp(&a_score).unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some(best) = candidate_matches.into_iter().next() {
        if best.confidence >= MIN_CONFIDENCE_THRESHOLD {
            return Ok(best);
        }
    }

    // Safe fallback: never guess
    Ok(DeviceIdentification::unrecognized())
}
