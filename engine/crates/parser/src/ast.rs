use crate::error::{ParserError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

/// Root structure of a declarative YAML format grammar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarFile {
    pub grammar: GrammarMetadata,
    pub detection: DetectionSection,
    pub structures: StructureSection,
}

impl GrammarFile {
    /// Loads and compiles a YAML grammar file into memory.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        let file = File::open(p).map_err(|e| ParserError::GrammarIoError {
            path: p.to_path_buf(),
            source: e,
        })?;

        let grammar: Self = serde_yaml::from_reader(file).map_err(|e| ParserError::GrammarParseError {
            path: p.to_path_buf(),
            source: e,
        })?;

        Ok(grammar)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarMetadata {
    pub id: String,
    pub name: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub chipset: Option<String>,
    pub descramble_plugin: Option<String>,
    pub version: String,
    pub tier: u8,
    pub description: String,
    pub citations: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSection {
    pub rules: Vec<DetectionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub offset: usize,
    pub magic_ascii: Option<String>,
    pub magic_hex: Option<String>,
    pub weight: Option<f32>,
    pub model_hint: Option<String>,
}

impl DetectionRule {
    /// Returns the expected raw byte signature for this detection rule.
    pub fn expected_bytes(&self) -> Result<Vec<u8>> {
        if let Some(ref hex_str) = self.magic_hex {
            hex::decode(hex_str).map_err(|_| ParserError::InvalidMagicRule {
                grammar_id: format!("Invalid hex: {}", hex_str),
            })
        } else if let Some(ref ascii_str) = self.magic_ascii {
            Ok(unescape_ascii(ascii_str))
        } else {
            Err(ParserError::InvalidMagicRule {
                grammar_id: "Missing magic_hex and magic_ascii".to_string(),
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructureSection {
    pub superblock: Option<SuperblockDef>,
    pub partition_table: Option<PartitionTableDef>,
    pub video_block: VideoBlockDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuperblockDef {
    pub offset: usize,
    pub size: usize,
    pub magic: Option<MagicDef>,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionTableDef {
    pub offset: usize,
    pub size: usize,
    pub magic: Option<MagicDef>,
    pub entries: Option<PartitionEntriesDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionEntriesDef {
    pub offset: usize,
    pub entry_size: usize,
    pub max_entries: Option<usize>,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoBlockDef {
    pub fixed_size: usize,
    pub header: VideoHeaderDef,
    pub payload: VideoPayloadDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoHeaderDef {
    pub size: usize,
    pub magic: MagicDef,
    pub fields: Vec<FieldDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoPayloadDef {
    pub offset: usize,
    pub length_field: Option<String>,
    pub default_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicDef {
    pub offset: usize,
    pub bytes_ascii: Option<String>,
    pub bytes_hex: Option<String>,
}

impl MagicDef {
    pub fn expected_bytes(&self) -> Result<Vec<u8>> {
        if let Some(ref hex_str) = self.bytes_hex {
            hex::decode(hex_str).map_err(|_| ParserError::InvalidMagicRule {
                grammar_id: format!("Invalid hex in magic: {}", hex_str),
            })
        } else if let Some(ref ascii_str) = self.bytes_ascii {
            Ok(unescape_ascii(ascii_str))
        } else {
            Err(ParserError::InvalidMagicRule {
                grammar_id: "MagicDef missing bytes_hex and bytes_ascii".to_string(),
            })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub offset: usize,
    pub endian: Option<String>,
    pub size: Option<usize>,
    pub role: Option<String>,
    pub encoding: Option<String>,
    pub timezone: Option<String>,
    pub flag_masks: Option<HashMap<String, u32>>,
}

/// Unescapes common ASCII escape sequences like \x00, \n, \r, \t.
pub fn unescape_ascii(input: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let h1 = chars.next().unwrap_or('0');
                    let h2 = chars.next().unwrap_or('0');
                    let hex_str = format!("{}{}", h1, h2);
                    if let Ok(b) = u8::from_str_radix(&hex_str, 16) {
                        bytes.push(b);
                    }
                }
                Some('0') => bytes.push(0),
                Some('n') => bytes.push(b'\n'),
                Some('r') => bytes.push(b'\r'),
                Some('t') => bytes.push(b'\t'),
                Some('\\') => bytes.push(b'\\'),
                Some(other) => {
                    bytes.push(b'\\');
                    bytes.push(other as u8);
                }
                None => bytes.push(b'\\'),
            }
        } else {
            bytes.push(c as u8);
        }
    }

    bytes
}
