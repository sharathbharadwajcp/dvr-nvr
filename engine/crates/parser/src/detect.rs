use crate::ast::GrammarFile;
use crate::error::{ParserError, Result};
use std::fs::{read_dir, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Scans the given `grammars_dir` for `.yaml` files, tests each against the initial bytes
/// of `evidence_path`, and returns the matching grammar file.
pub fn detect_grammar<P: AsRef<Path>, G: AsRef<Path>>(
    evidence_path: P,
    grammars_dir: G,
) -> Result<(GrammarFile, PathBuf)> {
    let ev_path = evidence_path.as_ref();
    let g_dir = grammars_dir.as_ref();

    // Read up to 64 KiB of evidence header bytes for detection
    let mut file = File::open(ev_path)?;
    let mut header_buf = vec![0u8; 65536];
    let n = file.read(&mut header_buf)?;
    let evidence_header = &header_buf[..n];

    let mut matches = Vec::new();

    let entries = read_dir(g_dir).map_err(|e| ParserError::GrammarIoError {
        path: g_dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            if let Ok(grammar) = GrammarFile::load_from_file(&path) {
                if matches_grammar(&grammar, evidence_header) {
                    matches.push((grammar, path));
                }
            }
        }
    }

    if matches.is_empty() {
        return Err(ParserError::DetectionFailed {
            evidence_path: ev_path.to_path_buf(),
            grammars_dir: g_dir.to_path_buf(),
        });
    }

    // Sort matches: prefer highest validation tier, then more specific rules count
    matches.sort_by(|a, b| {
        b.0.grammar
            .tier
            .cmp(&a.0.grammar.tier)
            .then_with(|| b.0.detection.rules.len().cmp(&a.0.detection.rules.len()))
    });

    Ok(matches.into_iter().next().unwrap())
}

/// Checks whether an evidence header matches all detection rules of a grammar.
pub fn matches_grammar(grammar: &GrammarFile, header: &[u8]) -> bool {
    if grammar.detection.rules.is_empty() {
        return false;
    }

    for rule in &grammar.detection.rules {
        let expected = match rule.expected_bytes() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let start = rule.offset;
        let end = start + expected.len();

        if header.len() < end {
            return false;
        }

        if &header[start..end] != expected.as_slice() {
            return false;
        }
    }

    true
}
