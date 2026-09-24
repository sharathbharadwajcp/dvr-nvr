use crate::error::{ParserError, Result};
use crate::interpreter::ExtractedRecord;
use crate::verify::IntegrityReport;
use recovery::CarvedFrame;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Clone)]
pub struct RecordFilter {
    pub channel_id: Option<u32>,
    pub start_timestamp: Option<u64>,
    pub end_timestamp: Option<u64>,
    pub keyframes_only: bool,
    pub scrambled_only: bool,
    pub descrambled_only: bool,
    pub corrupted_only: bool,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub struct CaseDatabase {
    conn: Connection,
    path: PathBuf,
}

impl CaseDatabase {
    /// Opens or creates an SQLite database in WAL mode at `db_path`.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();
        let conn = Connection::open(&path).map_err(|e| ParserError::DatabaseError {
            path: path.clone(),
            source: e,
        })?;

        // Forensic performance & safety: WAL mode
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(|e| ParserError::DatabaseError {
            path: path.clone(),
            source: e,
        })?;

        let db = Self { conn, path };
        db.initialize_schema()?;

        Ok(db)
    }

    fn initialize_schema(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS evidence_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    source_path TEXT NOT NULL,
                    whole_image_sha256 TEXT NOT NULL,
                    whole_image_md5 TEXT NOT NULL,
                    block_size INTEGER NOT NULL,
                    block_count INTEGER NOT NULL,
                    grammar_id TEXT NOT NULL,
                    validation_tier INTEGER NOT NULL,
                    acquired_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS extracted_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence_items(id),
                    block_index INTEGER NOT NULL,
                    byte_offset INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    normalized_timestamp TEXT NOT NULL,
                    sequence_num INTEGER NOT NULL,
                    payload_offset INTEGER NOT NULL,
                    payload_len INTEGER NOT NULL,
                    flags INTEGER NOT NULL,
                    is_scrambled INTEGER NOT NULL,
                    is_corrupted INTEGER NOT NULL,
                    block_type TEXT NOT NULL,
                    blake3_hash TEXT NOT NULL,
                    descrambled INTEGER NOT NULL DEFAULT 0,
                    descrambled_blake3_hash TEXT
                );

                CREATE TABLE IF NOT EXISTS carved_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence_items(id),
                    byte_offset INTEGER NOT NULL,
                    length INTEGER NOT NULL,
                    nal_type TEXT NOT NULL,
                    is_keyframe INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    blake3_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS verification_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_name TEXT NOT NULL,
                    evidence_path TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    is_pristine INTEGER NOT NULL,
                    whole_image_sha256_match INTEGER NOT NULL,
                    whole_image_md5_match INTEGER NOT NULL,
                    matched_blocks INTEGER NOT NULL,
                    total_blocks INTEGER NOT NULL,
                    block_discrepancies_count INTEGER NOT NULL,
                    db_discrepancies_count INTEGER NOT NULL,
                    details_json TEXT
                );

                CREATE TABLE IF NOT EXISTS correlated_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence_items(id),
                    event_type TEXT NOT NULL,
                    start_timestamp TEXT NOT NULL,
                    end_timestamp TEXT NOT NULL,
                    channels_involved TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS analytics_detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id INTEGER NOT NULL REFERENCES evidence_items(id),
                    block_index INTEGER NOT NULL,
                    channel_id INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    normalized_timestamp TEXT NOT NULL,
                    motion_energy REAL NOT NULL,
                    relevance_score REAL NOT NULL,
                    entity_class TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    bbox_json TEXT NOT NULL,
                    attributes_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_records_channel ON extracted_records(evidence_id, channel_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_records_block ON extracted_records(evidence_id, block_index);
                CREATE INDEX IF NOT EXISTS idx_carved_offset ON carved_records(evidence_id, byte_offset);
                CREATE INDEX IF NOT EXISTS idx_correlated_type ON correlated_events(evidence_id, event_type);
                CREATE INDEX IF NOT EXISTS idx_analytics_relevance ON analytics_detections(evidence_id, relevance_score DESC);
                CREATE INDEX IF NOT EXISTS idx_analytics_channel ON analytics_detections(evidence_id, channel_id, timestamp);",
            )
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        Ok(())
    }

    /// Records a case, evidence item, and all extracted block records in a single transaction.
    pub fn store_case_extraction(
        &mut self,
        case_name: &str,
        source_path: &str,
        whole_image_sha256: &str,
        whole_image_md5: &str,
        block_size: usize,
        block_count: usize,
        grammar_id: &str,
        validation_tier: u8,
        acquired_at: &str,
        records: &[ExtractedRecord],
    ) -> Result<(i64, i64)> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        // 1. Upsert case
        tx.execute(
            "INSERT INTO cases (case_name, created_at, notes)
             VALUES (?1, datetime('now'), 'Auto-created by dvrft parse')
             ON CONFLICT(case_name) DO NOTHING;",
            params![case_name],
        )
        .map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        let case_id: i64 = tx
            .query_row(
                "SELECT id FROM cases WHERE case_name = ?1;",
                params![case_name],
                |row| row.get(0),
            )
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        // 2. Insert evidence item
        tx.execute(
            "INSERT INTO evidence_items (case_id, source_path, whole_image_sha256, whole_image_md5, block_size, block_count, grammar_id, validation_tier, acquired_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);",
            params![
                case_id,
                source_path,
                whole_image_sha256,
                whole_image_md5,
                block_size as i64,
                block_count as i64,
                grammar_id,
                validation_tier as i64,
                acquired_at
            ],
        )
        .map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        let evidence_id = tx.last_insert_rowid();

        // 3. Batch insert extracted records
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO extracted_records (
                        evidence_id, block_index, byte_offset, channel_id, timestamp,
                        normalized_timestamp, sequence_num, payload_offset, payload_len, flags, is_scrambled,
                        is_corrupted, block_type, blake3_hash, descrambled, descrambled_blake3_hash
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16);",
                )
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;

            for r in records {
                stmt.execute(params![
                    evidence_id,
                    r.block_index as i64,
                    r.byte_offset as i64,
                    r.channel_id as i64,
                    r.timestamp as i64,
                    r.normalized_timestamp,
                    r.sequence_num as i64,
                    r.payload_offset as i64,
                    r.payload_len as i64,
                    r.flags as i64,
                    if r.is_scrambled { 1 } else { 0 },
                    if r.is_corrupted { 1 } else { 0 },
                    r.block_type,
                    r.blake3_hash,
                    if r.descrambled { 1 } else { 0 },
                    r.descrambled_blake3_hash
                ])
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;
            }
        }

        tx.commit().map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        Ok((case_id, evidence_id))
    }

    /// Stores carved frames in `carved_records`.
    pub fn store_carved_records(
        &mut self,
        evidence_id: i64,
        frames: &[CarvedFrame],
    ) -> Result<usize> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO carved_records (evidence_id, byte_offset, length, nal_type, is_keyframe, confidence, blake3_hash)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
                )
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;

            for f in frames {
                stmt.execute(params![
                    evidence_id,
                    f.byte_offset as i64,
                    f.length as i64,
                    f.nal_type,
                    if f.is_keyframe { 1 } else { 0 },
                    f.confidence,
                    f.blake3_hash
                ])
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;
            }
        }

        tx.commit().map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        Ok(frames.len())
    }

    /// Queries carved records for an evidence item (or all).
    pub fn query_carved_records(
        &self,
        evidence_id: Option<i64>,
    ) -> Result<Vec<CarvedFrame>> {
        let sql = match evidence_id {
            Some(_) => "SELECT byte_offset, length, nal_type, is_keyframe, confidence, blake3_hash FROM carved_records WHERE evidence_id = ?1 ORDER BY byte_offset ASC;",
            None => "SELECT byte_offset, length, nal_type, is_keyframe, confidence, blake3_hash FROM carved_records ORDER BY byte_offset ASC;",
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mapper = |row: &rusqlite::Row| {
            Ok(CarvedFrame {
                byte_offset: row.get::<_, i64>(0)? as u64,
                length: row.get::<_, i64>(1)? as usize,
                nal_type: row.get(2)?,
                is_keyframe: row.get::<_, i64>(3)? == 1,
                confidence: row.get(4)?,
                blake3_hash: row.get(5)?,
            })
        };

        let rows = if let Some(eid) = evidence_id {
            stmt.query_map(params![eid], mapper)
        } else {
            stmt.query_map([], mapper)
        }
        .map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?);
        }

        Ok(results)
    }

    /// Logs an integrity verification audit event.
    pub fn log_verification_audit(&mut self, report: &IntegrityReport) -> Result<()> {
        let details_json = serde_json::to_string(report).unwrap_or_default();
        self.conn
            .execute(
                "INSERT INTO verification_audit_log (
                    case_name, evidence_path, verified_at, is_pristine,
                    whole_image_sha256_match, whole_image_md5_match, matched_blocks,
                    total_blocks, block_discrepancies_count, db_discrepancies_count, details_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);",
                params![
                    report.case_name,
                    report.evidence_path,
                    report.audit_timestamp,
                    if report.is_pristine { 1 } else { 0 },
                    if report.whole_image_sha256_match { 1 } else { 0 },
                    if report.whole_image_md5_match { 1 } else { 0 },
                    report.matched_blocks as i64,
                    report.total_blocks as i64,
                    report.block_discrepancies.len() as i64,
                    report.db_record_discrepancies.len() as i64,
                    details_json
                ],
            )
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        Ok(())
    }

    /// Retrieves all extracted records sorted by block index.
    pub fn query_all_records(&self) -> Result<Vec<ExtractedRecord>> {
        self.query_records(&RecordFilter::default())
    }

    /// Queries extracted records with comprehensive filtering capabilities.
    pub fn query_records(&self, filter: &RecordFilter) -> Result<Vec<ExtractedRecord>> {
        let mut query = String::from(
            "SELECT block_index, byte_offset, channel_id, timestamp, normalized_timestamp,
                    sequence_num, payload_offset, payload_len, flags, is_scrambled,
                    is_corrupted, block_type, blake3_hash, descrambled, descrambled_blake3_hash
             FROM extracted_records WHERE 1=1"
        );

        let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(ch) = filter.channel_id {
            query.push_str(" AND channel_id = ?");
            params_vec.push((ch as i64).into());
        }

        if let Some(start_ts) = filter.start_timestamp {
            query.push_str(" AND timestamp >= ?");
            params_vec.push((start_ts as i64).into());
        }

        if let Some(end_ts) = filter.end_timestamp {
            query.push_str(" AND timestamp <= ?");
            params_vec.push((end_ts as i64).into());
        }

        if filter.keyframes_only {
            query.push_str(" AND (flags & 1) != 0");
        }

        if filter.scrambled_only {
            query.push_str(" AND is_scrambled = 1");
        }

        if filter.descrambled_only {
            query.push_str(" AND descrambled = 1");
        }

        if filter.corrupted_only {
            query.push_str(" AND is_corrupted = 1");
        }

        query.push_str(" ORDER BY block_index ASC");

        if let Some(limit) = filter.limit {
            query.push_str(&format!(" LIMIT {}", limit));
            if let Some(offset) = filter.offset {
                query.push_str(&format!(" OFFSET {}", offset));
            }
        }

        let mut stmt = self
            .conn
            .prepare(&query)
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let rusqlite_params: Vec<&dyn rusqlite::types::ToSql> = params_vec
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();

        let rows = stmt
            .query_map(rusqlite_params.as_slice(), |row| {
                Ok(ExtractedRecord {
                    block_index: row.get::<_, i64>(0)? as usize,
                    byte_offset: row.get::<_, i64>(1)? as u64,
                    channel_id: row.get::<_, i64>(2)? as u32,
                    timestamp: row.get::<_, i64>(3)? as u64,
                    normalized_timestamp: row.get(4)?,
                    sequence_num: row.get::<_, i64>(5)? as u32,
                    payload_offset: row.get::<_, i64>(6)? as u64,
                    payload_len: row.get::<_, i64>(7)? as usize,
                    flags: row.get::<_, i64>(8)? as u16,
                    is_scrambled: row.get::<_, i64>(9)? == 1,
                    is_corrupted: row.get::<_, i64>(10)? == 1,
                    block_type: row.get(11)?,
                    blake3_hash: row.get(12)?,
                    descrambled: row.get::<_, i64>(13)? == 1,
                    descrambled_blake3_hash: row.get(14)?,
                })
            })
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mut records = Vec::new();
        for r in rows {
            records.push(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?);
        }

        Ok(records)
    }

    /// Fetches the primary evidence item ID, if any.
    pub fn get_primary_evidence_id(&self) -> Result<Option<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM evidence_items LIMIT 1;")
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mut rows = stmt
            .query_map([], |row| row.get::<_, i64>(0))
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        if let Some(r) = rows.next() {
            Ok(Some(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?))
        } else {
            Ok(None)
        }
    }

    /// Fetches the primary evidence item grammar_id and validation_tier.
    pub fn get_primary_evidence_grammar_and_tier(&self) -> Result<Option<(String, u8)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT grammar_id, validation_tier FROM evidence_items LIMIT 1;")
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mut rows = stmt
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, u8>(1)?)))
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        if let Some(r) = rows.next() {
            Ok(Some(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?))
        } else {
            Ok(None)
        }
    }

    /// Stores correlated multi-camera events into `correlated_events`.
    pub fn store_correlated_events(
        &mut self,
        evidence_id: i64,
        events: &[CorrelatedDbEvent],
    ) -> Result<usize> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO correlated_events (evidence_id, event_type, start_timestamp, end_timestamp, channels_involved, confidence, details_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
                )
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;

            for ev in events {
                stmt.execute(params![
                    evidence_id,
                    ev.event_type,
                    ev.start_timestamp,
                    ev.end_timestamp,
                    ev.channels_involved,
                    ev.confidence,
                    ev.details_json
                ])
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;
            }
        }

        tx.commit().map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        Ok(events.len())
    }

    /// Queries correlated multi-camera events for an evidence item (or all).
    pub fn query_correlated_events(
        &self,
        evidence_id: Option<i64>,
    ) -> Result<Vec<CorrelatedDbEvent>> {
        let sql = match evidence_id {
            Some(_) => "SELECT id, event_type, start_timestamp, end_timestamp, channels_involved, confidence, details_json FROM correlated_events WHERE evidence_id = ?1 ORDER BY id ASC;",
            None => "SELECT id, event_type, start_timestamp, end_timestamp, channels_involved, confidence, details_json FROM correlated_events ORDER BY id ASC;",
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mapper = |row: &rusqlite::Row| {
            Ok(CorrelatedDbEvent {
                id: Some(row.get(0)?),
                event_type: row.get(1)?,
                start_timestamp: row.get(2)?,
                end_timestamp: row.get(3)?,
                channels_involved: row.get(4)?,
                confidence: row.get(5)?,
                details_json: row.get(6)?,
            })
        };

        let rows = if let Some(eid) = evidence_id {
            stmt.query_map(params![eid], mapper)
        } else {
            stmt.query_map([], mapper)
        }
        .map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?);
        }

        Ok(results)
    }

    /// Stores AI analytics detections into `analytics_detections`.
    pub fn store_analytics_detections(
        &mut self,
        evidence_id: i64,
        detections: &[AnalyticsDbDetection],
    ) -> Result<usize> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO analytics_detections (
                        evidence_id, block_index, channel_id, timestamp, normalized_timestamp,
                        motion_energy, relevance_score, entity_class, confidence, bbox_json, attributes_json
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11);",
                )
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;

            for d in detections {
                stmt.execute(params![
                    evidence_id,
                    d.block_index as i64,
                    d.channel_id as i64,
                    d.timestamp as i64,
                    d.normalized_timestamp,
                    d.motion_energy,
                    d.relevance_score,
                    d.entity_class,
                    d.confidence,
                    d.bbox_json,
                    d.attributes_json
                ])
                .map_err(|e| ParserError::DatabaseError {
                    path: self.path.clone(),
                    source: e,
                })?;
            }
        }

        tx.commit().map_err(|e| ParserError::DatabaseError {
            path: self.path.clone(),
            source: e,
        })?;

        Ok(detections.len())
    }

    /// Queries analytics detections filtered by minimum relevance, confidence, or entity class.
    pub fn query_analytics_detections(
        &self,
        evidence_id: Option<i64>,
        min_relevance: f64,
        min_confidence: f64,
        entity_class: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<AnalyticsDbDetection>> {
        let mut query = String::from(
            "SELECT id, block_index, channel_id, timestamp, normalized_timestamp,
                    motion_energy, relevance_score, entity_class, confidence, bbox_json, attributes_json
             FROM analytics_detections
             WHERE relevance_score >= ?1 AND confidence >= ?2"
        );

        let mut params_vec: Vec<rusqlite::types::Value> = vec![
            min_relevance.into(),
            min_confidence.into(),
        ];

        if let Some(eid) = evidence_id {
            query.push_str(" AND evidence_id = ?");
            params_vec.push(eid.into());
        }

        if let Some(cls) = entity_class {
            query.push_str(" AND entity_class = ?");
            params_vec.push(cls.to_string().into());
        }

        query.push_str(" ORDER BY relevance_score DESC, timestamp ASC");

        if let Some(lim) = limit {
            query.push_str(&format!(" LIMIT {}", lim));
        }

        let mut stmt = self
            .conn
            .prepare(&query)
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let rusqlite_params: Vec<&dyn rusqlite::types::ToSql> = params_vec
            .iter()
            .map(|v| v as &dyn rusqlite::types::ToSql)
            .collect();

        let rows = stmt
            .query_map(rusqlite_params.as_slice(), |row| {
                Ok(AnalyticsDbDetection {
                    id: Some(row.get(0)?),
                    block_index: row.get::<_, i64>(1)? as usize,
                    channel_id: row.get::<_, i64>(2)? as u32,
                    timestamp: row.get::<_, i64>(3)? as u64,
                    normalized_timestamp: row.get(4)?,
                    motion_energy: row.get(5)?,
                    relevance_score: row.get(6)?,
                    entity_class: row.get(7)?,
                    confidence: row.get(8)?,
                    bbox_json: row.get(9)?,
                    attributes_json: row.get(10)?,
                })
            })
            .map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(|e| ParserError::DatabaseError {
                path: self.path.clone(),
                source: e,
            })?);
        }

        Ok(results)
    }
}

/// Represents a correlated multi-camera event or anomaly stored in the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CorrelatedDbEvent {
    pub id: Option<i64>,
    pub event_type: String,
    pub start_timestamp: String,
    pub end_timestamp: String,
    pub channels_involved: String,
    pub confidence: f64,
    pub details_json: String,
}

/// Represents an AI video analytics detection stored in the database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct AnalyticsDbDetection {
    pub id: Option<i64>,
    pub block_index: usize,
    pub channel_id: u32,
    pub timestamp: u64,
    pub normalized_timestamp: String,
    pub motion_energy: f64,
    pub relevance_score: f64,
    pub entity_class: String,
    pub confidence: f64,
    pub bbox_json: String,
    pub attributes_json: String,
}
