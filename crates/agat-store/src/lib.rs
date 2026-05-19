//! Persistent feature store for agat samples and analyzer results.
//!
//! Backed by SQLite via rusqlite. Schema is migrated automatically on
//! [`Store::open`]. Phase 0 only exercised the `samples` table; Phase 1
//! adds insertion and retrieval for analyzer feature bundles.

use agat_core::{Error, FeatureBundle, Result, Sample, SampleId, SampleKind, SampleMetadata};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS samples (
    id              TEXT    PRIMARY KEY,
    kind            TEXT    NOT NULL,
    size            INTEGER NOT NULL,
    metadata_json   TEXT    NOT NULL,
    ingested_at     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS features (
    sample_id       TEXT    NOT NULL,
    analyzer        TEXT    NOT NULL,
    version         TEXT    NOT NULL,
    features_json   TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    PRIMARY KEY (sample_id, analyzer, version),
    FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id       TEXT    NOT NULL,
    analyzer        TEXT    NOT NULL,
    kind            TEXT    NOT NULL,
    blob            BLOB    NOT NULL,
    created_at      TEXT    NOT NULL,
    FOREIGN KEY (sample_id) REFERENCES samples(id)
);

CREATE INDEX IF NOT EXISTS idx_features_sample  ON features(sample_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_sample ON artifacts(sample_id);
"#;

pub struct Store {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct StoredSample {
    pub sample: Sample,
    pub ingested_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct FeatureRecord {
    pub sample_id: SampleId,
    pub analyzer: String,
    pub version: String,
    pub features: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(db_err)?;
        conn.execute_batch(SCHEMA_V1).map_err(db_err)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(db_err)?;
        conn.execute_batch(SCHEMA_V1).map_err(db_err)?;
        Ok(Self { conn })
    }

    pub fn insert_sample(&self, sample: &Sample) -> Result<()> {
        let meta = serde_json::to_string(&sample.metadata)?;
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO samples (id, kind, size, metadata_json, ingested_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sample.id.to_hex(),
                    sample.kind.as_str(),
                    sample.size as i64,
                    meta,
                    now
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get_sample(&self, id: &SampleId) -> Result<Option<StoredSample>> {
        let row = self
            .conn
            .query_row(
                "SELECT kind, size, metadata_json, ingested_at FROM samples WHERE id = ?1",
                params![id.to_hex()],
                |row| {
                    let kind: String = row.get(0)?;
                    let size: i64 = row.get(1)?;
                    let meta: String = row.get(2)?;
                    let ingested: String = row.get(3)?;
                    Ok((kind, size, meta, ingested))
                },
            )
            .optional()
            .map_err(db_err)?;

        match row {
            None => Ok(None),
            Some((kind, size, meta, ingested)) => {
                let metadata: SampleMetadata = serde_json::from_str(&meta)?;
                let ingested_at = parse_ts(&ingested)?;
                Ok(Some(StoredSample {
                    sample: Sample {
                        id: *id,
                        kind: SampleKind::from_str_lenient(&kind),
                        size: size as u64,
                        metadata,
                    },
                    ingested_at,
                }))
            }
        }
    }

    pub fn list_samples(&self) -> Result<Vec<StoredSample>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, size, metadata_json, ingested_at \
                 FROM samples ORDER BY ingested_at DESC",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map([], |row| {
                let id_hex: String = row.get(0)?;
                let kind: String = row.get(1)?;
                let size: i64 = row.get(2)?;
                let meta: String = row.get(3)?;
                let ingested: String = row.get(4)?;
                Ok((id_hex, kind, size, meta, ingested))
            })
            .map_err(db_err)?;

        let mut out = Vec::new();
        for row in rows {
            let (id_hex, kind, size, meta, ingested) = row.map_err(db_err)?;
            let id = SampleId::from_hex(&id_hex)?;
            let metadata: SampleMetadata = serde_json::from_str(&meta)?;
            let ingested_at = parse_ts(&ingested)?;
            out.push(StoredSample {
                sample: Sample {
                    id,
                    kind: SampleKind::from_str_lenient(&kind),
                    size: size as u64,
                    metadata,
                },
                ingested_at,
            });
        }
        Ok(out)
    }

    pub fn count_samples(&self) -> Result<u64> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM samples", [], |row| row.get(0))
            .map_err(db_err)?;
        Ok(n as u64)
    }

    pub fn insert_features(&self, sample_id: &SampleId, bundle: &FeatureBundle) -> Result<()> {
        let features_json = serde_json::to_string(&bundle.features)?;
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT OR REPLACE INTO features \
                 (sample_id, analyzer, version, features_json, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    sample_id.to_hex(),
                    bundle.analyzer,
                    bundle.version,
                    features_json,
                    now
                ],
            )
            .map_err(db_err)?;
        Ok(())
    }

    pub fn get_features(
        &self,
        sample_id: &SampleId,
        analyzer: &str,
    ) -> Result<Option<FeatureRecord>> {
        let row = self
            .conn
            .query_row(
                "SELECT version, features_json, created_at \
                 FROM features WHERE sample_id = ?1 AND analyzer = ?2 \
                 ORDER BY created_at DESC LIMIT 1",
                params![sample_id.to_hex(), analyzer],
                |row| {
                    let version: String = row.get(0)?;
                    let features_json: String = row.get(1)?;
                    let created_at: String = row.get(2)?;
                    Ok((version, features_json, created_at))
                },
            )
            .optional()
            .map_err(db_err)?;
        match row {
            None => Ok(None),
            Some((version, features_json, created_at)) => Ok(Some(FeatureRecord {
                sample_id: *sample_id,
                analyzer: analyzer.to_string(),
                version,
                features: serde_json::from_str(&features_json)?,
                created_at: parse_ts(&created_at)?,
            })),
        }
    }

    pub fn list_features(&self, sample_id: &SampleId) -> Result<Vec<FeatureRecord>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT analyzer, version, features_json, created_at \
                 FROM features WHERE sample_id = ?1 ORDER BY analyzer, version",
            )
            .map_err(db_err)?;
        let rows = stmt
            .query_map(params![sample_id.to_hex()], |row| {
                let analyzer: String = row.get(0)?;
                let version: String = row.get(1)?;
                let features_json: String = row.get(2)?;
                let created_at: String = row.get(3)?;
                Ok((analyzer, version, features_json, created_at))
            })
            .map_err(db_err)?;
        let mut out = Vec::new();
        for row in rows {
            let (analyzer, version, features_json, created_at) = row.map_err(db_err)?;
            out.push(FeatureRecord {
                sample_id: *sample_id,
                analyzer,
                version,
                features: serde_json::from_str(&features_json)?,
                created_at: parse_ts(&created_at)?,
            });
        }
        Ok(out)
    }
}

fn db_err(e: rusqlite::Error) -> Error {
    Error::Database(e.to_string())
}

fn parse_ts(s: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(s)
        .map_err(|e| Error::Database(format!("bad timestamp: {e}")))?
        .with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agat_core::Artifact;
    use serde_json::json;

    fn fixture_sample() -> Sample {
        Sample {
            id: SampleId::from_bytes(b"abc"),
            kind: SampleKind::Pe64,
            size: 3,
            metadata: SampleMetadata {
                original_filename: Some("abc.exe".into()),
                ..Default::default()
            },
        }
    }

    #[test]
    fn insert_and_list() {
        let store = Store::open_in_memory().unwrap();
        store.insert_sample(&fixture_sample()).unwrap();
        let list = store.list_samples().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].sample.id, fixture_sample().id);
    }

    #[test]
    fn count_is_correct() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.count_samples().unwrap(), 0);
        for i in 0..3u8 {
            store
                .insert_sample(&Sample {
                    id: SampleId::from_bytes(&[i]),
                    kind: SampleKind::Unknown,
                    size: 1,
                    metadata: SampleMetadata::default(),
                })
                .unwrap();
        }
        assert_eq!(store.count_samples().unwrap(), 3);
    }

    #[test]
    fn features_round_trip() {
        let store = Store::open_in_memory().unwrap();
        let sample = fixture_sample();
        store.insert_sample(&sample).unwrap();
        let bundle = FeatureBundle {
            analyzer: "static",
            version: "0.1.0",
            features: json!({"size": 42, "format": "Pe"}),
            artifacts: vec![Artifact {
                kind: "placeholder".into(),
                blob: vec![1, 2, 3],
            }],
        };
        store.insert_features(&sample.id, &bundle).unwrap();
        let got = store.get_features(&sample.id, "static").unwrap().unwrap();
        assert_eq!(got.analyzer, "static");
        assert_eq!(got.version, "0.1.0");
        assert_eq!(got.features["size"], 42);
    }
}
