use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Cursor},
    path::Path,
};

pub fn sync(db_path: &Path, report: &Path) -> Result<Value> {
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, report TEXT NOT NULL, upstream_hash TEXT, local_hash TEXT, synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS work_items (id TEXT PRIMARY KEY, run_id INTEGER NOT NULL, action TEXT, priority TEXT, confidence TEXT, payload TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT, FOREIGN KEY(run_id) REFERENCES runs(id)); CREATE INDEX IF NOT EXISTS work_items_queue ON work_items(resolved_at, priority, id);")?;
    let manifest: Value = serde_json::from_slice(&fs::read(report.join("llm-manifest.json"))?)?;
    let hashes = &manifest["inputHashes"];
    let previous_unresolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_items WHERE resolved_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO runs(report, upstream_hash, local_hash) VALUES (?1,?2,?3)",
        params![
            report.to_string_lossy(),
            hashes["upstream"].as_str(),
            hashes["local"]
                .as_str()
                .or_else(|| hashes["reproduction"].as_str())
        ],
    )?;
    let run_id = conn.last_insert_rowid();
    let file = fs::File::open(report.join("llm-work-items.jsonl"))?;
    let tx = conn.unchecked_transaction()?;
    let mut seen = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let item: Value = serde_json::from_str(&line)?;
        let id = item["id"].as_str().context("work item has no id")?;
        tx.execute("INSERT INTO work_items(id,run_id,action,priority,confidence,payload,last_seen,resolved_at) VALUES (?1,?2,?3,?4,?5,?6,CURRENT_TIMESTAMP,NULL) ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id, action=excluded.action, priority=excluded.priority, confidence=excluded.confidence, payload=excluded.payload, last_seen=CURRENT_TIMESTAMP, resolved_at=NULL", params![id, run_id, item["action"].as_str(), item["priority"].as_str(), item["confidence"].as_str(), line])?;
        seen += 1;
    }
    tx.execute(
        "UPDATE work_items SET resolved_at=CURRENT_TIMESTAMP WHERE run_id <> ?1 AND resolved_at IS NULL",
        params![run_id],
    )?;
    tx.commit()?;
    let remaining: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_items WHERE resolved_at IS NULL",
        [],
        |row| row.get(0),
    )?;
    let new_items = (remaining - previous_unresolved).max(0);
    let resolved = (previous_unresolved - remaining).max(0);
    // Reopened items are represented by their stable id becoming unresolved
    // again; counting them requires retaining a per-run event table. Keep the
    // field explicit and conservative until that event history is requested.
    let reopened = 0i64;
    Ok(
        serde_json::json!({"schema":"project-parity/state-sync-v1","runId":run_id,"workItems":seen,"new":new_items,"resolved":resolved,"reopened":reopened,"remaining":remaining,"db":db_path}),
    )
}

pub fn next(db_path: &Path, limit: usize) -> Result<Value> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare("SELECT id, action, priority, confidence, payload FROM work_items WHERE resolved_at IS NULL ORDER BY CASE priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 ELSE 2 END, id LIMIT ?1")?;
    let rows = stmt
        .query_map(params![limit as i64], |row| {
            let payload: String = row.get(4)?;
            serde_json::from_str::<Value>(&payload)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({"schema":"project-parity/state-next-v1","count":rows.len(),"items":rows}))
}

pub fn runs(db_path: &Path, limit: usize) -> Result<Value> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare(
        "SELECT id, report, upstream_hash, local_hash, synced_at FROM runs ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "report": row.get::<_, String>(1)?,
                "upstreamHash": row.get::<_, Option<String>>(2)?,
                "localHash": row.get::<_, Option<String>>(3)?,
                "syncedAt": row.get::<_, String>(4)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({"schema":"project-parity/state-runs-v1","count":rows.len(),"runs":rows}))
}

pub fn import_graph(db_path: &Path, artifact: &Path) -> Result<Value> {
    let mut conn = Connection::open(db_path)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS graph_nodes (id TEXT PRIMARY KEY, side TEXT NOT NULL, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS graph_edges (id TEXT PRIMARY KEY, side TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL, dynamic INTEGER NOT NULL, label TEXT, payload TEXT NOT NULL); CREATE INDEX IF NOT EXISTS graph_edges_source ON graph_edges(source); CREATE INDEX IF NOT EXISTS graph_edges_target ON graph_edges(target);")?;
    let input = fs::File::open(artifact).with_context(|| format!("open {}", artifact.display()))?;
    // The artifact is a concatenation of independent zstd frames.  Decode
    // the bounded compressed corpus once, then stream records into SQLite;
    // unlike the graph tables, no parsed node/edge collection is retained.
    let decoded = zstd::stream::decode_all(input)?;
    let tx = conn.transaction()?;
    let mut nodes = 0usize;
    let mut edges = 0usize;
    for line in BufReader::new(Cursor::new(decoded)).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: Value = serde_json::from_str(&line)?;
        match record["recordType"].as_str() {
            Some("node") => {
                let node = &record["node"];
                let id = node["id"].as_str().context("graph node has no id")?;
                tx.execute(
                    "INSERT OR REPLACE INTO graph_nodes(id,side,payload) VALUES (?1,?2,?3)",
                    params![id, record["side"].as_str(), serde_json::to_string(node)?],
                )?;
                nodes += 1;
            }
            Some("edge") => {
                let edge = &record["edge"];
                let id = format!(
                    "{}:{}:{}:{}:{}",
                    record["side"].as_str().unwrap_or(""),
                    edge["source"],
                    edge["target"],
                    edge["kind"],
                    edge["label"]
                );
                tx.execute("INSERT OR REPLACE INTO graph_edges(id,side,source,target,kind,dynamic,label,payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![id, record["side"].as_str(), edge["source"].as_str(), edge["target"].as_str(), edge["kind"].as_str(), edge["dynamic"].as_bool().unwrap_or(false), edge["label"].as_str(), serde_json::to_string(edge)?])?;
                edges += 1;
            }
            _ => {}
        }
    }
    tx.commit()?;
    Ok(
        serde_json::json!({"schema":"project-parity/graph-import-v1","nodes":nodes,"edges":edges,"db":db_path}),
    )
}

/// Import a CodeGraph SQLite snapshot as supplementary navigation evidence.
/// IDs are namespaced so CodeGraph can never overwrite authoritative Oxc
/// nodes, and the payload retains the original symbol metadata verbatim.
pub fn import_codegraph(db_path: &Path, source_db: &Path, side: &str) -> Result<Value> {
    let source = Connection::open(source_db)
        .with_context(|| format!("open CodeGraph database {}", source_db.display()))?;
    let mut target = Connection::open(db_path)
        .with_context(|| format!("open state database {}", db_path.display()))?;
    target.execute_batch("CREATE TABLE IF NOT EXISTS graph_nodes (id TEXT PRIMARY KEY, side TEXT NOT NULL, payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS graph_edges (id TEXT PRIMARY KEY, side TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL, kind TEXT NOT NULL, dynamic INTEGER NOT NULL, label TEXT, payload TEXT NOT NULL); CREATE INDEX IF NOT EXISTS graph_edges_source ON graph_edges(source); CREATE INDEX IF NOT EXISTS graph_edges_target ON graph_edges(target);")?;
    let tx = target.transaction()?;
    let mut nodes_stmt = source.prepare(
        "SELECT id, kind, name, qualified_name, file_path, language, start_line, end_line, start_column, end_column, docstring, signature, visibility, is_exported, is_async, is_static, is_abstract, decorators, type_parameters, updated_at, return_type FROM nodes ORDER BY id",
    )?;
    let node_rows = nodes_stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            serde_json::json!({
                "id": row.get::<_, String>(0)?,
                "kind": row.get::<_, String>(1)?,
                "name": row.get::<_, String>(2)?,
                "qualifiedName": row.get::<_, String>(3)?,
                "file": row.get::<_, String>(4)?,
                "language": row.get::<_, String>(5)?,
                "startLine": row.get::<_, i64>(6)?,
                "endLine": row.get::<_, i64>(7)?,
                "startColumn": row.get::<_, i64>(8)?,
                "endColumn": row.get::<_, i64>(9)?,
                "docstring": row.get::<_, Option<String>>(10)?,
                "signature": row.get::<_, Option<String>>(11)?,
                "visibility": row.get::<_, Option<String>>(12)?,
                "exported": row.get::<_, bool>(13)?,
                "async": row.get::<_, bool>(14)?,
                "static": row.get::<_, bool>(15)?,
                "abstract": row.get::<_, bool>(16)?,
                "decorators": row.get::<_, Option<String>>(17)?,
                "typeParameters": row.get::<_, Option<String>>(18)?,
                "updatedAt": row.get::<_, i64>(19)?,
                "returnType": row.get::<_, Option<String>>(20)?,
            }),
        ))
    })?;
    let mut nodes = 0usize;
    for row in node_rows {
        let (id, payload) = row?;
        let namespaced = format!("codegraph:{side}:{id}");
        tx.execute(
            "INSERT OR REPLACE INTO graph_nodes(id,side,payload) VALUES (?1,?2,?3)",
            params![
                namespaced,
                format!("codegraph-{side}"),
                serde_json::to_string(&payload)?
            ],
        )?;
        nodes += 1;
    }
    let mut edges_stmt = source.prepare(
        "SELECT id, source, target, kind, metadata, line, col, provenance FROM edges ORDER BY id",
    )?;
    let edge_rows = edges_stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<String>>(7)?,
        ))
    })?;
    let mut edges = 0usize;
    for row in edge_rows {
        let (id, source_id, target_id, kind, metadata, line, col, provenance) = row?;
        let source_id = format!("codegraph:{side}:{source_id}");
        let target_id = format!("codegraph:{side}:{target_id}");
        let edge_id = format!("codegraph:{side}:{id}");
        let payload = serde_json::json!({"id": id, "source": source_id, "target": target_id, "kind": kind, "metadata": metadata, "line": line, "column": col, "provenance": provenance});
        tx.execute(
            "INSERT OR REPLACE INTO graph_edges(id,side,source,target,kind,dynamic,label,payload) VALUES (?1,?2,?3,?4,?5,0,NULL,?6)",
            params![edge_id, format!("codegraph-{side}"), source_id, target_id, kind, serde_json::to_string(&payload)?],
        )?;
        edges += 1;
    }
    tx.commit()?;
    Ok(
        serde_json::json!({"schema":"project-parity/codegraph-import-v1","authority":"supplementary-navigation","side":side,"nodes":nodes,"edges":edges,"db":db_path,"source":source_db}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn report(dir: &Path, ids: &[&str]) {
        fs::write(
            dir.join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        let body = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","priority":"P1","action":"inspect"}}"#))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(dir.join("llm-work-items.jsonl"), format!("{body}\n")).unwrap();
    }

    #[test]
    fn sync_tracks_new_and_resolved_items() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b"]);
        let first = sync(&db, root.path()).unwrap();
        assert_eq!(first["new"], 2);
        report(root.path(), &["a"]);
        let second = sync(&db, root.path()).unwrap();
        assert_eq!(second["new"], 0);
        assert_eq!(second["resolved"], 1);
        assert_eq!(second["remaining"], 1);
    }

    #[test]
    fn graph_import_persists_typed_nodes_and_edges() {
        let root = tempdir().unwrap();
        let db = root.path().join("graph.sqlite");
        let artifact = root.path().join("graph.jsonl.zst");
        let records = concat!(
            "{\"recordType\":\"header\"}\n",
            "{\"recordType\":\"node\",\"side\":\"right\",\"node\":{\"id\":\"n1\"}}\n",
            "{\"recordType\":\"node\",\"side\":\"right\",\"node\":{\"id\":\"n2\"}}\n",
            "{\"recordType\":\"edge\",\"side\":\"right\",\"edge\":{\"source\":\"n1\",\"target\":\"n2\",\"kind\":\"Calls\",\"dynamic\":false,\"label\":null}}\n"
        );
        fs::write(
            &artifact,
            zstd::stream::encode_all(records.as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let result = import_graph(&db, &artifact).unwrap();
        assert_eq!(result["nodes"], 2);
        assert_eq!(result["edges"], 1);
        let conn = Connection::open(db).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM graph_edges WHERE kind='Calls'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
}
