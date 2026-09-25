use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Cursor},
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

use super::ENGINE_VERSION;

pub fn sync(db_path: &Path, report: &Path) -> Result<Value> {
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, report TEXT NOT NULL, upstream_hash TEXT, local_hash TEXT, synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS work_items (id TEXT PRIMARY KEY, run_id INTEGER NOT NULL, action TEXT, priority TEXT, confidence TEXT, payload TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT, batch_id TEXT, FOREIGN KEY(run_id) REFERENCES runs(id)); CREATE TABLE IF NOT EXISTS work_item_decisions (work_item_id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('skipped','pending_sync','done')), reason TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, payload TEXT, FOREIGN KEY(work_item_id) REFERENCES work_items(id)); CREATE INDEX IF NOT EXISTS work_items_queue ON work_items(resolved_at, priority, id); CREATE INDEX IF NOT EXISTS work_items_queue_phase ON work_items(resolved_at, CASE WHEN action='remove-or-justify-extra-local' THEN 4 WHEN action='locate-unlinked-upstream-branch' THEN 5 WHEN priority='P0' THEN 0 WHEN priority='P1' THEN 1 ELSE 2 END, id); CREATE INDEX IF NOT EXISTS work_items_queue_phase_confidence ON work_items(resolved_at, CASE WHEN action='remove-or-justify-extra-local' THEN 4 WHEN action='locate-unlinked-upstream-branch' THEN 5 WHEN priority='P0' THEN 0 WHEN priority='P1' THEN 1 ELSE 2 END, CASE confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, id); CREATE INDEX IF NOT EXISTS work_item_decisions_status ON work_item_decisions(status);")?;
    ensure_batch_schema(&conn)?;
    ensure_decision_schema(&conn)?;
    let manifest: Value = serde_json::from_slice(&fs::read(report.join("llm-manifest.json"))?)?;
    let hashes = &manifest["inputHashes"];
    let previous_unresolved: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL",
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
        tx.execute("INSERT INTO work_items(id,run_id,action,priority,confidence,payload,last_seen,resolved_at,batch_id) VALUES (?1,?2,?3,?4,?5,?6,CURRENT_TIMESTAMP,NULL,?7) ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id, action=excluded.action, priority=excluded.priority, confidence=excluded.confidence, payload=excluded.payload, last_seen=CURRENT_TIMESTAMP, resolved_at=NULL, batch_id=excluded.batch_id", params![id, run_id, item["action"].as_str(), item["priority"].as_str(), item["confidence"].as_str(), line, item["batchId"].as_str()])?;
        seen += 1;
    }
    tx.execute(
        "UPDATE work_items SET resolved_at=CURRENT_TIMESTAMP WHERE run_id <> ?1 AND resolved_at IS NULL",
        params![run_id],
    )?;
    tx.commit()?;
    let reopened: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL AND d.payload IS NOT NULL AND w.payload <> d.payload",
        params![run_id],
        |row| row.get(0),
    )?;
    conn.execute("DELETE FROM work_item_decisions WHERE payload IS NOT NULL AND EXISTS (SELECT 1 FROM work_items w WHERE w.id=work_item_decisions.work_item_id AND w.run_id=?1 AND w.resolved_at IS NULL AND w.payload <> work_item_decisions.payload)", params![run_id])?;
    // A reviewed item becomes durable only when the fresh report still has
    // the exact payload that was reviewed. Payload changes were cleared above,
    // so a changed item is reopened for fresh evidence review.
    let pending_released = conn.execute(
        "UPDATE work_item_decisions SET status='done' WHERE status='pending_sync'",
        [],
    )?;
    let remaining: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    let new_items = (remaining - previous_unresolved).max(0);
    let resolved = (previous_unresolved - remaining).max(0);
    Ok(
        serde_json::json!({"schema":"project-parity/state-sync-v1","runId":run_id,"workItems":seen,"new":new_items,"resolved":resolved,"reopened":reopened,"pendingReleased":pending_released,"remaining":remaining,"db":db_path}),
    )
}

pub fn next(db_path: &Path, limit: usize) -> Result<Value> {
    next_with_mode(db_path, limit, false, false)
}

/// Return queue locators without the full evidence payload, which remains
/// available through `show-work` for one selected item at a time.
pub fn next_summary(db_path: &Path, limit: usize) -> Result<Value> {
    next_with_mode(db_path, limit, true, false)
}

/// Return only the fields needed to route a bounded review slice. Full
/// evidence remains available through show-work/show-batch.
pub fn next_routing(db_path: &Path, limit: usize) -> Result<Value> {
    next_with_mode(db_path, limit, false, true)
}

/// Return grouped review routing together with compact owner locators.
pub fn next_routing_summary(db_path: &Path, limit: usize) -> Result<Value> {
    next_with_mode(db_path, limit, true, true)
}

/// Install the derived ordering index on an existing state database without
/// rescanning either source tree or changing queue decisions.
pub fn optimize_queue(db_path: &Path) -> Result<Value> {
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_batch_schema(&conn)?;
    conn.execute_batch("CREATE INDEX IF NOT EXISTS work_items_queue_phase_confidence ON work_items(resolved_at, CASE WHEN action='remove-or-justify-extra-local' THEN 4 WHEN action='locate-unlinked-upstream-branch' THEN 5 WHEN priority='P0' THEN 0 WHEN priority='P1' THEN 1 ELSE 2 END, CASE confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, batch_id, id);")?;
    Ok(serde_json::json!({
        "schema": "project-parity/state-optimize-queue-v1",
        "index": "work_items_queue_phase_confidence_batch",
        "db": db_path,
    }))
}

/// Add the derived batch locator to older state databases and build an index
/// that keeps evidence for the same semantic owner adjacent in queue slices.
fn ensure_batch_schema(conn: &Connection) -> Result<()> {
    let has_batch_id: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('work_items') WHERE name='batch_id')",
        [],
        |row| row.get(0),
    )?;
    if !has_batch_id {
        conn.execute_batch("ALTER TABLE work_items ADD COLUMN batch_id TEXT;")?;
    }
    conn.execute(
        "UPDATE work_items SET batch_id=json_extract(payload,'$.batchId') WHERE batch_id IS NULL AND json_valid(payload)",
        [],
    )?;
    conn.execute_batch("CREATE INDEX IF NOT EXISTS work_items_queue_phase_confidence_batch ON work_items(resolved_at, CASE WHEN action='remove-or-justify-extra-local' THEN 4 WHEN action='locate-unlinked-upstream-branch' THEN 5 WHEN priority='P0' THEN 0 WHEN priority='P1' THEN 1 ELSE 2 END, CASE confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, batch_id, id);")?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SummaryOwner {
    file: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidencePathLocator {
    left: Option<SummaryOwner>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceVariant {
    evidence_path: Option<Vec<EvidencePathLocator>>,
}

fn local_context_files(
    evidence_path: Option<Vec<EvidencePathLocator>>,
    evidence_variants: Option<Vec<EvidenceVariant>>,
) -> Vec<String> {
    let mut files = std::collections::BTreeSet::new();
    for locator in evidence_path.into_iter().flatten() {
        if let Some(file) = locator.left.and_then(|owner| owner.file) {
            files.insert(file);
        }
    }
    for variant in evidence_variants.into_iter().flatten() {
        for locator in variant.evidence_path.into_iter().flatten() {
            if let Some(file) = locator.left.and_then(|owner| owner.file) {
                files.insert(file);
            }
        }
    }
    files.into_iter().collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SummaryWorkItem {
    id: String,
    action: Option<String>,
    priority: Option<String>,
    confidence: Option<String>,
    batch_id: Option<String>,
    reason: Option<String>,
    local: Option<Vec<SummaryOwner>>,
    upstream: Option<Vec<SummaryOwner>>,
    evidence_path: Option<Vec<EvidencePathLocator>>,
    evidence_variants: Option<Vec<EvidenceVariant>>,
}

fn summarize_owners(owners: Option<Vec<SummaryOwner>>) -> (usize, usize, Vec<String>) {
    let owners = owners.unwrap_or_default();
    let owner_count = owners.len();
    let mut files = owners
        .into_iter()
        .filter_map(|owner| owner.file)
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();
    let file_count = files.len();
    files.truncate(1);
    (owner_count, file_count, files)
}

fn next_with_mode(db_path: &Path, limit: usize, summary: bool, routing: bool) -> Result<Value> {
    // SQLite WAL readers on macOS still need to open the database directory
    // for the -shm sidecar. A strict READ_ONLY connection therefore fails on
    // a healthy WAL database with SQLITE_CANTOPEN (14). This command remains
    // logically read-only: it executes only SELECTs, while using a normal
    // connection so SQLite can safely attach the WAL. A bounded busy timeout
    // prevents an active sync from turning queue inspection into an unbounded
    // hang.
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_report_is_synced(&conn)?;
    // Order only the small queue key first. Sorting the full payload here makes
    // SQLite materialize tens of thousands of large JSON blobs before LIMIT
    // can apply, which is both slow and capable of exhausting disk space.
    // Local-only extras and unlinked executable branches are deliberately late
    // audit phases. Large generated/compatibility-heavy sets can otherwise
    // starve upstream functionality gaps. Keep both classes in the queue and
    // surface them automatically after earlier phases are exhausted.
    let mut stmt = conn.prepare("SELECT w.id, w.action, w.priority, w.confidence, w.payload FROM work_items w JOIN (SELECT w.id FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id LIMIT ?1) next ON next.id=w.id ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id")?;
    let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(4))?;
    let items = if routing && summary {
        rows.map(|row| -> Result<Value> {
            let payload = row?;
            let item: SummaryWorkItem = serde_json::from_str(&payload)?;
            let local_files = item
                .local
                .as_ref()
                .into_iter()
                .flatten()
                .filter_map(|owner| owner.file.clone())
                .collect::<std::collections::BTreeSet<_>>();
            let upstream_files = item
                .upstream
                .as_ref()
                .into_iter()
                .flatten()
                .filter_map(|owner| owner.file.clone())
                .collect::<std::collections::BTreeSet<_>>();
            let (local_owners, local_file_count, local_file_samples) = summarize_owners(item.local);
            let (upstream_owners, upstream_file_count, upstream_file_samples) =
                summarize_owners(item.upstream);
            let local_context_files =
                local_context_files(item.evidence_path, item.evidence_variants);
            Ok(serde_json::json!({
                "id": item.id, "action": item.action,
                "priority": item.priority, "confidence": item.confidence,
                "batchId": item.batch_id,
                "reason": item.reason,
                "localOwnerCount": local_owners,
                "localFileCount": local_file_count,
                "localFileSamples": local_file_samples,
                "localFiles": local_files,
                "localContextFiles": local_context_files,
                "upstreamFiles": upstream_files,
                "upstreamOwnerCount": upstream_owners,
                "upstreamFileCount": upstream_file_count,
                "upstreamFileSamples": upstream_file_samples,
            }))
        })
        .collect::<Result<Vec<_>>>()?
    } else if routing {
        rows.map(|row| -> Result<Value> {
            let payload = row?;
            let item: RoutingWorkItem = serde_json::from_str(&payload)?;
            let mut local_files = item
                .local
                .unwrap_or_default()
                .into_iter()
                .filter_map(|owner| owner.file)
                .collect::<Vec<_>>();
            local_files.sort();
            local_files.dedup();
            let mut upstream_files = item
                .upstream
                .unwrap_or_default()
                .into_iter()
                .filter_map(|owner| owner.file)
                .collect::<Vec<_>>();
            upstream_files.sort();
            upstream_files.dedup();
            let mut local_context_files =
                local_context_files(item.evidence_path, item.evidence_variants);
            local_context_files.sort();
            local_context_files.dedup();
            Ok(serde_json::json!({
                "id": item.id,
                "batchId": item.batch_id,
                "action": item.action,
                "priority": item.priority,
                "confidence": item.confidence,
                "localFiles": local_files,
                "localContextFiles": local_context_files,
                "upstreamFiles": upstream_files,
            }))
        })
        .collect::<Result<Vec<_>>>()?
    } else if summary {
        rows.map(|row| -> Result<Value> {
            let payload = row?;
            // Deserialize only queue locators. Serde skips the potentially
            // large evidence subtree without allocating a full `Value` tree.
            let item: SummaryWorkItem = serde_json::from_str(&payload)?;
            let (local_owners, local_file_count, local_file_samples) = summarize_owners(item.local);
            let (upstream_owners, upstream_file_count, upstream_file_samples) =
                summarize_owners(item.upstream);
            Ok(serde_json::json!({
                "id": item.id, "action": item.action,
                "priority": item.priority, "confidence": item.confidence,
                "batchId": item.batch_id,
                "reason": item.reason,
                "localOwnerCount": local_owners,
                "localFileCount": local_file_count,
                "localFileSamples": local_file_samples,
                "upstreamOwnerCount": upstream_owners,
                "upstreamFileCount": upstream_file_count,
                "upstreamFileSamples": upstream_file_samples,
            }))
        })
        .collect::<Result<Vec<_>>>()?
    } else {
        rows.map(|row| -> Result<Value> {
            let payload = row?;
            Ok(serde_json::from_str(&payload)?)
        })
        .collect::<Result<Vec<Value>>>()?
    };
    ensure_report_contains_items(&conn, &items)?;
    let output = if routing {
        let mut review_groups = BTreeMap::<String, Vec<usize>>::new();
        let mut local_file_groups = BTreeMap::<String, Vec<usize>>::new();
        let mut local_context_file_groups = BTreeMap::<String, Vec<usize>>::new();
        let mut upstream_file_groups = BTreeMap::<String, Vec<usize>>::new();
        let mut unbatched = Vec::new();
        let mut compact_items = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            if let Some(batch_id) = item["batchId"].as_str() {
                review_groups
                    .entry(batch_id.to_string())
                    .or_default()
                    .push(index);
            } else {
                unbatched.push(index);
            }
            let mut compact = item.clone();
            if let Some(object) = compact.as_object_mut() {
                object.remove("batchId");
                if let Some(files) = object.get("localFiles").and_then(Value::as_array) {
                    for file in files.iter().filter_map(Value::as_str) {
                        local_file_groups
                            .entry(file.to_string())
                            .or_default()
                            .push(index);
                    }
                }
                if let Some(files) = object.get("localContextFiles").and_then(Value::as_array) {
                    for file in files.iter().filter_map(Value::as_str) {
                        local_context_file_groups
                            .entry(file.to_string())
                            .or_default()
                            .push(index);
                    }
                }
                if let Some(files) = object.get("upstreamFiles").and_then(Value::as_array) {
                    for file in files.iter().filter_map(Value::as_str) {
                        upstream_file_groups
                            .entry(file.to_string())
                            .or_default()
                            .push(index);
                    }
                }
            }
            compact_items.push(compact);
        }
        let review_groups = review_groups
            .into_iter()
            .map(|(batch_id, item_indexes)| {
                serde_json::json!({
                    "batchId": batch_id,
                    "count": item_indexes.len(),
                    "itemIndexes": item_indexes,
                })
            })
            .collect::<Vec<_>>();
        // Overlapping LOCAL owner or graph-context files stay in one review
        // partition. Context files are locators, not proof of a local match.
        // Connected components (rather than grouping by only the first file)
        // prevent a multi-file item from being split across parallel workers.
        let mut parents = (0..items.len()).collect::<Vec<_>>();
        for indexes in local_file_groups
            .values()
            .chain(local_context_file_groups.values())
        {
            if let Some((&first, rest)) = indexes.split_first() {
                for &index in rest {
                    union_sets(&mut parents, first, index);
                }
            }
        }
        let mut owner_groups = BTreeMap::<usize, Vec<usize>>::new();
        let mut ownerless = Vec::new();
        for (index, item) in compact_items.iter().enumerate() {
            if item["localFiles"]
                .as_array()
                .is_some_and(|files| !files.is_empty())
                || item["localContextFiles"]
                    .as_array()
                    .is_some_and(|files| !files.is_empty())
            {
                let root = find_set(&mut parents, index);
                owner_groups.entry(root).or_default().push(index);
            } else {
                ownerless.push(index);
            }
        }
        let owner_groups = owner_groups
            .into_values()
            .map(|item_indexes| {
                let files = item_indexes
                    .iter()
                    .filter_map(|index| compact_items[*index]["localFiles"].as_array())
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>();
                let context_files = item_indexes
                    .iter()
                    .filter_map(|index| compact_items[*index]["localContextFiles"].as_array())
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>();
                serde_json::json!({
                    "itemIndexes": item_indexes,
                    "localFiles": files,
                    "localContextFiles": context_files,
                })
            })
            .collect::<Vec<_>>();
        // Ownerless LOCAL candidates still have upstream owners worth
        // inspecting. Group their shared upstream files so reviewers can
        // reuse one read-only owner context and assign these locators without
        // repeatedly reopening the same bundle regions. This does not merge
        // verdicts or replace LOCAL overlap groups.
        let mut upstream_parents = (0..items.len()).collect::<Vec<_>>();
        for indexes in upstream_file_groups.values() {
            if let Some((&first, rest)) = indexes.split_first() {
                for &index in rest {
                    union_sets(&mut upstream_parents, first, index);
                }
            }
        }
        let mut upstream_groups = BTreeMap::<usize, Vec<usize>>::new();
        for (index, item) in compact_items.iter().enumerate() {
            if item["upstreamFiles"]
                .as_array()
                .is_some_and(|files| !files.is_empty())
            {
                let root = find_set(&mut upstream_parents, index);
                upstream_groups.entry(root).or_default().push(index);
            }
        }
        let upstream_groups = upstream_groups
            .into_values()
            .map(|item_indexes| {
                let files = item_indexes
                    .iter()
                    .filter_map(|index| compact_items[*index]["upstreamFiles"].as_array())
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<std::collections::BTreeSet<_>>();
                serde_json::json!({
                    "itemIndexes": item_indexes,
                    "upstreamFiles": files,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "schema": "project-parity/state-next-v2",
            "routing": true,
            "summary": summary,
            "count": items.len(),
            "reviewGroups": review_groups,
            "ownerGroups": owner_groups,
            "upstreamGroups": upstream_groups,
            "ownerlessItemIndexes": ownerless,
            "unbatchedItemIndexes": unbatched,
            "items": compact_items,
        })
    } else {
        serde_json::json!({
            "schema": "project-parity/state-next-v1",
            "summary": summary,
            "count": items.len(),
            "items": items,
        })
    };
    Ok(output)
}

/// A report can be regenerated independently of the SQLite queue (for example,
/// by a watcher or a failed/interrupted sync). Do not hand out IDs from that
/// stale queue: the corresponding evidence may no longer exist in the report.
/// Checking the manifest timestamp is constant-time and does not rescan inputs.
fn ensure_report_is_synced(conn: &Connection) -> Result<()> {
    let latest: Option<(String, i64)> = conn
        .query_row(
            "SELECT report, CAST(strftime('%s', synced_at) AS INTEGER) FROM runs ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((report, synced_at)) = latest else {
        return Ok(());
    };
    let manifest = Path::new(&report).join("llm-manifest.json");
    let modified_at = match fs::metadata(&manifest).and_then(|metadata| metadata.modified()) {
        Ok(modified_at) => modified_at,
        // Older/external report layouts may not have a manifest timestamp. The
        // normal sync path will report missing evidence when it is requested.
        Err(_) => return Ok(()),
    };
    let Ok(age) = modified_at.duration_since(UNIX_EPOCH) else {
        return Ok(());
    };
    let modified_seconds = age.as_secs() as i64;
    // SQLite's CURRENT_TIMESTAMP has one-second precision. Permit the same
    // second (and one tick of filesystem timestamp skew) for a fresh sync.
    if modified_seconds > synced_at.saturating_add(1) {
        bail!(
            "parity report manifest is newer than the queue state (report: {}, state synced: {}). Run `project-parity sync` before requesting the next item",
            manifest.display(),
            synced_at
        );
    }
    let manifest_value: Value = serde_json::from_slice(
        &fs::read(&manifest)
            .with_context(|| format!("read parity report manifest {}", manifest.display()))?,
    )?;
    if let Some(report_engine) = manifest_value["engine"].as_str() {
        if report_engine != ENGINE_VERSION {
            bail!(
                "parity report was generated by engine {report_engine}, but this CLI uses {ENGINE_VERSION}; run `project-parity sync` before requesting the next item"
            );
        }
    }
    Ok(())
}

/// Guard the bounded queue slice against a report/state mismatch. The index is
/// already emitted for `show-work`; checking at most `limit` IDs here prevents
/// wasting a review cycle on work whose evidence is absent from the current
/// report. Older reports without an index retain their legacy behavior.
fn ensure_report_contains_items(conn: &Connection, items: &[Value]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let report: Option<String> = conn
        .query_row(
            "SELECT report FROM runs ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(report) = report else {
        return Ok(());
    };
    let index_path = Path::new(&report).join("llm-work-items.index.json");
    let index = match fs::read(&index_path) {
        Ok(index) => index,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("read {}", index_path.display())),
    };
    let index: Value = serde_json::from_slice(&index)
        .with_context(|| format!("parse {}", index_path.display()))?;
    let records = index["records"]
        .as_object()
        .context("work-item index has no records object")?;
    let missing = items
        .iter()
        .filter_map(|item| item["id"].as_str())
        .filter(|id| !records.contains_key(*id))
        .take(10)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "queue state contains IDs absent from the current report index (examples: {}). Run `project-parity sync` before reviewing these items",
            missing.join(", ")
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RoutingWorkItem {
    id: String,
    batch_id: Option<String>,
    action: Option<String>,
    priority: Option<String>,
    confidence: Option<String>,
    local: Option<Vec<SummaryOwner>>,
    upstream: Option<Vec<SummaryOwner>>,
    evidence_path: Option<Vec<EvidencePathLocator>>,
    evidence_variants: Option<Vec<EvidenceVariant>>,
}

fn find_set(parents: &mut [usize], item: usize) -> usize {
    if parents[item] != item {
        parents[item] = find_set(parents, parents[item]);
    }
    parents[item]
}

fn union_sets(parents: &mut [usize], left: usize, right: usize) {
    let left_root = find_set(parents, left);
    let right_root = find_set(parents, right);
    if left_root != right_root {
        parents[right_root] = left_root;
    }
}

pub fn mark_pending_sync(db_path: &Path, work_item_id: &str, reason: &str) -> Result<Value> {
    let reason = reason.trim();
    if reason.is_empty() {
        anyhow::bail!("REASON must not be empty");
    }
    let mut conn =
        Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_decision_schema(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_undecided(&tx, work_item_id)?;
    tx.execute(
        "INSERT INTO work_item_decisions(work_item_id,status,reason,payload) SELECT ?1,'pending_sync',?2,payload FROM work_items WHERE id=?1 AND resolved_at IS NULL",
        params![work_item_id, reason],
    )?;
    tx.commit()?;
    Ok(
        serde_json::json!({"schema":"project-parity/state-done-v1","id":work_item_id,"status":"pending_sync","reason":reason,"db":db_path}),
    )
}

/// Mark a reviewed batch as waiting for the next authoritative sync in one
/// transaction. The payload snapshot is retained for every item so sync can
/// reopen only items whose evidence changed in the meantime.
pub fn mark_pending_sync_batch(
    db_path: &Path,
    work_item_ids: &[String],
    reason: &str,
) -> Result<Value> {
    let reason = reason.trim();
    if reason.is_empty() {
        anyhow::bail!("REASON must not be empty");
    }
    if work_item_ids.is_empty() {
        anyhow::bail!("at least one WORK_ITEM_ID is required");
    }
    let mut ids = work_item_ids.to_vec();
    ids.sort();
    ids.dedup();
    let mut conn =
        Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_decision_schema(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for id in &ids {
        require_undecided(&tx, id)?;
    }
    for id in &ids {
        tx.execute(
            "INSERT INTO work_item_decisions(work_item_id,status,reason,payload) SELECT ?1,'pending_sync',?2,payload FROM work_items WHERE id=?1 AND resolved_at IS NULL",
            params![id, reason],
        )?;
    }
    let pending_sync: i64 = tx.query_row(
        "SELECT COUNT(*) FROM work_items w JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.status='pending_sync'",
        [],
        |row| row.get(0),
    )?;
    tx.commit()?;
    Ok(serde_json::json!({
        "schema": "project-parity/state-done-batch-v1",
        "count": ids.len(),
        "pendingSync": pending_sync,
        "ids": ids,
        "status": "pending_sync",
        "reason": reason,
        "db": db_path,
    }))
}

pub fn skip(db_path: &Path, work_item_id: &str, reason: &str) -> Result<Value> {
    let reason = reason.trim();
    if reason.is_empty() {
        anyhow::bail!("REASON must not be empty");
    }
    let mut conn =
        Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_decision_schema(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_undecided(&tx, work_item_id)?;
    tx.execute(
        "INSERT INTO work_item_decisions(work_item_id,status,reason,payload) SELECT ?1,'skipped',?2,payload FROM work_items WHERE id=?1 AND resolved_at IS NULL",
        params![work_item_id, reason],
    )?;
    tx.commit()?;
    Ok(
        serde_json::json!({"schema":"project-parity/state-skip-v1","id":work_item_id,"status":"skipped","reason":reason,"db":db_path}),
    )
}

/// Mark an evidence-backed vendor/compiler batch as durably skipped in one
/// transaction. Like the pending-sync batch, validate every ID first so a
/// typo cannot leave a partially classified segment.
pub fn skip_batch(db_path: &Path, work_item_ids: &[String], reason: &str) -> Result<Value> {
    let reason = reason.trim();
    if reason.is_empty() {
        anyhow::bail!("REASON must not be empty");
    }
    if work_item_ids.is_empty() {
        anyhow::bail!("at least one WORK_ITEM_ID is required");
    }
    let mut ids = work_item_ids.to_vec();
    ids.sort();
    ids.dedup();
    let mut conn =
        Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_decision_schema(&conn)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for id in &ids {
        require_undecided(&tx, id)?;
    }
    for id in &ids {
        tx.execute(
            "INSERT INTO work_item_decisions(work_item_id,status,reason,payload) SELECT ?1,'skipped',?2,payload FROM work_items WHERE id=?1 AND resolved_at IS NULL",
            params![id, reason],
        )?;
    }
    tx.commit()?;
    Ok(serde_json::json!({
        "schema": "project-parity/state-skip-batch-v1",
        "count": ids.len(),
        "ids": ids,
        "status": "skipped",
        "reason": reason,
        "db": db_path,
    }))
}

fn require_undecided(conn: &Connection, work_item_id: &str) -> Result<()> {
    let status: Option<Option<String>> = conn
        .query_row(
            "SELECT d.status FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.id=?1 AND w.resolved_at IS NULL",
            params![work_item_id],
            |row| row.get(0),
        )
        .optional()?;
    match status {
        None => anyhow::bail!("unresolved work item not found: {work_item_id}"),
        Some(Some(status)) => anyhow::bail!(
            "work item {work_item_id} already has decision status '{status}'; refusing to overwrite it"
        ),
        Some(None) => Ok(()),
    }
}

fn ensure_decision_schema(conn: &Connection) -> Result<()> {
    let has_payload: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('work_item_decisions') WHERE name='payload')", [], |row| row.get(0))?;
    if !has_payload {
        conn.execute(
            "ALTER TABLE work_item_decisions ADD COLUMN payload TEXT",
            [],
        )?;
    }
    let schema: String = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='work_item_decisions'",
        [],
        |row| row.get(0),
    )?;
    if !schema.contains("pending_sync") || !schema.contains("'done'") {
        conn.execute_batch("ALTER TABLE work_item_decisions RENAME TO work_item_decisions_legacy; CREATE TABLE work_item_decisions (work_item_id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('skipped','pending_sync','done')), reason TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, payload TEXT, FOREIGN KEY(work_item_id) REFERENCES work_items(id)); INSERT INTO work_item_decisions(work_item_id,status,reason,decided_at,payload) SELECT work_item_id,status,reason,decided_at,payload FROM work_item_decisions_legacy; DROP TABLE work_item_decisions_legacy; CREATE INDEX IF NOT EXISTS work_item_decisions_status ON work_item_decisions(status);")?;
    }
    Ok(())
}

pub fn stats(db_path: &Path) -> Result<Value> {
    let conn = Connection::open(db_path).with_context(|| format!("open {}", db_path.display()))?;
    let (active, skipped, pending_sync, done, resolved, deferred): (i64, i64, i64, i64, i64, i64) = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.work_item_id IS NULL THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='skipped' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='pending_sync' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='done' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NOT NULL THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.work_item_id IS NULL AND w.action IN ('remove-or-justify-extra-local','locate-unlinked-upstream-branch') THEN 1 ELSE 0 END), 0)
         FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    )?;
    let mut breakdown_stmt = conn.prepare(
        "SELECT CASE WHEN w.action IN ('remove-or-justify-extra-local','locate-unlinked-upstream-branch') THEN 'P2' ELSE COALESCE(w.priority,'unknown') END, COALESCE(w.confidence,'unknown'), COALESCE(w.action,'unknown'), COUNT(*)
         FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id
         WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL
         GROUP BY w.priority, w.confidence, w.action
         ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END,
                  CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END,
                  w.action",
    )?;
    let queue_breakdown = breakdown_stmt
        .query_map([], |row| {
            Ok(serde_json::json!({
                "priority": row.get::<_, String>(0)?,
                "confidence": row.get::<_, String>(1)?,
                "action": row.get::<_, String>(2)?,
                "count": row.get::<_, i64>(3)?,
            }))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(
        serde_json::json!({"schema":"project-parity/state-stats-v1","active":active,"actionable":active-deferred,"deferred":deferred,"skipped":skipped,"pendingSync":pending_sync,"done":done,"resolved":resolved,"tracked":active+skipped+pending_sync+done+resolved,"queueBreakdown":queue_breakdown,"db":db_path}),
    )
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
    fn next_refuses_to_issue_ids_when_report_manifest_is_newer_than_state() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute("UPDATE runs SET synced_at='2000-01-01 00:00:00'", [])
            .unwrap();

        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("manifest is newer than the queue state"));
        assert!(error.to_string().contains("project-parity sync"));
    }

    #[test]
    fn next_refuses_to_use_a_queue_generated_by_an_older_engine() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"engine":"rust-oxc-0.126.0/v38","inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute("UPDATE runs SET synced_at='2999-01-01 00:00:00'", [])
            .unwrap();

        let error = next(&db, 10).unwrap_err();
        assert!(error.to_string().contains("generated by engine"));
        assert!(error.to_string().contains("project-parity sync"));
    }

    #[test]
    fn next_rejects_queue_ids_missing_from_the_current_report_index() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["stale-item"]);
        sync(&db, root.path()).unwrap();
        fs::write(
            root.path().join("llm-work-items.index.json"),
            r#"{"schema":"project-parity/jsonl-index-v1","records":{}}"#,
        )
        .unwrap();

        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("queue state contains IDs absent from the current report index"));
        assert!(error.to_string().contains("stale-item"));
    }

    #[test]
    fn reviewed_skip_is_excluded_and_counted() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b"]);
        sync(&db, root.path()).unwrap();
        skip(
            &db,
            "a",
            "compiled ES5 form already covered by restored TS owner",
        )
        .unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        let stats = stats(&db).unwrap();
        assert_eq!(stats["active"], 1);
        assert_eq!(stats["skipped"], 1);
        assert_eq!(stats["resolved"], 0);
    }

    #[test]
    fn stats_breaks_down_only_unreviewed_queue_by_priority_confidence_and_action() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"candidate\",\"priority\":\"P0\",\"confidence\":\"candidate\",\"action\":\"port\"}\n",
                "{\"id\":\"proven\",\"priority\":\"P1\",\"confidence\":\"proven-structure\",\"action\":\"inspect\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();
        skip(&db, "candidate", "verified generated compatibility helper").unwrap();

        let stats = stats(&db).unwrap();
        assert_eq!(stats["active"], 1);
        assert_eq!(stats["skipped"], 1);
        assert_eq!(stats["queueBreakdown"].as_array().unwrap().len(), 1);
        assert_eq!(stats["queueBreakdown"][0]["priority"], "P1");
        assert_eq!(stats["queueBreakdown"][0]["confidence"], "proven-structure");
        assert_eq!(stats["queueBreakdown"][0]["action"], "inspect");
        assert_eq!(stats["queueBreakdown"][0]["count"], 1);
    }

    #[test]
    fn stats_reports_deferred_locator_actions_as_p2_even_if_legacy_rows_say_p0() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"locator\",\"priority\":\"P0\",\"confidence\":\"unknown\",\"action\":\"locate-unlinked-upstream-branch\"}\n",
                "{\"id\":\"extra\",\"priority\":\"P0\",\"confidence\":\"unknown\",\"action\":\"remove-or-justify-extra-local\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let stats = stats(&db).unwrap();
        assert_eq!(stats["active"], 2);
        assert_eq!(stats["actionable"], 0);
        assert_eq!(stats["deferred"], 2);
        assert!(stats["queueBreakdown"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["priority"] == "P2"));
    }

    #[test]
    fn next_summary_keeps_batch_output_compact_and_preserves_owner_locators() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            r#"{"id":"a","priority":"P1","action":"inspect","confidence":"ambiguous","batchId":"b1","reason":"Compare the complete competing owner chains.","evidence":"large payload","local":[{"file":"src/local.ts"},{"file":"src/other.ts"},{"file":"src/third.ts"},{"file":"src/fourth.ts"}],"upstream":[{"file":"dist/upstream.js"}]}"#,
        ).unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_summary(&db, 100).unwrap();
        let item = &result["items"][0];
        assert_eq!(result["summary"], true);
        assert_eq!(item["id"], "a");
        assert_eq!(
            item["reason"],
            "Compare the complete competing owner chains."
        );
        assert_eq!(item["localOwnerCount"], 4);
        assert_eq!(item["localFileCount"], 4);
        assert_eq!(item["localFileSamples"].as_array().unwrap().len(), 1);
        assert_eq!(item["localFileSamples"][0], "src/fourth.ts");
        assert_eq!(item["upstreamOwnerCount"], 1);
        assert_eq!(item["upstreamFileCount"], 1);
        assert_eq!(item["upstreamFileSamples"][0], "dist/upstream.js");
        assert!(item.get("evidence").is_none());
        assert!(next(&db, 100).unwrap()["items"][0]
            .get("evidence")
            .is_some());
    }

    #[test]
    fn next_summary_honors_requested_limit() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b", "c"]);
        sync(&db, root.path()).unwrap();
        assert_eq!(next_summary(&db, 2).unwrap()["count"], 2);
    }

    #[test]
    fn next_routing_returns_only_queue_locators() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            r#"{"id":"a","priority":"P1","action":"inspect","confidence":"candidate","batchId":"b1","reason":"large reason","evidence":{"source":"large payload"},"local":[{"file":"src/local.ts"}],"upstream":[{"file":"dist/upstream.js"}]}"#,
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 100).unwrap();
        let item = &result["items"][0];
        assert_eq!(result["routing"], true);
        assert_eq!(item["id"], "a");
        assert_eq!(item["action"], "inspect");
        assert_eq!(item["priority"], "P1");
        assert_eq!(item["confidence"], "candidate");
        assert!(item.get("reason").is_none());
        assert!(item.get("evidence").is_none());
        assert!(item.get("local").is_none());
        assert_eq!(item["localFiles"], serde_json::json!(["src/local.ts"]));
        assert_eq!(
            item["upstreamFiles"],
            serde_json::json!(["dist/upstream.js"])
        );
        assert_eq!(
            result["ownerGroups"][0]["itemIndexes"],
            serde_json::json!([0])
        );
        assert_eq!(
            result["reviewGroups"][0]["itemIndexes"],
            serde_json::json!([0])
        );
    }

    #[test]
    fn next_routing_groups_selected_ids_by_evidence_batch() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"a\",\"priority\":\"P1\",\"action\":\"inspect\",\"batchId\":\"shared\",\"local\":[{\"file\":\"src/shared.ts\"}]}\n",
                "{\"id\":\"b\",\"priority\":\"P1\",\"action\":\"inspect\",\"batchId\":\"shared\",\"local\":[{\"file\":\"src/shared.ts\"}]}\n",
                "{\"id\":\"c\",\"priority\":\"P1\",\"action\":\"inspect\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 100).unwrap();
        assert_eq!(result["count"], 3);
        assert_eq!(result["reviewGroups"][0]["batchId"], "shared");
        assert_eq!(result["reviewGroups"][0]["count"], 2);
        let indexes = result["reviewGroups"][0]["itemIndexes"].as_array().unwrap();
        let grouped_ids = indexes
            .iter()
            .map(|index| {
                result["items"][index.as_u64().unwrap() as usize]["id"]
                    .as_str()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(grouped_ids, ["a", "b"]);
        let unbatched_index = result["unbatchedItemIndexes"][0].as_u64().unwrap() as usize;
        assert_eq!(result["items"][unbatched_index]["id"], "c");
        let ownerless_index = result["ownerlessItemIndexes"][0].as_u64().unwrap() as usize;
        assert_eq!(result["items"][ownerless_index]["id"], "c");
        assert_eq!(
            result["items"][ownerless_index]["upstreamFiles"],
            serde_json::json!([])
        );
        assert!(result["items"][0].get("batchId").is_none());
    }

    #[test]
    fn routing_owner_groups_keep_transitively_overlapping_local_files_together() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"a\",\"priority\":\"P1\",\"batchId\":\"a\",\"local\":[{\"file\":\"src/a.ts\"}]}\n",
                "{\"id\":\"b\",\"priority\":\"P1\",\"batchId\":\"b\",\"local\":[{\"file\":\"src/a.ts\"},{\"file\":\"src/b.ts\"}]}\n",
                "{\"id\":\"c\",\"priority\":\"P1\",\"batchId\":\"c\",\"local\":[{\"file\":\"src/b.ts\"}]}\n",
                "{\"id\":\"d\",\"priority\":\"P1\",\"batchId\":\"d\",\"local\":[{\"file\":\"src/isolated.ts\"}]}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 10).unwrap();
        let groups = result["ownerGroups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        let shared = groups
            .iter()
            .find(|group| group["localFiles"].as_array().unwrap().len() == 2)
            .unwrap();
        assert_eq!(shared["itemIndexes"], serde_json::json!([0, 1, 2]));
        assert_eq!(
            shared["localFiles"],
            serde_json::json!(["src/a.ts", "src/b.ts"])
        );
    }

    #[test]
    fn routing_groups_ownerless_items_by_overlapping_upstream_files() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"a\",\"priority\":\"P1\",\"upstream\":[{\"file\":\"dist/shared.js\"}]}\n",
                "{\"id\":\"b\",\"priority\":\"P1\",\"upstream\":[{\"file\":\"dist/shared.js\"},{\"file\":\"dist/other.js\"}]}\n",
                "{\"id\":\"c\",\"priority\":\"P1\",\"upstream\":[{\"file\":\"dist/isolated.js\"}]}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 10).unwrap();
        let groups = result["upstreamGroups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        let shared = groups
            .iter()
            .find(|group| group["upstreamFiles"].as_array().unwrap().len() == 2)
            .unwrap();
        assert_eq!(shared["itemIndexes"], serde_json::json!([0, 1]));
        assert_eq!(
            shared["upstreamFiles"],
            serde_json::json!(["dist/other.js", "dist/shared.js"])
        );
        assert_eq!(result["ownerGroups"].as_array().unwrap().len(), 0);
        assert_eq!(result["ownerlessItemIndexes"], serde_json::json!([0, 1, 2]));
    }

    #[test]
    fn routing_uses_evidence_path_local_context_without_claiming_a_local_match() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                r#"{"id":"a","priority":"P0","action":"port-missing-upstream-branch","evidencePath":[{"left":{"file":"src/shared.ts"},"right":{"file":"dist/a.js"}}]}"#,
                "\n",
                r#"{"id":"b","priority":"P0","action":"port-missing-upstream-branch","local":[],"evidenceVariants":[{"evidencePath":[{"left":{"file":"src/shared.ts"},"right":{"file":"dist/b.js"}}]}]}"#,
                "\n",
                r#"{"id":"c","priority":"P0","action":"port-missing-upstream-branch","upstream":[{"file":"dist/orphan.js"}]}"#,
                "\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 10).unwrap();
        assert_eq!(result["items"][0]["localFiles"], serde_json::json!([]));
        assert_eq!(
            result["items"][0]["localContextFiles"],
            serde_json::json!(["src/shared.ts"])
        );
        assert_eq!(result["items"][1]["localFiles"], serde_json::json!([]));
        assert_eq!(
            result["items"][1]["localContextFiles"],
            serde_json::json!(["src/shared.ts"])
        );
        assert_eq!(result["ownerlessItemIndexes"], serde_json::json!([2]));
        let groups = result["ownerGroups"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["itemIndexes"], serde_json::json!([0, 1]));
        assert_eq!(groups[0]["localFiles"], serde_json::json!([]));
        assert_eq!(
            groups[0]["localContextFiles"],
            serde_json::json!(["src/shared.ts"])
        );
    }

    #[test]
    fn next_keeps_equal_priority_evidence_batches_adjacent() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"a\",\"priority\":\"P1\",\"confidence\":\"candidate\",\"batchId\":\"batch-a\"}\n",
                "{\"id\":\"b\",\"priority\":\"P1\",\"confidence\":\"candidate\",\"batchId\":\"batch-b\"}\n",
                "{\"id\":\"c\",\"priority\":\"P1\",\"confidence\":\"candidate\",\"batchId\":\"batch-a\"}\n",
                "{\"id\":\"d\",\"priority\":\"P1\",\"confidence\":\"candidate\",\"batchId\":\"batch-b\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing(&db, 4).unwrap();
        let ids = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["a", "c", "b", "d"]);
        assert_eq!(result["reviewGroups"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn next_routing_summary_combines_groups_with_compact_owner_locators() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            r#"{"id":"a","priority":"P1","action":"inspect","confidence":"candidate","batchId":"b1","reason":"Check full owner chain","evidence":{"large":"payload"},"local":[{"file":"src/local.ts"}],"upstream":[{"file":"dist/upstream.js"}]}"#,
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let result = next_routing_summary(&db, 100).unwrap();
        assert_eq!(result["routing"], true);
        assert_eq!(result["summary"], true);
        assert_eq!(
            result["reviewGroups"][0]["itemIndexes"],
            serde_json::json!([0])
        );
        assert_eq!(result["items"][0]["reason"], "Check full owner chain");
        assert_eq!(result["items"][0]["localFileSamples"][0], "src/local.ts");
        assert_eq!(
            result["items"][0]["upstreamFileSamples"][0],
            "dist/upstream.js"
        );
        assert_eq!(
            result["items"][0]["upstreamFiles"],
            serde_json::json!(["dist/upstream.js"])
        );
        assert_eq!(
            result["upstreamGroups"][0]["itemIndexes"],
            serde_json::json!([0])
        );
        assert!(result["items"][0].get("evidence").is_none());
    }

    #[test]
    fn queue_priority_order_uses_rank_index_without_temporary_sort() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b", "c"]);
        sync(&db, root.path()).unwrap();

        let conn = Connection::open(&db).unwrap();
        let plan = conn
            .prepare(
        "EXPLAIN QUERY PLAN SELECT w.id FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id LIMIT 100",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
            .join("\n");

        assert!(
            plan.contains("work_items_queue_phase_confidence_batch"),
            "{plan}"
        );
        assert!(!plan.contains("USE TEMP B-TREE FOR ORDER BY"), "{plan}");
    }

    #[test]
    fn next_orders_stronger_evidence_first_within_priority() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"weak\",\"priority\":\"P0\",\"action\":\"port-missing-upstream-branch\",\"confidence\":\"weak-candidate\"}\n",
                "{\"id\":\"candidate\",\"priority\":\"P0\",\"action\":\"port-missing-upstream-branch\",\"confidence\":\"candidate\"}\n",
                "{\"id\":\"proven\",\"priority\":\"P0\",\"action\":\"port-missing-upstream-branch\",\"confidence\":\"proven-structure\"}\n",
                "{\"id\":\"p1\",\"priority\":\"P1\",\"action\":\"resolve-ambiguous-owners\",\"confidence\":\"proven-structure\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();
        let result = next(&db, 4).unwrap();
        let ids = result["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["proven", "candidate", "weak", "p1"]);
    }

    #[test]
    fn low_value_local_extras_and_unlinked_branches_are_deferred() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"late\",\"priority\":\"P0\",\"action\":\"locate-unlinked-upstream-branch\"}\n",
                "{\"id\":\"port\",\"priority\":\"P0\",\"action\":\"port-missing-upstream-branch\"}\n",
                "{\"id\":\"ambiguous\",\"priority\":\"P1\",\"action\":\"resolve-ambiguous-owners\"}\n",
                "{\"id\":\"extra\",\"priority\":\"P2\",\"action\":\"remove-or-justify-extra-local\"}\n",
                "{\"id\":\"other-p2\",\"priority\":\"P2\",\"action\":\"inspect-unresolved-upstream-graph-context\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();
        let items = next(&db, 5).unwrap()["items"].as_array().unwrap().clone();
        let ids = items
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["port", "ambiguous", "other-p2", "extra", "late"]);
        let stats = stats(&db).unwrap();
        assert_eq!(stats["deferred"], 2);
        assert_eq!(stats["actionable"], 3);
    }

    #[test]
    fn done_is_excluded_until_sync_then_remains_done_if_payload_is_unchanged() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "a", "local patch is complete; wait for the next sync").unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        assert_eq!(stats(&db).unwrap()["pendingSync"], 1);

        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["pendingReleased"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        assert_eq!(stats(&db).unwrap()["pendingSync"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);
    }

    #[test]
    fn reviewed_batch_is_atomic_and_excluded() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b", "c"]);
        sync(&db, root.path()).unwrap();
        let ids = vec!["c".to_string(), "a".to_string(), "a".to_string()];
        let result = mark_pending_sync_batch(&db, &ids, "reviewed batch; sync pending").unwrap();
        assert_eq!(result["count"], 2);
        assert_eq!(result["pendingSync"], 2);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        assert_eq!(stats(&db).unwrap()["pendingSync"], 2);
    }

    #[test]
    fn reviewed_batch_rejects_unknown_id_without_partial_write() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b"]);
        sync(&db, root.path()).unwrap();
        let ids = vec!["a".to_string(), "missing".to_string()];
        assert!(mark_pending_sync_batch(&db, &ids, "reviewed").is_err());
        assert_eq!(stats(&db).unwrap()["pendingSync"], 0);
    }

    #[test]
    fn skipped_batch_is_atomic_and_counted() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b", "c"]);
        sync(&db, root.path()).unwrap();
        let ids = vec!["c".to_string(), "a".to_string(), "a".to_string()];
        let result = skip_batch(&db, &ids, "installed vendor package").unwrap();
        assert_eq!(result["count"], 2);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        assert_eq!(stats(&db).unwrap()["skipped"], 2);
    }

    #[test]
    fn decisions_never_overwrite_an_existing_status() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a", "b", "c"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "a", "reviewed; sync pending").unwrap();

        let batch = vec!["a".to_string(), "b".to_string()];
        assert!(skip_batch(&db, &batch, "false positive").is_err());
        assert!(mark_pending_sync_batch(&db, &batch, "reviewed batch").is_err());
        assert_eq!(stats(&db).unwrap()["pendingSync"], 1);
        assert_eq!(stats(&db).unwrap()["skipped"], 0);
        assert_eq!(next(&db, 10).unwrap()["count"], 2);

        skip(&db, "b", "evidence-backed false positive").unwrap();
        assert!(mark_pending_sync(&db, "b", "should not replace skip").is_err());
        assert_eq!(stats(&db).unwrap()["pendingSync"], 1);
        assert_eq!(stats(&db).unwrap()["skipped"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn done_reopens_when_reviewed_payload_changes() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "a", "reviewed").unwrap();
        report(root.path(), &[r#"a"#]);
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            "{\"id\":\"a\",\"priority\":\"P0\",\"action\":\"changed\"}\n",
        )
        .unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn legacy_decision_schema_is_migrated_before_pending_done() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE work_items (id TEXT PRIMARY KEY, run_id INTEGER NOT NULL, payload TEXT NOT NULL, resolved_at TEXT); CREATE TABLE work_item_decisions (work_item_id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('skipped')), reason TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO work_items(id,run_id,payload) VALUES ('a',1,'{}');")
            .unwrap();
        drop(conn);

        mark_pending_sync(&db, "a", "legacy database migration").unwrap();
        let conn = Connection::open(&db).unwrap();
        let status: String = conn
            .query_row(
                "SELECT status FROM work_item_decisions WHERE work_item_id='a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "pending_sync");
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
