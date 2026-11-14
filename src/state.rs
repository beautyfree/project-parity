use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, Cursor},
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use super::ENGINE_VERSION;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RootIdentity {
    local: PathBuf,
    upstream: PathBuf,
}

impl RootIdentity {
    pub fn paths(&self) -> (&Path, &Path) {
        (&self.local, &self.upstream)
    }

    pub fn new(local: &Path, upstream: &Path) -> Result<Self> {
        Ok(Self {
            local: local.canonicalize().with_context(|| format!("resolve local root {}", local.display()))?,
            upstream: upstream.canonicalize().with_context(|| format!("resolve upstream root {}", upstream.display()))?,
        })
    }

    fn from_values(local: &Value, upstream: &Value) -> Result<Self> {
        let local = Path::new(local.as_str().context("missing local root provenance")?);
        let upstream = Path::new(upstream.as_str().context("missing upstream root provenance")?);
        if !local.is_absolute() || !upstream.is_absolute() {
            bail!("root provenance must contain absolute paths; refusing ambiguous relocation");
        }
        Self::new(local, upstream)
    }

    fn require(&self, requested: &Self, owner: &Path) -> Result<()> {
        if self != requested {
            bail!(
                "root identity mismatch at {}: belongs to local {} and upstream {}; requested local {} and upstream {}. Use a separate report and state database for different roots",
                owner.display(), self.local.display(), self.upstream.display(),
                requested.local.display(), requested.upstream.display()
            );
        }
        Ok(())
    }

    pub fn lock_report_status(&self, report: &Path) -> Result<(super::SyncLock, PathBuf)> {
        let report = destination_path(report)?;
        // A resync may still own the report when the watcher fails. Wait so its
        // exit cannot leave a completed resync advertising a running watcher.
        let lock = lock_resource(&report, true)?;
        let marker = report.join("root-identity.json");
        let retained: RootIdentity = serde_json::from_slice(&fs::read(&marker)?)?;
        // These paths were canonicalized at startup and persisted before any
        // report writes. Status must still work after a source is unmounted.
        retained.require(self, &marker)?;
        Ok((lock, report))
    }
}

struct ReportIdentity {
    roots: RootIdentity,
    local_hash: String,
    upstream_hash: String,
}

fn read_report_identity(path: &Path, manifest: bool) -> Result<ReportIdentity> {
    let value: Value = serde_json::from_slice(&fs::read(path).with_context(|| format!("read provenance {}", path.display()))?)
        .with_context(|| format!("parse provenance {}", path.display()))?;
    let (local, upstream, local_hash, upstream_hash) = if manifest {
        (&value["localRoot"], &value["analysisProjection"],
         value["inputHashes"]["local"].as_str().or_else(|| value["inputHashes"]["reproduction"].as_str()),
         value["inputHashes"]["upstream"].as_str())
    } else {
        (&value["left"]["root"], &value["right"]["root"],
         value["left"]["projectSha256"].as_str(), value["right"]["projectSha256"].as_str())
    };
    Ok(ReportIdentity {
        roots: RootIdentity::from_values(local, upstream)?,
        local_hash: local_hash.filter(|hash| !hash.is_empty()).context("missing local provenance hash")?.to_owned(),
        upstream_hash: upstream_hash.filter(|hash| !hash.is_empty()).context("missing upstream provenance hash")?.to_owned(),
    })
}

fn check_report_identity(report: &Path, expected: &RootIdentity, allow_interrupted: bool, state_db: Option<&Path>) -> Result<()> {
    if !report.exists() {
        return Ok(());
    }
    let marker = report.join("root-identity.json");
    let mut known = false;
    let mut interrupted = false;
    if marker.exists() {
        let value: Value = serde_json::from_slice(&fs::read(&marker)?)?;
        let roots: RootIdentity = serde_json::from_value(value.clone())?;
        RootIdentity::new(&roots.local, &roots.upstream)?.require(expected, &marker)?;
        interrupted = value["generationInProgress"].as_bool() == Some(true);
        if interrupted && !allow_interrupted {
            bail!("report generation is incomplete at {}; regenerate it with the same roots before syncing state", report.display());
        }
        known = true;
    }
    for (name, manifest) in [("llm-manifest.json", true), ("report.json", false)] {
        let path = report.join(name);
        if path.exists() {
            if interrupted && serde_json::from_slice::<Value>(&fs::read(&path)?).is_err() {
                // Only a recorded interrupted generation may replace truncated
                // metadata. Valid foreign roots and untracked corruption fail.
                continue;
            }
            read_report_identity(&path, manifest)?.roots.require(expected, &path)?;
            known = true;
        }
    }
    if !known {
        let mut state_files = Vec::new();
        if let Some(db) = state_db {
            let db = destination_path(db)?;
            let name = db.file_name().context("state has no file name")?.to_string_lossy();
            state_files.extend([db.clone(), db.with_file_name(format!("{name}-wal")), db.with_file_name(format!("{name}-shm")), resource_lock_path(&db)?]);
        }
        for entry in fs::read_dir(report)? {
            let entry = entry?;
            if state_files.contains(&destination_path(&entry.path())?) {
                continue;
            }
            // No report was published if only the uncommitted identity temp
            // remains. An existing state DB is still checked independently.
            if entry.file_name() != ".root-identity.json.tmp" || !entry.file_type()?.is_file() {
                bail!("no root provenance in nonempty report {}; refusing to overwrite it", report.display());
            }
        }
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)", [table], |row| row.get(0))?)
}

fn legacy_report_path(db: &Path, stored: &str) -> Result<PathBuf> {
    let stored = Path::new(stored);
    if stored.is_absolute() {
        return stored.canonicalize().context("legacy report is missing; cannot establish state root identity");
    }
    // Old runs stored paths relative to the invocation directory. Only one
    // existing interpretation is safe; a moved database is not a root migration.
    let mut candidates = std::collections::BTreeSet::new();
    for base in std::iter::once(std::env::current_dir()?).chain(db.ancestors().skip(1).map(Path::to_path_buf)) {
        if let Ok(path) = base.join(stored).canonicalize() {
            candidates.insert(path);
        }
    }
    if candidates.len() != 1 {
        bail!("legacy report path {} is missing or ambiguous; cannot establish state root identity", stored.display());
    }
    Ok(candidates.pop_first().expect("one report path checked"))
}

fn database_identity(conn: &Connection, db: &Path) -> Result<Option<RootIdentity>> {
    if table_exists(conn, "parity_identity")? {
        let (local, upstream): (String, String) = conn.query_row(
            "SELECT local_root, upstream_root FROM parity_identity WHERE id=1", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).context("state root identity is incomplete")?;
        return Ok(Some(RootIdentity::new(Path::new(&local), Path::new(&upstream))?));
    }
    if !table_exists(conn, "runs")? {
        let tables: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |row| row.get(0))?;
        if tables != 0 { bail!("existing database has no parity run provenance: {}", db.display()); }
        return Ok(None);
    }
    let latest: Option<(String, Option<String>, Option<String>, Option<i64>)> = conn.query_row(
        "SELECT report, local_hash, upstream_hash, CAST(strftime('%s', synced_at) AS INTEGER) FROM runs ORDER BY id DESC LIMIT 1", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional()?;
    let Some((stored, local_hash, upstream_hash, synced_at)) = latest else {
        for table in ["work_items", "work_item_decisions"] {
            if table_exists(conn, table)? && conn.query_row(&format!("SELECT EXISTS(SELECT 1 FROM {table})"), [], |row| row.get::<_, bool>(0))? {
                bail!("state contains decisions or work without run provenance: {}", db.display());
            }
        }
        return Ok(None);
    };
    let report = legacy_report_path(db, &stored)?;
    let manifest = report.join("llm-manifest.json");
    let path = if manifest.exists() { manifest } else { report.join("report.json") };
    let prior = read_report_identity(&path, path.file_name().is_some_and(|name| name == "llm-manifest.json"))?;
    let modified = fs::metadata(&path)?.modified()?.duration_since(UNIX_EPOCH)?;
    let synced_at = synced_at.filter(|time| *time >= 0).context("legacy run has no valid sync timestamp")?;
    // Rootless databases cannot independently authenticate historical roots.
    // Trust only retained, mutually consistent artifacts predating the recorded
    // run; same-second timestamps are ambiguous. Backdated substitutions cannot
    // be detected by this legacy format. New databases persist roots directly.
    if local_hash.as_deref() != Some(&prior.local_hash)
        || upstream_hash.as_deref() != Some(&prior.upstream_hash)
        || modified >= Duration::from_secs(synced_at as u64)
    {
        bail!("legacy report no longer matches the latest recorded run at {}; refusing to infer state roots", path.display());
    }
    check_report_identity(&report, &prior.roots, false, Some(db))?;
    Ok(Some(prior.roots))
}

fn require_nonempty_database_file(db: &Path) -> Result<()> {
    let metadata = fs::metadata(db)
        .with_context(|| format!("state database does not exist: {}", db.display()))?;
    if !metadata.is_file() {
        bail!("state database path is not a regular file: {}", db.display());
    }
    if metadata.len() == 0 {
        bail!(
            "state database is an empty file: {}; refusing to create a fresh queue or overwrite the missing ledger",
            db.display()
        );
    }
    Ok(())
}

fn open_existing_database(db: &Path) -> Result<Connection> {
    require_nonempty_database_file(db)?;
    Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .with_context(|| format!("open state database {}", db.display()))
}

fn open_or_create_state_database(db: &Path) -> Result<Connection> {
    let flags = if db.exists() {
        require_nonempty_database_file(db)?;
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    };
    Connection::open_with_flags(db, flags)
        .with_context(|| format!("open state database {}", db.display()))
}

fn check_database_identity(db: &Path, expected: &RootIdentity) -> Result<()> {
    if db.exists() {
        require_nonempty_database_file(db)?;
        // Never use immutable mode: it can ignore live WAL decisions.
        let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_millis(1000))?;
        if let Some(roots) = database_identity(&conn, db)? {
            roots.require(expected, db)?;
        }
    }
    Ok(())
}

fn store_database_identity(conn: &Connection, roots: &RootIdentity) -> Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS parity_identity (id INTEGER PRIMARY KEY CHECK(id=1), local_root TEXT NOT NULL, upstream_root TEXT NOT NULL)")?;
    conn.execute("INSERT OR IGNORE INTO parity_identity(id,local_root,upstream_root) VALUES (1,?1,?2)", params![roots.local.to_string_lossy(), roots.upstream.to_string_lossy()])?;
    Ok(())
}

pub fn destination_path(path: &Path) -> Result<PathBuf> {
    if path.exists() { return Ok(path.canonicalize()?); }
    let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
    let parent = absolute.parent().context("destination has no parent")?;
    Ok(destination_path(parent)?.join(absolute.file_name().context("destination has no file name")?))
}

fn resource_lock_path(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().context("destination has no file name")?.to_string_lossy();
    Ok(path.with_file_name(format!(".{name}.project-parity.lock")))
}

fn lock_resource(path: &Path, wait: bool) -> Result<super::SyncLock> {
    let lock = resource_lock_path(path)?;
    fs::create_dir_all(lock.parent().context("lock has no parent")?)?;
    super::acquire_path_lock(&lock, wait)
}

fn write_report_marker(report: &Path, roots: &RootIdentity, in_progress: bool) -> Result<()> {
    let temporary = report.join(".root-identity.json.tmp");
    if let Ok(metadata) = fs::symlink_metadata(&temporary) {
        if !metadata.is_file() { bail!("identity temporary path is not a regular file: {}", temporary.display()); }
        fs::remove_file(&temporary)?;
    }
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
    serde_json::to_writer(&mut file, &serde_json::json!({
        "local": roots.local,
        "upstream": roots.upstream,
        "generationInProgress": in_progress,
    }))?;
    file.sync_all()?;
    fs::rename(temporary, report.join("root-identity.json"))?;
    fs::File::open(report)?.sync_all()?;
    Ok(())
}

/// Holds the report and database writer locks through generation/reconciliation.
pub struct SyncGuard {
    roots: RootIdentity,
    report: PathBuf,
    db: Option<PathBuf>,
    _locks: Vec<super::SyncLock>,
}

impl SyncGuard {
    pub fn paths(&self) -> (&Path, &Path, &Path) {
        (&self.roots.local, &self.roots.upstream, &self.report)
    }

    fn acquire(roots: RootIdentity, report: &Path, db: Option<&Path>, generation: bool) -> Result<Self> {
        let report = destination_path(report)?;
        let db = db.map(destination_path).transpose()?;
        let check = || -> Result<()> {
            check_report_identity(&report, &roots, generation, db.as_deref())?;
            if let Some(db) = &db { check_database_identity(db, &roots)?; }
            Ok(())
        };
        check()?;
        let mut resources = vec![report.clone()];
        resources.extend(db.iter().cloned());
        resources.sort();
        resources.dedup();
        let mut locks = Vec::new();
        for path in resources {
            locks.push(lock_resource(&path, false)?);
        }
        check()?;
        Ok(Self { roots, report, db, _locks: locks })
    }

    pub fn for_generation(local: &Path, upstream: &Path, report: &Path, db: Option<&Path>) -> Result<Self> {
        let guard = Self::acquire(RootIdentity::new(local, upstream)?, report, db, true)?;
        if let Some(db) = &guard.db {
            if db.exists() {
                let mut conn = open_existing_database(db)?;
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if let Some(roots) = database_identity(&tx, db)? { roots.require(&guard.roots, db)?; }
                // Bind verified legacy provenance before its report can be replaced.
                // A later generation failure leaves decisions intact and roots known.
                store_database_identity(&tx, &guard.roots)?;
                tx.commit()?;
            }
        }
        fs::create_dir_all(&guard.report)?;
        write_report_marker(&guard.report, &guard.roots, true)?;
        Ok(guard)
    }

    pub fn finish_generation(&self) -> Result<()> {
        write_report_marker(&self.report, &self.roots, false)
    }

    pub fn sync(&self) -> Result<Value> {
        let db = self.db.as_deref().context("no state database selected")?;
        sync_locked(db, &self.report, &self.roots)
    }
}

pub fn validate_generation(local: &Path, upstream: &Path, report: &Path, db: Option<&Path>) -> Result<()> {
    let roots = RootIdentity::new(local, upstream)?;
    check_report_identity(report, &roots, true, db)?;
    if let Some(db) = db { check_database_identity(db, &roots)?; }
    Ok(())
}

fn compatible_legacy_variant_action(current: Option<&str>, variant: &str) -> bool {
    match (current, variant) {
        (Some(current), variant) if current == variant => true,
        (
            Some("port-missing-upstream-branch" | "inspect-unverified-missing-branch"),
            "port-missing-upstream-branch" | "inspect-unverified-missing-branch" | "inspect-structural-frontier",
        ) => true,
        (
            Some("reconcile-changed-branch" | "inspect-unverified-changed-branch"),
            "reconcile-changed-branch" | "inspect-unverified-changed-branch",
        ) => true,
        (
            Some("resolve-ambiguous-owners" | "remove-or-justify-extra-local"),
            "inspect-structural-frontier",
        ) => true,
        _ => false,
    }
}

fn deferred_work_segment_routing_preserves_evidence(previous: &Value, current: &Value) -> bool {
    let previous_action = previous.get("action").and_then(Value::as_str);
    let current_action = current.get("action").and_then(Value::as_str);
    if !matches!(
        previous_action,
        Some("locate-unlinked-upstream-branch" | "remove-or-justify-extra-local")
    ) || previous_action != current_action
        || previous.get("evidenceVariants").is_some()
        || current.get("evidenceVariants").is_some()
    {
        return false;
    }

    let Some(previous_ids) = previous.get("inspectNodeIds").and_then(Value::as_array) else {
        return false;
    };
    let Some(current_ids) = current.get("inspectNodeIds").and_then(Value::as_array) else {
        return false;
    };
    if previous_ids.is_empty() || previous_ids != current_ids {
        return false;
    }

    let Some(previous_owner) = previous.get("semanticOwner").and_then(Value::as_object) else {
        return false;
    };
    let Some(current_owner) = current.get("semanticOwner").and_then(Value::as_object) else {
        return false;
    };
    let Some(action) = previous_action else {
        return false;
    };
    let (Some(previous_file), Some(current_file)) = (
        previous_owner.get("file").and_then(Value::as_str),
        current_owner.get("file").and_then(Value::as_str),
    ) else {
        return false;
    };
    let (Some(previous_segment), Some(current_segment)) = (
        previous_owner.get("segment").and_then(Value::as_u64),
        current_owner.get("segment").and_then(Value::as_u64),
    ) else {
        return false;
    };
    if previous_segment == current_segment
        || previous_owner.get("kind").and_then(Value::as_str) != Some("WorkSegment")
        || current_owner.get("kind").and_then(Value::as_str) != Some("WorkSegment")
        || previous_owner.get("action").and_then(Value::as_str) != Some(action)
        || current_owner.get("action").and_then(Value::as_str) != Some(action)
        || previous_file != current_file
        || previous_owner.get("maximumWorkItems").and_then(Value::as_u64) != Some(32)
        || current_owner.get("maximumWorkItems").and_then(Value::as_u64) != Some(32)
    {
        return false;
    }

    let route_hash_matches = |item: &Value, file: &str, segment: u64| {
        let route_key = format!("{action}:segment:{file}:{segment}");
        let digest = crate::sha256(route_key);
        let expected = format!("batch-{}", &digest[..20]);
        item.get("batchId").and_then(Value::as_str) == Some(expected.as_str())
    };
    if !route_hash_matches(previous, previous_file, previous_segment)
        || !route_hash_matches(current, current_file, current_segment)
    {
        return false;
    }

    let mut previous = previous.clone();
    let mut current = current.clone();
    for value in [&mut previous, &mut current] {
        let Some(object) = value.as_object_mut() else {
            return false;
        };
        object.remove("batchId");
        if let Some(owner) = object.get_mut("semanticOwner").and_then(Value::as_object_mut) {
            owner.remove("segment");
        }
    }
    previous == current
}

fn routing_reclassification_preserves_evidence(previous: &str, current: &str) -> bool {
    let Ok(mut previous) = serde_json::from_str::<Value>(previous) else {
        return false;
    };
    let Ok(mut current) = serde_json::from_str::<Value>(current) else {
        return false;
    };
    if deferred_work_segment_routing_preserves_evidence(&previous, &current) {
        return true;
    }
    let previous_action = previous["action"].as_str();
    let current_action = current["action"].as_str();
    let same_frontier = matches!(
        (previous_action, current_action),
        (
            Some("port-missing-upstream-branch"),
            Some("inspect-unverified-missing-branch")
        ) | (
            Some("reconcile-changed-branch"),
            Some("inspect-unverified-changed-branch")
        ) | (
            Some("port-missing-upstream-branch"),
            Some("inspect-weak-missing-branch")
        ) | (
            Some("reconcile-changed-branch"),
            Some("inspect-weak-changed-branch")
        ) | (
            Some("inspect-weak-missing-branch"),
            Some("inspect-unverified-missing-branch")
        ) | (
            Some("inspect-weak-changed-branch"),
            Some("inspect-unverified-changed-branch")
        ) | (
            Some("inspect-unverified-missing-branch"),
            Some("inspect-structural-frontier")
        ) | (
            Some("inspect-unverified-changed-branch"),
            Some("inspect-structural-frontier")
        ) | (
            Some("resolve-ambiguous-owners"),
            Some("inspect-structural-frontier")
        ) | (
            Some("remove-or-justify-extra-local"),
            Some("inspect-structural-frontier")
        )
    );
    let same_action = previous_action.is_some() && previous_action == current_action;
    // A v73 coalesced item could select a weaker route as its representative
    // even when another variant carried the same owner's active route.
    // Only permit this promotion during the actionless-variant migration.
    let legacy_promotion = matches!(
        (previous_action, current_action),
        (
            Some("inspect-unverified-missing-branch" | "inspect-weak-missing-branch"),
            Some("port-missing-upstream-branch")
        ) | (
            Some("inspect-unverified-changed-branch" | "inspect-weak-changed-branch"),
            Some("reconcile-changed-branch")
        )
    );
    // Only the v73 schema omitted per-variant actions. Do not erase routing
    // metadata from two current payloads: a changed route must be reviewed.
    let legacy_variants = previous.get("evidenceVariants").and_then(Value::as_array);
    let current_variants = current.get("evidenceVariants").and_then(Value::as_array);
    let legacy_variant_migration = match (legacy_variants, current_variants) {
        (Some(old), Some(new)) if !old.is_empty() && old.len() == new.len() => {
            old.iter().all(|variant| variant.is_object() && variant.get("action").is_none())
                && new.iter().all(|variant| {
                    variant.get("action").and_then(Value::as_str)
                        .is_some_and(|action| compatible_legacy_variant_action(current_action, action))
                })
        }
        _ => false,
    };
    if !same_frontier && !same_action && !(legacy_promotion && legacy_variant_migration) {
        return false;
    }
    if legacy_variant_migration {
        const STRUCTURAL_REASON: &str = "The frontier is supported only by structural or neighboring graph evidence; keep it visible for later review.";
        const OLD_REASONS: &[&str] = &[
            "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change.",
            "An exact renamed owner has multiple valid graph routes; no arbitrary binding was promoted.",
            "A typed local edge has no corresponding upstream edge at the first divergence.",
        ];
        let new_variants = current["evidenceVariants"].as_array().expect("legacy variants checked");
        for old in previous["evidenceVariants"].as_array_mut().expect("legacy variants checked") {
            if !old["reason"].as_str().is_some_and(|reason| OLD_REASONS.contains(&reason)) {
                continue;
            }
            let mut comparable_old = old.clone();
            comparable_old.as_object_mut().expect("variant object checked").remove("reason");
            let matching_structural = new_variants.iter().any(|new| {
                if new["action"] != "inspect-structural-frontier" || new["reason"] != STRUCTURAL_REASON {
                    return false;
                }
                let mut comparable_new = new.clone();
                let object = comparable_new.as_object_mut().expect("variant object checked");
                object.remove("action");
                object.remove("reason");
                comparable_new == comparable_old
            });
            if matching_structural {
                old["reason"] = Value::String(STRUCTURAL_REASON.to_owned());
            }
        }
    }
    for value in [&mut previous, &mut current] {
        if let Some(object) = value.as_object_mut() {
            if same_frontier || legacy_promotion {
                for key in ["action", "priority", "confidence", "reason", "batchId"] {
                    object.remove(key);
                }
            } else if same_action {
                // Priority and rationale are analyzer triage metadata. A new
                // classification must not reopen a human decision when the
                // action and all source evidence remain identical.
                for key in ["priority", "confidence", "reason"] {
                    object.remove(key);
                }
            }
            if legacy_variant_migration {
                if let Some(variants) = object.get_mut("evidenceVariants").and_then(Value::as_array_mut) {
                    for variant in variants.iter_mut() {
                        if let Some(variant) = variant.as_object_mut() {
                            variant.remove("action");
                        }
                    }
                    variants.sort_by_cached_key(|variant| serde_json::to_string(variant).unwrap_or_default());
                }
            }
        }
    }
    previous == current
}

fn remove_stable_locator_fields(value: &mut Value) -> (usize, bool) {
    fn visit(value: &mut Value, root: bool, count: &mut usize, complete: &mut bool) {
        match value {
            Value::Object(object) => {
                if object.get("stableFingerprint").and_then(Value::as_str).is_some_and(|value| !value.is_empty()) {
                    *count += 1;
                    for key in ["id", "line", "start", "end", "origin"] {
                        object.remove(key);
                    }
                } else if !root && object.contains_key("id") {
                    *complete = false;
                }
                for (key, child) in object.iter_mut() {
                    if key != "legacyIds" {
                        visit(child, false, count, complete);
                    }
                }
            }
            Value::Array(values) => values.iter_mut().for_each(|child| visit(child, false, count, complete)),
            _ => {}
        }
    }
    let mut count = 0;
    let mut complete = true;
    visit(value, true, &mut count, &mut complete);
    (count, complete)
}
fn review_evidence_matches(previous: &str, current: &str) -> bool {
    let (Ok(previous_value), Ok(current_value)) = (
        serde_json::from_str::<Value>(previous),
        serde_json::from_str::<Value>(current),
    ) else {
        return false;
    };
    if previous_value == current_value || routing_reclassification_preserves_evidence(previous, current) {
        return true;
    }
    let mut previous_stable = previous_value;
    let mut current_stable = current_value;
    let (previous_count, previous_complete) = remove_stable_locator_fields(&mut previous_stable);
    let (current_count, current_complete) = remove_stable_locator_fields(&mut current_stable);
    if previous_count == 0 || current_count == 0 || !previous_complete || !current_complete {
        return false;
    }
    for value in [&mut previous_stable, &mut current_stable] {
        if let Some(object) = value.as_object_mut() {
            object.remove("batchId");
            object.remove("legacyIds");
            object.remove("inspectNodeIds");
            object.remove("inspectNodeIdsFromOwners");
        }
    }
    let previous = serde_json::to_string(&previous_stable).unwrap_or_default();
    let current = serde_json::to_string(&current_stable).unwrap_or_default();
    previous == current || routing_reclassification_preserves_evidence(&previous, &current)
}
fn legacy_rekey_payload_matches(previous: &str, current: &str, legacy_id: &str) -> bool {
    let (Ok(mut previous), Ok(mut current)) = (
        serde_json::from_str::<Value>(previous),
        serde_json::from_str::<Value>(current),
    ) else {
        return false;
    };
    if !current["legacyIds"]
        .as_array()
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(legacy_id)))
    {
        return false;
    }
    fn remove_locator_fields(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if object.contains_key("file") && object.contains_key("id") {
                    for key in ["id", "line", "start", "end", "origin", "stableFingerprint"] {
                        object.remove(key);
                    }
                }
                object.values_mut().for_each(remove_locator_fields);
            }
            Value::Array(values) => values.iter_mut().for_each(remove_locator_fields),
            _ => {}
        }
    }
    for value in [&mut previous, &mut current] {
        if let Some(object) = value.as_object_mut() {
            for key in [
                "id",
                "legacyIds",
                "batchId",
                "inspectNodeIds",
                "inspectNodeIdsFromOwners",
            ] {
                object.remove(key);
            }
        }
        remove_locator_fields(value);
    }
    review_evidence_matches(
        &serde_json::to_string(&previous).unwrap_or_default(),
        &serde_json::to_string(&current).unwrap_or_default(),
    )
}
fn stable_review_payload_matches(previous: &str, current: &str) -> bool {
    let (Ok(mut previous), Ok(mut current)) = (
        serde_json::from_str::<Value>(previous),
        serde_json::from_str::<Value>(current),
    ) else {
        return false;
    };
    for value in [&mut previous, &mut current] {
        if let Some(object) = value.as_object_mut() {
            for key in ["id", "legacyIds", "batchId", "inspectNodeIds", "inspectNodeIdsFromOwners"] {
                object.remove(key);
            }
        }
    }
    review_evidence_matches(
        &serde_json::to_string(&previous).unwrap_or_default(),
        &serde_json::to_string(&current).unwrap_or_default(),
    )
}
fn stable_review_payload_key(payload: &str) -> Option<String> {
    let mut value = serde_json::from_str::<Value>(payload).ok()?;
    let (count, complete) = remove_stable_locator_fields(&mut value);
    if count == 0 || !complete {
        return None;
    }
    let object = value.as_object_mut()?;
    for key in [
        "id",
        "legacyIds",
        "action",
        "priority",
        "confidence",
        "reason",
        "batchId",
        "inspectNodeIds",
        "inspectNodeIdsFromOwners",
    ] {
        object.remove(key);
    }
    Some(serde_json::to_string(&value).unwrap_or_default())
}
fn migrate_legacy_decisions(
    conn: &Connection,
    run_id: i64,
    local_hash: &str,
    upstream_hash: &str,
    engine_sha256: Option<&str>,
    dependency_hash: Option<&str>,
) -> Result<usize> {
    let (Some(_engine_sha256), Some(dependency_hash)) = (engine_sha256, dependency_hash) else {
        return Ok(0);
    };
    let old_decisions = {
        let mut stmt = conn.prepare(
            "SELECT d.work_item_id,d.status,d.reason,d.decided_at,d.payload,r.local_hash
             FROM work_item_decisions d
             JOIN work_items w ON w.id=d.work_item_id
             JOIN runs r ON r.id=w.run_id
             WHERE w.run_id<>?1 AND d.status IN ('done','skipped','pending_sync')
               AND d.payload IS NOT NULL AND r.upstream_hash=?2
               AND r.engine_sha256 IS NOT NULL AND r.dependency_hash=?3",
        )?;
        let rows = stmt.query_map(params![run_id, upstream_hash, dependency_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if old_decisions.is_empty() { return Ok(0); }
    let new_items = {
        let mut stmt = conn.prepare("SELECT id,payload FROM work_items WHERE run_id=?1")?;
        let rows = stmt.query_map(params![run_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let old_by_id = old_decisions.into_iter().map(|row| (row.0.clone(), row)).collect::<HashMap<_, _>>();
    let mut alias_targets = HashMap::<String, HashSet<String>>::new();
    for (new_id, current) in &new_items {
        let Ok(item) = serde_json::from_str::<Value>(current) else { continue };
        for alias in item["legacyIds"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            alias_targets.entry(alias.to_owned()).or_default().insert(new_id.clone());
        }
    }
    let mut old_to_new = HashMap::<String, BTreeMap<String, String>>::new();
    let mut new_to_old = HashMap::<String, BTreeMap<String, String>>::new();
    for (new_id, current) in &new_items {
        let Ok(item) = serde_json::from_str::<Value>(current) else { continue };
        let Some(aliases) = item["legacyIds"].as_array() else { continue };
        for alias in aliases.iter().filter_map(Value::as_str) {
            if alias_targets.get(alias).is_none_or(|targets| targets.len() != 1) { continue; }
            let Some(old) = old_by_id.get(alias) else { continue };
            let unchanged_project = old.5 == local_hash;
            let exact_legacy_match = unchanged_project && legacy_rekey_payload_matches(&old.4, current, alias);
            let stable_match = stable_review_payload_matches(&old.4, current);
            if old.0 == *new_id || !(exact_legacy_match || stable_match) { continue; }
            old_to_new.entry(alias.to_owned()).or_default().insert(new_id.clone(), current.clone());
            new_to_old.entry(new_id.clone()).or_default().insert(alias.to_owned(), current.clone());
        }
    }
    // IDs and aliases can both change after unrelated local edits. Carry a
    // decision across that boundary only when stable source evidence maps
    // one-to-one to a current item; ambiguity stays open for review.
    let mut current_by_stable_evidence = HashMap::<String, Vec<(String, String)>>::new();
    for (new_id, current) in &new_items {
        if let Some(key) = stable_review_payload_key(current) {
            current_by_stable_evidence
                .entry(key)
                .or_default()
                .push((new_id.clone(), current.clone()));
        }
    }
    for (old_id, old) in &old_by_id {
        let Some(key) = stable_review_payload_key(&old.4) else { continue };
        let Some(candidates) = current_by_stable_evidence.get(&key) else { continue };
        for (new_id, current) in candidates {
            if old_id == new_id || !stable_review_payload_matches(&old.4, current) {
                continue;
            }
            old_to_new.entry(old_id.clone()).or_default().insert(new_id.clone(), current.clone());
            new_to_old.entry(new_id.clone()).or_default().insert(old_id.clone(), current.clone());
        }
    }
    let mut migrated = 0;
    for (old_id, candidates) in old_to_new {
        if candidates.len() != 1 { continue; }
        let (new_id, current) = candidates.into_iter().next().expect("one migration candidate");
        if new_to_old.get(&new_id).is_none_or(|old_ids| old_ids.len() != 1) { continue; }
        let old = old_by_id.get(&old_id).expect("candidate came from old decision");
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO work_item_decisions(work_item_id,status,reason,decided_at,payload) VALUES (?1,?2,?3,?4,?5)",
            params![new_id, old.1, old.2, old.3, current],
        )?;
        if inserted != 1 { continue; }
        conn.execute(
            "INSERT INTO work_item_id_migrations(old_work_item_id,new_work_item_id,run_id,status,reason,decided_at,previous_payload,current_payload) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
            params![old_id, new_id, run_id, old.1, old.2, old.3, old.4, current],
        )?;
        conn.execute("DELETE FROM work_item_decisions WHERE work_item_id=?1", params![old_id])?;
        migrated += 1;
    }
    Ok(migrated)
}
fn ensure_queue_index(conn: &Connection, name: &str, confidence: bool, batch: bool) -> Result<()> {
    let mut ordering = "CASE WHEN action='remove-or-justify-extra-local' THEN 4 WHEN action='locate-unlinked-upstream-branch' THEN 5 WHEN action='inspect-structural-frontier' THEN 6 WHEN priority='P0' THEN 0 WHEN priority='P1' THEN 1 ELSE 2 END".to_string();
    if confidence {
        ordering.push_str(", CASE confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END");
    }
    if batch {
        ordering.push_str(", batch_id");
    }
    let expected = format!("CREATE INDEX {name} ON work_items(resolved_at, {ordering}, id)");
    let existing: Option<String> = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=?1",
        params![name],
        |row| row.get(0),
    ).optional()?;
    if existing.as_deref() != Some(expected.as_str()) {
        // A stale expression index cannot serve the new ordering. Rebuild it
        // atomically once; subsequent syncs keep the current index intact.
        let tx = if conn.is_autocommit() { Some(conn.unchecked_transaction()?) } else { None };
        conn.execute_batch(&format!("DROP INDEX IF EXISTS {name}; {expected};"))?;
        if let Some(tx) = tx { tx.commit()?; }
    }
    Ok(())
}

fn validate_report_roots(manifest: &Value) -> Result<()> {
    validate_report_roots_with_artifact(manifest, true)
}

fn validate_report_roots_for_queue_read(manifest: &Value) -> Result<()> {
    validate_report_roots_with_artifact(manifest, false)
}

fn is_legacy_checkpoint_snapshot(manifest: &Value, has_pending_sync: bool) -> bool {
    has_pending_sync
        && manifest["schema"].as_str() == Some("project-parity/llm-manifest-v3")
        && manifest["engine"].as_str() == Some(ENGINE_VERSION)
        && manifest.get("engineArtifact").is_none()
        && manifest.get("workItemsIntegrity").is_none()
}

fn validate_report_roots_with_artifact(manifest: &Value, require_artifact: bool) -> Result<()> {
    if manifest["schema"].as_str() == Some("project-parity/llm-manifest-v3") {
        let report_engine = manifest["engine"]
            .as_str()
            .context("current report missing engine")?;
        if report_engine != ENGINE_VERSION {
            bail!(
                "parity report was generated by engine {report_engine}, but this CLI uses {ENGINE_VERSION}; regenerate the report before syncing state"
            );
        }
        if require_artifact {
            let Some(executable_sha256) = manifest["engineArtifact"]["executableSha256"].as_str() else {
                bail!("current report missing a valid engineArtifact.executableSha256");
            };
            if executable_sha256.len() != 64
                || !executable_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("current report missing a valid engineArtifact.executableSha256");
            }
            let current_executable = std::env::current_exe()
                .context("resolve current Project Parity executable")?;
            let current_sha256 = super::sha256_file(&current_executable)
                .context("hash current Project Parity executable")?;
            if !executable_sha256.eq_ignore_ascii_case(&current_sha256) {
                bail!(
                    "parity report was generated by a different Project Parity executable (report {executable_sha256}, current {current_sha256}); regenerate the report before syncing state"
                );
            }
        }
        let local = manifest["localRoot"].as_str().filter(|s| !s.is_empty()).context("current report missing localRoot")?;
        let upstream = manifest["analysisProjection"].as_str().filter(|s| !s.is_empty()).context("current report missing analysisProjection")?;
        for (name, root) in [("localRoot", local), ("analysisProjection", upstream)] {
            let path = Path::new(root);
            if !path.is_absolute() || !path.is_dir() {
                bail!("current report {name} must be an existing absolute directory: {root}");
            }
        }
        return crate::ensure_separate_nested_roots(Path::new(local), Path::new(upstream));
    }
    if let (Some(local), Some(upstream)) = (manifest["localRoot"].as_str(), manifest["analysisProjection"].as_str()) {
        fn normalize_absolute(path: &Path) -> Option<PathBuf> {
            use std::path::Component;
            if !path.is_absolute() { return None; }
            let mut result = PathBuf::new();
            for component in path.components() {
                match component {
                    Component::CurDir => {},
                    Component::ParentDir => { if result.parent().is_some() { result.pop(); } },
                    other => result.push(other.as_os_str()),
                }
            }
            Some(result)
        }
        if Path::new(local).exists() && Path::new(upstream).exists() {
            return crate::ensure_separate_nested_roots(Path::new(local), Path::new(upstream));
        }
        if let (Some(a), Some(b)) = (normalize_absolute(Path::new(local)), normalize_absolute(Path::new(upstream))) {
            if a != b && (a.starts_with(&b) || b.starts_with(&a)) {
                bail!("project roots overlap: {} and {}; move the nested input outside the other root", a.display(), b.display());
            }
        }
    }
    Ok(())
}

pub fn sync(db_path: &Path, report: &Path) -> Result<Value> {
    let manifest: Value = serde_json::from_slice(&fs::read(report.join("llm-manifest.json"))?)?;
    validate_report_roots(&manifest)?;
    let incoming = read_report_identity(&report.join("llm-manifest.json"), true)?;
    SyncGuard::acquire(incoming.roots, report, Some(db_path), false)?.sync()
}

fn sync_locked(db_path: &Path, report: &Path, roots: &RootIdentity) -> Result<Value> {
    let manifest: Value = serde_json::from_slice(&fs::read(report.join("llm-manifest.json"))?)?;
    validate_report_roots(&manifest)?;
    let incoming = read_report_identity(&report.join("llm-manifest.json"), true)?;
    incoming.roots.require(roots, report)?;
    check_report_identity(report, roots, true, Some(db_path))?;
    let shared = super::llm_context::read_shared_work_evidence(report)?;
    let mut conn = open_or_create_state_database(db_path)?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    if let Some(previous) = database_identity(&conn, db_path)? { previous.require(roots, db_path)?; }
    conn.execute_batch("PRAGMA journal_mode=WAL")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let conn = &tx;
    if let Some(previous) = database_identity(conn, db_path)? { previous.require(roots, db_path)?; }
    store_database_identity(conn, roots)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, report TEXT NOT NULL, upstream_hash TEXT, local_hash TEXT, synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS work_items (id TEXT PRIMARY KEY, run_id INTEGER NOT NULL, action TEXT, priority TEXT, confidence TEXT, payload TEXT NOT NULL, first_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, resolved_at TEXT, batch_id TEXT, FOREIGN KEY(run_id) REFERENCES runs(id)); CREATE TABLE IF NOT EXISTS work_item_decisions (work_item_id TEXT PRIMARY KEY, status TEXT NOT NULL CHECK(status IN ('skipped','pending_sync','done')), reason TEXT NOT NULL, decided_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, payload TEXT, FOREIGN KEY(work_item_id) REFERENCES work_items(id)); CREATE INDEX IF NOT EXISTS work_items_queue ON work_items(resolved_at, priority, id); CREATE INDEX IF NOT EXISTS work_item_decisions_status ON work_item_decisions(status);")?;
    ensure_queue_index(&conn, "work_items_queue_phase", false, false)?;
    ensure_queue_index(&conn, "work_items_queue_phase_confidence", true, false)?;
    ensure_batch_schema(&conn)?;
    ensure_decision_schema(&conn)?;
    ensure_run_receipt_schema(&conn)?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS work_item_id_migrations (old_work_item_id TEXT NOT NULL,new_work_item_id TEXT NOT NULL,run_id INTEGER NOT NULL,status TEXT NOT NULL,reason TEXT NOT NULL,decided_at TEXT NOT NULL,previous_payload TEXT NOT NULL,current_payload TEXT NOT NULL,PRIMARY KEY(old_work_item_id,new_work_item_id,run_id),FOREIGN KEY(old_work_item_id) REFERENCES work_items(id),FOREIGN KEY(new_work_item_id) REFERENCES work_items(id),FOREIGN KEY(run_id) REFERENCES runs(id))")?;
    conn.execute_batch("CREATE TEMP TABLE previous_seen (id TEXT PRIMARY KEY); INSERT INTO previous_seen SELECT id FROM work_items WHERE resolved_at IS NULL; CREATE TEMP TABLE previous_unresolved (id TEXT PRIMARY KEY); INSERT INTO previous_unresolved SELECT w.id FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL;")?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS work_item_decision_history (id INTEGER PRIMARY KEY, work_item_id TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, decided_at TEXT NOT NULL, payload TEXT, reopened_run_id INTEGER NOT NULL, reopened_payload TEXT NOT NULL, FOREIGN KEY(work_item_id) REFERENCES work_items(id), FOREIGN KEY(reopened_run_id) REFERENCES runs(id));")?;
    // Older ledgers contain decision snapshots and require an event column.
    for column in ["reopened_run_id INTEGER", "reopened_payload TEXT"] {
        let name = column.split_once(' ').unwrap().0;
        let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('work_item_decision_history') WHERE name=?1)", params![name], |row| row.get(0))?;
        if !exists {
            conn.execute_batch(&format!("ALTER TABLE work_item_decision_history ADD COLUMN {column}"))?;
        }
    }
    let history_has_event: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('work_item_decision_history') WHERE name='event')", [], |row| row.get(0))?;
    let engine_sha256 = manifest["engineArtifact"]["executableSha256"].as_str();
    let dependency_hash = manifest["inputHashes"]["dependencies"].as_str();
    let work_items_sha256 = manifest["workItemsIntegrity"]["sha256"].as_str();
    let work_items_count = manifest["workItemsIntegrity"]["records"].as_i64();
    conn.execute(
        "INSERT INTO runs(report, upstream_hash, local_hash, engine_sha256, dependency_hash, work_items_sha256, work_items_count) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            report.to_string_lossy(),
            incoming.upstream_hash,
            incoming.local_hash,
            engine_sha256,
            dependency_hash,
            work_items_sha256,
            work_items_count,
        ],
    )?;
    let run_id = conn.last_insert_rowid();
    let file = fs::File::open(report.join("llm-work-items.jsonl"))?;
    let mut reader = BufReader::new(file);
    let mut raw_line = Vec::new();
    let mut work_items_digest = Sha256::new();
    let mut seen = 0usize;
    loop {
        raw_line.clear();
        if reader.read_until(b'\n', &mut raw_line)? == 0 {
            break;
        }
        work_items_digest.update(&raw_line);
        if raw_line.last() == Some(&b'\n') {
            raw_line.pop();
        }
        if raw_line.last() == Some(&b'\r') {
            raw_line.pop();
        }
        let line = std::str::from_utf8(&raw_line)
            .context("work-item JSONL is not UTF-8")?
            .to_owned();
        if line.trim().is_empty() {
            continue;
        }
        let item: Value = serde_json::from_str(&line)?;
        let compact = item.get("upstreamEvidenceRef").is_some()
            || item.get("inspectNodeIdsFromOwners").is_some();
        let item = super::llm_context::expand_work_evidence(item, &shared)?;
        let line = if compact {
            serde_json::to_string(&item)?
        } else {
            line
        };
        let id = item["id"].as_str().context("work item has no id")?;
        tx.execute("INSERT INTO work_items(id,run_id,action,priority,confidence,payload,last_seen,resolved_at,batch_id) VALUES (?1,?2,?3,?4,?5,?6,CURRENT_TIMESTAMP,NULL,?7) ON CONFLICT(id) DO UPDATE SET run_id=excluded.run_id, action=excluded.action, priority=excluded.priority, confidence=excluded.confidence, payload=excluded.payload, last_seen=CURRENT_TIMESTAMP, resolved_at=NULL, batch_id=excluded.batch_id", params![id, run_id, item["action"].as_str(), item["priority"].as_str(), item["confidence"].as_str(), line, item["batchId"].as_str()])?;
        seen += 1;
    }
    if manifest["schema"].as_str() == Some("project-parity/llm-manifest-v3") {
        let integrity = &manifest["workItemsIntegrity"];
        let expected_records = integrity["records"]
            .as_u64()
            .context("current report is missing workItemsIntegrity.records")?;
        let expected_sha256 = integrity["sha256"]
            .as_str()
            .context("current report is missing workItemsIntegrity.sha256")?;
        let actual_sha256 = format!("{:x}", work_items_digest.finalize());
        if expected_records != seen as u64 || expected_sha256 != actual_sha256 {
            bail!(
                "report work-item artifact failed integrity check (manifest records: {expected_records}, read records: {seen}, manifest sha256: {expected_sha256}, actual sha256: {actual_sha256}); regenerate the report before syncing state"
            );
        }
    }
    tx.execute(
        "UPDATE work_items SET resolved_at=CURRENT_TIMESTAMP WHERE run_id <> ?1 AND resolved_at IS NULL",
        params![run_id],
    )?;
    let migrated = migrate_legacy_decisions(
        conn, run_id, &incoming.local_hash, &incoming.upstream_hash, engine_sha256, dependency_hash,
    )?;
    // Preserve reviewed decisions across routing and coalesced-evidence schema
    // changes only when the underlying owner and evidence are unchanged.
    // Substantive evidence changes still reopen the item below.
    let reclassified = {
        let mut stmt = tx.prepare(
            "SELECT d.work_item_id, d.payload, w.payload FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL AND d.payload IS NOT NULL",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, previous, current) in reclassified {
        if review_evidence_matches(&previous, &current) {
            tx.execute(
                "UPDATE work_item_decisions SET payload=?2 WHERE work_item_id=?1",
                params![id, current],
            )?;
        }
    }
    let reopened: i64 = conn.query_row(
        "SELECT COUNT(*) FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL AND (d.payload IS NULL OR w.payload <> d.payload)",
        params![run_id],
        |row| row.get(0),
    )?;
    let (event_column, event_value) = if history_has_event { (",event", ",'snapshot'") } else { ("", "") };
    tx.execute(&format!("INSERT INTO work_item_decision_history(work_item_id,status,reason,decided_at,payload,reopened_run_id,reopened_payload{event_column}) SELECT d.work_item_id,d.status,d.reason,d.decided_at,d.payload,?1,w.payload{event_value} FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL AND (d.payload IS NULL OR w.payload <> d.payload)"), params![run_id])?;
    conn.execute("DELETE FROM work_item_decisions WHERE EXISTS (SELECT 1 FROM work_items w WHERE w.id=work_item_decisions.work_item_id AND w.run_id=?1 AND w.resolved_at IS NULL AND (work_item_decisions.payload IS NULL OR w.payload <> work_item_decisions.payload))", params![run_id])?;
    let mut active_decisions = {
        let mut stmt = tx.prepare(
            "SELECT d.work_item_id FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL",
        )?;
        let rows = stmt.query_map(params![run_id], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<HashSet<_>>>()?
    };
    let historical_decisions = {
        let mut stmt = tx.prepare(
            "SELECT h.work_item_id,h.status,h.reason,h.decided_at,h.payload,w.payload FROM work_item_decision_history h JOIN work_items w ON w.id=h.work_item_id WHERE w.run_id=?1 AND w.resolved_at IS NULL AND h.payload IS NOT NULL ORDER BY h.id DESC",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    let mut restored = 0;
    for (id, status, reason, decided_at, previous, current) in historical_decisions {
        if active_decisions.contains(&id)
            || !matches!(status.as_str(), "done" | "skipped" | "pending_sync")
            || !review_evidence_matches(&previous, &current)
        {
            continue;
        }
        tx.execute(
            "INSERT INTO work_item_decisions(work_item_id,status,reason,decided_at,payload) VALUES (?1,?2,?3,?4,?5)",
            params![id, status, reason, decided_at, current],
        )?;
        active_decisions.insert(id);
        restored += 1;
    }
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
    let new_items: i64 = tx.query_row(
        "SELECT COUNT(*) FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id LEFT JOIN previous_seen p ON p.id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL AND p.id IS NULL",
        [], |row| row.get(0),
    )?;
    let resolved: i64 = tx.query_row(
        "SELECT COUNT(*) FROM previous_unresolved p LEFT JOIN work_items w ON w.id=p.id LEFT JOIN work_item_decisions d ON d.work_item_id=p.id WHERE w.id IS NULL OR w.resolved_at IS NOT NULL OR d.work_item_id IS NOT NULL",
        [], |row| row.get(0),
    )?;
    tx.commit()?;
    Ok(
        serde_json::json!({"schema":"project-parity/state-sync-v1","runId":run_id,"workItems":seen,"new":new_items,"resolved":resolved,"reopened":reopened,"restored":restored,"pendingReleased":pending_released,"migrated":migrated,"remaining":remaining,"db":db_path}),
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
    let conn = open_existing_database(db_path)?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_batch_schema(&conn)?;
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
    ensure_queue_index(conn, "work_items_queue_phase_confidence_batch", true, true)?;
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
    let conn = open_existing_database(db_path)?;
    conn.busy_timeout(Duration::from_millis(1000))?;
    ensure_report_is_synced(db_path, &conn)?;
    // Order only the small queue key first. Sorting the full payload here makes
    // SQLite materialize tens of thousands of large JSON blobs before LIMIT
    // can apply, which is both slow and capable of exhausting disk space.
    // Local-only extras and unlinked executable branches are deliberately late
    // audit phases. Large generated/compatibility-heavy sets can otherwise
    // starve upstream functionality gaps. Keep both classes in the queue and
    // surface them automatically after earlier phases are exhausted.
    let mut stmt = conn.prepare("SELECT w.id, w.action, w.priority, w.confidence, w.payload FROM work_items w JOIN (SELECT w.id FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.action='inspect-structural-frontier' THEN 6 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id LIMIT ?1) next ON next.id=w.id ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.action='inspect-structural-frontier' THEN 6 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id")?;
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
    ensure_report_contains_items(db_path, &conn, &items)?;
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
/// Local source edits are expected while reviewed decisions accumulate; sync
/// compares each saved payload with the next report before making it durable.
fn resolve_report_path(db_path: &Path, report: &str) -> PathBuf {
    let report_path = PathBuf::from(report);
    if report_path.is_absolute() {
        return report_path;
    }

    let cwd = std::env::current_dir().ok();
    let absolute_db_path = if db_path.is_absolute() {
        Some(db_path.to_path_buf())
    } else {
        cwd.as_ref().map(|cwd| cwd.join(db_path))
    };
    let mut candidates = vec![report_path.clone()];
    if let Some(cwd) = &cwd {
        candidates.push(cwd.join(&report_path));
    }
    if let Some(db_parent) = absolute_db_path.as_deref().and_then(Path::parent) {
        candidates.push(db_parent.join(&report_path));
        if let Some(workspace_root) = db_parent.parent() {
            candidates.push(workspace_root.join(&report_path));
        }
    }
    candidates.dedup();

    candidates
        .into_iter()
        .find(|candidate| candidate.join("llm-manifest.json").is_file())
        .unwrap_or(report_path)
}

/// State DBs in the tool's local campaign directories must not bypass the
/// freshness guard when their report manifest cannot be resolved.
fn is_parity_campaign_db(db_path: &Path) -> bool {
    db_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == ".parity" || name.starts_with(".parity-"))
}

fn ensure_report_is_synced(db_path: &Path, conn: &Connection) -> Result<()> {
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
    let report = resolve_report_path(db_path, &report);
    let manifest = report.join("llm-manifest.json");
    let modified_at = match fs::metadata(&manifest).and_then(|metadata| metadata.modified()) {
        Ok(modified_at) => modified_at,
        // Older/external report layouts may not have a manifest timestamp. The
        // normal sync path will report missing evidence when it is requested.
        Err(error) if is_parity_campaign_db(db_path) => bail!(
            "parity report manifest is unavailable for campaign state (state: {}, report: {}): {error}",
            db_path.display(),
            manifest.display()
        ),
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
    validate_report_roots_for_queue_read(&manifest_value)?;
    if let Some(report_engine) = manifest_value["engine"].as_str() {
        if report_engine != ENGINE_VERSION {
            bail!(
                "parity report was generated by engine {report_engine}, but this CLI uses {ENGINE_VERSION}; run `project-parity sync` before requesting the next item"
            );
        }
    }
    let has_pending_sync = if table_exists(conn, "work_item_decisions")? {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM work_item_decisions d JOIN work_items w ON w.id=d.work_item_id WHERE d.status='pending_sync' AND w.resolved_at IS NULL)",
            [],
            |row| row.get::<_, bool>(0),
        )?
    } else {
        false
    };
    let legacy_checkpoint_snapshot = is_legacy_checkpoint_snapshot(&manifest_value, has_pending_sync);
    for (side, root, expected_hash) in [
        (
            "local",
            manifest_value["localRoot"].as_str(),
            manifest_value["inputFingerprints"]["local"]["sha256"].as_str(),
        ),
        (
            "upstream",
            manifest_value["analysisProjection"].as_str(),
            manifest_value["inputFingerprints"]["upstream"]["sha256"].as_str(),
        ),
    ] {
        let Some(root) = root else {
            if manifest_value["engine"].as_str() == Some(ENGINE_VERSION) {
                bail!(
                    "parity report manifest is missing the {side} source root. Regenerate the report and run `project-parity sync` before requesting the next item"
                );
            }
            continue;
        };
        let Some(expected_hash) = expected_hash else {
            if manifest_value["engine"].as_str() == Some(ENGINE_VERSION) {
                bail!(
                    "parity report manifest is missing the {side} source fingerprint. Regenerate the report and run `project-parity sync` before requesting the next item"
                );
            }
            continue;
        };
        let selected_files: Vec<(PathBuf, String)> = serde_json::from_value(
            manifest_value["inputFingerprints"][side]["inputFiles"].clone(),
        )
        .context(format!("manifest has no {side} input files"))?;
        let current_hash = crate::fingerprint_input(Path::new(root), &selected_files)?;
        if current_hash != expected_hash && !(side == "local" && has_pending_sync) {
            bail!(
                "parity report {side} source inputs changed since report generation (root: {root}). Regenerate the report, then run `project-parity sync` before requesting the next item"
            );
        }
    }
    if let Some(dependencies) = manifest_value["inputFingerprints"]["dependencies"].as_object() {
        let root = dependencies["root"]
            .as_str()
            .context("dependency input fingerprint has no root")?;
        let expected_hash = dependencies["sha256"]
            .as_str()
            .context("dependency input fingerprint has no hash")?;
        let input_roots: Vec<crate::DependencyInputRoot> = serde_json::from_value(
            dependencies
                .get("packageRoots")
                .cloned()
                .context("dependency input fingerprint has no package roots")?,
        )?;
        let resolution_queries: Vec<crate::DependencyResolutionQuery> = serde_json::from_value(
            dependencies
                .get("resolutionQueries")
                .cloned()
                .context("dependency input fingerprint has no resolution queries")?,
        )?;
        let selected_files: Vec<(PathBuf, String)> = serde_json::from_value(
            dependencies
                .get("inputFiles")
                .cloned()
                .context("dependency input fingerprint has no input files")?,
        )?;
        let current_hash = crate::fingerprint_dependency_input(
            Path::new(root),
            &input_roots,
            &selected_files,
            &resolution_queries,
        )?;
        if current_hash != expected_hash && !legacy_checkpoint_snapshot {
            bail!(
                "parity report dependency source inputs changed since report generation (root: {root}). Regenerate the report, then run `project-parity sync` before requesting the next item"
            );
        }
    } else if manifest_value["inputHashes"]["dependencies"].is_string()
        && manifest_value["engine"].as_str() == Some(ENGINE_VERSION)
    {
        bail!(
            "parity report manifest is missing dependency source fingerprints. Regenerate the report and run `project-parity sync` before requesting the next item"
        );
    }
    Ok(())
}

/// Guard the bounded queue slice against a report/state mismatch. The index is
/// already emitted for `show-work`; checking at most `limit` IDs here prevents
/// wasting a review cycle on work whose evidence is absent from the current
/// report. Older reports without an index retain their legacy behavior.
fn ensure_report_contains_items(db_path: &Path, conn: &Connection, items: &[Value]) -> Result<()> {
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
    let report = resolve_report_path(db_path, &report);
    let index_path = report.join("llm-work-items.index.json");
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
    let mut conn = open_existing_database(db_path)?;
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
    let mut conn = open_existing_database(db_path)?;
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
    let mut conn = open_existing_database(db_path)?;
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
    let mut conn = open_existing_database(db_path)?;
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

fn ensure_run_receipt_schema(conn: &Connection) -> Result<()> {
    for (name, column_type) in [
        ("engine_sha256", "TEXT"),
        ("dependency_hash", "TEXT"),
        ("work_items_sha256", "TEXT"),
        ("work_items_count", "INTEGER"),
    ] {
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('runs') WHERE name=?1)",
            params![name],
            |row| row.get(0),
        )?;
        if !exists {
            conn.execute_batch(&format!("ALTER TABLE runs ADD COLUMN {name} {column_type}"))?;
        }
    }
    Ok(())
}

pub fn stats(db_path: &Path) -> Result<Value> {
    let conn = open_existing_database(db_path)?;
    let (active, skipped, pending_sync, done, resolved, deferred): (i64, i64, i64, i64, i64, i64) = conn.query_row(
        "SELECT
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.work_item_id IS NULL THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='skipped' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='pending_sync' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.status='done' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NOT NULL THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN w.resolved_at IS NULL AND d.work_item_id IS NULL AND w.action IN ('remove-or-justify-extra-local','locate-unlinked-upstream-branch','inspect-structural-frontier') THEN 1 ELSE 0 END), 0)
         FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    )?;
    let mut breakdown_stmt = conn.prepare(
        "SELECT CASE WHEN w.action IN ('remove-or-justify-extra-local','locate-unlinked-upstream-branch','inspect-structural-frontier') THEN 'P2' ELSE COALESCE(w.priority,'unknown') END, COALESCE(w.confidence,'unknown'), COALESCE(w.action,'unknown'), COUNT(*)
         FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id
         WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL
         GROUP BY w.priority, w.confidence, w.action
         ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.action='inspect-structural-frontier' THEN 6 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END,
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
    let conn = open_existing_database(db_path)?;
    let has_receipt_column = |name: &str| -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('runs') WHERE name=?1)",
            params![name],
            |row| row.get(0),
        )?)
    };
    let optional_column = |name: &str| -> Result<&'static str> {
        Ok(if has_receipt_column(name)? {
            match name {
                "engine_sha256" => "engine_sha256",
                "dependency_hash" => "dependency_hash",
                "work_items_sha256" => "work_items_sha256",
                "work_items_count" => "work_items_count",
                _ => bail!("unsupported run receipt column: {name}"),
            }
        } else {
            "NULL"
        })
    };
    let sql = format!(
        "SELECT id, report, upstream_hash, local_hash, synced_at, {}, {}, {}, {} FROM runs ORDER BY id DESC LIMIT ?1",
        optional_column("engine_sha256")?,
        optional_column("dependency_hash")?,
        optional_column("work_items_sha256")?,
        optional_column("work_items_count")?,
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(serde_json::json!({
                "id": row.get::<_, i64>(0)?,
                "report": row.get::<_, String>(1)?,
                "upstreamHash": row.get::<_, Option<String>>(2)?,
                "localHash": row.get::<_, Option<String>>(3)?,
                "syncedAt": row.get::<_, String>(4)?,
                "engineSha256": row.get::<_, Option<String>>(5)?,
                "dependencyHash": row.get::<_, Option<String>>(6)?,
                "workItemsSha256": row.get::<_, Option<String>>(7)?,
                "workItemsCount": row.get::<_, Option<i64>>(8)?,
            }))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(serde_json::json!({"schema":"project-parity/state-runs-v1","count":rows.len(),"runs":rows}))
}

pub fn import_graph(db_path: &Path, artifact: &Path) -> Result<Value> {
    // This command owns a standalone graph database and intentionally creates
    // it when absent; unlike queue commands, it cannot create work items.
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
    let mut target = open_existing_database(db_path)?;
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

    fn test_manifest(dir: &Path) -> String {
        serde_json::json!({
            "localRoot": dir.canonicalize().unwrap(),
            "analysisProjection": dir.canonicalize().unwrap(),
            "inputHashes": {"upstream": "u", "reproduction": "l"},
        }).to_string()
    }

    fn report(dir: &Path, ids: &[&str]) {
        fs::write(
            dir.join("llm-manifest.json"),
            test_manifest(dir),
        )
        .unwrap();
        let body = ids
            .iter()
            .map(|id| format!(r#"{{"id":"{id}","priority":"P1","action":"inspect"}}"#))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(dir.join("llm-work-items.jsonl"), format!("{body}\n")).unwrap();
    }

    fn report_items(dir: &Path, items: &[Value]) {
        fs::write(dir.join("llm-manifest.json"), test_manifest(dir)).unwrap();
        let body = items.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
        fs::write(dir.join("llm-work-items.jsonl"), format!("{body}\n")).unwrap();
    }

    fn root_report(dir: &Path, local: &Path, upstream: &Path) {
        fs::create_dir_all(dir).unwrap();
        report(dir, &["done", "pending", "skipped"]);
        fs::write(dir.join("llm-manifest.json"), serde_json::json!({
            "engine": "rust-oxc-0.126.0/v73",
            "localRoot": local,
            "analysisProjection": upstream,
            "inputHashes": {"upstream": "u", "local": "l"},
        }).to_string()).unwrap();
        fs::write(dir.join("report.json"), serde_json::json!({
            "left": {"root": local, "projectSha256": "l"},
            "right": {"root": upstream, "projectSha256": "u"},
        }).to_string()).unwrap();
        // Represent retained v73 artifacts that clearly predate their DB run.
        for name in ["llm-manifest.json", "report.json"] {
            fs::File::options().write(true).open(dir.join(name)).unwrap()
                .set_times(fs::FileTimes::new().set_modified(std::time::SystemTime::now() - Duration::from_secs(60))).unwrap();
        }
    }

    fn reviewed_state(db: &Path, report: &Path) {
        sync(db, report).unwrap();
        mark_pending_sync(db, "done", "reviewed").unwrap();
        sync(db, report).unwrap();
        mark_pending_sync(db, "pending", "reviewed").unwrap();
        skip(db, "skipped", "verified false positive").unwrap();
    }

    fn state_snapshot(db: &Path) -> Vec<(String, String)> {
        let conn = Connection::open(db).unwrap();
        let mut rows = Vec::new();
        for table in ["runs", "work_items", "work_item_decisions", "sqlite_master"] {
            let mut stmt = conn.prepare(&format!("SELECT * FROM {table} ORDER BY 1")).unwrap();
            let count = stmt.column_count();
            let values = stmt.query_map([], |row| {
                Ok((0..count).map(|i| format!("{:?}", row.get_ref(i).unwrap())).collect::<Vec<_>>().join("|"))
            }).unwrap();
            rows.extend(values.map(|value| (table.to_owned(), value.unwrap())));
        }
        rows
    }

    #[test]
    fn run_receipts_upgrade_legacy_rows_and_remain_queryable() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE runs (id INTEGER PRIMARY KEY, report TEXT NOT NULL, upstream_hash TEXT, local_hash TEXT, synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO runs(report,upstream_hash,local_hash) VALUES ('legacy','u','l');").unwrap();

        let before = runs(&db, 1).unwrap();
        assert!(before["runs"][0]["engineSha256"].is_null());
        ensure_run_receipt_schema(&conn).unwrap();
        conn.execute(
            "UPDATE runs SET engine_sha256=?1, dependency_hash=?2, work_items_sha256=?3, work_items_count=?4 WHERE id=1",
            params!["engine", "dependencies", "items", 12],
        ).unwrap();

        let after = runs(&db, 1).unwrap();
        assert_eq!(after["runs"][0]["engineSha256"], "engine");
        assert_eq!(after["runs"][0]["dependencyHash"], "dependencies");
        assert_eq!(after["runs"][0]["workItemsSha256"], "items");
        assert_eq!(after["runs"][0]["workItemsCount"], 12);
    }

    #[test]
    fn root_identity_rejects_foreign_state_sync_without_changing_decisions() {
        for foreign_local in [false, true] {
            let root = tempdir().unwrap();
            let local = root.path().join("local");
            let upstream = root.path().join("upstream");
            let foreign = root.path().join("foreign");
            for path in [&local, &upstream, &foreign] { fs::create_dir(path).unwrap(); }
            let prior = root.path().join("prior");
            let incoming = root.path().join("incoming");
            let db = root.path().join("state.sqlite");
            root_report(&prior, &local, &upstream);
            reviewed_state(&db, &prior);
            root_report(&incoming, if foreign_local { &foreign } else { &local }, if foreign_local { &upstream } else { &foreign });
            let before = state_snapshot(&db);
            assert!(sync(&db, &incoming).is_err(), "foreign roots must not reconcile identical hashes and IDs");
            assert_eq!(state_snapshot(&db), before);
        }
    }

    #[test]
    fn root_identity_rejects_missing_or_replaced_legacy_provenance() {
        for replacement in [None, Some("wrong hashes"), Some("newer report"), Some("same second")] {
            let root = tempdir().unwrap();
            let prior = root.path().join("prior");
            let incoming = root.path().join("incoming");
            let db = root.path().join("state.sqlite");
            root_report(&prior, root.path(), root.path());
            reviewed_state(&db, &prior);
            Connection::open(&db).unwrap().execute_batch("DROP TABLE IF EXISTS parity_identity").unwrap();
            root_report(&incoming, root.path(), root.path());
            match replacement {
                None => {
                    fs::remove_file(prior.join("llm-manifest.json")).unwrap();
                    fs::remove_file(prior.join("report.json")).unwrap();
                }
                Some("wrong hashes") => {
                    let mut value: Value = serde_json::from_slice(&fs::read(prior.join("llm-manifest.json")).unwrap()).unwrap();
                    value["inputHashes"]["local"] = Value::String("overwritten".into());
                    fs::write(prior.join("llm-manifest.json"), value.to_string()).unwrap();
                }
                Some("newer report") => {
                    let file = fs::File::options().write(true).open(prior.join("llm-manifest.json")).unwrap();
                    file.set_times(fs::FileTimes::new().set_modified(std::time::SystemTime::now() + Duration::from_secs(10))).unwrap();
                }
                _ => {
                    let at: u64 = Connection::open(&db).unwrap().query_row("SELECT CAST(strftime('%s', synced_at) AS INTEGER) FROM runs ORDER BY id DESC LIMIT 1", [], |row| row.get(0)).unwrap();
                    fs::File::options().write(true).open(prior.join("llm-manifest.json")).unwrap()
                        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(at))).unwrap();
                }
            }
            let before = state_snapshot(&db);
            assert!(sync(&db, &incoming).is_err(), "legacy identity cannot come from the incoming report");
            assert_eq!(state_snapshot(&db), before);
        }
    }

    #[test]
    fn root_identity_accepts_stable_legacy_engine_migration_and_report_fallback() {
        for fallback in [false, true] {
            let root = tempdir().unwrap();
            let prior = root.path().join("prior");
            let incoming = root.path().join("incoming");
            let db = root.path().join("state.sqlite");
            root_report(&prior, root.path(), root.path());
            reviewed_state(&db, &prior);
            Connection::open(&db).unwrap().execute_batch("DROP TABLE IF EXISTS parity_identity").unwrap();
            if fallback {
                fs::remove_file(prior.join("llm-manifest.json")).unwrap();
            }
            root_report(&incoming, root.path(), root.path());
            let mut value: Value = serde_json::from_slice(&fs::read(incoming.join("llm-manifest.json")).unwrap()).unwrap();
            value["engine"] = Value::String(ENGINE_VERSION.into());
            value["inputHashes"]["local"] = Value::String("new source contents".into());
            fs::write(incoming.join("llm-manifest.json"), value.to_string()).unwrap();
            let result = sync(&db, &incoming).unwrap();
            assert_eq!(result["pendingReleased"], 1);
            assert_eq!(result["reopened"], 0);
            assert_eq!(stats(&db).unwrap()["done"], 2);
            assert_eq!(stats(&db).unwrap()["skipped"], 1);
            fs::remove_dir_all(&prior).unwrap();
            assert!(sync(&db, &incoming).is_ok(), "persisted roots survive removal of the legacy report");
        }
    }

    #[test]
    fn root_identity_failed_reconciliation_rolls_back_legacy_schema_and_decisions() {
        let root = tempdir().unwrap();
        let prior = root.path().join("prior");
        let incoming = root.path().join("incoming");
        let db = root.path().join("state.sqlite");
        root_report(&prior, root.path(), root.path());
        reviewed_state(&db, &prior);
        Connection::open(&db).unwrap().execute_batch("DROP TABLE IF EXISTS parity_identity; DROP INDEX work_items_queue_phase").unwrap();
        root_report(&incoming, root.path(), root.path());
        fs::write(incoming.join("llm-work-items.jsonl"), "{\"id\":\"new\"}\ninvalid json\n").unwrap();
        let before = state_snapshot(&db);
        assert!(sync(&db, &incoming).is_err());
        assert_eq!(state_snapshot(&db), before);
    }

    #[test]
    fn root_identity_legacy_relative_paths_require_one_existing_interpretation() {
        for ambiguous in [false, true] {
            let root = tempdir().unwrap();
            let nested = root.path().join("nested");
            fs::create_dir(&nested).unwrap();
            let prior = nested.join("report");
            let incoming = root.path().join("incoming");
            let db = nested.join("state.sqlite");
            root_report(&prior, root.path(), root.path());
            reviewed_state(&db, &prior);
            Connection::open(&db).unwrap().execute_batch("DROP TABLE parity_identity; UPDATE runs SET report='report'").unwrap();
            if ambiguous { root_report(&root.path().join("report"), root.path(), root.path()); }
            root_report(&incoming, root.path(), root.path());
            let before = state_snapshot(&db);
            let result = sync(&db, &incoming);
            if ambiguous {
                assert!(result.is_err());
                assert_eq!(state_snapshot(&db), before);
            } else {
                assert_eq!(result.unwrap()["pendingReleased"], 1);
            }
        }
    }

    #[test]
    fn root_identity_direct_state_sync_rejects_tracked_incomplete_generation() {
        let root = tempdir().unwrap();
        let report = root.path().join("report");
        let db = root.path().join("state.sqlite");
        root_report(&report, root.path(), root.path());
        reviewed_state(&db, &report);
        drop(SyncGuard::for_generation(root.path(), root.path(), &report, Some(&db)).unwrap());
        let before = state_snapshot(&db);
        assert!(sync(&db, &report).is_err());
        assert_eq!(state_snapshot(&db), before);
    }

    fn add_current_manifest(dir: &Path, root: &Path, record_count: usize) {
        let work_items = fs::read(dir.join("llm-work-items.jsonl")).unwrap();
        let local = root.join("local");
        let upstream = root.join("upstream");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&upstream).unwrap();
        let manifest = serde_json::json!({
            "schema":"project-parity/llm-manifest-v3",
            "engine":ENGINE_VERSION,
            "engineArtifact":{"executableSha256":crate::sha256_file(&std::env::current_exe().unwrap()).unwrap()},
            "localRoot":local,
            "analysisProjection":upstream,
            "inputHashes":{"local":"l","upstream":"u"},
            "workItemsIntegrity":{
                "sha256":crate::sha256(work_items),
                "records":record_count,
            },
        });
        fs::write(
            dir.join("llm-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    fn write_receipted_report(dir: &Path, local: &Path, upstream: &Path, local_hash: &str, items: &[Value]) {
        fs::create_dir_all(dir).unwrap();
        fs::create_dir_all(local).unwrap();
        fs::create_dir_all(upstream).unwrap();
        let body = if items.is_empty() {
            String::new()
        } else {
            format!("{}\n", items.iter().map(Value::to_string).collect::<Vec<_>>().join("\n"))
        };
        fs::write(dir.join("llm-work-items.jsonl"), &body).unwrap();
        let manifest = serde_json::json!({
            "schema":"project-parity/llm-manifest-v3",
            "engine":ENGINE_VERSION,
            "engineArtifact":{"executableSha256":crate::sha256_file(&std::env::current_exe().unwrap()).unwrap()},
            "localRoot":local,
            "analysisProjection":upstream,
            "inputHashes":{"local":local_hash,"upstream":"upstream-hash","dependencies":"dependency-hash"},
            "inputFingerprints":{"local":{"sha256":crate::fingerprint_input(local, &[]).unwrap(),"inputFiles":[]},"upstream":{"sha256":crate::fingerprint_input(upstream, &[]).unwrap(),"inputFiles":[]},"dependencies":{"root":local,"sha256":crate::fingerprint_dependency_input(local, &[], &[], &[]).unwrap(),"packageRoots":[],"resolutionQueries":[],"inputFiles":[]}},
            "workItemsIntegrity":{"sha256":crate::sha256(body),"records":items.len()},
        });
        fs::write(dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn state_commands_do_not_create_a_missing_database() {
        let root = tempdir().unwrap();
        let db = root.path().join("missing/state.sqlite");

        assert!(stats(&db).is_err());
        assert!(!db.exists());
        assert!(mark_pending_sync(&db, "work-item", "reviewed").is_err());
        assert!(!db.exists());
    }

    #[test]
    fn state_sync_refuses_an_existing_empty_database_without_changing_it() {
        let root = tempdir().unwrap();
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        let report_dir = root.path().join("report");
        let db = root.path().join("state.sqlite");
        write_receipted_report(&report_dir, &local, &upstream, "local-hash", &[]);
        fs::write(&db, []).unwrap();

        let error = sync(&db, &report_dir).unwrap_err();

        assert!(error.to_string().contains("state database is an empty file"));
        assert_eq!(fs::metadata(&db).unwrap().len(), 0);
    }

    #[test]
    fn sync_rejects_truncated_or_same_count_corrupt_work_item_artifact() {
        let root = tempdir().unwrap();
        let report_dir = root.path().join("report");
        fs::create_dir_all(&report_dir).unwrap();
        let db = root.path().join(".parity-5040/state.sqlite");
        fs::create_dir_all(db.parent().unwrap()).unwrap();

        report(&report_dir, &["a", "b"]);
        add_current_manifest(&report_dir, root.path(), 2);
        sync(&db, &report_dir).unwrap();
        mark_pending_sync(&db, "a", "reviewed").unwrap();

        fs::write(report_dir.join("llm-work-items.jsonl"), "{\"id\":\"a\",\"priority\":\"P1\",\"action\":\"inspect\"}\n").unwrap();
        let error = sync(&db, &report_dir).unwrap_err();
        assert!(error.to_string().contains("work-item artifact failed integrity check"));

        fs::write(
            report_dir.join("llm-work-items.jsonl"),
            "{\"id\":\"a\",\"priority\":\"P1\",\"action\":\"inspect\"}\n{\"id\":\"c\",\"priority\":\"P1\",\"action\":\"inspect\"}\n",
        )
        .unwrap();
        let error = sync(&db, &report_dir).unwrap_err();
        assert!(error.to_string().contains("work-item artifact failed integrity check"));

        let conn = Connection::open(&db).unwrap();
        assert_eq!(conn.query_row("SELECT count(*) FROM runs", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(conn.query_row("SELECT count(*) FROM work_items WHERE run_id=1", [], |row| row.get::<_, i64>(0)).unwrap(), 2);
        assert_eq!(conn.query_row("SELECT reason FROM work_item_decisions WHERE work_item_id='a'", [], |row| row.get::<_, String>(0)).unwrap(), "reviewed");
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
        report(root.path(), &["b"]);
        let third = sync(&db, root.path()).unwrap();
        assert_eq!(third["new"], 1);
        assert_eq!(third["resolved"], 1);
        assert_eq!(third["remaining"], 1);
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
    fn next_resolves_campaign_relative_report_from_database_location() {
        let root = tempdir().unwrap();
        let campaign = root.path().join(".parity-5040");
        let report_dir = campaign.join("report");
        fs::create_dir_all(&report_dir).unwrap();
        let db = campaign.join("state.sqlite");
        report(&report_dir, &["a"]);
        sync(&db, &report_dir).unwrap();

        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE runs SET report='.parity-5040/report', synced_at='2000-01-01 00:00:00'",
            [],
        )
        .unwrap();
        drop(conn);

        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("manifest is newer than the queue state"));
        assert!(error.to_string().contains(".parity-5040/report/llm-manifest.json"));
    }

    #[test]
    fn next_refuses_campaign_state_when_report_manifest_is_missing() {
        let root = tempdir().unwrap();
        let campaign = root.path().join(".parity-5040");
        let report_dir = campaign.join("report");
        fs::create_dir_all(&report_dir).unwrap();
        let db = campaign.join("state.sqlite");
        report(&report_dir, &["a"]);
        sync(&db, &report_dir).unwrap();
        fs::remove_file(report_dir.join("llm-manifest.json")).unwrap();

        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("manifest is unavailable for campaign state"));
    }

    #[test]
    fn next_preserves_legacy_queue_when_report_manifest_is_missing() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        fs::remove_file(root.path().join("llm-manifest.json")).unwrap();

        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn next_rejects_nested_report_inputs_even_if_fingerprints_match() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let upstream = local.join("reference");
        fs::create_dir_all(&upstream).unwrap();
        fs::create_dir_all(&report_dir).unwrap();
        fs::write(upstream.join("index.js"), "export const value = 1").unwrap();
        report(&report_dir, &["a"]);
        let manifest = serde_json::json!({
            "engine": ENGINE_VERSION,
            "localRoot": local.display().to_string(),
            "analysisProjection": upstream.display().to_string(),
            "inputFingerprints": {
                "local": {"sha256": crate::fingerprint_input(&local, &[]).unwrap(), "inputFiles": []},
                "upstream": {"sha256": crate::fingerprint_input(&upstream, &[]).unwrap(), "inputFiles": []},
            },
        });
        sync(&db, &report_dir).unwrap();
        fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(next(&db, 10).unwrap_err().to_string().contains("project roots overlap"));
        let mut reverse = manifest;
        reverse["localRoot"] = upstream.display().to_string().into();
        reverse["analysisProjection"] = local.display().to_string().into();
        fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&reverse).unwrap()).unwrap();
        assert!(next(&db, 10).unwrap_err().to_string().contains("project roots overlap"));
    }

    #[test]
    fn sync_rejects_nested_roots_before_creating_or_changing_state() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let absent_db = root.path().join("absent.sqlite");
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let upstream = local.join("reference");
        fs::create_dir_all(&upstream).unwrap();
        fs::create_dir_all(&report_dir).unwrap();
        report(&report_dir, &["a"]);
        sync(&db, &report_dir).unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute("INSERT INTO work_item_decisions(work_item_id,status,reason) VALUES ('a','done','retained')", []).unwrap();
        drop(conn);
        for (first, second) in [(&local, &upstream), (&upstream, &local)] {
            let manifest = serde_json::json!({"localRoot":first,"analysisProjection":second});
            fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(sync(&db, &report_dir).unwrap_err().to_string().contains("project roots overlap"));
            assert!(sync(&absent_db, &report_dir).is_err());
            assert!(!absent_db.exists());
            let conn = Connection::open(&db).unwrap();
            assert_eq!(conn.query_row("SELECT count(*) FROM runs", [], |row| row.get::<_, i64>(0)).unwrap(), 1);
            assert_eq!(conn.query_row("SELECT reason FROM work_item_decisions WHERE work_item_id='a'", [], |row| row.get::<_, String>(0)).unwrap(), "retained");
        }
    }

    #[test]
    fn sync_rejects_missing_nested_absolute_roots_without_creating_database() {
        let root = tempdir().unwrap();
        let db = root.path().join("absent.sqlite");
        let report_dir = root.path().join("report");
        fs::create_dir_all(&report_dir).unwrap();
        report(&report_dir, &["a"]);
        let local = root.path().join("missing");
        let upstream = local.join("extra").join("..").join("reference");
        for (first, second) in [(&local, &upstream), (&upstream, &local)] {
            let manifest = serde_json::json!({"localRoot":first,"analysisProjection":second});
            fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(sync(&db, &report_dir).unwrap_err().to_string().contains("project roots overlap"));
            assert!(!db.exists());
        }
        let disjoint = serde_json::json!({"localRoot":local,"analysisProjection":root.path().join("other")});
        assert!(validate_report_roots(&disjoint).is_ok());
        assert!(validate_report_roots(&serde_json::json!({})).is_ok());
    }

    #[test]
    fn current_report_requires_resolvable_roots_before_opening_database() {
        let root = tempdir().unwrap();
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let missing = root.path().join("missing");
        let db = root.path().join("absent.sqlite");
        fs::create_dir_all(&report_dir).unwrap();
        fs::create_dir_all(&local).unwrap();
        report(&report_dir, &["a"]);
        let mut manifest = serde_json::json!({
            "schema":"project-parity/llm-manifest-v3",
            "engine":ENGINE_VERSION,
            "engineArtifact":{"executableSha256":crate::sha256_file(&std::env::current_exe().unwrap()).unwrap()},
            "localRoot":local,
            "analysisProjection":missing,
        });
        for change in 0..3 {
            if change == 1 { manifest.as_object_mut().unwrap().remove("localRoot"); }
            if change == 2 { manifest["localRoot"] = "relative".into(); }
            fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(sync(&db, &report_dir).is_err());
            assert!(!db.exists());
        }
        #[cfg(unix)] {
            let broken = root.path().join("broken");
            std::os::unix::fs::symlink(&missing, &broken).unwrap();
            manifest["localRoot"] = local.display().to_string().into();
            manifest["analysisProjection"] = broken.display().to_string().into();
            fs::write(report_dir.join("llm-manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
            assert!(sync(&db, &report_dir).is_err());
            assert!(!db.exists());
        }
        let legacy = serde_json::json!({"localRoot": local, "analysisProjection": missing});
        assert!(validate_report_roots(&legacy).is_ok());
    }

    #[test]
    fn current_report_requires_engine_artifact_fingerprint() {
        let root = tempdir().unwrap();
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&upstream).unwrap();
        let mut manifest = serde_json::json!({
            "schema":"project-parity/llm-manifest-v3",
            "engine":ENGINE_VERSION,
            "localRoot":local,
            "analysisProjection":upstream,
        });
        assert!(validate_report_roots(&manifest)
            .unwrap_err()
            .to_string()
            .contains("engineArtifact.executableSha256"));
        manifest["engineArtifact"] = serde_json::json!({"executableSha256":crate::sha256_file(&std::env::current_exe().unwrap()).unwrap()});
        assert!(validate_report_roots(&manifest).is_ok());
        manifest["engineArtifact"]["executableSha256"] = "b".repeat(64).into();
        assert!(validate_report_roots(&manifest)
            .unwrap_err()
            .to_string()
            .contains("different Project Parity executable"));
        manifest["engineArtifact"]["executableSha256"] = "not-a-hash".into();
        assert!(validate_report_roots(&manifest)
            .unwrap_err()
            .to_string()
            .contains("engineArtifact.executableSha256"));
    }

    #[test]
    fn queue_reads_accept_v79_snapshot_without_sync_artifact_receipt() {
        let root = tempdir().unwrap();
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&upstream).unwrap();
        let mut manifest = serde_json::json!({
            "schema":"project-parity/llm-manifest-v3",
            "engine":ENGINE_VERSION,
            "localRoot":local,
            "analysisProjection":upstream,
        });

        assert!(validate_report_roots_for_queue_read(&manifest).is_ok());
        assert!(validate_report_roots(&manifest).is_err());
        assert!(!is_legacy_checkpoint_snapshot(&manifest, false));
        assert!(is_legacy_checkpoint_snapshot(&manifest, true));

        manifest["engineArtifact"] = serde_json::json!({"executableSha256":"a".repeat(64)});
        assert!(!is_legacy_checkpoint_snapshot(&manifest, true));
        manifest.as_object_mut().unwrap().remove("engineArtifact");

        manifest["engine"] = "another-engine".into();
        assert!(validate_report_roots_for_queue_read(&manifest).is_err());
        assert!(!is_legacy_checkpoint_snapshot(&manifest, true));
    }

    #[cfg(unix)]
    #[test]
    fn report_roots_resolve_existing_symlinks_before_checking_overlap() {
        let root = tempdir().unwrap();
        let local = root.path().join("local");
        let external = root.path().join("external");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&external).unwrap();
        let link = local.join("reference");
        std::os::unix::fs::symlink(&external, &link).unwrap();
        assert!(validate_report_roots(&serde_json::json!({"localRoot":local,"analysisProjection":link})).is_ok());
    }

    #[test]
    fn next_refuses_local_edits_without_pending_sync_decisions() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        fs::create_dir_all(local.join("src")).unwrap();
        fs::create_dir_all(upstream.join("src")).unwrap();
        fs::create_dir_all(&report_dir).unwrap();
        fs::write(local.join("src/index.ts"), "export const value = 1\n").unwrap();
        fs::write(upstream.join("src/index.ts"), "export const value = 1\n").unwrap();
        report(&report_dir, &["a"]);
        let local_fingerprint = crate::fingerprint_input(&local, &[]).unwrap();
        let upstream_fingerprint = crate::fingerprint_input(&upstream, &[]).unwrap();
        let manifest = serde_json::json!({
            "engine": ENGINE_VERSION,
            "localRoot": local.display().to_string(),
            "analysisProjection": upstream.display().to_string(),
            "inputHashes": {
                "local": "analysis-hash-that-may-include-dependencies",
                "upstream": "analysis-hash",
            },
            "inputFingerprints": {
                "local": {"sha256": local_fingerprint, "inputFiles": []},
                "upstream": {"sha256": upstream_fingerprint, "inputFiles": []},
            },
        });
        fs::write(
            report_dir.join("llm-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        sync(&db, &report_dir).unwrap();

        fs::write(local.join("src/index.ts"), "export const value = 2\n").unwrap();

        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("local source inputs changed since report generation"));
    }

    #[test]
    fn next_keeps_the_synced_snapshot_after_local_edits_during_checkpoint() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        fs::create_dir_all(local.join("src")).unwrap();
        fs::create_dir_all(upstream.join("src")).unwrap();
        fs::create_dir_all(&report_dir).unwrap();
        let local_file = local.join("src/index.ts");
        let upstream_file = upstream.join("src/index.ts");
        let unrelated_test = local.join("src/unrelated.test.ts");
        fs::write(&local_file, "export const value = 1\n").unwrap();
        fs::write(&upstream_file, "export const value = 1\n").unwrap();
        fs::write(&unrelated_test, "export const testValue = 1\n").unwrap();
        report(&report_dir, &["a", "b"]);
        let manifest = serde_json::json!({
            "engine": ENGINE_VERSION,
            "localRoot": local.display().to_string(),
            "analysisProjection": upstream.display().to_string(),
            "inputHashes": {"local": "l", "upstream": "u"},
            "inputFingerprints": {
                "local": {
                    "sha256": crate::fingerprint_input(&local, &[]).unwrap(),
                    "inputFiles": [],
                },
                "upstream": {
                    "sha256": crate::fingerprint_input(&upstream, &[]).unwrap(),
                    "inputFiles": [],
                },
            },
        });
        fs::write(
            report_dir.join("llm-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        sync(&db, &report_dir).unwrap();
        mark_pending_sync(&db, "a", "reviewed patch awaiting checkpoint").unwrap();
        fs::write(&unrelated_test, "export const testValue = 2\n").unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        let added_file = local.join("src/added.ts");
        fs::write(&added_file, "export const added = true\n").unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
        fs::remove_file(&added_file).unwrap();

        fs::write(&upstream_file, "export const value = 2\n").unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("upstream source inputs changed since report generation"));

        fs::write(&upstream_file, "export const value = 1\n").unwrap();
        fs::remove_file(&local_file).unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);

        fs::write(&local_file, "export const value = 1\n").unwrap();
        fs::write(local.join("src/index.ts.map"), "{}\n").unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);

        fs::remove_file(local.join("src/index.ts.map")).unwrap();
        fs::write(local.join("tsconfig.json"), r#"{"compilerOptions":{"paths":{}}}"#)
            .unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);

        fs::remove_file(local.join("tsconfig.json")).unwrap();
        fs::write(local.join("package.json"), r#"{"name":"fixture"}"#).unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn next_accepts_unchanged_dependency_backed_report_with_parse_failure() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let report_dir = root.path().join("report");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        let dependency_root = local.clone();
        let dependency_package = dependency_root.join("node_modules/demo");
        fs::create_dir_all(local.join("src")).unwrap();
        fs::create_dir_all(upstream.join("src")).unwrap();
        fs::create_dir_all(dependency_package.join("dist")).unwrap();
        fs::create_dir_all(&report_dir).unwrap();
        fs::write(local.join("src/unreadable.ts"), [0xff, 0xfe]).unwrap();
        fs::write(upstream.join("src/index.ts"), "export const value = 1\n").unwrap();
        fs::write(
            dependency_package.join("package.json"),
            r#"{"name":"demo","version":"1.0.0","dependencies":{"missing-transitive":"1.0.0"}}"#,
        )
        .unwrap();
        let dependency_file = dependency_package.join("dist/index.js");
        fs::write(&dependency_file, "export const dependency = 1\n").unwrap();
        let unrelated_dependency_test = dependency_package.join("dist/index.test.js");
        fs::write(&unrelated_dependency_test, "export const testValue = 1\n").unwrap();
        let dependency_input_root = crate::DependencyInputRoot {
            package_root: dependency_package.clone(),
            resolution_paths: vec![dependency_package.clone()],
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
        };
        let dependency_queries = vec![
            crate::DependencyResolutionQuery {
                from: local.join("src"),
                name: "demo".to_string(),
            },
            crate::DependencyResolutionQuery {
                from: dependency_package.clone(),
                name: "missing-transitive".to_string(),
            },
        ];
        let (dependency_inputs, _) = crate::discover_dependency_package_files(
            &dependency_package,
            &dependency_input_root,
        )
        .unwrap();
        let dependency_fingerprint = crate::fingerprint_dependency_input(
            &dependency_root,
            std::slice::from_ref(&dependency_input_root),
            &dependency_inputs,
            &dependency_queries,
        )
        .unwrap();
        report(&report_dir, &["parse-failure"]);
        let manifest = serde_json::json!({
            "engine": ENGINE_VERSION,
            "localRoot": local.display().to_string(),
            "analysisProjection": upstream.display().to_string(),
            "inputHashes": {
                "local": "combined-local-and-dependency-analysis-hash",
                "upstream": "u",
                "dependencies": "dependency-analysis-hash",
            },
            "inputFingerprints": {
                "local": {
                    "sha256": crate::fingerprint_input(&local, &[]).unwrap(),
                    "inputFiles": [],
                },
                "upstream": {
                    "sha256": crate::fingerprint_input(&upstream, &[]).unwrap(),
                    "inputFiles": [],
                },
                "dependencies": {
                    "root": dependency_root.display().to_string(),
                    "sha256": dependency_fingerprint,
                    "packageRoots": [dependency_input_root],
                    "inputFiles": dependency_inputs,
                    "resolutionQueries": dependency_queries,
                },
            },
        });
        fs::write(
            report_dir.join("llm-manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        sync(&db, &report_dir).unwrap();

        let output = next(&db, 10).unwrap();
        assert_eq!(output["count"], 1);

        fs::write(
            &unrelated_dependency_test,
            "export const testValue = 2\n",
        )
        .unwrap();
        assert_eq!(next(&db, 10).unwrap()["count"], 1);

        fs::write(&dependency_file, "export const dependency = 2\n").unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));

        fs::write(&dependency_file, "export const dependency = 1\n").unwrap();
        let added_file = dependency_package.join("dist/added.js");
        fs::write(&added_file, "export const added = true\n").unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));

        fs::remove_file(&added_file).unwrap();
        fs::remove_file(&dependency_file).unwrap();
        let alternate_root = dependency_package.join("lib");
        fs::create_dir_all(&alternate_root).unwrap();
        fs::write(alternate_root.join("index.js"), "export const dependency = 1\n").unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));
        fs::remove_file(alternate_root.join("index.js")).unwrap();
        fs::remove_dir(&alternate_root).unwrap();
        fs::write(&dependency_file, "export const dependency = 1\n").unwrap();

        let missing_package = dependency_package.join("node_modules/missing-transitive");
        fs::create_dir_all(&missing_package).unwrap();
        fs::write(
            missing_package.join("package.json"),
            r#"{"name":"missing-transitive","version":"1.0.0"}"#,
        )
        .unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));

        fs::write(dependency_file.with_extension("js.map"), "{}\n").unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));

        fs::remove_file(dependency_file.with_extension("js.map")).unwrap();
        fs::write(
            dependency_package.join("package.json"),
            r#"{"name":"demo","version":"1.0.1","dependencies":{"missing-transitive":"1.0.0"}}"#,
        )
        .unwrap();
        let error = next(&db, 10).unwrap_err();
        assert!(error
            .to_string()
            .contains("dependency source inputs changed since report generation"));
    }

    #[test]
    fn sync_rejects_a_current_manifest_generated_by_an_older_engine() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        fs::write(
            root.path().join("llm-manifest.json"),
            r#"{"schema":"project-parity/llm-manifest-v3","engine":"rust-oxc-0.126.0/v38","inputHashes":{"upstream":"u","reproduction":"l"}}"#,
        )
        .unwrap();
        let conn = Connection::open(&db).unwrap();
        let error = sync(&db, root.path()).unwrap_err();
        assert!(error.to_string().contains("generated by engine"));
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
        )
        .unwrap();
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            concat!(
                "{\"id\":\"locator\",\"priority\":\"P0\",\"confidence\":\"unknown\",\"action\":\"locate-unlinked-upstream-branch\"}\n",
                "{\"id\":\"extra\",\"priority\":\"P0\",\"confidence\":\"unknown\",\"action\":\"remove-or-justify-extra-local\"}\n",
                "{\"id\":\"structural\",\"priority\":\"P0\",\"confidence\":\"weak-candidate\",\"action\":\"inspect-structural-frontier\"}\n"
            ),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();

        let stats = stats(&db).unwrap();
        assert_eq!(stats["active"], 3);
        assert_eq!(stats["actionable"], 0);
        assert_eq!(stats["deferred"], 3);
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
        "EXPLAIN QUERY PLAN SELECT w.id FROM work_items w LEFT JOIN work_item_decisions d ON d.work_item_id=w.id WHERE w.resolved_at IS NULL AND d.work_item_id IS NULL ORDER BY CASE WHEN w.action='remove-or-justify-extra-local' THEN 4 WHEN w.action='locate-unlinked-upstream-branch' THEN 5 WHEN w.action='inspect-structural-frontier' THEN 6 WHEN w.priority='P0' THEN 0 WHEN w.priority='P1' THEN 1 ELSE 2 END, CASE w.confidence WHEN 'proven-structure' THEN 0 WHEN 'proven-bundle-normalized' THEN 0 WHEN 'candidate' THEN 1 WHEN 'weak-candidate' THEN 2 ELSE 3 END, w.batch_id, w.id LIMIT 100",
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
            test_manifest(root.path()),
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
            test_manifest(root.path()),
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
    fn structural_frontiers_are_deferred_after_active_work() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(root.path().join("llm-manifest.json"), test_manifest(root.path())).unwrap();
        fs::write(root.path().join("llm-work-items.jsonl"), concat!(
            "{\"id\":\"structural\",\"priority\":\"P0\",\"action\":\"inspect-structural-frontier\"}\n",
            "{\"id\":\"active\",\"priority\":\"P2\",\"action\":\"inspect\"}\n"
        )).unwrap();
        sync(&db, root.path()).unwrap();
        let items = next(&db, 2).unwrap()["items"].as_array().unwrap().clone();
        assert_eq!(items[0]["id"], "active");
        assert_eq!(items[1]["id"], "structural");
        let stats = stats(&db).unwrap();
        assert_eq!(stats["deferred"], 1);
        assert_eq!(stats["actionable"], 1);
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
        let conn = Connection::open(&db).unwrap();
        let archived: (String, String, String) = conn.query_row(
            "SELECT status, reason, payload FROM work_item_decision_history WHERE work_item_id='a'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(archived.0, "pending_sync");
        assert_eq!(archived.1, "reviewed");
        assert!(archived.2.contains("\"id\":\"a\""));
    }

    #[test]
    fn sync_rekeys_legacy_decision_only_with_matching_receipt_and_unique_evidence() {
        let root = tempdir().unwrap();
        let report_dir = root.path().join("report");
        let db = root.path().join("state.sqlite");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        let old_id = "work-legacy-offset-id";
        let location = serde_json::json!({
            "id":"left:src/editor.ts:10:40:0","file":"src/editor.ts","kind":"Function",
            "line":1,"start":10,"end":40,
        });
        let old = serde_json::json!({
            "id":old_id,"action":"reconcile-changed-owner","priority":"P1","confidence":"candidate",
            "reason":"review the changed owner","local":[location],"upstream":[],"evidencePath":[],
            "inspectNodeIds":["left:src/editor.ts:10:40:0"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "local-hash", &[old]);
        sync(&db, &report_dir).unwrap();
        mark_pending_sync(&db, old_id, "reviewed source and callers").unwrap();

        let mut stable_location = location.clone();
        stable_location["id"] = "left:src/editor.ts:11:41:0".into();
        stable_location["line"] = 2.into();
        stable_location["start"] = 11.into();
        stable_location["end"] = 41.into();
        stable_location["stableFingerprint"] = "stable-review-v1:unchanged-owner".into();
        let current = serde_json::json!({
            "id":"work-stable-offset-independent-id","legacyIds":[old_id],
            "action":"reconcile-changed-owner","priority":"P2","confidence":"weak-candidate",
            "reason":"same owner, updated triage","local":[stable_location],"upstream":[],"evidencePath":[],
            "inspectNodeIds":["left:src/editor.ts:11:41:0"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "local-hash", &[current]);
        let result = sync(&db, &report_dir).unwrap();
        assert_eq!(result["migrated"], 1);
        assert_eq!(result["remaining"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);
        let conn = Connection::open(&db).unwrap();
        let migrated: (String, String, String) = conn.query_row(
            "SELECT old_work_item_id,new_work_item_id,status FROM work_item_id_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).unwrap();
        assert_eq!(migrated, (old_id.into(), "work-stable-offset-independent-id".into(), "pending_sync".into()));
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM work_item_decisions WHERE work_item_id=?1", [old_id], |row| row.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(conn.query_row("SELECT status FROM work_item_decisions WHERE work_item_id='work-stable-offset-independent-id'", [], |row| row.get::<_, String>(0)).unwrap(), "done");
    }

    #[test]
    fn sync_does_not_rekey_when_input_receipt_changes_or_alias_is_ambiguous() {
        let root = tempdir().unwrap();
        let report_dir = root.path().join("report");
        let db = root.path().join("state.sqlite");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        let old_id = "work-legacy-offset-id";
        let old = serde_json::json!({
            "id":old_id,"action":"inspect","priority":"P1","local":[{"id":"left:a","file":"a.ts","kind":"Function","start":1,"end":4}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "local-hash", &[old]);
        sync(&db, &report_dir).unwrap();
        mark_pending_sync(&db, old_id, "reviewed").unwrap();

        let current = serde_json::json!({
            "id":"work-stable-new","legacyIds":[old_id],"action":"inspect","priority":"P1",
            "local":[{"id":"left:a","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","start":1,"end":4}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "changed-local-hash", &[current.clone()]);
        assert_eq!(sync(&db, &report_dir).unwrap()["migrated"], 0);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);

        let ambiguous_a = serde_json::json!({
            "id":"work-stable-a","legacyIds":[old_id],"action":"inspect","priority":"P1",
            "local":[{"id":"left:a","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","start":1,"end":4}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a"],
        });
        let ambiguous_b = serde_json::json!({
            "id":"work-stable-b","legacyIds":[old_id],"action":"inspect","priority":"P1",
            "local":[{"id":"left:a","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","start":1,"end":4}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "changed-local-hash", &[ambiguous_a, ambiguous_b]);
        assert_eq!(sync(&db, &report_dir).unwrap()["migrated"], 0);
        assert_eq!(next(&db, 10).unwrap()["count"], 2);
    }

    #[test]
    fn sync_migrates_decision_across_local_hash_change_by_unique_stable_evidence() {
        let root = tempdir().unwrap();
        let report_dir = root.path().join("report");
        let db = root.path().join("state.sqlite");
        let local = root.path().join("local");
        let upstream = root.path().join("upstream");
        let old = serde_json::json!({
            "id":"work-old-owner-id","action":"inspect","priority":"P1",
            "local":[{"id":"left:a:1:4:0","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","start":1,"end":4}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a:1:4:0"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "local-hash-before", &[old]);
        sync(&db, &report_dir).unwrap();
        mark_pending_sync(&db, "work-old-owner-id", "reviewed stable owner evidence").unwrap();

        let current = serde_json::json!({
            "id":"work-new-owner-id","action":"inspect","priority":"P2",
            "local":[{"id":"left:a:20:23:0","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","start":20,"end":23}],
            "upstream":[],"evidencePath":[],"inspectNodeIds":["left:a:20:23:0"],
        });
        write_receipted_report(&report_dir, &local, &upstream, "local-hash-after", &[current]);
        let result = sync(&db, &report_dir).unwrap();
        assert_eq!(result["migrated"], 1);
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["remaining"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 0);
    }

    #[test]
    fn stable_locator_evidence_ignores_only_offsets_and_ids() {
        let previous = serde_json::json!({
            "id":"work-stable","action":"inspect","priority":"P1",
            "local":[{"id":"left:a:10:20:0","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","line":1,"start":10,"end":20}],
        });
        let moved = serde_json::json!({
            "id":"work-stable","action":"inspect","priority":"P2",
            "local":[{"id":"left:a:50:60:2","stableFingerprint":"stable-a","file":"a.ts","kind":"Function","line":4,"start":50,"end":60}],
        });
        assert!(review_evidence_matches(&previous.to_string(), &moved.to_string()));
        let changed = serde_json::json!({
            "id":"work-stable","action":"inspect","priority":"P2",
            "local":[{"id":"left:a:50:60:2","stableFingerprint":"changed","file":"a.ts","kind":"Function","line":4,"start":50,"end":60}],
        });
        assert!(!review_evidence_matches(&previous.to_string(), &changed.to_string()));
    }

    #[test]
    fn sync_restores_reviewed_decisions_when_identical_evidence_returns() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let original = vec![
            serde_json::json!({"id":"done","priority":"P1","action":"inspect"}),
            serde_json::json!({"id":"skipped","priority":"P1","action":"inspect"}),
        ];
        report_items(root.path(), &original);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "done", "reviewed source and callers").unwrap();
        sync(&db, root.path()).unwrap();
        skip(&db, "skipped", "confirmed local-only helper").unwrap();

        report_items(root.path(), &[
            serde_json::json!({"id":"done","priority":"P0","action":"changed"}),
            serde_json::json!({"id":"skipped","priority":"P0","action":"changed"}),
        ]);
        assert_eq!(sync(&db, root.path()).unwrap()["reopened"], 2);
        report_items(root.path(), &[]);
        sync(&db, root.path()).unwrap();
        report_items(root.path(), &original);

        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["restored"], 2);
        assert_eq!(result["new"], 0);
        assert_eq!(stats(&db).unwrap()["active"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);
        assert_eq!(stats(&db).unwrap()["skipped"], 1);
    }

    #[test]
    fn legacy_decision_history_is_preserved_when_a_decision_reopens() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "a", "reviewed").unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("DROP TABLE work_item_decision_history; CREATE TABLE work_item_decision_history (id INTEGER PRIMARY KEY, work_item_id TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, decided_at TEXT NOT NULL, payload TEXT, event TEXT NOT NULL CHECK(event IN ('snapshot','decision')), recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); INSERT INTO work_item_decision_history(work_item_id,status,reason,decided_at,event) VALUES ('a','done','old history','2020-01-01','decision');").unwrap();
        fs::write(root.path().join("llm-work-items.jsonl"), "{\"id\":\"a\",\"priority\":\"P0\",\"action\":\"changed\"}\n").unwrap();
        assert_eq!(sync(&db, root.path()).unwrap()["reopened"], 1);
        let rows: Vec<(String, String, Option<i64>)> = conn.prepare("SELECT event,reason,reopened_run_id FROM work_item_decision_history ORDER BY id").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        assert_eq!(rows, vec![("decision".into(), "old history".into(), None), ("snapshot".into(), "reviewed".into(), Some(2))]);
    }

    #[test]
    fn sync_reopens_legacy_decisions_without_payload_evidence() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["done", "skipped"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "done", "reviewed before payload snapshots").unwrap();
        sync(&db, root.path()).unwrap();
        skip(&db, "skipped", "verified before payload snapshots").unwrap();

        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "UPDATE work_item_decisions SET payload=NULL WHERE work_item_id IN ('done','skipped')",
            [],
        )
        .unwrap();

        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["new"], 0);
        assert_eq!(result["reopened"], 2);
        assert_eq!(stats(&db).unwrap()["active"], 2);
        assert_eq!(next(&db, 10).unwrap()["count"], 2);
        let decisions: i64 = conn
            .query_row("SELECT COUNT(*) FROM work_item_decisions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(decisions, 0);

        let history: Vec<(String, String, Option<String>, String)> = conn
            .prepare(
                "SELECT h.status,h.reason,h.payload,h.reopened_payload FROM work_item_decision_history h WHERE h.reopened_run_id=(SELECT MAX(id) FROM runs) ORDER BY h.work_item_id",
            )
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            history,
            vec![
                (
                    "done".into(),
                    "reviewed before payload snapshots".into(),
                    None,
                    conn.query_row(
                        "SELECT payload FROM work_items WHERE id='done'",
                        [],
                        |row| row.get(0)
                    )
                    .unwrap(),
                ),
                (
                    "skipped".into(),
                    "verified before payload snapshots".into(),
                    None,
                    conn.query_row(
                        "SELECT payload FROM work_items WHERE id='skipped'",
                        [],
                        |row| row.get(0)
                    )
                    .unwrap(),
                ),
            ]
        );
    }

    #[test]
    fn reopening_rolls_back_history_and_decision_on_failure() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "a", "reviewed").unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TRIGGER reject_reopen BEFORE DELETE ON work_item_decisions BEGIN SELECT RAISE(ABORT, 'reject reopen'); END;").unwrap();
        fs::write(root.path().join("llm-work-items.jsonl"), "{\"id\":\"a\",\"priority\":\"P0\",\"action\":\"changed\"}\n").unwrap();
        assert!(sync(&db, root.path()).is_err());
        let decision: String = conn.query_row("SELECT reason FROM work_item_decisions WHERE work_item_id='a'", [], |row| row.get(0)).unwrap();
        let history: i64 = conn.query_row("SELECT COUNT(*) FROM work_item_decision_history", [], |row| row.get(0)).unwrap();
        let runs: i64 = conn.query_row("SELECT COUNT(*) FROM runs", [], |row| row.get(0)).unwrap();
        assert_eq!((decision.as_str(), history, runs), ("reviewed", 0, 1));
    }

    #[test]
    fn structural_reclassification_preserves_same_evidence_but_reopens_changed_evidence() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        fs::write(
            root.path().join("llm-manifest.json"),
            test_manifest(root.path()),
        )
        .unwrap();
        let mut item = serde_json::json!({
            "id":"work:owner-pair",
            "action":"port-missing-upstream-branch",
            "priority":"P0",
            "confidence":"candidate",
            "reason":"A typed upstream edge has no local counterpart.",
            "batchId":"batch:port",
            "local":[{"id":"left:edge","file":"src/local.ts","line":10}],
            "upstream":[{"id":"right:edge","file":"dist/chunk.js","line":20}],
            "evidencePath":[{"basis":"seed-unit","left":{"id":"left:owner"},"right":{"id":"right:owner"}}],
            "inspectNodeIds":["left:edge","right:edge"]
        });
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", serde_json::to_string(&item).unwrap()),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:owner-pair", "reviewed; no local change needed").unwrap();

        item["action"] = serde_json::json!("inspect-unverified-missing-branch");
        item["priority"] = serde_json::json!("P2");
        item["confidence"] = serde_json::json!("weak-candidate");
        item["reason"] = serde_json::json!("Inspect behavior before proposing a source change.");
        item["batchId"] = serde_json::json!("batch:inspect");
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", serde_json::to_string(&item).unwrap()),
        )
        .unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);

        item["upstream"][0]["line"] = serde_json::json!(21);
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", serde_json::to_string(&item).unwrap()),
        )
        .unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn deferred_work_segment_repartition_preserves_unchanged_evidence_only() {
        let make_item = |segment: u64, inspect_id: &str| {
            let action = "locate-unlinked-upstream-branch";
            let file = "dist/part.js";
            let route = format!("{action}:segment:{file}:{segment}");
            let digest = crate::sha256(route);
            serde_json::json!({
                "id":"work:stable-segment-item",
                "action":action,
                "priority":"P2",
                "confidence":"unknown",
                "reason":"Inspect this unlinked statement.",
                "batchId":format!("batch-{}", &digest[..20]),
                "semanticOwner":{
                    "kind":"WorkSegment",
                    "action":action,
                    "file":file,
                    "segment":segment,
                    "maximumWorkItems":32
                },
                "inspectNodeIds":[inspect_id],
                "upstream":[{"id":inspect_id}]
            })
        };

        let previous = make_item(15, "right:dist/part.js:graph:Statement:303871:305093:47212");
        let repartitioned = make_item(16, "right:dist/part.js:graph:Statement:303871:305093:47212");
        assert!(deferred_work_segment_routing_preserves_evidence(
            &previous,
            &repartitioned
        ));

        let changed_inspect = make_item(16, "right:dist/part.js:graph:Statement:303872:305093:47212");
        assert!(!deferred_work_segment_routing_preserves_evidence(
            &previous,
            &changed_inspect
        ));

        let mut wrong_hash = repartitioned.clone();
        wrong_hash["batchId"] = serde_json::json!("batch:not-derived-from-route");
        assert!(!deferred_work_segment_routing_preserves_evidence(
            &previous,
            &wrong_hash
        ));

        let mut changed_owner = repartitioned.clone();
        changed_owner["semanticOwner"]["file"] = serde_json::json!("dist/other.js");
        assert!(!deferred_work_segment_routing_preserves_evidence(
            &previous,
            &changed_owner
        ));

        let mut coalesced = repartitioned;
        coalesced["evidenceVariants"] = serde_json::json!([{"inspectNodeIds":["variant"]}]);
        assert!(!deferred_work_segment_routing_preserves_evidence(
            &previous,
            &coalesced
        ));
    }

    #[test]
    fn deferred_work_segment_sync_updates_snapshot_without_reopening() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let action = "locate-unlinked-upstream-branch";
        let file = "dist/part.js";
        let inspect_id = "right:dist/part.js:graph:Statement:303871:305093:47212";
        let make_item = |segment: u64| {
            let route = format!("{action}:segment:{file}:{segment}");
            let digest = crate::sha256(route);
            serde_json::json!({
                "id":"work:stable-segment-item",
                "action":action,
                "priority":"P2",
                "confidence":"unknown",
                "reason":"Inspect this unlinked statement.",
                "batchId":format!("batch-{}", &digest[..20]),
                "semanticOwner":{
                    "kind":"WorkSegment",
                    "action":action,
                    "file":file,
                    "segment":segment,
                    "maximumWorkItems":32
                },
                "inspectNodeIds":[inspect_id],
                "upstream":[{"id":inspect_id}]
            })
        };
        let mut first = make_item(15);
        report(root.path(), &[]);
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", first),
        )
        .unwrap();
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:stable-segment-item", "reviewed").unwrap();

        first = make_item(16);
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", first),
        )
        .unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(stats(&db).unwrap()["done"], 1);
        let stored: String = Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT payload FROM work_item_decisions WHERE work_item_id='work:stable-segment-item'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&stored).unwrap(), first);

        let mut changed = make_item(16);
        changed["inspectNodeIds"][0] =
            serde_json::json!("right:dist/part.js:graph:Statement:303872:305093:47212");
        changed["upstream"][0]["id"] =
            serde_json::json!("right:dist/part.js:graph:Statement:303872:305093:47212");
        fs::write(
            root.path().join("llm-work-items.jsonl"),
            format!("{}\n", changed),
        )
        .unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn same_action_triage_reclassification_preserves_decision_but_changed_evidence_reopens() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        let mut item = serde_json::json!({
            "id":"work:stable-owner",
            "action":"reconcile-changed-branch",
            "priority":"P2",
            "confidence":"weak-candidate",
            "reason":"The owner fingerprint matches, but graph correspondence is not established.",
            "local":[{"id":"left:owner","file":"src/local.ts","line":10}],
            "upstream":[{"id":"right:owner","file":"dist/chunk.js","line":20}],
            "evidencePath":[{"basis":"owner-fingerprint"}],
            "inspectNodeIds":["left:owner","right:owner"]
        });
        report_items(root.path(), &[item.clone()]);
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:stable-owner", "Reviewed against source").unwrap();

        item["priority"] = serde_json::json!("P1");
        item["confidence"] = serde_json::json!("candidate");
        item["reason"] = serde_json::json!("The best owner correspondence is changed-candidate.");
        report_items(root.path(), &[item.clone()]);
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["pendingReleased"], 1);
        assert_eq!(stats(&db).unwrap()["done"], 1);

        item["upstream"][0]["id"] = serde_json::json!("right:other-owner");
        report_items(root.path(), &[item]);
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 1);
        assert_eq!(next(&db, 10).unwrap()["count"], 1);
    }

    #[test]
    fn weak_to_unverified_reclassification_preserves_reviewed_evidence() {
        for (previous_action, current_action) in [
            (
                "inspect-weak-missing-branch",
                "inspect-unverified-missing-branch",
            ),
            (
                "inspect-weak-changed-branch",
                "inspect-unverified-changed-branch",
            ),
        ] {
            let previous = serde_json::json!({
                "id": "work:owner-pair",
                "action": previous_action,
                "priority": "P2",
                "confidence": "weak-candidate",
                "reason": "Only structural AST edges differ.",
                "batchId": "batch:old",
                "local": [{"id":"left:edge","file":"src/local.ts","line":10}],
                "upstream": [{"id":"right:edge","file":"dist/chunk.js","line":20}]
            });
            let current = serde_json::json!({
                "id": "work:owner-pair",
                "action": current_action,
                "priority": "P2",
                "confidence": "weak-candidate",
                "reason": "Inspect semantics before proposing a source change.",
                "batchId": "batch:new",
                "local": [{"id":"left:edge","file":"src/local.ts","line":10}],
                "upstream": [{"id":"right:edge","file":"dist/chunk.js","line":20}]
            });
            assert!(routing_reclassification_preserves_evidence(
                &previous.to_string(),
                &current.to_string()
            ));
        }
    }

    #[test]
    fn unverified_to_structural_reclassification_preserves_decisions() {
        for (previous_action, status) in [
            ("inspect-unverified-missing-branch", "done"),
            ("inspect-unverified-changed-branch", "pending_sync"),
            ("resolve-ambiguous-owners", "done"),
            ("remove-or-justify-extra-local", "pending_sync"),
        ] {
            let root = tempdir().unwrap();
            let db = root.path().join("state.sqlite");
            fs::write(root.path().join("llm-manifest.json"), test_manifest(root.path())).unwrap();
            let mut item = serde_json::json!({
                "id":"work:frontier",
                "action":previous_action,
                "priority":"P2",
                "confidence":"weak-candidate",
                "reason":"Review frontier semantics.",
                "batchId":"batch:old",
                "local":[{"id":"left:edge","file":"src/local.ts","line":10}],
                "upstream":[{"id":"right:edge","file":"dist/chunk.js","line":20}],
                "evidencePath":[{"basis":"neighbor-shape"}],
                "inspectNodeIds":["left:edge","right:edge"]
            });
            fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
            sync(&db, root.path()).unwrap();
            if status == "pending_sync" {
                mark_pending_sync(&db, "work:frontier", "reviewed; sync pending").unwrap();
            } else {
                skip(&db, "work:frontier", "reviewed as non-actionable").unwrap();
            }

            item["action"] = serde_json::json!("inspect-structural-frontier");
            item["priority"] = serde_json::json!("P2");
            item["confidence"] = serde_json::json!("weak-candidate");
            item["reason"] = serde_json::json!("Only weak graph evidence supports this frontier.");
            item["batchId"] = serde_json::json!("batch:new");
            fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
            let result = sync(&db, root.path()).unwrap();
            assert_eq!(result["reopened"], 0, "{previous_action}");
            if status == "pending_sync" {
                assert_eq!(result["pendingReleased"], 1, "{previous_action}");
                assert_eq!(stats(&db).unwrap()["done"], 1, "{previous_action}");
            } else {
                assert_eq!(stats(&db).unwrap()["skipped"], 1, "{previous_action}");
            }
        }
    }

    #[test]
    fn coalesced_reclassification_preserves_only_unchanged_evidence() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &[]);
        let variant = |id: &str| serde_json::json!({
            "priority":"P2", "confidence":"weak-candidate", "reason":"The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change.",
            "local":[], "upstream":[{"id":id}],
            "evidencePath":[{"basis":"neighbor-shape", "right":{"id":id}}],
            "inspectNodeIds":[id]
        });
        let mut item = serde_json::json!({
            "id":"work:coalesced", "action":"inspect-unverified-missing-branch",
            "priority":"P2", "confidence":"weak-candidate", "reason":"old route",
            "local":[], "upstream":[{"id":"a"},{"id":"b"}],
            "evidencePath":[{"basis":"neighbor-shape"}], "inspectNodeIds":["a","b"],
            "evidenceVariants":[variant("a"),variant("b")]
        });
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:coalesced", "reviewed").unwrap();
        item["action"] = serde_json::json!("inspect-structural-frontier");
        item["reason"] = serde_json::json!("new route");
        let variants = item["evidenceVariants"].as_array_mut().unwrap();
        variants.reverse();
        for variant in variants {
            variant["action"] = serde_json::json!("inspect-structural-frontier");
            variant["reason"] = serde_json::json!("The frontier is supported only by structural or neighboring graph evidence; keep it visible for later review.");
        }
        let previous: String = Connection::open(&db).unwrap().query_row(
            "SELECT payload FROM work_item_decisions WHERE work_item_id='work:coalesced'", [], |row| row.get(0)
        ).unwrap();
        let mut changed_reason = item.clone();
        changed_reason["evidenceVariants"][0]["reason"] = serde_json::json!("A genuinely different review reason");
        assert!(!routing_reclassification_preserves_evidence(&previous, &changed_reason.to_string()));
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["pendingReleased"], 1);
        assert_eq!(stats(&db).unwrap()["done"], 1);

        item["evidenceVariants"][0]["evidencePath"][0]["right"]["id"] = serde_json::json!("changed");
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 1);
    }

    #[test]
    fn queue_index_migration_rebuilds_only_stale_definitions() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &["a"]);
        sync(&db, root.path()).unwrap();
        let conn = Connection::open(&db).unwrap();
        conn.execute_batch("DROP INDEX work_items_queue_phase; CREATE INDEX work_items_queue_phase ON work_items(resolved_at, priority, id); DROP INDEX work_items_queue_phase_confidence; CREATE INDEX work_items_queue_phase_confidence ON work_items(resolved_at, priority, id); DROP INDEX work_items_queue_phase_confidence_batch; CREATE INDEX work_items_queue_phase_confidence_batch ON work_items(resolved_at, priority, id);").unwrap();
        drop(conn);
        sync(&db, root.path()).unwrap();
        let conn = Connection::open(&db).unwrap();
        for name in ["work_items_queue_phase", "work_items_queue_phase_confidence", "work_items_queue_phase_confidence_batch"] {
            let sql: String = conn.query_row("SELECT sql FROM sqlite_master WHERE name=?1", [name], |row| row.get(0)).unwrap();
            assert!(sql.contains("inspect-structural-frontier"), "{name}");
        }
        let before: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0)).unwrap();
        drop(conn);
        sync(&db, root.path()).unwrap();
        let conn = Connection::open(&db).unwrap();
        let after: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0)).unwrap();
        assert_eq!(after, before, "unchanged indexes should not be rebuilt");
        drop(conn);
        optimize_queue(&db).unwrap();
        let conn = Connection::open(&db).unwrap();
        let after_optimize: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0)).unwrap();
        drop(conn);
        sync(&db, root.path()).unwrap();
        let conn = Connection::open(&db).unwrap();
        let after_sync: i64 = conn.query_row("PRAGMA schema_version", [], |row| row.get(0)).unwrap();
        assert_eq!(after_sync, after_optimize, "sync must retain optimized indexes");
    }

    #[test]
    fn coalesced_schema_migration_preserves_same_action_decision() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &[]);
        let mut item = serde_json::json!({
            "id":"work:coalesced", "action":"inspect-unresolved-upstream-graph-context",
            "priority":"P2", "confidence":"unknown", "reason":"module boundary",
            "evidenceVariants":[{"priority":"P2", "confidence":"unknown", "reason":"module boundary", "upstream":[{"id":"edge"}]}]
        });
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:coalesced", "reviewed").unwrap();
        item["evidenceVariants"][0]["action"] = serde_json::json!("inspect-unresolved-upstream-graph-context");
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["pendingReleased"], 1);
        assert_eq!(stats(&db).unwrap()["done"], 1);
    }

    #[test]
    fn legacy_coalesced_mixed_routes_preserve_decisions_only_for_unchanged_evidence() {
        let root = tempdir().unwrap();
        let db = root.path().join("state.sqlite");
        report(root.path(), &[]);
        let mut item = serde_json::json!({
            "id":"work:mixed", "action":"inspect-unverified-missing-branch",
            "priority":"P2", "confidence":"weak-candidate", "reason":"review",
            "evidenceVariants":[
                {"priority":"P2", "confidence":"weak-candidate", "reason":"review", "upstream":[{"id":"a"}]},
                {"priority":"P2", "confidence":"weak-candidate", "reason":"structural", "upstream":[{"id":"b"}]}
            ]
        });
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        sync(&db, root.path()).unwrap();
        mark_pending_sync(&db, "work:mixed", "reviewed").unwrap();
        let previous = item.to_string();
        item["evidenceVariants"][0]["action"] = serde_json::json!("inspect-unverified-missing-branch");
        item["evidenceVariants"][1]["action"] = serde_json::json!("inspect-structural-frontier");
        let mut unrelated = item.clone();
        unrelated["evidenceVariants"][1]["action"] = serde_json::json!("unrelated-route");
        assert!(!routing_reclassification_preserves_evidence(&previous, &unrelated.to_string()));
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        let result = sync(&db, root.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["pendingReleased"], 1);
        assert_eq!(stats(&db).unwrap()["done"], 1);

        item["evidenceVariants"][1]["upstream"][0]["id"] = serde_json::json!("changed");
        fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
        assert_eq!(sync(&db, root.path()).unwrap()["reopened"], 1);
    }

    #[test]
    fn legacy_variant_routes_must_share_the_current_frontier_identity() {
        assert!(compatible_legacy_variant_action(Some("inspect-unverified-missing-branch"), "port-missing-upstream-branch"));
        assert!(compatible_legacy_variant_action(Some("resolve-ambiguous-owners"), "inspect-structural-frontier"));
        assert!(compatible_legacy_variant_action(Some("remove-or-justify-extra-local"), "inspect-structural-frontier"));
        assert!(!compatible_legacy_variant_action(Some("inspect-unresolved-upstream-graph-context"), "inspect-structural-frontier"));
        assert!(!compatible_legacy_variant_action(Some("inspect-unverified-missing-branch"), "reconcile-changed-branch"));
    }

    #[test]
    fn legacy_coalesced_representative_promotion_preserves_only_legacy_evidence() {
        for (review_action, active_action) in [
            ("inspect-unverified-missing-branch", "port-missing-upstream-branch"),
            ("inspect-unverified-changed-branch", "reconcile-changed-branch"),
        ] {
            let previous = serde_json::json!({
                "id":"work:owner", "action":review_action, "priority":"P2",
                "confidence":"weak-candidate", "reason":"review",
                "evidenceVariants":[
                    {"priority":"P2", "confidence":"weak-candidate", "reason":"review", "upstream":[{"id":"a"}]},
                    {"priority":"P0", "confidence":"candidate", "reason":"active", "upstream":[{"id":"b"}]}
                ]
            });
            let mut current = previous.clone();
            current["action"] = serde_json::json!(active_action);
            current["priority"] = serde_json::json!("P0");
            current["confidence"] = serde_json::json!("candidate");
            current["reason"] = serde_json::json!("active");
            current["evidenceVariants"][0]["action"] = serde_json::json!(review_action);
            current["evidenceVariants"][1]["action"] = serde_json::json!(active_action);
            assert!(routing_reclassification_preserves_evidence(&previous.to_string(), &current.to_string()));
            let mut modern_previous = previous.clone();
            modern_previous["evidenceVariants"][0]["action"] = serde_json::json!(review_action);
            modern_previous["evidenceVariants"][1]["action"] = serde_json::json!(active_action);
            assert!(!routing_reclassification_preserves_evidence(&modern_previous.to_string(), &current.to_string()));
        }
    }

    #[test]
    fn changed_coalesced_variant_routing_reopens_reviewed_decision() {
        for (field, changed, reclassify) in [
            ("action", "inspect-structural-frontier", false),
            ("action", "inspect-structural-frontier", true),
            ("priority", "P0", false),
            ("confidence", "candidate", false),
            ("reason", "changed route", false),
            ("batchId", "new-batch", false),
        ] {
            let root = tempdir().unwrap();
            let db = root.path().join("state.sqlite");
            report(root.path(), &[]);
            let mut item = serde_json::json!({
                "id":"work:coalesced", "action":"inspect-unverified-missing-branch",
                "priority":"P2", "confidence":"weak-candidate", "reason":"old route",
                "evidenceVariants":[{"action":"inspect-unverified-missing-branch", "priority":"P2", "confidence":"weak-candidate", "reason":"old route", "batchId":"old-batch", "upstream":[{"id":"edge"}]}]
            });
            fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
            sync(&db, root.path()).unwrap();
            mark_pending_sync(&db, "work:coalesced", "reviewed").unwrap();
            item["evidenceVariants"][0][field] = serde_json::json!(changed);
            if reclassify {
                item["action"] = serde_json::json!("inspect-structural-frontier");
            }
            fs::write(root.path().join("llm-work-items.jsonl"), format!("{}\n", item)).unwrap();
            let result = sync(&db, root.path()).unwrap();
            assert_eq!(result["reopened"], 1, "changed {field}, reclassified={reclassify}");
        }
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
