use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    io::{BufRead, BufReader, BufWriter, Seek, Write},
    path::Path,
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use super::{
    graph_behavior_hashes, graph_similarity, location, normalized_graph_token, sha256,
    AmbiguousGroup, DivergenceFrontier, GraphNode, GraphNodeRef, GraphRelation, GroupCandidate,
    Location, MatchRecord, ProjectIndex, Unit, Unmatched,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LlmSummary {
    pub(crate) upstream_executable_nodes: usize,
    pub(crate) upstream_semantic_nodes: usize,
    pub(crate) covered_nodes: usize,
    pub(crate) dependency_covered_nodes: usize,
    pub(crate) dependency_files: usize,
    pub(crate) dependency_graph_nodes: usize,
    pub(crate) dependency_graph_retained: bool,
    pub(crate) dependency_parse_failures: usize,
    pub(crate) actionable_nodes: usize,
    pub(crate) work_items: usize,
    pub(crate) batches: usize,
    pub(crate) parse_failures: usize,
    pub(crate) dispositions: BTreeMap<String, usize>,
    pub(crate) actions: BTreeMap<String, usize>,
}

struct BatchAccumulator {
    priority: Option<String>,
    actions: BTreeMap<String, usize>,
    local_files: BTreeSet<String>,
    work_item_count: usize,
    semantic_owner: Value,
}

impl Default for BatchAccumulator {
    fn default() -> Self {
        Self {
            priority: None,
            actions: BTreeMap::new(),
            local_files: BTreeSet::new(),
            work_item_count: 0,
            semantic_owner: Value::Null,
        }
    }
}

#[derive(Clone)]
struct UnitDisposition {
    status: &'static str,
    confidence: &'static str,
    work_item_id: Option<String>,
}

struct WorkItemDraft {
    action: &'static str,
    priority: &'static str,
    confidence: &'static str,
    reason: String,
    local: Vec<Value>,
    upstream: Vec<Value>,
    evidence_path: Vec<Value>,
    identities: Vec<String>,
}

fn same_file_identity(left: &crate::FileRecord, right: &crate::FileRecord) -> bool {
    left.file == right.file
        && left.source_sha256 == right.source_sha256
        && left.source_map_sha256 == right.source_map_sha256
}

fn candidate_owner_triage(record: &MatchRecord) -> (&'static str, &'static str) {
    // Reciprocal feature ranking narrows the review locator, but does not
    // establish owner identity or behavior. Keep it visible behind evidence
    // that can actually corroborate a change.
    if record.basis == "mutual-best-fuzzy" {
        ("P2", "weak-candidate")
    } else {
        ("P1", record.confidence)
    }
}

fn write_json_lines(path: &Path, values: &[Value]) -> Result<()> {
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut output = BufWriter::new(file);
    // Keep the seek index compact while writing.  Storing one serde_json::Value
    // per record here used several hundred MB for the parity work queue and
    // made the final report appear hung on large upstream bundles.
    let mut records = Vec::<(String, u64, usize)>::new();
    let mut groups = BTreeMap::<String, Vec<(u64, usize)>>::new();
    for value in values {
        let line = serde_json::to_vec(&value)?;
        let offset = output.stream_position()?;
        output.write_all(&line)?;
        output.write_all(b"\n")?;
        if let Some(id) = value["id"].as_str() {
            records.push((id.to_string(), offset, line.len() + 1));
        }
        if let Some(batch_id) = value["batchId"].as_str() {
            groups
                .entry(batch_id.to_string())
                .or_default()
                .push((offset, line.len() + 1));
        }
    }
    output
        .flush()
        .with_context(|| format!("write {}", path.display()))?;
    let index_path = jsonl_index_path(path);
    let mut index = BufWriter::new(
        fs::File::create(&index_path)
            .with_context(|| format!("create {}", index_path.display()))?,
    );
    write!(
        index,
        "{{\"schema\":\"project-parity/jsonl-index-v1\",\"records\":{{"
    )?;
    for (record_index, (id, offset, length)) in records.iter().enumerate() {
        if record_index > 0 {
            write!(index, ",")?;
        }
        write!(
            index,
            "{}:{{\"offset\":{},\"length\":{}}}",
            serde_json::to_string(id)?,
            offset,
            length
        )?;
    }
    write!(index, "}},\"groups\":{{")?;
    for (group_index, (group, entries)) in groups.iter().enumerate() {
        if group_index > 0 {
            write!(index, ",")?;
        }
        write!(index, "{}:[", serde_json::to_string(group)?)?;
        for (entry_index, (offset, length)) in entries.iter().enumerate() {
            if entry_index > 0 {
                write!(index, ",")?;
            }
            write!(index, "{{\"offset\":{},\"length\":{}}}", offset, length)?;
        }
        write!(index, "]")?;
    }
    writeln!(index, "}}}}")?;
    index
        .flush()
        .with_context(|| format!("write {}", index_path.display()))
}

/// Intern only the repeated, large candidate arrays. This is a storage
/// representation; all consumers expand it before interpreting evidence or
/// comparing reviewed payloads. IDs and ordering remain unchanged.
fn intern_work_evidence(item: &mut Value, shared: &mut HashMap<String, Value>) -> Result<()> {
    if let Some(id) = item.get("upstreamEvidenceRef") {
        anyhow::ensure!(item.get("upstream").is_none(), "inline and referenced upstream evidence");
        anyhow::ensure!(id.as_str().is_some_and(|id| shared.contains_key(id)), "missing interned upstream evidence");
        return Ok(());
    }
    if item["action"] != "resolve-ambiguous-owners" {
        return Ok(());
    }
    let serialized = serde_json::to_vec(&item["upstream"])?;
    if serialized.len() < 1024 {
        return Ok(());
    }
    let id = sha256(&serialized);
    // The normal draft's inspect list is precisely local IDs followed by
    // upstream IDs. Elide it only when that equality is exact; coalesced
    // variants can have a different ordering and keep their explicit list.
    let inspect_ids = owner_inspect_ids(item);
    if item.get("inspectNodeIds") == Some(&inspect_ids) {
        item.as_object_mut()
            .context("work item is not an object")?
            .remove("inspectNodeIds");
        item["inspectNodeIdsFromOwners"] = json!(true);
    }
    let upstream = item
        .as_object_mut()
        .context("work item is not an object")?
        .remove("upstream")
        .context("work item has no upstream evidence")?;
    shared.entry(id.clone()).or_insert(upstream);
    item["upstreamEvidenceRef"] = json!(id);
    Ok(())
}

pub(crate) fn compact_work_evidence(output: &Path, items: &mut [Value], mut shared: HashMap<String, Value>) -> Result<()> {
    for item in items { intern_work_evidence(item, &mut shared)?; }
    let records = shared.into_iter().collect::<BTreeMap<_, _>>().into_iter()
        .map(|(id, upstream)| Ok(json!({"id":id,"upstream":upstream})));
    write_streaming_json_lines_fallible(&output.join("llm-shared-evidence.jsonl"), records)
}

fn owner_inspect_ids(item: &Value) -> Value {
    json!(item["local"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(item["upstream"].as_array().into_iter().flatten())
        .filter_map(|owner| owner["id"].as_str())
        .collect::<Vec<_>>())
}

pub(crate) fn read_shared_work_evidence(output: &Path) -> Result<HashMap<String, Value>> {
    let path = output.join("llm-shared-evidence.jsonl");
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let mut shared = HashMap::new();
    for line in BufReader::new(fs::File::open(&path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut record: Value = serde_json::from_str(&line)?;
        let id = record["id"]
            .as_str()
            .context("shared evidence has no id")?
            .to_owned();
        let upstream = record
            .as_object_mut()
            .context("shared evidence is not an object")?
            .remove("upstream")
            .context("shared evidence has no upstream")?;
        anyhow::ensure!(
            sha256(serde_json::to_vec(&upstream)?) == id,
            "shared evidence hash mismatch: {id}"
        );
        anyhow::ensure!(
            shared.insert(id.clone(), upstream).is_none(),
            "duplicate shared evidence: {id}"
        );
    }
    Ok(shared)
}

pub(crate) fn expand_work_evidence(
    mut item: Value,
    shared: &HashMap<String, Value>,
) -> Result<Value> {
    if let Some(reference) = item.get("upstreamEvidenceRef") {
        let id = reference
            .as_str()
            .context("upstream evidence reference is not a string")?;
        let upstream = shared
            .get(id)
            .with_context(|| format!("missing shared upstream evidence: {id}"))?;
        anyhow::ensure!(
            item.get("upstream").is_none(),
            "work item has both inline and referenced upstream evidence"
        );
        let upstream = upstream.clone();
        item.as_object_mut()
            .context("work item is not an object")?
            .remove("upstreamEvidenceRef");
        item["upstream"] = upstream;
    }
    if let Some(flag) = item.get("inspectNodeIdsFromOwners") {
        anyhow::ensure!(flag == &json!(true), "invalid derived inspect-node flag");
        anyhow::ensure!(
            item.get("inspectNodeIds").is_none(),
            "work item has both explicit and derived inspect-node IDs"
        );
        anyhow::ensure!(
            item["local"].is_array() && item["upstream"].is_array(),
            "derived inspect-node IDs require owner arrays"
        );
        let ids = owner_inspect_ids(&item);
        item.as_object_mut()
            .context("work item is not an object")?
            .remove("inspectNodeIdsFromOwners");
        item["inspectNodeIds"] = ids;
    }
    Ok(item)
}

fn write_streaming_json_lines_fallible<I>(path: &Path, values: I) -> Result<()>
where
    I: IntoIterator<Item = Result<Value>>,
{
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut output = BufWriter::new(file);
    for value in values {
        let value = value?;
        let line = serde_json::to_vec(&value)?;
        output.write_all(&line)?;
        output.write_all(b"\n")?;
    }
    output
        .flush()
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn jsonl_index_path(path: &Path) -> std::path::PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if let Some(stem) = name.strip_suffix(".jsonl.zst") {
        return path.with_file_name(format!("{stem}.index.json"));
    }
    path.with_extension("index.json")
}

fn write_seekable_json_lines_fallible<I>(path: &Path, values: I) -> Result<()>
where
    I: IntoIterator<Item = Result<Value>>,
{
    let mut file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut chunk = Vec::new();
    let mut ids = BTreeSet::<String>::new();
    let mut index = BTreeMap::<String, Vec<usize>>::new();
    let mut chunks_meta = Vec::new();
    let flush = |file: &mut fs::File,
                 chunks_meta: &mut Vec<Value>,
                 index: &mut BTreeMap<String, Vec<usize>>,
                 chunk: &mut Vec<u8>,
                 ids: &mut BTreeSet<String>|
     -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let compressed = zstd::stream::encode_all(chunk.as_slice(), 3)?;
        let offset = file.stream_position()?;
        file.write_all(&compressed)?;
        let number = chunks_meta.len();
        for id in ids.iter() {
            index.entry(id.clone()).or_default().push(number);
        }
        chunks_meta.push(json!({"offset": offset, "length": compressed.len()}));
        chunk.clear();
        ids.clear();
        Ok(())
    };
    for value in values {
        let value = value?;
        let line = serde_json::to_vec(&value)?;
        chunk.extend_from_slice(&line);
        chunk.push(b'\n');
        if let Some(id) = value["id"].as_str() {
            ids.insert(id.to_string());
        }
        if chunk.len() >= 64 * 1024 {
            flush(
                &mut file,
                &mut chunks_meta,
                &mut index,
                &mut chunk,
                &mut ids,
            )?;
        }
    }
    flush(
        &mut file,
        &mut chunks_meta,
        &mut index,
        &mut chunk,
        &mut ids,
    )?;
    file.flush()?;
    let artifact = json!({
        "schema": "project-parity/jsonl-index-v1",
        "chunks": chunks_meta,
        "records": index,
    });
    let index_path = jsonl_index_path(path);
    fs::write(
        &index_path,
        format!("{}\n", serde_json::to_string_pretty(&artifact)?),
    )
    .with_context(|| format!("write {}", index_path.display()))
}

struct LosslessGraphRecords {
    lines: std::io::Lines<BufReader<zstd::stream::read::Decoder<'static, BufReader<fs::File>>>>,
    record_type: &'static str,
}

impl Iterator for LosslessGraphRecords {
    type Item = Result<Value>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let line = self.lines.next()?;
            match line {
                Ok(line) if !line.trim().is_empty() => match serde_json::from_str::<Value>(&line) {
                    Ok(record) if record["recordType"] == self.record_type => {
                        return Some(Ok(record))
                    }
                    Ok(_) => continue,
                    Err(error) => return Some(Err(error.into())),
                },
                Ok(_) => continue,
                Err(error) => return Some(Err(error.into())),
            }
        }
    }
}

fn lossless_graph_records<'a>(
    project: &'a ProjectIndex,
    record_type: &'static str,
) -> Result<Box<dyn Iterator<Item = Result<Value>> + 'a>> {
    if let Some(path) = &project.graph_artifact {
        let file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
        let decoded = zstd::stream::read::Decoder::new(file)?;
        return Ok(Box::new(LosslessGraphRecords {
            lines: BufReader::new(decoded).lines(),
            record_type,
        }));
    }
    if record_type == "node" {
        return Ok(Box::new(
            project
                .graph_nodes
                .iter()
                .map(|node| Ok(json!({"recordType":"node","node":node}))),
        ));
    }
    Ok(Box::new(
        project
            .graph_edges
            .iter()
            .map(|edge| Ok(json!({"recordType":"edge","edge":edge}))),
    ))
}

fn location_value(location: &Location) -> Value {
    serde_json::to_value(location).expect("Location serializes")
}

fn graph_node_value(node: &GraphNodeRef) -> Value {
    serde_json::to_value(node).expect("GraphNodeRef serializes")
}

fn graph_node_ref(node: &GraphNode) -> GraphNodeRef {
    GraphNodeRef {
        id: node.id.clone(),
        file: node.file.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        line: node.line,
        start: node.start,
        end: node.end,
    }
}

fn work_item_id(action: &str, identities: impl IntoIterator<Item = String>) -> String {
    // Identities are collected from graph/hash-map traversals whose iteration
    // order is not a stable part of the evidence.  A work-item ID must name
    // the evidence set, not the incidental order in which it was discovered;
    // otherwise an unchanged report reopens the same item under a new ID.
    let identities = identities.into_iter().collect::<Vec<_>>();
    // Frontier evidence can legitimately contain several equivalent edge
    // routes, and unmatched-local candidates are ranked with unstable ties.
    // Those alternatives belong in the payload, not in the durable queue key.
    // The first identity is the local owner for local-only work; the first two
    // are the matched source-owner pair for a branch frontier.
    let identity_action = match action {
        "inspect-unverified-missing-branch" => "port-missing-upstream-branch",
        "inspect-unverified-changed-branch" => "reconcile-changed-branch",
        "inspect-weak-missing-branch" => "port-missing-upstream-branch",
        "inspect-weak-changed-branch" => "reconcile-changed-branch",
        _ => action,
    };
    let identities = match identity_action {
        "remove-or-justify-extra-local" => identities.into_iter().take(1).collect(),
        "port-missing-upstream-branch" | "reconcile-changed-branch" => {
            identities.into_iter().take(2).collect()
        }
        _ => identities,
    };
    let identities = identities.into_iter().collect::<BTreeSet<_>>();
    let material = std::iter::once(identity_action.to_string())
        .chain(identities)
        .collect::<Vec<_>>()
        .join("\0");
    format!("work-{}", &sha256(material)[..20])
}

fn frontier_identity_override<'a>(base_action: &'a str, routed_action: &str) -> Option<&'a str> {
    (routed_action == "inspect-structural-frontier").then_some(base_action)
}

fn relation_path(
    relation_by_pair: &HashMap<(String, String), &GraphRelation>,
    left: &str,
    right: &str,
) -> Vec<Value> {
    let mut cursor = (left.to_string(), right.to_string());
    let mut seen = HashSet::new();
    let mut path = Vec::new();
    while seen.insert(cursor.clone()) {
        let Some(relation) = relation_by_pair.get(&cursor) else {
            break;
        };
        path.push(json!({
            "basis": relation.basis,
            "depth": relation.depth,
            "viaEdge": relation.via_edge,
            "left": relation.left,
            "right": relation.right,
        }));
        let Some(source) = &relation.source else {
            break;
        };
        cursor = (source.left.id.clone(), source.right.id.clone());
    }
    path.reverse();
    path
}

/// Shape/neighbor matches are useful locators, but do not establish a shared
/// owner or package provenance by themselves. Keep such frontiers visible while
/// routing them behind owner-anchored findings; semantic edge chains retain
/// their normal triage.
fn frontier_triage(
    frontier_edge_kinds: &[&str],
    priority: &str,
    confidence: &str,
) -> (&'static str, &'static str) {
    // The correspondence path can cross an unrelated sibling use. Only the
    // edge at this divergence can corroborate this frontier's behavior.
    if !frontier_edge_kinds.iter().any(|edge| is_behavior_edge(edge)) {
        ("P2", "weak-candidate")
    } else {
        (
            match priority {
                "P0" => "P0",
                "P1" => "P1",
                _ => "P2",
            },
            match confidence {
                "proven-structure" => "proven-structure",
                "proven-bundle-normalized" => "proven-bundle-normalized",
                "candidate" => "candidate",
                _ => "weak-candidate",
            },
        )
    }
}

fn is_behavior_edge(edge: &str) -> bool {
    let edge_kind = edge.rsplit_once(':').map_or(edge, |(_, kind)| kind);
    // Reads of constants and configuration can affect behavior too. An edge
    // corroborates the need for review; it does not prove owner equivalence.
    matches!(edge_kind, "Calls" | "References" | "Instantiates" | "Renders")
}

fn frontier_work_action(
    action: &'static str,
    edge_kinds: &[&str],
    defer_structural: bool,
) -> (&'static str, &'static str) {
    // As in frontier triage, behavior in the correspondence path is context,
    // not evidence about the edge that is actually missing or changed.
    if edge_kinds.iter().any(|edge| is_behavior_edge(edge)) {
        return (action, "");
    }
    if defer_structural {
        return (
            "inspect-structural-frontier",
            "The frontier is supported only by structural or neighboring graph evidence; keep it visible for later review.",
        );
    }
    match action {
        "port-missing-upstream-branch" => (
            "inspect-unverified-missing-branch",
            "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change.",
        ),
        "reconcile-changed-branch" => (
            "inspect-unverified-changed-branch",
            "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change.",
        ),
        _ => (action, ""),
    }
}

fn should_defer_structural_frontier(
    evidence_path: &[Value],
    has_behavior_edge: bool,
    changed_branch: bool,
    weak_candidate: bool,
) -> bool {
    // Changed branches stay actionable because containment can carry return,
    // guard, and side-effect behavior even without a Calls edge.
    // A local binding under a globally inferred owner does not strengthen the
    // owner correspondence; its trust is bounded by the path's root.
    let weak_global_root = evidence_path.first().is_some_and(|relation| relation["basis"] == "global-behavior");
    !has_behavior_edge
        && !changed_branch
        && weak_candidate
        && !evidence_path.is_empty()
        && evidence_path.iter().all(|relation| {
            relation["basis"].as_str().is_some_and(|basis| {
                basis == "global-behavior"
                    || (basis.starts_with("neighbor-") && (basis != "neighbor-binding-owner" || weak_global_root))
            })
        })
}

fn unlinked_upstream_triage() -> (&'static str, &'static str) {
    // There is no owner correspondence or package provenance yet. Preserve
    // the completeness locator, but don't label it as a confirmed urgent bug.
    ("P2", "unknown")
}

fn push_work_item(items: &mut Vec<Value>, draft: WorkItemDraft) -> String {
    push_work_item_with_identity_action(items, draft, None)
}

fn push_work_item_with_identity_action(
    items: &mut Vec<Value>,
    draft: WorkItemDraft,
    identity_action: Option<&str>,
) -> String {
    let id = work_item_id(identity_action.unwrap_or(draft.action), draft.identities);
    let inspect_node_ids = draft
        .local
        .iter()
        .chain(&draft.upstream)
        .filter_map(|location| location["id"].as_str())
        .collect::<Vec<_>>();
    items.push(json!({
        "id": id,
        "priority": draft.priority,
        "action": draft.action,
        "confidence": draft.confidence,
        "reason": draft.reason,
        "local": draft.local,
        "upstream": draft.upstream,
        "evidencePath": draft.evidence_path,
        "inspectNodeIds": inspect_node_ids,
    }));
    id
}

/// One stable work-item ID may be emitted by several divergent edges beneath
/// the same owner pair. Keep the decision unit singular, but preserve every
/// distinct edge payload so indexed `show-work` and state sync cannot silently
/// select only the last occurrence.
fn coalesce_work_items(items: Vec<Value>, shared: &HashMap<String, Value>) -> Result<Vec<Value>> {
    // Group by the compact identity first. Full serialized keys are needed
    // only while deduplicating one identity's variants, not for the entire
    // queue at once (those keys alone can exceed a GB on bundled projects).
    let mut by_id = BTreeMap::<String, Vec<Value>>::new();
    let mut unkeyed = 0usize;
    for item in items {
        let id = item["id"].as_str().map(str::to_string).unwrap_or_else(|| {
            unkeyed += 1;
            format!("__unkeyed-{unkeyed}")
        });
        by_id.entry(id).or_default().push(item);
    }

    by_id
        .into_values()
        .map(|mut items| {
            if items.len() == 1 { return Ok(items.pop().expect("one work item")); }
            let items = items.into_iter().map(|item| expand_work_evidence(item, shared)).collect::<Result<Vec<_>>>()?;
            let unique = items
                .into_iter()
                .map(|item| {
                    (
                        serde_json::to_string(&item).expect("work item serializes"),
                        item,
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let variants = unique.into_values().collect::<Vec<_>>();
            if variants.len() == 1 {
                return Ok(variants.into_iter().next().expect("one work item"));
            }

            let mut merged = variants[0].clone();
            for key in ["local", "upstream", "evidencePath", "inspectNodeIds"] {
                let mut values = BTreeMap::<String, Value>::new();
                for variant in &variants {
                    for value in variant[key].as_array().into_iter().flatten() {
                        let serialized =
                            serde_json::to_string(value).expect("evidence value serializes");
                        values.entry(serialized).or_insert_with(|| value.clone());
                    }
                }
                merged[key] = Value::Array(values.into_values().collect());
            }
            merged["evidenceVariants"] = Value::Array(
                variants
                    .into_iter()
                    .map(|variant| {
                        json!({
                            "action": variant["action"],
                            "priority": variant["priority"],
                            "confidence": variant["confidence"],
                            "reason": variant["reason"],
                            "local": variant["local"],
                            "upstream": variant["upstream"],
                            "evidencePath": variant["evidencePath"],
                            "inspectNodeIds": variant["inspectNodeIds"],
                        })
                    })
                    .collect(),
            );
            let active_fields = merged["evidenceVariants"]
                .as_array()
                .and_then(|variants| {
                    variants
                        .iter()
                        .filter(|variant| variant["action"] != "inspect-structural-frontier")
                        .min_by_key(|variant| {
                            let priority = match variant["priority"].as_str() {
                                Some("P0") => 0,
                                Some("P1") => 1,
                                _ => 2,
                            };
                            let confidence = match variant["confidence"].as_str() {
                                Some("proven-structure" | "proven-bundle-normalized") => 0,
                                Some("candidate") => 1,
                                Some("weak-candidate") => 2,
                                _ => 3,
                            };
                            (priority, confidence)
                        })
                })
                .map(|active| {
                    ["action", "priority", "confidence", "reason"]
                        .into_iter()
                        .map(|key| (key, active[key].clone()))
                        .collect::<Vec<_>>()
                });
            if let Some(active_fields) = active_fields {
                for (key, value) in active_fields {
                    merged[key] = value;
                }
            }
            Ok(merged)
        })
        .collect()
}

// Exact source-range owner lookup. Project units are ID-ordered, not start-
// ordered. Keep that order for equal-width ties; index starts and maximum ends
// separately so queries prune unrelated earlier ranges without cloning units.
struct UnitIntervals<'a> {
    units: Vec<&'a Unit>,
    by_start: Vec<usize>,
    max_end: Vec<u32>,
}

impl<'a> UnitIntervals<'a> {
    fn new(units: Vec<&'a Unit>) -> Self {
        let mut by_start = (0..units.len()).collect::<Vec<_>>();
        by_start.sort_by_key(|&index| units[index].start);
        let base = units.len().next_power_of_two();
        let mut max_end = vec![0; base * 2];
        for (position, &index) in by_start.iter().enumerate() {
            max_end[base + position] = units[index].end;
        }
        for index in (1..base).rev() {
            max_end[index] = max_end[index * 2].max(max_end[index * 2 + 1]);
        }
        Self { units, by_start, max_end }
    }

    fn containing(&self, node: &GraphNode) -> Option<&'a Unit> {
        let limit = self.by_start.partition_point(|&index| self.units[index].start <= node.start);
        let mut best = None;
        self.visit(1, 0, self.max_end.len() / 2, limit, node.end, &mut best);
        best.map(|index| self.units[index])
    }

    fn visit(&self, tree: usize, start: usize, end: usize, limit: usize, node_end: u32, best: &mut Option<usize>) {
        if start >= limit || self.max_end[tree] < node_end {
            return;
        }
        if end - start == 1 {
            let index = self.by_start[start];
            let width = self.units[index].end - self.units[index].start;
            if best.is_none_or(|previous| {
                let previous_width = self.units[previous].end - self.units[previous].start;
                width < previous_width || (width == previous_width && index > previous)
            }) {
                *best = Some(index);
            }
            return;
        }
        let middle = (start + end) / 2;
        self.visit(tree * 2 + 1, middle, end, limit, node_end, best);
        self.visit(tree * 2, start, middle, limit, node_end, best);
    }
}

fn containing_unit<'a>(
    node: &GraphNode,
    units_by_file: &HashMap<&str, UnitIntervals<'a>>,
) -> Option<&'a Unit> {
    units_by_file.get(node.file.as_str())?.containing(node)
}

fn unit_for_node<'a>(
    node: &GraphNode,
    units_by_file: &HashMap<&str, UnitIntervals<'a>>,
) -> Option<&'a Unit> {
    containing_unit(node, units_by_file).or_else(|| {
        units_by_file
            .get(node.file.as_str())?
            .units
            .iter()
            .copied()
            .find(|unit| unit.start == node.start && unit.end == node.end)
    })
}

fn semantic_owner(
    item: &Value,
    shared: &HashMap<String, Value>,
    units_by_id: &HashMap<&str, &Unit>,
    units_by_file: &HashMap<&str, UnitIntervals<'_>>,
    node_by_id: &HashMap<&str, &GraphNode>,
    parent_by_child: &HashMap<&str, &str>,
) -> (String, Value) {
    let upstream_value = item.get("upstream").or_else(|| item["upstreamEvidenceRef"].as_str().and_then(|id| shared.get(id)))
        .and_then(Value::as_array)
        .and_then(|locations| locations.first());
    if let Some(upstream_value) = upstream_value {
        if let Some(id) = upstream_value["id"].as_str() {
            if let Some(unit) = units_by_id.get(id) {
                return (
                    format!("upstream-unit:{id}"),
                    location_value(&location(unit)),
                );
            }
            if let Some(node) = node_by_id.get(id) {
                if let Some(unit) = containing_unit(node, units_by_file) {
                    return (
                        format!("upstream-unit:{}", unit.id),
                        location_value(&location(unit)),
                    );
                }

                let mut root = *node;
                let mut cursor = id;
                let mut seen = HashSet::new();
                while seen.insert(cursor) {
                    let Some(parent_id) = parent_by_child.get(cursor).copied() else {
                        break;
                    };
                    let Some(parent) = node_by_id.get(parent_id).copied() else {
                        break;
                    };
                    if parent.kind == "File"
                        || (parent.kind == "Scope" && parent.label.starts_with("depth-0:"))
                    {
                        break;
                    }
                    if matches!(parent.kind.as_str(), "Statement" | "Function" | "Class") {
                        root = parent;
                    }
                    cursor = parent_id;
                }
                return (
                    format!("upstream-graph-root:{}", root.id),
                    graph_node_value(&graph_node_ref(root)),
                );
            }
        }
        if let Some(file) = upstream_value["file"].as_str() {
            return (
                format!("upstream-file:{file}"),
                json!({"kind": "File", "file": file}),
            );
        }
    }

    let local_value = item["local"]
        .as_array()
        .and_then(|locations| locations.first());
    if let Some(local_value) = local_value {
        if let Some(id) = local_value["id"].as_str() {
            return (format!("local-only:{id}"), local_value.clone());
        }
        if let Some(file) = local_value["file"].as_str() {
            return (
                format!("local-only-file:{file}"),
                json!({"kind": "File", "file": file}),
            );
        }
    }
    (
        "unroutable".to_string(),
        json!({"kind": "Unknown", "label": "unroutable"}),
    )
}

fn dependency_package(file: &str) -> Option<String> {
    let path = file.strip_prefix("npm/")?;
    if path.starts_with('@') {
        let mut parts = path.split('/');
        let scope = parts.next()?;
        let package = parts.next()?;
        Some(format!("{scope}/{package}"))
    } else {
        path.split('/').next().map(str::to_string)
    }
}

fn dependency_package_key(file: &str) -> Option<String> {
    let package = dependency_package(file)?;
    if package.starts_with('@') {
        let (scope, name) = package.split_once('/')?;
        Some(format!("{scope}/{}", name.split('@').next()?))
    } else {
        Some(package.split('@').next()?.to_string())
    }
}

fn unique_dependency_evidence<'a, T>(
    candidates: impl IntoIterator<Item = &'a T>,
    file: impl Fn(&T) -> &str,
    value: impl Fn(&T) -> Value,
    basis: &'static str,
) -> Option<Value>
where
    T: 'a,
{
    let mut package_name: Option<String> = None;
    let mut sources = Vec::new();
    for candidate in candidates {
        let dependency_file = file(candidate);
        let package = dependency_package(dependency_file)?;
        match package_name.as_deref() {
            None => package_name = Some(package),
            Some(existing) if existing != package => return None,
            Some(_) => {}
        }
        if sources.len() < 3 {
            sources.push(value(candidate));
        }
    }
    let package = package_name?;
    Some(json!({
        "basis": basis,
        "package": package,
        "sources": sources,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_llm_context(
    output: &Path,
    left: &ProjectIndex,
    right: &ProjectIndex,
    matches: &[MatchRecord],
    ambiguous: &[AmbiguousGroup],
    groups: &[GroupCandidate],
    graph_relations: &[GraphRelation],
    frontiers: &[DivergenceFrontier],
    unmatched_left: &[Unmatched],
    unmatched_right: &[Unmatched],
    dependencies: Option<&ProjectIndex>,
) -> Result<LlmSummary> {
    let mut work_items = Vec::<Value>::new();
    let shared_work_evidence = HashMap::new();
    let mut unit_dispositions = HashMap::<String, UnitDisposition>::new();
    let mut upstream_work_by_node = HashMap::<String, String>::new();
    let mut ambiguous_left_ids = HashSet::<String>::new();
    let mut ambiguous_right_confidence = HashMap::<String, &'static str>::new();
    let identical_files = right
        .files
        .iter()
        .filter_map(|right_file| {
            left.files
                .iter()
                .find(|left_file| same_file_identity(left_file, right_file))
                .map(|_| right_file.file.as_str())
        })
        .collect::<HashSet<_>>();
    let identical_location = |location: &Location| identical_files.contains(location.file.as_str());

    for failure in &right.failures {
        push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "restore-upstream-coverage",
                priority: "P0",
                confidence: "unknown",
                reason: format!(
                    "The authoritative upstream file could not be parsed: {}",
                    failure.error
                ),
                local: Vec::new(),
                upstream: vec![json!({"file": failure.file, "error": failure.error})],
                evidence_path: Vec::new(),
                identities: vec![failure.file.clone()],
            },
        );
    }
    for failure in &left.failures {
        push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "restore-local-coverage",
                priority: "P0",
                confidence: "unknown",
                reason: format!("The local file could not be parsed: {}", failure.error),
                local: vec![json!({"file": failure.file, "error": failure.error})],
                upstream: Vec::new(),
                evidence_path: Vec::new(),
                identities: vec![failure.file.clone()],
            },
        );
    }

    for record in matches {
        if identical_location(&record.right) {
            unit_dispositions.insert(
                record.right.id.clone(),
                UnitDisposition {
                    status: "structurally-equal",
                    confidence: "proven-structure",
                    work_item_id: None,
                },
            );
            continue;
        }
        if matches!(
            record.confidence,
            "proven-structure" | "proven-bundle-normalized"
        ) {
            unit_dispositions.insert(
                record.right.id.clone(),
                UnitDisposition {
                    status: "structurally-equal",
                    confidence: record.confidence,
                    work_item_id: None,
                },
            );
            continue;
        }
        let local = vec![location_value(&record.left)];
        let upstream = vec![location_value(&record.right)];
        let (priority, confidence) = candidate_owner_triage(record);
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "reconcile-changed-owner",
                priority,
                confidence,
                reason: format!(
                    "The best owner correspondence is {}, but normalized structure is not proven equal (basis {}, score {:.4}).",
                    record.status, record.basis, record.score
                ),
               local: local.clone(),
                upstream,
                evidence_path: Vec::new(),
                identities: vec![record.left.id.clone(), record.right.id.clone()],
            },
        );
        unit_dispositions.insert(
            record.right.id.clone(),
            UnitDisposition {
                status: "changed-candidate",
                confidence,
                work_item_id: Some(id),
            },
        );
    }

    for group in ambiguous {
        if group.right.iter().all(identical_location) {
            continue;
        }
        // Preserve fingerprint ambiguity in the report, but do not present a
        // duplicate-shape candidate as change work without an owner chain.
        ambiguous_left_ids.extend(group.left.iter().map(|location| location.id.clone()));
        for location in &group.right {
            ambiguous_right_confidence
                .entry(location.id.clone())
                .or_insert(group.confidence);
        }
    }

    for group in groups {
        if group.right.iter().all(identical_location) {
            continue;
        }
        let upstream = group.right.iter().map(location_value).collect::<Vec<_>>();
        let local = group.left.iter().map(location_value).collect::<Vec<_>>();
        let identities = group
            .left
            .iter()
            .chain(&group.right)
            .map(|location| location.id.clone())
            .collect::<Vec<_>>();
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "verify-extract-inline-owner",
                priority: "P1",
                confidence: group.confidence,
                reason: format!(
                    "Possible {} correspondence (score {:.4}, coverage {:.4}, precision {:.4}) crosses owner boundaries.",
                    group.relation, group.score, group.coverage, group.precision
                ),
               local: local.clone(),
                upstream,
                evidence_path: Vec::new(),
                identities,
            },
        );
        for location in &group.right {
            unit_dispositions
                .entry(location.id.clone())
                .or_insert_with(|| UnitDisposition {
                    status: "extract-inline-candidate",
                    confidence: group.confidence,
                    work_item_id: Some(id.clone()),
                });
        }
    }

    // Stronger split/merge evidence above takes precedence over a repeated
    // fingerprint; remaining ambiguous owners stay diagnostic-only.
    for (id, confidence) in ambiguous_right_confidence {
        unit_dispositions.entry(id).or_insert(UnitDisposition {
            status: "ambiguous",
            confidence,
            work_item_id: None,
        });
    }

    for record in unmatched_right {
        if identical_location(&record.location) {
            unit_dispositions.insert(
                record.location.id.clone(),
                UnitDisposition {
                    status: "structurally-equal",
                    confidence: "proven-structure",
                    work_item_id: None,
                },
            );
            continue;
        }
        unit_dispositions
            .entry(record.location.id.clone())
            .or_insert(UnitDisposition {
                status: "unmatched-upstream",
                confidence: "unknown",
                work_item_id: None,
            });
    }

    for record in unmatched_left {
        if identical_location(&record.location) || ambiguous_left_ids.contains(&record.location.id) {
            continue;
        }
        let local = vec![location_value(&record.location)];
        let upstream = record
            .candidates
            .iter()
            .take(3)
            .map(|candidate| {
                let mut value = location_value(&candidate.location);
                value["candidateScore"] = json!(candidate.score);
                value["candidateBasis"] = json!(candidate.basis);
                value["channels"] =
                    serde_json::to_value(candidate.channels).expect("scores serialize");
                value
            })
            .collect::<Vec<_>>();
        push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "remove-or-justify-extra-local",
                priority: "P2",
                confidence: "unknown",
                reason: "A local owner has no promoted upstream counterpart. It may be obsolete, local-only, or split differently.".to_string(),
               local,
                upstream,
                evidence_path: Vec::new(),
                identities: std::iter::once(record.location.id.clone())
                    .chain(
                        record
                            .candidates
                            .iter()
                            .map(|candidate| candidate.location.id.clone()),
                    )
                    .collect(),
            },
        );
    }

    let units_by_file =
        right
            .units
            .iter()
            .fold(HashMap::<&str, Vec<&Unit>>::new(), |mut by_file, unit| {
                by_file.entry(unit.file.as_str()).or_default().push(unit);
                by_file
            })
            .into_iter()
            .map(|(file, units)| (file, UnitIntervals::new(units)))
            .collect::<HashMap<_, _>>();
    let frontier_by_right = frontiers
        .iter()
        .filter_map(|frontier| Some((frontier.right_edge.as_ref()?.target.id.as_str(), frontier)))
        .collect::<HashMap<_, _>>();
    let mut right_nodes = right
        .graph_nodes
        .iter()
        .filter(|node| matches!(node.kind.as_str(), "Statement" | "Function" | "Class"))
        .collect::<Vec<_>>();
    right_nodes.sort_by(|left, right| left.id.cmp(&right.id));
    let mut right_nodes_by_file = BTreeMap::<&str, Vec<&GraphNode>>::new();
    for node in &right_nodes {
        right_nodes_by_file
            .entry(node.file.as_str())
            .or_default()
            .push(*node);
    }
    let mut left_nodes_by_file_kind = HashMap::<(&str, &str), Vec<&GraphNode>>::new();
    for node in &left.graph_nodes {
        left_nodes_by_file_kind
            .entry((node.file.as_str(), node.kind.as_str()))
            .or_default()
            .push(node);
    }
    let node_by_id = right
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let units_by_id = right
        .units
        .iter()
        .map(|unit| (unit.id.as_str(), unit))
        .collect::<HashMap<_, _>>();
    let parent_by_child = right
        .graph_edges
        .iter()
        .filter(|edge| edge.kind == "Contains")
        .map(|edge| (edge.target.as_str(), edge.source.as_str()))
        .collect::<HashMap<_, _>>();
    let left_parent_by_child = left
        .graph_edges
        .iter()
        .filter(|edge| edge.kind == "Contains")
        .map(|edge| (edge.target.as_str(), edge.source.as_str()))
        .collect::<HashMap<_, _>>();
    let mut node_status = HashMap::<String, (&'static str, &'static str, Option<String>)>::new();
    for node in &right_nodes {
        let status = if let Some(frontier) = frontier_by_right.get(node.id.as_str()) {
            (
                if frontier.classification == "missing-local-branch" {
                    "missing-local"
                } else if frontier.classification == "ambiguous-correspondence" {
                    "ambiguous"
                } else {
                    "changed-branch"
                },
                frontier.confidence,
                upstream_work_by_node.get(&node.id).cloned(),
            )
        } else if identical_files.contains(node.file.as_str()) {
            ("structurally-equal", "proven-structure", None)
        } else if let Some(unit) = unit_for_node(node, &units_by_file) {
            if let Some(disposition) = unit_dispositions.get(&unit.id) {
                if disposition.status == "unmatched-upstream" {
                    ("unlinked-upstream", "unknown", None)
                } else {
                    (
                        disposition.status,
                        disposition.confidence,
                        disposition.work_item_id.clone(),
                    )
                }
            } else {
                ("unlinked-upstream", "unknown", None)
            }
        } else {
            ("unlinked-upstream", "unknown", None)
        };
        node_status.insert(node.id.clone(), status);
    }

    // A proven owner can still leave an exactly-corresponding executable child
    // looking unlinked when the child has no standalone unit disposition.  Do
    // this only for a direct, exact structural relation whose local and
    // upstream owner chains both agree; never promote fuzzy or merely named
    // descendants.
    for relation in graph_relations {
        if relation.basis != "neighbor-structural-exact"
            || relation.via_edge.as_deref() != Some("Contains")
            || relation.depth != 1
        {
            continue;
        }
        let Some(source) = relation.source.as_ref() else {
            continue;
        };
        if parent_by_child.get(relation.right.id.as_str()).copied()
            != Some(source.right.id.as_str())
            || left_parent_by_child.get(relation.left.id.as_str()).copied()
                != Some(source.left.id.as_str())
        {
            continue;
        }
        let Some(owner_status) = node_status.get(source.right.id.as_str()) else {
            continue;
        };
        if owner_status.0 != "structurally-equal" || owner_status.1 != "proven-structure" {
            continue;
        }
        if node_status
            .get(relation.right.id.as_str())
            .map(|status| status.0)
            == Some("unlinked-upstream")
        {
            node_status.insert(
                relation.right.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
        }
    }

    let mut dependency_evidence_by_node = HashMap::<String, Value>::new();
    let mut dependency_candidates_by_node = HashMap::<String, Value>::new();
    if let Some(dependencies) = dependencies {
        let dependency_package_file_counts =
            dependencies
                .files
                .iter()
                .fold(HashMap::<String, usize>::new(), |mut counts, file| {
                    if let Some(package) = dependency_package_key(file.file.as_str()) {
                        *counts.entry(package).or_default() += 1;
                    }
                    counts
                });
        let dependency_units_by_hash = dependencies.units.iter().fold(
            HashMap::<&str, Vec<&Unit>>::new(),
            |mut by_hash, unit| {
                by_hash
                    .entry(unit.strict_sha256.as_str())
                    .or_default()
                    .push(unit);
                by_hash
            },
        );
        // A bundled top-level statement often has no containing upstream
        // `Unit`, even when its normalized AST is exactly one dependency
        // unit. Index the linked structural hash separately so the owner
        // chain can still be proven without requiring a synthetic container.
        let dependency_units_by_linked_hash = dependencies.units.iter().fold(
            HashMap::<&str, Vec<&Unit>>::new(),
            |mut by_hash, unit| {
                by_hash
                    .entry(unit.linked_sha256.as_str())
                    .or_default()
                    .push(unit);
                by_hash
            },
        );
        let dependency_behavior = graph_behavior_hashes(dependencies);
        let dependency_nodes_by_hash = dependencies.graph_nodes.iter().fold(
            HashMap::<&str, Vec<&GraphNode>>::new(),
            |mut by_hash, node| {
                if let Some(hash) = dependency_behavior.get(&node.id) {
                    by_hash.entry(hash.as_str()).or_default().push(node);
                }
                by_hash
            },
        );
        let upstream_behavior = graph_behavior_hashes(right);
        // Normalized graph matching must not scan the entire dependency AST
        // for every unmatched upstream node.  Build an inverted index on
        // (kind, normalized-token) and start each lookup from its rarest
        // shared token. Complete-unit routes remain separate; graph tokens
        // only narrow the bounded candidate fallback.
        let imported_dependency_packages = left
            .graph_nodes
            .iter()
            .filter(|node| node.kind == "External")
            .filter_map(|node| node.label.strip_prefix("module:"))
            .map(str::to_string)
            .collect::<HashSet<_>>();
        let mut dependency_package_node_counts = HashMap::<String, usize>::new();
        if dependencies.graph_nodes.len() > 250_000 {
            for candidate in &dependencies.graph_nodes {
                if let Some(package) = dependency_package_key(candidate.file.as_str()) {
                    *dependency_package_node_counts.entry(package).or_default() += 1;
                }
            }
        }
        let (dependency_nodes_by_kind_token, dependency_token_frequency) = if dependencies
            .graph_nodes
            .len()
            <= 250_000
            || !imported_dependency_packages.is_empty()
        {
            let mut nodes_by_kind_token = HashMap::<(String, String), Vec<&GraphNode>>::new();
            let mut token_frequency = HashMap::<(String, String), usize>::new();
            for candidate in &dependencies.graph_nodes {
                if dependencies.graph_nodes.len() > 250_000
                    && dependency_package_key(candidate.file.as_str()).is_none_or(|package| {
                        !imported_dependency_packages.contains(&package)
                            || dependency_package_node_counts
                                .get(&package)
                                .copied()
                                .unwrap_or(usize::MAX)
                                > 10_000
                    })
                {
                    continue;
                }
                let keys = candidate
                    .tokens
                    .iter()
                    .filter_map(|token| normalized_graph_token(token))
                    .map(|token| (candidate.kind.clone(), token))
                    .collect::<HashSet<_>>();
                for key in keys {
                    nodes_by_kind_token
                        .entry(key.clone())
                        .or_default()
                        .push(candidate);
                    *token_frequency.entry(key).or_default() += 1;
                }
            }
            (nodes_by_kind_token, token_frequency)
        } else {
            // The unit routes and semantic-hash locators above remain useful
            // for dependency corpora without a local package import
            // boundary. Do not build a String-heavy inverted index for
            // millions of AST nodes when there is no safe package scope.
            (HashMap::new(), HashMap::new())
        };

        for node in &right_nodes {
            if !matches!(
                node_status.get(&node.id).map(|status| status.0),
                Some("unlinked-upstream" | "missing-local" | "changed-branch")
            ) {
                continue;
            }
            let unit_evidence = unit_for_node(node, &units_by_file).and_then(|unit| {
                unique_dependency_evidence(
                    dependency_units_by_hash
                        .get(unit.strict_sha256.as_str())
                        .into_iter()
                        .flatten()
                        .copied(),
                    |candidate| candidate.file.as_str(),
                    |candidate| location_value(&location(candidate)),
                    "exact-normalized-unit",
                )
            });
            // Graph-node linkedSha256 and unit linked_sha256 are different
            // projections: the former describes the graph node's structural
            // neighborhood, while the latter describes the complete owner
            // unit. Keep the complete-unit route distinct from the graph-node
            // locator: a top-level node without a collected owner does not gain
            // a complete-owner certificate from this fallback.
            let linked_unit_evidence = unit_for_node(node, &units_by_file)
                .and_then(|unit| {
                    unique_dependency_evidence(
                        dependency_units_by_linked_hash
                            .get(unit.linked_sha256.as_str())
                            .into_iter()
                            .flatten()
                            .copied(),
                        |candidate| candidate.file.as_str(),
                        |candidate| location_value(&location(candidate)),
                        "exact-linked-unit",
                    )
                });
            let linked_graph_evidence = unique_dependency_evidence(
                dependency_units_by_linked_hash
                    .get(node.linked_sha256.as_str())
                    .into_iter()
                    .flatten()
                    .copied(),
                |candidate| candidate.file.as_str(),
                |candidate| location_value(&location(candidate)),
                "exact-linked-graph-node",
            );
            let graph_evidence = upstream_behavior.get(&node.id).and_then(|hash| {
                unique_dependency_evidence(
                    dependency_nodes_by_hash
                        .get(hash.as_str())
                        .into_iter()
                        .flatten()
                        .copied(),
                    |candidate| candidate.file.as_str(),
                    |candidate| graph_node_value(&graph_node_ref(candidate)),
                    "exact-semantic-neighborhood",
                )
            });
            let normalized_graph_evidence = || {
                let mut lookup_keys = node
                    .tokens
                    .iter()
                    .filter_map(|token| normalized_graph_token(token))
                    .map(|token| (node.kind.clone(), token))
                    .filter(|key| dependency_token_frequency.contains_key(key))
                    .collect::<Vec<_>>();
                lookup_keys.sort_by_key(|key| dependency_token_frequency[key]);
                let first_candidates = lookup_keys
                    .first()
                    .and_then(|key| dependency_nodes_by_kind_token.get(key))
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<Vec<_>>();
                // Do not materialize or repeatedly scan a broad first bucket.
                // Complete-unit routes remain separate; graph hints are
                // optional and must stay bounded on large
                // dependency graphs.
                // Fuzzy dependency evidence is only a bounded fallback. A
                // common token is not useful evidence and makes a large
                // direct-package projection quadratic across the upstream
                // bundle; none of these graph hints certifies ownership.
                if first_candidates.len() > 512 {
                    return None;
                }
                let mut candidates = first_candidates;
                // A common token can still produce a large bucket. Intersect
                // with the next rarest shared tokens before scoring; if the
                // bucket remains broad, decline fuzzy evidence rather than
                // turning every unmatched node into an O(N) dependency scan.
                for key in lookup_keys.iter().skip(1) {
                    if candidates.len() <= 512 {
                        break;
                    }
                    let Some(other) = dependency_nodes_by_kind_token.get(key) else {
                        continue;
                    };
                    let ids = other
                        .iter()
                        .map(|candidate| candidate.id.as_str())
                        .collect::<HashSet<_>>();
                    candidates.retain(|candidate| ids.contains(candidate.id.as_str()));
                }
                if candidates.len() > 512 {
                    return None;
                }
                let mut scored = candidates
                    .into_iter()
                    .filter_map(|candidate| {
                        let package = dependency_package(candidate.file.as_str())?;
                        let package_key = dependency_package_key(candidate.file.as_str())?;
                        Some((
                            graph_similarity(node, candidate),
                            package_key,
                            package,
                            candidate,
                        ))
                    })
                    .collect::<Vec<_>>();
                scored.sort_by(|left, right| {
                    right
                        .0
                        .total_cmp(&left.0)
                        .then_with(|| left.1.cmp(&right.1))
                        .then_with(|| left.2.cmp(&right.2))
                        .then_with(|| left.3.id.cmp(&right.3.id))
                });
                let best = scored.first()?;
                let second_score = scored.get(1).map(|candidate| candidate.0).unwrap_or(0.0);
                let tiny_package = dependency_package_file_counts
                    .get(best.1.as_str())
                    .copied()
                    .is_some_and(|count| count <= 8);
                let minimum_score = if tiny_package { 0.72 } else { 0.98 };
                if best.0 < minimum_score || best.0 - second_score < 0.03 {
                    return None;
                }
                let package_key = best.1.as_str();
                let package = best.2.as_str();
                if scored
                    .iter()
                    .take_while(|candidate| candidate.0 >= best.0 - 0.03)
                    .any(|candidate| candidate.1 != package_key)
                {
                    return None;
                }
                Some(json!({
                    "basis": if tiny_package {
                        "unique-normalized-tiny-package"
                    } else {
                        "unique-normalized-graph-package"
                    },
                    "package": package,
                    "score": best.0,
                    "source": graph_node_value(&graph_node_ref(best.3)),
                }))
            };
            if let Some(evidence) = unit_evidence
                .or(linked_unit_evidence)
            {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(node.id.clone(), evidence);
            } else if let Some(evidence) = linked_graph_evidence
                .or(graph_evidence)
                .or_else(normalized_graph_evidence)
            {
                // Neighborhood hashes and graph scores locate possible package
                // owners; they do not authenticate the complete body or its
                // captured/imported bindings. Preserve the suggestion without
                // changing disposition, confidence, or the normal repair route.
                dependency_candidates_by_node.insert(node.id.clone(), json!({
                    "confidence": "candidate",
                    "reason": "graph-locator-without-complete-owner-binding-proof",
                    "evidence": evidence,
                }));
            }
        }

        // Contains identifies syntax ownership, not complete dependency behavior.
        // A matching descendant does not certify its application parent or siblings;
        // a parent locator likewise cannot certify a separately collected child.
        // Keep each unresolved node in its normal queue until its own complete body
        // and binding obligations are proved. Do not inherit dependency disposition
        // from either direction of this graph, including after graph compaction.

    }

    // CJS wrappers require the same structural evidence as other executable
    // nodes. Adjacency to an imported package cannot establish equivalence.
    // Dependency ownership is resolved before frontier work is emitted. A
    // frontier can be a false positive when a bundled dependency owner is
    // structurally covered by LOCAL; in that case the proof must suppress the
    // candidate instead of leaving a stale P0 in the queue.
    let relation_by_pair = graph_relations
        .iter()
        .map(|relation| {
            (
                (relation.left.id.clone(), relation.right.id.clone()),
                relation,
            )
        })
        .collect::<HashMap<_, _>>();
    for frontier in frontiers {
        let Some(right_edge) = frontier.right_edge.as_ref() else {
            continue;
        };
        if identical_files.contains(right_edge.target.file.as_str())
            || node_status
                .get(&right_edge.target.id)
                .is_some_and(|status| {
                    matches!(
                        status.0,
                        "structurally-equal" | "dependency-structurally-equal"
                    )
                })
        {
            continue;
        }
        let (action, priority, reason) = match frontier.classification {
            "missing-local-branch" => (
                "port-missing-upstream-branch",
                "P0",
                "A typed upstream edge has no corresponding local edge at the first divergence.",
            ),
            "changed-branch" => (
                "reconcile-changed-branch",
                "P0",
                "Local and upstream typed edges diverge below a matched semantic path.",
            ),
            "ambiguous-correspondence" => (
                "resolve-ambiguous-owners",
                "P1",
                "An exact renamed owner has multiple valid graph routes; no arbitrary binding was promoted.",
            ),
            _ => (
                "remove-or-justify-extra-local",
                "P2",
                "A typed local edge has no corresponding upstream edge at the first divergence.",
            ),
        };
        let identity_action = action;
        let local = frontier
            .left_edge
            .as_ref()
            .map(|edge| graph_node_value(&edge.target))
            .into_iter()
            .collect::<Vec<_>>();
        let upstream = vec![graph_node_value(&right_edge.target)];
        let identities = std::iter::once(frontier.source_left.id.clone())
            .chain(std::iter::once(frontier.source_right.id.clone()))
            .chain(frontier.left_edge.iter().map(|edge| edge.target.id.clone()))
            .chain(std::iter::once(right_edge.target.id.clone()))
            .collect::<Vec<_>>();
        let evidence_path = relation_path(
            &relation_by_pair,
            &frontier.source_left.id,
            &frontier.source_right.id,
        );
        let frontier_edge_kinds = frontier
            .left_edge
            .iter()
            .chain(frontier.right_edge.iter())
            .map(|edge| edge.kind.as_str())
            .collect::<Vec<_>>();
        let (action, priority, confidence, reason) =
            if right_edge.target.kind == "External"
                && right_edge.target.label == "module:<current>"
            {
                (
                    "inspect-unresolved-upstream-graph-context",
                    "P2",
                    "unknown",
                    "This frontier reaches the current-module export boundary, not an executable owner. Review the exported/imported contract against its owning symbols.",
                )
            } else {
                let (priority, confidence) = frontier_triage(
                    &frontier_edge_kinds,
                    priority,
                    frontier.confidence,
                );
                let (action, routed_reason) = frontier_work_action(
                    action,
                    &frontier_edge_kinds,
                    should_defer_structural_frontier(
                        &evidence_path,
                        frontier_edge_kinds.iter().any(|edge| is_behavior_edge(edge)),
                        frontier.classification == "changed-branch",
                        confidence == "weak-candidate",
                    ),
                );
                let reason = if routed_reason.is_empty() { reason } else { routed_reason };
                (action, priority, confidence, reason)
            };
        let id = push_work_item_with_identity_action(
            &mut work_items,
            WorkItemDraft {
                action,
                priority,
                confidence,
                reason: reason.to_string(),
                local,
                upstream,
                evidence_path,
                identities,
            },
            frontier_identity_override(identity_action, action),
        );
        upstream_work_by_node.insert(right_edge.target.id.clone(), id.clone());
        if let Some(status) = node_status.get_mut(&right_edge.target.id) {
            status.2 = Some(id);
        }
    }

    let mut unlinked_root_by_node = HashMap::<String, String>::new();
    for node in &right_nodes {
        if node_status.get(&node.id).map(|status| status.0) != Some("unlinked-upstream") {
            continue;
        }
        let mut root = node.id.as_str();
        let mut cursor = node.id.as_str();
        let mut seen = HashSet::new();
        while seen.insert(cursor) {
            let Some(parent) = parent_by_child.get(cursor).copied() else {
                break;
            };
            if node_status.get(parent).map(|status| status.0) == Some("unlinked-upstream") {
                root = parent;
            }
            cursor = parent;
        }
        unlinked_root_by_node.insert(node.id.clone(), root.to_string());
    }
    let unlinked_roots = unlinked_root_by_node
        .values()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut work_by_unlinked_root = HashMap::<String, String>::new();
    for root_id in unlinked_roots {
        let Some(node) = node_by_id.get(root_id.as_str()) else {
            continue;
        };
        let node_ref = graph_node_ref(node);
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "locate-unlinked-upstream-branch",
                priority: unlinked_upstream_triage().0,
                confidence: unlinked_upstream_triage().1,
                reason: "This executable upstream branch is outside every matched, candidate, ambiguous, or frontier owner. Descendants are assigned to the same work item.".to_string(),
               local: Vec::new(),
                upstream: vec![graph_node_value(&node_ref)],
                evidence_path: Vec::new(),
                identities: vec![root_id.clone()],
            },
        );
        work_by_unlinked_root.insert(root_id, id);
    }
    for (node_id, root_id) in unlinked_root_by_node {
        if let (Some(status), Some(work_item_id)) = (
            node_status.get_mut(&node_id),
            work_by_unlinked_root.get(&root_id),
        ) {
            status.2 = Some(work_item_id.clone());
        }
    }

    // The executable ledger drives code-change work. The semantic ledger below
    // additionally retains every graph node (module, binding, scope, file,
    // external and statement) in a compact compressed form. Nodes that have no
    // proven owner are routed to one bounded context work item per upstream
    // file instead of silently vanishing or flooding the queue with hundreds
    // of thousands of near-identical tasks.
    let executable_ids = right_nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<HashSet<_>>();
    let context_needs_work = |node: &GraphNode| {
        if identical_files.contains(node.file.as_str()) {
            return false;
        }
        if executable_ids.contains(node.id.as_str()) {
            return false;
        }
        if let Some(unit) = containing_unit(node, &units_by_file) {
            if let Some(disposition) = unit_dispositions.get(&unit.id) {
                // A child is covered only by an actual structural proof. A
                // candidate may inherit its owner's work route, but is never
                // silently classified as covered graph context.
                return disposition.status == "structurally-equal"
                    || disposition.work_item_id.is_some();
            }
        }
        let mut cursor = node.id.as_str();
        let mut seen = HashSet::new();
        while seen.insert(cursor) {
            let Some(parent) = parent_by_child.get(cursor).copied() else {
                break;
            };
            if node_status
                .get(parent)
                .is_some_and(|status| status.0 != "unlinked-upstream")
            {
                return false;
            }
            cursor = parent;
        }
        true
    };
    let context_files = right
        .graph_nodes
        .iter()
        .filter(|node| context_needs_work(node))
        .map(|node| node.file.clone())
        .collect::<BTreeSet<_>>();
    let mut work_by_context_file = HashMap::<String, String>::new();
    for file in context_files {
        let representative = right
            .graph_nodes
            .iter()
            .find(|node| node.file == file && node.kind == "File")
            .or_else(|| right.graph_nodes.iter().find(|node| node.file == file))
            .expect("context file has a graph node");
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "inspect-unresolved-upstream-graph-context",
                priority: "P2",
                confidence: "unknown",
                reason: "This upstream file has semantic context nodes outside every executable owner and graph correspondence. Inspect this file's compact semantic-ledger rows and graph adjacency before treating it as covered.".to_string(),
               local: Vec::new(),
                upstream: vec![graph_node_value(&graph_node_ref(representative))],
                evidence_path: Vec::new(),
                identities: vec![format!("semantic-context:{file}")],
            },
        );
        work_by_context_file.insert(file, id);
    }

    let mut dispositions = BTreeMap::<String, usize>::new();
    let mut covered_nodes = 0;
    let mut actionable_nodes = 0;
    for node in &right_nodes {
        let (status, _confidence, work_item_id) = node_status
            .get(&node.id)
            .cloned()
            .expect("every upstream executable node has a disposition");
        *dispositions.entry(status.to_string()).or_default() += 1;
        if matches!(
            status,
            "structurally-equal" | "dependency-structurally-equal"
        ) {
            covered_nodes += 1;
        }
        if work_item_id.is_some() {
            actionable_nodes += 1;
        }
        let containing = containing_unit(node, &units_by_file);
        let _ = containing;
    }
    let mut work_items = coalesce_work_items(work_items, &shared_work_evidence)?;
    let mut routes = work_items
        .iter()
        .map(|item| {
            // These two high-volume actions are immediately routed into
            // bounded file segments below. Avoid resolving a full graph owner
            // first for every member; that walk is redundant and dominates
            // large-bundle report generation.
            if matches!(
                item["action"].as_str(),
                Some("locate-unlinked-upstream-branch") | Some("remove-or-justify-extra-local")
            ) {
                ("deferred-segment-route".to_string(), Value::Null)
            } else {
                semantic_owner(
                    item,
                    &shared_work_evidence,
                    &units_by_id,
                    &units_by_file,
                    &node_by_id,
                    &parent_by_child,
                )
            }
        })
        .collect::<Vec<_>>();
    for action in [
        "locate-unlinked-upstream-branch",
        "remove-or-justify-extra-local",
    ] {
        let mut members = work_items
            .iter()
            .enumerate()
            .filter(|(_, item)| item["action"].as_str() == Some(action))
            .map(|(index, item)| {
                let location = item["upstream"]
                    .as_array()
                    .and_then(|locations| locations.first())
                    .or_else(|| {
                        item["local"]
                            .as_array()
                            .and_then(|locations| locations.first())
                    });
                (
                    index,
                    location
                        .and_then(|value| value["file"].as_str())
                        .unwrap_or("<unknown>")
                        .to_string(),
                    location
                        .and_then(|value| value["start"].as_u64())
                        .unwrap_or(0),
                    item["id"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect::<Vec<_>>();
        members.sort_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.2.cmp(&right.2))
                .then_with(|| left.3.cmp(&right.3))
        });
        let mut next_member_by_file = HashMap::<String, usize>::new();
        for (index, file, _, _) in members {
            let member = next_member_by_file.entry(file.clone()).or_insert(0);
            let segment_ordinal = *member / 32;
            *member += 1;
            let route_key = format!("{action}:segment:{file}:{segment_ordinal}");
            routes[index] = (
                route_key,
                json!({
                    "kind": "WorkSegment",
                    "action": action,
                    "file": file,
                    "segment": segment_ordinal,
                    "maximumWorkItems": 32,
                }),
            );
        }
    }

    let mut batch_accumulators = BTreeMap::<String, BatchAccumulator>::new();
    for (item, (route_key, owner)) in work_items.iter_mut().zip(routes) {
        let batch_id = format!("batch-{}", &sha256(&route_key)[..20]);
        item["batchId"] = json!(batch_id);
        item["semanticOwner"] = owner.clone();

        let batch = batch_accumulators.entry(route_key).or_default();
        batch.semantic_owner = owner;
        batch.work_item_count += 1;
        if let Some(priority) = item["priority"].as_str() {
            if batch
                .priority
                .as_ref()
                .is_none_or(|current| priority < current.as_str())
            {
                batch.priority = Some(priority.to_string());
            }
        }
        if let Some(action) = item["action"].as_str() {
            *batch.actions.entry(action.to_string()).or_default() += 1;
        }
        if let Some(locations) = item["local"].as_array() {
            for file in locations
                .iter()
                .filter_map(|location| location["file"].as_str())
            {
                batch.local_files.insert(file.to_string());
            }
        }
    }
    work_items.sort_by(|left, right| {
        left["priority"]
            .as_str()
            .cmp(&right["priority"].as_str())
            .then_with(|| left["batchId"].as_str().cmp(&right["batchId"].as_str()))
            .then_with(|| left["action"].as_str().cmp(&right["action"].as_str()))
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });
    let batches = batch_accumulators
        .into_iter()
        .map(|(route_key, batch)| {
            let batch_id = format!("batch-{}", &sha256(&route_key)[..20]);
            json!({
                "id": batch_id,
                "priority": batch.priority.unwrap_or_else(|| "P2".to_string()),
                "semanticOwner": batch.semantic_owner,
                "workItemCount": batch.work_item_count,
                "actions": batch.actions,
                "localCandidateFiles": batch.local_files.into_iter().take(12).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    compact_work_evidence(output, &mut work_items, shared_work_evidence)?;
    write_json_lines(&output.join("llm-work-items.jsonl"), &work_items)?;
    write_json_lines(&output.join("llm-batches.jsonl"), &batches)?;
    // Publication is sequential. Once the indexed queue is on disk, the
    // semantic ledgers only need its counts and per-node routing maps, not
    // every expanded evidence payload. Release those payloads before decoding
    // the lossless graph stream; large bundles otherwise retain both phases.
    let work_item_count = work_items.len();
    let batch_count = batches.len();
    let mut actions = BTreeMap::<String, usize>::new();
    for item in &work_items {
        if let Some(action) = item["action"].as_str() {
            *actions.entry(action.to_string()).or_default() += 1;
        }
    }
    drop(work_items);
    drop(batches);
    let executable_records = right_nodes.iter().map(|node| {
        let (status, confidence, work_item_id) = node_status
            .get(&node.id)
            .cloned()
            .expect("every upstream executable node has a disposition");
        let containing = containing_unit(node, &units_by_file);
        Ok(json!({
            "disposition": status,
            "confidence": confidence,
            "workItemId": work_item_id,
            "upstream": graph_node_ref(node),
            "containingUnitId": containing.map(|unit| unit.id.as_str()),
            "dependencyEvidence": dependency_evidence_by_node.get(&node.id),
            "dependencyCandidateEvidence": dependency_candidates_by_node.get(&node.id),
        }))
    });
    write_streaming_json_lines_fallible(
        &output.join("upstream-executable-ledger.jsonl"),
        executable_records,
    )?;
    let mut upstream_semantic_nodes = 0usize;
    let semantic_records = lossless_graph_records(right, "node")?.map(|record| {
        let record = record?;
        let node: GraphNode = serde_json::from_value(record["node"].clone())?;
        upstream_semantic_nodes += 1;
        let (status, confidence, work_item_id) = if let Some(status) = node_status.get(&node.id) {
            status.clone()
        } else if let Some(unit) = containing_unit(&node, &units_by_file) {
            match unit_dispositions.get(&unit.id) {
                Some(disposition) if disposition.status == "structurally-equal" => {
                    ("structurally-equal", disposition.confidence, None)
                }
                Some(disposition) if disposition.work_item_id.is_some() => (
                    "inherited-owner-work",
                    disposition.confidence,
                    disposition.work_item_id.clone(),
                ),
                _ => (
                    "unresolved-graph-context",
                    "unknown",
                    work_by_context_file.get(&node.file).cloned(),
                ),
            }
        } else {
            (
                "unresolved-graph-context",
                "unknown",
                work_by_context_file.get(&node.file).cloned(),
            )
        };
        Ok(json!({
            "id": node.id,
            "dependencyCandidateEvidence": dependency_candidates_by_node.get(&node.id),
            "disposition": status,
            "confidence": confidence,
            "workItemId": work_item_id,
            "file": node.file,
            "kind": node.kind,
            "label": node.label,
            "line": node.line,
            "start": node.start,
            "end": node.end,
        }))
    });
    write_seekable_json_lines_fallible(
        &output.join("upstream-semantic-ledger.jsonl.zst"),
        semantic_records,
    )?;

    // Nodes alone cannot explain a divergence such as a changed import name
    // or member property. Keep every authoritative edge in a compact ledger
    // too, with the same owner route used by its source node.
    let streamed_edges = lossless_graph_records(right, "edge")?.map(|record| {
        let record = record?;
        let edge: super::GraphEdge = serde_json::from_value(record["edge"].clone())?;
        let (status, confidence, work_item_id) = if let Some(status) = node_status.get(edge.source.as_str())
        {
            status.clone()
        } else if let Some(source) = node_by_id.get(edge.source.as_str()) {
            match containing_unit(source, &units_by_file)
                .and_then(|unit| unit_dispositions.get(&unit.id))
            {
                Some(disposition) if disposition.status == "structurally-equal" => {
                    ("structurally-equal", disposition.confidence, None)
                }
                Some(disposition) if disposition.work_item_id.is_some() => (
                    "inherited-owner-work",
                    disposition.confidence,
                    disposition.work_item_id.clone(),
                ),
                _ => (
                    "unresolved-graph-context",
                    "unknown",
                    work_by_context_file.get(&source.file).cloned(),
                ),
            }
        } else {
            ("unresolved-graph-context", "unknown", None)
        };
        let source = node_by_id
            .get(edge.source.as_str())
            .map(|node| graph_node_ref(node));
        let target = node_by_id
            .get(edge.target.as_str())
            .map(|node| graph_node_ref(node));
        Ok(json!({
                "id": format!("edge-{}", &sha256(format!("{}\0{}\0{}\0{}\0{}", edge.source, edge.target, edge.kind, edge.dynamic, edge.label.as_deref().unwrap_or("")))[..20]),
                "disposition": status,
                "confidence": confidence,
                "workItemId": work_item_id,
                "source": source,
                "target": target,
                "kind": edge.kind,
                "dynamic": edge.dynamic,
                "label": edge.label,
                "sourceId": edge.source,
                "targetId": edge.target,
            }))
    });
    // Package provenance and dependency-source links are attached after the
    // per-file stream is written. Append those authoritative post-index edges
    // so the LLM edge ledger has the same complete edge set as the semantic
    // graph artifact without duplicating ordinary file edges.
    let edge_records = streamed_edges.chain(
        right
            .graph_edges
            .iter()
            .filter(|edge| {
                matches!(
                    edge.kind.as_str(),
                    "ResolvesToPackage"
                        | "ResolvesToPackageCandidate"
                        | "ResolvesToDependencySource"
                        | "ResolvesTo"
                        | "BindsTo"
                        | "ReExportsTo"
                )
            })
            .map(|edge| {
                let (status, confidence, work_item_id) = if let Some(status) = node_status.get(edge.source.as_str()) {
                    status.clone()
                } else {
                    ("unresolved-graph-context", "unknown", None)
                };
                let source = node_by_id.get(edge.source.as_str()).map(|node| graph_node_ref(node));
                let target = node_by_id.get(edge.target.as_str()).map(|node| graph_node_ref(node));
                Ok(json!({
                    "id": format!("edge-{}", &sha256(format!("{}\0{}\0{}\0{}\0{}", edge.source, edge.target, edge.kind, edge.dynamic, edge.label.as_deref().unwrap_or("")))[..20]),
                    "disposition": status,
                    "confidence": confidence,
                    "workItemId": work_item_id,
                    "source": source,
                    "target": target,
                    "sourceId": edge.source,
                    "targetId": edge.target,
                    "kind": edge.kind,
                    "dynamic": edge.dynamic,
                    "label": edge.label,
                }))
            }),
    );
    write_seekable_json_lines_fallible(
        &output.join("upstream-semantic-edge-ledger.jsonl.zst"),
        edge_records,
    )?;

    let summary = LlmSummary {
        upstream_executable_nodes: right_nodes.len(),
        upstream_semantic_nodes,
        covered_nodes,
        // File inventory is already exposed separately. Neither available
        // packages nor graph-only hints count as covered executable nodes.
        dependency_covered_nodes: dependency_evidence_by_node.len(),
        dependency_files: dependencies.map_or(0, |index| index.files.len()),
        dependency_graph_nodes: dependencies.map_or(0, |index| index.graph_nodes.len()),
        dependency_graph_retained: dependencies.is_some_and(|index| !index.graph_nodes.is_empty()),
        dependency_parse_failures: dependencies.map_or(0, |index| index.failures.len()),
        actionable_nodes,
        work_items: work_item_count,
        batches: batch_count,
        parse_failures: left.failures.len() + right.failures.len(),
        dispositions,
        actions,
    };
    let manifest = json!({
        "schema": "project-parity/llm-manifest-v3",
        "engine": super::ENGINE_VERSION,
        "orientation": "upstream-led",
        "authoritativeTarget": right.corpus.source_root.as_deref().unwrap_or(&right.root),
        "analysisProjection": right.root,
        "localRoot": left.root,
        "inputHashes": {
            "local": left.project_sha256,
            "upstream": right.project_sha256,
            "dependencies": dependencies.map(|index| index.project_sha256.as_str()),
        },
        "inputFingerprints": {
            "local": {
                "sha256": left.input_fingerprint,
                "inputFiles": left.input_files,
            },
            "upstream": {
                "sha256": right.input_fingerprint,
                "inputFiles": right.input_files,
            },
            "dependencies": dependencies.map(|index| json!({
                "root": index.root,
                "sha256": index.input_fingerprint,
                "packageRoots": index.input_roots,
                "inputFiles": index.input_files,
                "resolutionQueries": index.dependency_queries,
            })),
        },
        "summary": summary,
        "artifacts": {
            "report": "report.json",
            "visualReport": "report.html",
            "workItems": "llm-work-items.jsonl",
            "sharedWorkEvidence": "llm-shared-evidence.jsonl",
            "batches": "llm-batches.jsonl",
            "upstreamExecutableLedger": "upstream-executable-ledger.jsonl",
            "upstreamSemanticLedger": "upstream-semantic-ledger.jsonl.zst",
            "upstreamSemanticLedgerIndex": "upstream-semantic-ledger.index.json",
            "upstreamSemanticEdgeLedger": "upstream-semantic-edge-ledger.jsonl.zst",
            "upstreamSemanticEdgeLedgerIndex": "upstream-semantic-edge-ledger.index.json",
            "dependencyEvidenceCorpus": "dependency-evidence-corpus.json",
            "dependencyProvenance": "dependency-provenance.jsonl",
            "dependencyBindingContracts": "dependency-binding-contracts.jsonl",
            "semanticGraph": "semantic-graph.jsonl.zst",
            "semanticGraphIndex": "semantic-graph.index.sqlite",
            "graphRelations": "graph-relations.jsonl",
            "divergenceFrontiers": "divergence-frontiers.jsonl",
            "unmatchedLocal": "unmatched-left.jsonl",
            "unmatchedUpstream": "unmatched-right.jsonl",
            "taskBrief": "LLM_TASK_BRIEF.md"
        },
        "zeroLossContract": {
            "scope": "Every parsed upstream semantic graph node and typed edge has exactly one compact ledger row; executable Function, Class, and Statement owners additionally have one detailed executable-ledger row.",
            "actionable": "Every unresolved executable or semantic-context branch points to a work item; structurally covered/context nodes are retained but omitted from the action queue.",
            "failures": "Parse failures become P0 work items and prevent a successful CLI exit."
        },
        "dependencyCorpus": dependencies.map(|index| json!({
            "files": index.files.len(),
            "parseFailures": index.failures.len(),
            "contract": "Dependency evidence only classifies exact structural matches. It never removes an upstream node from the ledger, and failures do not weaken the zero-loss contract for the authoritative upstream corpus.",
        })),
        "workItemContract": {
            "schema": "project-parity/llm-work-item-v2",
            "storage": "Large repeated upstream candidate arrays are interned in llm-shared-evidence.jsonl by SHA256. upstreamEvidenceRef replaces the stored upstream field. inspectNodeIdsFromOwners elides the inspect list only when it exactly equals local IDs followed by upstream IDs. show-work/show-works/show-batch/inspect expand losslessly; state-sync compares expanded canonical payloads so changing storage does not reopen reviewed evidence. Missing or corrupt shared evidence fails closed.",
            "routing": "Start with llm-batches.jsonl. Each row is one semantic owner, not an emitted bundle. Use project-parity show-batch <REPORT_DIRECTORY> <BATCH_ID> [LIMIT] [OFFSET] to load a bounded page, then inspect its node ids.",
            "inspect": "For each inspectNodeIds entry, run project-parity inspect <REPORT_DIRECTORY> <NODE_ID>. The inspector validates source and source-map hashes before returning the full source span and relations.",
            "acceptance": [
                "Read the complete upstream owner and every local owner/candidate named by the item.",
                "Trace callers, dependencies, state transitions, side effects, and error paths before editing.",
                "Treat the report's upstream/right side as authoritative; do not invent behavior to satisfy a score.",
                "After editing, regenerate this report and require the item to disappear or become structurally covered.",
                "Run focused tests plus the relevant runtime/visual gate; AST correspondence alone is not behavioral parity."
            ]
        },
        "dependencyProvenanceContract": "Every static import edge is recorded with its importing file, specifier, imported export and resolution state. Package name and version are emitted only after Node-style installed-package resolution; unresolved and local edges remain explicit. Runtime fingerprints cover the selected executable package surface, never identifiers alone.",
        "semanticGraphContract": "semantic-graph.jsonl.zst is lossless: it contains every parsed node and typed edge from both input trees, plus input project hashes. semantic-graph.index.sqlite maps node ids to independent zstd chunks for indexed graph-node lookup. Older report bundles with semantic-graph.index.json are migrated to the SQLite lookup index on first graph-node access. upstream-semantic-ledger.jsonl.zst and upstream-semantic-edge-ledger.jsonl.zst are also concatenated-frame artifacts with adjacent indexes, so inspection can decode only the relevant ledger frame. Use project-parity graph-node REPORT_DIRECTORY NODE_ID [LIMIT] [OFFSET] to page a node's incoming and outgoing edges.",
        "evidenceBoundary": "This bundle routes an LLM to source evidence. It does not authorize blind patch application and does not prove runtime, native, asset, or pixel parity."
    });
    fs::write(
        output.join("llm-manifest.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    let dependency_corpus = dependencies.map(|index| {
        json!({
            "schema": "project-parity/dependency-evidence-corpus-v1",
            "root": index.root,
            "corpus": index.corpus,
            "projectSha256": index.project_sha256,
            "inputRoots": index.input_roots,
            "files": index.files,
            "failures": index.failures,
            "skipped": index.skipped,
            "boundary": "This is a third evidence corpus for installed dependencies. It is not an authoritative input and does not replace or reduce the upstream executable ledger.",
        })
    });
    fs::write(
        output.join("dependency-evidence-corpus.json"),
        format!("{}\n", serde_json::to_string_pretty(&dependency_corpus)?),
    )?;
    fs::write(
        output.join("LLM_TASK_BRIEF.md"),
        r#"# Upstream parity work queue

Use `llm-manifest.json` as the entry point and `llm-batches.jsonl` as the routing index. Each batch is rooted at a semantic function, class, statement branch, or local-only owner rather than a generated chunk. Load bounded pages with `project-parity show-batch <REPORT_DIRECTORY> <BATCH_ID> [LIMIT] [OFFSET]`; the response includes `total`, `remaining`, and `nextOffset`. Its records come from `llm-work-items.jsonl`, the complete action queue. The authoritative target is the report's upstream/right side. `upstream-semantic-ledger.jsonl.zst` is the completeness ledger: every parsed upstream graph node appears exactly once. `upstream-semantic-edge-ledger.jsonl.zst` retains each typed upstream edge with the source owner's route. `upstream-executable-ledger.jsonl` is the detailed executable-owner projection.

Process P0, then P1, then P2. Exact installed-dependency matches are retained in the ledger as `dependency-structurally-equal` with package/source evidence and do not pollute the action queue. For each item, inspect every listed node with `project-parity inspect <REPORT_DIRECTORY> <NODE_ID>`, read the complete upstream and local owners plus their callers/dependencies, and determine whether the local project must be changed. Scores and graph propagation are locator evidence, never permission to copy blindly or claim parity.

`inspect-unverified-missing-branch` and `inspect-unverified-changed-branch` have no behavioral-edge corroboration in the graph. They can still represent a real behavior difference (for example, changed return values also use `Contains` edges), so inspect the complete owner and decide from its semantics before editing.

Edit only local sources. Treat the upstream input as read-only. After each coherent patch, run focused tests and the relevant runtime or rendered-output validation, regenerate the matcher report, and confirm that the work item disappears or moves to a justified covered disposition. A source/AST match alone does not close behavioral, native, asset, or pixel parity.
"#,
    )?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::{
        candidate_owner_triage, coalesce_work_items,
        compact_work_evidence, expand_work_evidence, frontier_identity_override, frontier_triage, frontier_work_action,
        push_work_item, push_work_item_with_identity_action, read_shared_work_evidence,
        same_file_identity, should_defer_structural_frontier, unlinked_upstream_triage,
        work_item_id, WorkItemDraft,
        write_json_lines,
    };
    use crate::{FileRecord, Location, MatchRecord};
    use serde_json::json;

    #[test]
    fn frontier_identity_override_only_applies_to_structural_routing() {
        let identities = vec!["left:owner".to_string(), "right:owner".to_string(), "right:edge".to_string()];
        let base = "port-missing-upstream-branch";
        let module = "inspect-unresolved-upstream-graph-context";
        let selected = frontier_identity_override(base, module).unwrap_or(module);
        assert_eq!(work_item_id(selected, identities.clone()), work_item_id(module, identities.clone()));
        let structural = "inspect-structural-frontier";
        let selected = frontier_identity_override(base, structural).unwrap_or(structural);
        assert_eq!(work_item_id(selected, identities.clone()), work_item_id(base, identities));
    }

    fn file_record(file: &str, source_sha256: &str, source_map_sha256: Option<&str>) -> FileRecord {
        FileRecord {
            file: file.to_string(),
            bytes: 0,
            source_sha256: source_sha256.to_string(),
            source_map_sha256: source_map_sha256.map(str::to_string),
            source_map_error: None,
            units: 0,
        }
    }

    fn test_location(id: &str) -> Location {
        Location {
            id: id.to_string(),
            file: "fixture.ts".to_string(),
            kind: "Function".to_string(),
            name: None,
            line: 1,
            start: 0,
            end: 1,
            origin: None,
        }
    }

    #[test]
    fn file_identity_requires_matching_path_and_source_evidence() {
        let canonical = file_record("src/runtime.ts", "source-a", Some("map-a"));
        assert!(same_file_identity(
            &canonical,
            &file_record("src/runtime.ts", "source-a", Some("map-a"))
        ));

        // Similar names or contents in different roots are only locators. They
        // need normal unit/graph evidence before the report can cover them.
        assert!(!same_file_identity(
            &canonical,
            &file_record("apps/runtime.ts", "source-a", Some("map-a"))
        ));
        assert!(!same_file_identity(
            &canonical,
            &file_record("src/runtime.ts", "source-b", Some("map-a"))
        ));
        assert!(!same_file_identity(
            &canonical,
            &file_record("src/runtime.ts", "source-a", Some("map-b"))
        ));
    }

    #[test]
    fn candidate_triage_requires_more_than_fingerprint_or_feature_ranking() {
        for score in [0.72, 0.9999] {
            let fuzzy_pair = MatchRecord {
                confidence: "candidate",
                status: "changed-candidate",
                basis: "mutual-best-fuzzy",
                score,
                channels: None,
                left: test_location("left:fuzzy"),
                right: test_location("right:fuzzy"),
            };
            assert_eq!(
                candidate_owner_triage(&fuzzy_pair),
                ("P2", "weak-candidate")
            );
        }

        let exact_dependency_change = MatchRecord {
            confidence: "candidate",
            status: "dependency-context-changed",
            basis: "strict-dependency-context",
            score: 1.0,
            channels: None,
            left: test_location("left:dependency"),
            right: test_location("right:dependency"),
        };
        assert_eq!(
            candidate_owner_triage(&exact_dependency_change),
            ("P1", "candidate")
        );

        assert_eq!(
            frontier_triage(&["Calls"], "P1", "candidate"),
            ("P1", "candidate")
        );
    }

    #[test]
    fn early_candidate_interning_preserves_owner_routes_and_coalesced_variants() {
        use super::{intern_work_evidence, semantic_owner};
        use std::collections::HashMap;
        let upstream = (0..200).map(|i| json!({"id":format!("right:{i}"),"file":"chunk.js","line":i})).collect::<Vec<_>>();
        let mut original = (0..20).map(|i| json!({
            "id":format!("work:{i}"),"action":"resolve-ambiguous-owners","priority":"P1","confidence":"candidate",
            "reason":"ambiguous owner","local":[{"id":format!("left:{i}"),"file":"local.ts"}],"upstream":upstream,
            "evidencePath":[],"inspectNodeIds":std::iter::once(format!("left:{i}")).chain((0..200).map(|n|format!("right:{n}"))).collect::<Vec<_>>()
        })).collect::<Vec<_>>();
        let mut variant = original[0].clone();
        variant["evidencePath"] = json!([{"viaEdge":"Calls"}]);
        original.push(variant);
        let expected = coalesce_work_items(original.clone(), &HashMap::new()).unwrap();
        let mut compact = original.clone();
        let mut shared = HashMap::new();
        for (item, source) in compact.iter_mut().zip(&original) {
            intern_work_evidence(item, &mut shared).unwrap();
            assert!(item.get("upstream").is_none());
            assert_eq!(semantic_owner(item, &shared, &HashMap::new(), &HashMap::new(), &HashMap::new(), &HashMap::new()),
                semantic_owner(source, &HashMap::new(), &HashMap::new(), &HashMap::new(), &HashMap::new(), &HashMap::new()));
        }
        assert_eq!(shared.len(), 1);
        assert!(serde_json::to_vec(&compact).unwrap().len() < serde_json::to_vec(&original).unwrap().len() / 10);
        let mut merged = coalesce_work_items(compact, &shared).unwrap();
        let output = tempfile::tempdir().unwrap();
        compact_work_evidence(output.path(), &mut merged, shared).unwrap();
        let shared = read_shared_work_evidence(output.path()).unwrap();
        let expanded = merged.into_iter().map(|item| expand_work_evidence(item, &shared).unwrap()).collect::<Vec<_>>();
        assert_eq!(expanded, expected);
    }

    #[test]
    fn interval_owner_lookup_matches_exhaustive_id_ordered_ranges() {
        use super::{containing_unit, UnitIntervals};
        use crate::{semantic_graph::GraphNode, Unit};
        use std::collections::HashMap;
        let mut seed = 73u64;
        let mut next = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            (seed >> 32) as u32
        };
        for count in [0, 1, 3, 10, 100, 1000] {
            let ranges = (0..count).map(|_| {
                let start = next() % 300;
                (start, start + next() % 200)
            }).chain([(10,20), (100,110), (0,90), (0,90)]).collect::<Vec<_>>();
            let units = ranges.into_iter().enumerate().map(|(i,(start,end))| Unit {
                id: i.to_string(), file: "fixture.js".into(), kind: "Function".into(),
                name: None, start, end, line: 1, origin: None, nodes_approx: 0,
                strict_sha256: String::new(), linked_sha256: String::new(),
                tokens: Default::default(), features: Default::default(),
            }).collect::<Vec<_>>();
            let index = HashMap::from([("fixture.js", UnitIntervals::new(units.iter().collect()))]);
            let mut node = GraphNode {
                id: String::new(), file: "fixture.js".into(), kind: "Statement".into(),
                label: String::new(), start: 0, end: 0, line: 1, scope: None,
                linked_sha256: String::new(), tokens: Default::default(),
            };
            // Includes zero-width boundary nodes, overlap and identical-range ties.
            for _ in 0..10000 {
                node.start = next() % 500;
                node.end = node.start + next() % 100;
                let expected = units.iter().rev()
                    .filter(|u| u.start <= node.start && u.end >= node.end)
                    .min_by_key(|u| u.end - u.start);
                assert_eq!(containing_unit(&node, &index).map(|u| &u.id), expected.map(|u| &u.id));
            }
            node.file = "absent.js".into();
            assert!(containing_unit(&node, &index).is_none());
            assert!(UnitIntervals::new(vec![]).containing(&node).is_none());
        }
    }

    #[test]
    fn shared_candidate_storage_round_trips_complete_evidence_and_reviewed_decisions() {
        let output = tempfile::tempdir().unwrap();
        let local = tempfile::tempdir().unwrap();
        let upstream_root = tempfile::tempdir().unwrap();
        let upstream = (0..80)
            .map(|i| json!({"id":format!("right:{i}"),"file":"chunk.js","line":i}))
            .collect::<Vec<_>>();
        let original = (0..3).map(|i| json!({
            "id":format!("work:{i}"), "action":"resolve-ambiguous-owners", "priority":"P1", "confidence":"candidate",
            "upstream":upstream, "local":[{"id":format!("left:{i}")}], "inspectNodeIds":std::iter::once(format!("left:{i}")).chain((0..80).map(|n| format!("right:{n}"))).collect::<Vec<_>>(), "batchId":"batch:shared"
        })).collect::<Vec<_>>();
        write_json_lines(&output.path().join("llm-work-items.jsonl"), &original).unwrap();
        write_json_lines(
            &output.path().join("llm-batches.jsonl"),
            &[json!({"id":"batch:shared","workItemCount":3})],
        )
        .unwrap();
        std::fs::write(
            output.path().join("llm-manifest.json"),
            serde_json::to_vec(&json!({
                "engine": crate::ENGINE_VERSION,
                "localRoot": local.path().canonicalize().unwrap(),
                "analysisProjection": upstream_root.path().canonicalize().unwrap(),
                "inputHashes": {"local": "fixture-local", "upstream": "fixture-upstream"}
            })).unwrap(),
        )
        .unwrap();
        let db = output.path().join("state.sqlite");
        crate::state::sync(&db, output.path()).unwrap();
        crate::state::mark_pending_sync(&db, "work:0", "reviewed unchanged evidence").unwrap();

        let mut compact = original.clone();
        compact_work_evidence(output.path(), &mut compact, std::collections::HashMap::new()).unwrap();
        write_json_lines(&output.path().join("llm-work-items.jsonl"), &compact).unwrap();
        let shared = read_shared_work_evidence(output.path()).unwrap();
        assert_eq!(shared.len(), 1);
        assert!(
            std::fs::metadata(output.path().join("llm-work-items.jsonl"))
                .unwrap()
                .len()
                < 2000
        );
        for (item, expected) in compact.iter().zip(&original) {
            assert_eq!(
                expand_work_evidence(item.clone(), &shared).unwrap(),
                *expected
            );
            assert_eq!(
                crate::show_work(output.path(), expected["id"].as_str().unwrap()).unwrap(),
                *expected
            );
        }
        assert_eq!(
            crate::show_works(output.path(), &["work:2".into(), "work:0".into()]).unwrap()["items"],
            json!([original[2], original[0]])
        );
        assert_eq!(
            crate::show_batch(output.path(), "batch:shared", 3, 0).unwrap()["items"],
            json!(original)
        );
        assert_eq!(
            crate::read_json_lines(&output.path().join("llm-work-items.jsonl")).unwrap(),
            original
        );
        let result = crate::state::sync(&db, output.path()).unwrap();
        assert_eq!(result["reopened"], 0);
        assert_eq!(result["pendingReleased"], 1);

        // Removing referenced evidence must fail without publishing a new run.
        std::fs::remove_file(output.path().join("llm-shared-evidence.jsonl")).unwrap();
        assert!(crate::state::sync(&db, output.path()).is_err());
        let conn = rusqlite::Connection::open(&db).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM runs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row(
                "SELECT status FROM work_item_decisions WHERE work_item_id='work:0'",
                [],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "done"
        );
    }

    #[test]
    fn shared_evidence_rejects_corruption_and_ambiguous_inline_override() {
        let output = tempfile::tempdir().unwrap();
        std::fs::write(
            output.path().join("llm-shared-evidence.jsonl"),
            "{\"id\":\"bad\",\"upstream\":[]}\n",
        )
        .unwrap();
        assert!(read_shared_work_evidence(output.path()).is_err());
        assert!(expand_work_evidence(
            json!({"upstreamEvidenceRef":"missing"}),
            &std::collections::HashMap::new()
        )
        .is_err());
        let shared = std::collections::HashMap::from([("valid".into(), json!([]))]);
        assert!(expand_work_evidence(
            json!({"upstreamEvidenceRef":"valid","upstream":[]}),
            &shared
        )
        .is_err());
    }

    #[test]
    fn structural_frontiers_require_behavior_on_the_divergent_edge() {
        assert_eq!(unlinked_upstream_triage(), ("P2", "unknown"));
        assert_eq!(frontier_triage(&[], "P0", "candidate"), ("P2", "weak-candidate"));
        assert_eq!(frontier_triage(&["Contains"], "P0", "candidate"), ("P2", "weak-candidate"));
        assert_eq!(frontier_triage(&["NextStatement"], "P0", "candidate"), ("P2", "weak-candidate"));
        assert_eq!(frontier_triage(&["References"], "P0", "candidate"), ("P0", "candidate"));
        assert_eq!(
            frontier_work_action("port-missing-upstream-branch", &["References"], false),
            ("port-missing-upstream-branch", "")
        );
        assert_eq!(
            frontier_triage(&["Calls"], "P0", "candidate"),
            ("P0", "candidate")
        );
        assert_eq!(frontier_work_action("port-missing-upstream-branch", &["Calls"], false), ("port-missing-upstream-branch", ""));
        assert_eq!(
            frontier_work_action("port-missing-upstream-branch", &["Contains"], false),
            (
                "inspect-unverified-missing-branch",
                "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change."
            )
        );
        assert_eq!(
            frontier_work_action("port-missing-upstream-branch", &[], false),
            (
                "inspect-unverified-missing-branch",
                "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change."
            )
        );
        assert_eq!(
            frontier_work_action("reconcile-changed-branch", &["Incoming:Defines"], false),
            (
                "inspect-unverified-changed-branch",
                "The frontier has no behavioral-edge corroboration; inspect its semantics before proposing a code change."
            )
        );
    }

    #[test]
    fn structural_frontier_deferral_requires_only_weak_graph_evidence() {
        assert!(!should_defer_structural_frontier(&[], false, false, true));
        assert!(should_defer_structural_frontier(
            &[json!({"basis":"global-behavior"}), json!({"basis":"neighbor-shape"})],
            false, false, true
        ));
        assert!(!should_defer_structural_frontier(
            &[json!({"basis":"neighbor-binding-owner"})], false, false, true
        ));
        assert!(!should_defer_structural_frontier(
            &[json!({"basis":"seed-unit"})], false, false, true
        ));
        assert!(!should_defer_structural_frontier(
            &[json!({"basis":"global-behavior"})], true, false, true
        ));
        assert!(!should_defer_structural_frontier(&[json!({"basis":"neighbor-shape"})], false, true, true));
        assert!(!should_defer_structural_frontier(
            &[json!({"basis":"neighbor-shape"})], false, false, false
        ));
        assert_eq!(frontier_work_action("port-missing-upstream-branch", &[], true).0, "inspect-structural-frontier");
    }

    #[test]
    fn local_binding_does_not_strengthen_a_weak_global_owner_route() {
        let weak = [json!({"basis":"global-behavior"}), json!({"basis":"neighbor-normalized"}), json!({"basis":"neighbor-binding-owner"})];
        let seeded = [json!({"basis":"seed-unit"}), json!({"basis":"neighbor-binding-owner"})];
        let unknown = [json!({"basis":"global-behavior"}), json!({"basis":"unknown"}), json!({"basis":"neighbor-binding-owner"})];
        assert!(should_defer_structural_frontier(&weak, false, false, true));
        assert!(!should_defer_structural_frontier(&seeded, false, false, true));
        assert!(!should_defer_structural_frontier(&unknown, false, false, true));
        assert!(!should_defer_structural_frontier(&weak, true, false, true));
        assert!(!should_defer_structural_frontier(&weak, false, true, true));
        assert!(!should_defer_structural_frontier(&weak, false, false, false));
        for edge in ["Calls", "References", "Incoming:References", "Instantiates", "Renders"] {
            assert_eq!(frontier_triage(&[edge], "P0", "candidate"), ("P0", "candidate"));
            assert_eq!(frontier_work_action("port-missing-upstream-branch", &[edge], true).0, "port-missing-upstream-branch");
        }
    }

    #[test]
    fn work_item_ids_are_independent_of_identity_discovery_order() {
        let forward = work_item_id(
            "resolve-ambiguous-owners",
            vec![
                "right:z".to_string(),
                "left:a".to_string(),
                "right:b".to_string(),
            ],
        );
        let reverse = work_item_id(
            "resolve-ambiguous-owners",
            vec![
                "right:b".to_string(),
                "right:z".to_string(),
                "left:a".to_string(),
            ],
        );
        assert_eq!(forward, reverse);
    }

    #[test]
    fn work_item_ids_ignore_unstable_frontier_and_candidate_details() {
        let frontier_a = work_item_id(
            "port-missing-upstream-branch",
            vec![
                "left:owner".to_string(),
                "right:owner".to_string(),
                "right:edge-a".to_string(),
            ],
        );
        let frontier_b = work_item_id(
            "port-missing-upstream-branch",
            vec![
                "left:owner".to_string(),
                "right:owner".to_string(),
                "right:edge-b".to_string(),
            ],
        );
        assert_eq!(frontier_a, frontier_b);

        let structural_frontier = work_item_id(
            "inspect-weak-missing-branch",
            vec![
                "left:owner".to_string(),
                "right:owner".to_string(),
                "right:edge-a".to_string(),
            ],
        );
        assert_eq!(structural_frontier, frontier_a);

        let structural_change = work_item_id(
            "inspect-weak-changed-branch",
            vec![
                "left:owner".to_string(),
                "right:owner".to_string(),
                "right:edge-a".to_string(),
            ],
        );
        let changed_branch = work_item_id(
            "reconcile-changed-branch",
            vec![
                "left:owner".to_string(),
                "right:owner".to_string(),
                "right:edge-a".to_string(),
            ],
        );
        assert_eq!(structural_change, changed_branch);

        let local_a = work_item_id(
            "remove-or-justify-extra-local",
            vec!["left:owner".to_string(), "right:candidate-a".to_string()],
        );
        let local_b = work_item_id(
            "remove-or-justify-extra-local",
            vec!["left:owner".to_string(), "right:candidate-b".to_string()],
        );
        assert_eq!(local_a, local_b);
    }

    #[test]
    fn coalescing_preserves_distinct_frontier_evidence_and_keeps_other_items() {
        let make_item = |id: &str, node_id: &str| {
            json!({
                "id": id,
                "priority": "P0",
                "action": "port-missing-upstream-branch",
                "confidence": "candidate",
                "reason": "missing typed edge",
                "local": [],
                "upstream": [{"id": node_id, "file": "dist/chunk.js"}],
                "evidencePath": [{"right": {"id": "right:owner"}}],
                "inspectNodeIds": [node_id],
            })
        };
        let merged = coalesce_work_items(vec![
            make_item("work-owner", "right:edge-a"),
            make_item("work-other", "right:edge-c"),
            make_item("work-owner", "right:edge-b"),
            make_item("work-owner", "right:edge-a"),
        ], &std::collections::HashMap::new()).unwrap();

        assert_eq!(merged.len(), 2);
        let owner = merged
            .iter()
            .find(|item| item["id"] == "work-owner")
            .unwrap();
        assert_eq!(owner["evidenceVariants"].as_array().unwrap().len(), 2);
        assert_eq!(owner["upstream"].as_array().unwrap().len(), 2);
        assert_eq!(owner["inspectNodeIds"].as_array().unwrap().len(), 2);
        assert!(merged.iter().any(|item| item["id"] == "work-other"));
    }

    #[test]
    fn coalescing_keeps_frontier_active_when_any_route_has_stronger_evidence() {
        let identities = vec![
            "left:owner".to_string(),
            "right:owner".to_string(),
            "left:edge".to_string(),
            "right:edge".to_string(),
        ];
        let make_draft = |action, priority, confidence, basis| WorkItemDraft {
            action,
            priority,
            confidence,
            reason: "frontier evidence".to_string(),
            local: vec![json!({"id":"left:edge","file":"src/local.ts"})],
            upstream: vec![json!({"id":"right:edge","file":"dist/chunk.js"})],
            evidence_path: vec![json!({"basis":basis})],
            identities: identities.clone(),
        };
        let mut items = Vec::new();
        let structural_id = push_work_item_with_identity_action(
            &mut items,
            make_draft(
                "inspect-structural-frontier",
                "P2",
                "weak-candidate",
                "neighbor-shape",
            ),
            Some("port-missing-upstream-branch"),
        );
        let active_id = push_work_item(
            &mut items,
            make_draft(
                "inspect-unverified-missing-branch",
                "P0",
                "candidate",
                "seed-unit",
            ),
        );
        assert_eq!(structural_id, active_id, "routing preserves the base frontier identity");
        let merged = coalesce_work_items(items, &std::collections::HashMap::new()).unwrap();
        assert_eq!(merged.len(), 1);
        let item = &merged[0];
        assert_eq!(item["action"], "inspect-unverified-missing-branch");
        assert_eq!(item["priority"], "P0");
        assert_eq!(item["confidence"], "candidate");
        assert_eq!(item["evidenceVariants"].as_array().unwrap().len(), 2);
        assert!(item["evidenceVariants"].as_array().unwrap().iter().any(|variant| {
            variant["action"] == "inspect-structural-frontier"
        }));

        // A corroborating reference must keep an owner active even when a
        // second route for the same owner is deferred as purely structural.
        let mut referenced = Vec::new();
        push_work_item_with_identity_action(
            &mut referenced,
            make_draft("inspect-structural-frontier", "P2", "weak-candidate", "neighbor-shape"),
            Some("port-missing-upstream-branch"),
        );
        let reference_action = frontier_work_action("port-missing-upstream-branch", &["References"], true).0;
        push_work_item(&mut referenced, make_draft(reference_action, "P0", "candidate", "global-behavior"));
        let merged = coalesce_work_items(referenced, &std::collections::HashMap::new()).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0]["action"], "port-missing-upstream-branch");
        assert_eq!(merged[0]["priority"], "P0");
    }
}
