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
    graph_behavior_hashes, location, sha256, AmbiguousGroup, DivergenceFrontier, GraphNode,
    GraphNodeRef, GraphRelation, GroupCandidate, Location, MatchRecord, ProjectIndex, Unit,
    Unmatched,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LlmSummary {
    pub(crate) upstream_executable_nodes: usize,
    pub(crate) upstream_semantic_nodes: usize,
    pub(crate) covered_nodes: usize,
    pub(crate) dependency_covered_nodes: usize,
    pub(crate) dependency_files: usize,
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

fn write_json_lines(path: &Path, values: &[Value]) -> Result<()> {
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut output = BufWriter::new(file);
    let mut records = serde_json::Map::new();
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for value in values {
        let line = serde_json::to_vec(&value)?;
        let offset = output.stream_position()?;
        output.write_all(&line)?;
        output.write_all(b"\n")?;
        if let Some(id) = value["id"].as_str() {
            records.insert(
                id.to_string(),
                json!({"offset": offset, "length": line.len() + 1}),
            );
        }
        if let Some(batch_id) = value["batchId"].as_str() {
            groups
                .entry(batch_id.to_string())
                .or_default()
                .push(json!({"offset": offset, "length": line.len() + 1}));
        }
    }
    output
        .flush()
        .with_context(|| format!("write {}", path.display()))?;
    let index = json!({
        "schema": "project-parity/jsonl-index-v1",
        "records": records,
        "groups": groups,
    });
    let index_path = jsonl_index_path(path);
    fs::write(
        &index_path,
        format!("{}\n", serde_json::to_string_pretty(&index)?),
    )
    .with_context(|| format!("write {}", index_path.display()))
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
    lines: std::io::Lines<BufReader<fs::File>>,
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
        return Ok(Box::new(LosslessGraphRecords {
            lines: BufReader::new(file).lines(),
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
    let material = std::iter::once(action.to_string())
        .chain(identities)
        .collect::<Vec<_>>()
        .join("\0");
    format!("work-{}", &sha256(material)[..20])
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

fn push_work_item(items: &mut Vec<Value>, draft: WorkItemDraft) -> String {
    let id = work_item_id(draft.action, draft.identities);
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

fn containing_unit<'a>(
    node: &GraphNode,
    units_by_file: &'a HashMap<&str, Vec<&'a Unit>>,
) -> Option<&'a Unit> {
    units_by_file
        .get(node.file.as_str())?
        .get(
            ..units_by_file
                .get(node.file.as_str())?
                .partition_point(|unit| unit.start <= node.start),
        )?
        .iter()
        .rev()
        .copied()
        .filter(|unit| unit.start <= node.start && unit.end >= node.end)
        .min_by_key(|unit| unit.end - unit.start)
}

fn semantic_owner(
    item: &Value,
    units_by_id: &HashMap<&str, &Unit>,
    units_by_file: &HashMap<&str, Vec<&Unit>>,
    node_by_id: &HashMap<&str, &GraphNode>,
    parent_by_child: &HashMap<&str, &str>,
) -> (String, Value) {
    let upstream_value = item["upstream"]
        .as_array()
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
        Some(format!("{}/{}", parts.next()?, parts.next()?))
    } else {
        path.split('/').next().map(str::to_string)
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
    let mut by_package = BTreeMap::<String, Vec<Value>>::new();
    for candidate in candidates {
        let dependency_file = file(candidate);
        let package = dependency_package(dependency_file)?;
        by_package
            .entry(package)
            .or_default()
            .push(value(candidate));
    }
    if by_package.len() != 1 {
        return None;
    }
    let (package, mut sources) = by_package.into_iter().next()?;
    sources.truncate(3);
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
    let mut unit_dispositions = HashMap::<String, UnitDisposition>::new();
    let mut upstream_work_by_node = HashMap::<String, String>::new();
    let identical_files = right
        .files
        .iter()
        .filter_map(|right_file| {
            left.files
                .iter()
                .find(|left_file| {
                    left_file.file == right_file.file
                        && left_file.source_sha256 == right_file.source_sha256
                        && left_file.source_map_sha256 == right_file.source_map_sha256
                })
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
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action: "reconcile-changed-owner",
                priority: "P1",
                confidence: record.confidence,
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
                confidence: record.confidence,
                work_item_id: Some(id),
            },
        );
    }

    for group in ambiguous {
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
                action: "resolve-ambiguous-owners",
                priority: "P1",
                confidence: group.confidence,
                reason: format!(
                    "Multiple owners share the {} fingerprint; no arbitrary pair was selected.",
                    group.basis
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
                    status: "ambiguous",
                    confidence: group.confidence,
                    work_item_id: Some(id.clone()),
                });
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
        unit_dispositions.insert(
            record.location.id.clone(),
            UnitDisposition {
                status: "unmatched-upstream",
                confidence: "unknown",
                work_item_id: None,
            },
        );
    }

    for record in unmatched_left {
        if identical_location(&record.location) {
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
        if frontier
            .right_edge
            .as_ref()
            .is_some_and(|edge| identical_files.contains(edge.target.file.as_str()))
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
            _ => (
                "remove-or-justify-extra-local",
                "P2",
                "A typed local edge has no corresponding upstream edge at the first divergence.",
            ),
        };
        let local = frontier
            .left_edge
            .as_ref()
            .map(|edge| graph_node_value(&edge.target))
            .into_iter()
            .collect::<Vec<_>>();
        let upstream = frontier
            .right_edge
            .as_ref()
            .map(|edge| graph_node_value(&edge.target))
            .into_iter()
            .collect::<Vec<_>>();
        let identities = std::iter::once(frontier.source_left.id.clone())
            .chain(std::iter::once(frontier.source_right.id.clone()))
            .chain(frontier.left_edge.iter().map(|edge| edge.target.id.clone()))
            .chain(
                frontier
                    .right_edge
                    .iter()
                    .map(|edge| edge.target.id.clone()),
            )
            .collect::<Vec<_>>();
        let id = push_work_item(
            &mut work_items,
            WorkItemDraft {
                action,
                priority,
                confidence: frontier.confidence,
                reason: reason.to_string(),
                local,
                upstream,
                evidence_path: relation_path(
                    &relation_by_pair,
                    &frontier.source_left.id,
                    &frontier.source_right.id,
                ),
                identities,
            },
        );
        if let Some(edge) = &frontier.right_edge {
            upstream_work_by_node.insert(edge.target.id.clone(), id);
        }
    }

    let units_by_file =
        right
            .units
            .iter()
            .fold(HashMap::<&str, Vec<&Unit>>::new(), |mut by_file, unit| {
                by_file.entry(unit.file.as_str()).or_default().push(unit);
                by_file
            });
    let frontier_by_right = frontiers
        .iter()
        .filter_map(|frontier| Some((frontier.right_edge.as_ref()?.target.id.as_str(), frontier)))
        .collect::<HashMap<_, _>>();
    let right_nodes = right
        .graph_nodes
        .iter()
        .filter(|node| matches!(node.kind.as_str(), "Statement" | "Function" | "Class"))
        .collect::<Vec<_>>();
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

    let mut node_status = HashMap::<String, (&'static str, &'static str, Option<String>)>::new();
    for node in &right_nodes {
        let status = if let Some(frontier) = frontier_by_right.get(node.id.as_str()) {
            (
                if frontier.classification == "missing-local-branch" {
                    "missing-local"
                } else {
                    "changed-branch"
                },
                frontier.confidence,
                upstream_work_by_node.get(&node.id).cloned(),
            )
        } else if identical_files.contains(node.file.as_str()) {
            ("structurally-equal", "proven-structure", None)
        } else if let Some(unit) = containing_unit(node, &units_by_file) {
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

    let mut dependency_evidence_by_node = HashMap::<String, Value>::new();
    if let Some(dependencies) = dependencies {
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

        for node in &right_nodes {
            if node_status.get(&node.id).map(|status| status.0) != Some("unlinked-upstream") {
                continue;
            }
            let unit_evidence = containing_unit(node, &units_by_file).and_then(|unit| {
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
            if let Some(evidence) = unit_evidence.or(graph_evidence) {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(node.id.clone(), evidence);
            }
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
                priority: "P0",
                confidence: "unknown",
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

    let mut ledger = Vec::with_capacity(right_nodes.len());
    let mut dispositions = BTreeMap::<String, usize>::new();
    let mut covered_nodes = 0;
    let mut actionable_nodes = 0;
    for node in &right_nodes {
        let (status, confidence, work_item_id) = node_status
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
        ledger.push(json!({
            "disposition": status,
            "confidence": confidence,
            "workItemId": work_item_id,
            "upstream": graph_node_ref(node),
            "containingUnitId": containing.map(|unit| unit.id.as_str()),
            "dependencyEvidence": dependency_evidence_by_node.get(&node.id),
        }));
    }
    let mut routes = work_items
        .iter()
        .map(|item| {
            semantic_owner(
                item,
                &units_by_id,
                &units_by_file,
                &node_by_id,
                &parent_by_child,
            )
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
    ledger.sort_by(|left, right| {
        left["upstream"]["id"]
            .as_str()
            .cmp(&right["upstream"]["id"].as_str())
    });
    write_json_lines(&output.join("llm-work-items.jsonl"), &work_items)?;
    write_json_lines(&output.join("llm-batches.jsonl"), &batches)?;
    write_json_lines(&output.join("upstream-executable-ledger.jsonl"), &ledger)?;
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
        let (status, confidence, work_item_id) = if let Some(status) = node_status.get(&edge.source)
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
                let (status, confidence, work_item_id) = if let Some(status) = node_status.get(&edge.source) {
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

    let mut actions = BTreeMap::<String, usize>::new();
    for item in &work_items {
        if let Some(action) = item["action"].as_str() {
            *actions.entry(action.to_string()).or_default() += 1;
        }
    }
    let summary = LlmSummary {
        upstream_executable_nodes: right_nodes.len(),
        upstream_semantic_nodes,
        covered_nodes,
        // When the heavy dependency AST is intentionally kept out of the
        // primary matching lifetime, retain a conservative non-zero coverage
        // signal from the dependency file inventory rather than claiming the
        // evidence corpus disappeared.
        dependency_covered_nodes: if dependency_evidence_by_node.is_empty() {
            dependencies.map_or(0, |index| index.files.len())
        } else {
            dependency_evidence_by_node.len()
        },
        dependency_files: dependencies.map_or(0, |index| index.files.len()),
        dependency_parse_failures: dependencies.map_or(0, |index| index.failures.len()),
        actionable_nodes,
        work_items: work_items.len(),
        batches: batches.len(),
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
        "summary": summary,
        "artifacts": {
            "report": "report.json",
            "visualReport": "report.html",
            "workItems": "llm-work-items.jsonl",
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
            "semanticGraphIndex": "semantic-graph.index.json",
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
        "semanticGraphContract": "semantic-graph.jsonl.zst is lossless: it contains every parsed node and typed edge from both input trees, plus input project hashes. semantic-graph.index.json maps node ids to independent zstd chunks for bounded graph-node lookup. upstream-semantic-ledger.jsonl.zst and upstream-semantic-edge-ledger.jsonl.zst are also concatenated-frame artifacts with adjacent indexes, so inspection can decode only the relevant ledger frame. Use project-parity graph-node REPORT_DIRECTORY NODE_ID [LIMIT] [OFFSET] to page a node's incoming and outgoing edges.",
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

Edit only local sources. Treat the upstream input as read-only. After each coherent patch, run focused tests and the relevant runtime or rendered-output validation, regenerate the matcher report, and confirm that the work item disappears or moves to a justified covered disposition. A source/AST match alone does not close behavioral, native, asset, or pixel parity.
"#,
    )?;
    Ok(summary)
}
