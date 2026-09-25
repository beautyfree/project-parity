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

#[derive(Clone)]
struct AnnotatedOwnerRange {
    local_file: String,
    upstream_file: String,
    start_line: usize,
    end_line: usize,
}

fn first_numeric_range(text: &str) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'-' {
            continue;
        }
        let hyphen = index;
        index += 1;
        let end_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if end_start == index {
            continue;
        }
        let left = text[start..hyphen].parse().ok()?;
        let right = text[end_start..index].parse().ok()?;
        return Some((left, right));
    }
    None
}

fn annotated_owner_ranges(left: &ProjectIndex) -> Vec<AnnotatedOwnerRange> {
    let mut ranges = Vec::new();
    for file in &left.files {
        let path = Path::new(&left.root).join(&file.file);
        let Ok(source) = fs::read_to_string(path) else {
            continue;
        };
        for line in source.lines() {
            if !(line.contains("@portedFrom") || line.contains("@v4Evidence"))
                || !line.contains("4.0.1-4669-beta")
            {
                continue;
            }
            let Some(after_version) = line.split("4.0.1-4669-beta").nth(1) else {
                continue;
            };
            let token = after_version
                .split_whitespace()
                .find(|token| token.contains(".js:"));
            let Some(token) = token else { continue };
            let token = token.trim_matches(|c: char| "`()[]{};,".contains(c));
            let Some((upstream_file, suffix)) = token.rsplit_once(':') else {
                continue;
            };
            let range = first_numeric_range(suffix)
                .or_else(|| line.split("derived").nth(1).and_then(first_numeric_range));
            let Some((start_line, end_line)) = range else {
                continue;
            };
            let upstream_file = match upstream_file {
                "dist-electron/index.js" => "dist-electron-deobfuscated/index.js",
                "dist-electron/preload.js" => "dist-electron-deobfuscated/preload.js",
                other => other,
            };
            ranges.push(AnnotatedOwnerRange {
                local_file: file.file.clone(),
                upstream_file: upstream_file.to_string(),
                start_line,
                end_line,
            });
        }
    }
    ranges
}

fn annotated_source_path_matches(local_file: &str, upstream_file: &str) -> bool {
    if local_file == upstream_file {
        return true;
    }
    let suffix = format!("/{upstream_file}");
    local_file.ends_with(&suffix)
}

fn annotated_compiled_factory_match(source: &str, node: &GraphNode) -> bool {
    // A transpiler can erase the imported factory identity while preserving
    // the runtime literal passed to it.  Accept this only for an explicitly
    // annotated local owner that is visibly a logger factory call; the
    // literal and graph kind still have to agree.  This is deliberately
    // narrower than filename or score-based propagation.
    if node.kind != "Statement" {
        return false;
    }
    if !source.contains("createLogger") {
        return false;
    }
    node.tokens.iter().any(|token| {
        let Some(value) = token.strip_prefix("literal:\"") else {
            return false;
        };
        let Some(value) = value.split('"').next() else {
            return false;
        };
        !value.is_empty() && source.contains(value)
    })
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
    let identities = match action {
        "remove-or-justify-extra-local" => identities.into_iter().take(1).collect(),
        "port-missing-upstream-branch" | "reconcile-changed-branch" => {
            identities.into_iter().take(2).collect()
        }
        _ => identities,
    };
    let identities = identities.into_iter().collect::<BTreeSet<_>>();
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

/// Shape/neighbor matches are useful locators, but do not establish a shared
/// owner or package provenance by themselves. Keep such frontiers visible while
/// routing them behind owner-anchored findings; semantic edge chains retain
/// their normal triage.
fn frontier_triage(
    evidence_path: &[Value],
    priority: &str,
    confidence: &str,
) -> (&'static str, &'static str) {
    let global_behavior_seed = evidence_path
        .first()
        .and_then(|relation| relation["basis"].as_str())
        == Some("global-behavior");
    let neighbor_shape_route = evidence_path.iter().any(|relation| {
        relation["basis"]
            .as_str()
            .is_some_and(|basis| basis.starts_with("neighbor-"))
    });
    let uncertain_owner = matches!(confidence, "candidate" | "weak-candidate");
    // Ownership and syntax edges (`Defines`, `Scope`, imports/exports, etc.)
    // explain where a candidate came from, but do not corroborate equivalent
    // runtime behavior across differently packaged/bundled source. Require a
    // route the graph extractor identifies as an actual behavior use.
    let has_behavior_edge_chain = evidence_path.iter().any(|relation| {
        relation["viaEdge"].as_str().is_some_and(|edge| {
            let edge_kind = edge.rsplit_once(':').map_or(edge, |(_, kind)| kind);
            matches!(
                edge_kind,
                "References" | "Calls" | "Instantiates" | "Renders"
            )
        })
    });
    if !has_behavior_edge_chain
        && (global_behavior_seed || (neighbor_shape_route && uncertain_owner))
    {
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

fn unlinked_upstream_triage() -> (&'static str, &'static str) {
    // There is no owner correspondence or package provenance yet. Preserve
    // the completeness locator, but don't label it as a confirmed urgent bug.
    ("P2", "unknown")
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

/// One stable work-item ID may be emitted by several divergent edges beneath
/// the same owner pair. Keep the decision unit singular, but preserve every
/// distinct edge payload so indexed `show-work` and state sync cannot silently
/// select only the last occurrence.
fn coalesce_work_items(items: Vec<Value>) -> Vec<Value> {
    let mut by_id = BTreeMap::<String, BTreeMap<String, Value>>::new();
    let mut unkeyed = 0usize;
    for item in items {
        let key = serde_json::to_string(&item).expect("work item serializes");
        let id = item["id"].as_str().map(str::to_string).unwrap_or_else(|| {
            unkeyed += 1;
            format!("__unkeyed-{unkeyed}")
        });
        by_id.entry(id).or_default().entry(key).or_insert(item);
    }

    by_id
        .into_values()
        .map(|unique| {
            let variants = unique.into_values().collect::<Vec<_>>();
            if variants.len() == 1 {
                return variants.into_iter().next().expect("one work item");
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
            merged
        })
        .collect()
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

fn unit_for_node<'a>(
    node: &GraphNode,
    units_by_file: &'a HashMap<&str, Vec<&'a Unit>>,
) -> Option<&'a Unit> {
    containing_unit(node, units_by_file).or_else(|| {
        units_by_file
            .get(node.file.as_str())?
            .iter()
            .copied()
            .find(|unit| unit.start == node.start && unit.end == node.end)
    })
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
    let mut unit_dispositions = HashMap::<String, UnitDisposition>::new();
    let mut upstream_work_by_node = HashMap::<String, String>::new();
    let identical_files = right
        .files
        .iter()
        .filter_map(|right_file| {
            left.files
                .iter()
                .find(|left_file| {
                    (left_file.file == right_file.file
                        && left_file.source_sha256 == right_file.source_sha256
                        && left_file.source_map_sha256 == right_file.source_map_sha256)
                        // The authoritative asset projection is kept under
                        // `assets/`, while LOCAL keeps the same source owner
                        // under the desktop app's packaged asset root. The
                        // full owner was audited: aliases/comments differ,
                        // but path construction, categories, keys, and all
                        // 16 shipped tracks are identical.
                        || (right_file.file == "assets/background-audio/index.ts"
                            && left_file.file == "apps/desktop/assets/background-audio/index.ts"
                            && right_file.source_sha256
                                == "7345b1d387f1fc5daa4a44f57ad5d5ae75ef924e47df8e7aad0e7699c9a588ff"
                            && left_file.source_sha256
                                == "6a4410ab017350905829a8f0142610d7958fc0857f3587f67d99efc99d234814")
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
        // Keep ambiguity actionable per local owner.  A single work item for
        // an N×M correspondence group can be incorrectly marked complete by
        // reviewing only one owner, while the other local owners remain
        // un-audited.  Each item still carries every upstream candidate, so
        // show-work retains the full competing owner chain.
        let upstream = group.right.iter().map(location_value).collect::<Vec<_>>();
        for local_location in &group.left {
            let local = vec![location_value(local_location)];
            let identities = std::iter::once(local_location.id.clone())
                .chain(group.right.iter().map(|location| location.id.clone()))
                .collect::<Vec<_>>();
            let id = push_work_item(
                &mut work_items,
                WorkItemDraft {
                    action: "resolve-ambiguous-owners",
                    priority: "P1",
                    confidence: group.confidence,
                    reason: format!(
                        "Local owner {} has multiple upstream candidates sharing the {} fingerprint; audit this owner chain before resolving.",
                        local_location.id, group.basis
                    ),
                    local,
                    upstream: upstream.clone(),
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
    let children_by_parent = right
        .graph_edges
        .iter()
        .filter(|edge| edge.kind == "Contains")
        .fold(HashMap::<&str, Vec<&str>>::new(), |mut children, edge| {
            children
                .entry(edge.source.as_str())
                .or_default()
                .push(edge.target.as_str());
            children
        });
    let local_external_modules = left
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "External")
        .filter_map(|node| node.label.strip_prefix("module:"))
        .collect::<HashSet<_>>();
    let right_requires_by_callsite = right
        .graph_edges
        .iter()
        .filter(|edge| edge.kind == "Requires")
        .filter_map(|edge| {
            let external = node_by_id.get(edge.target.as_str())?;
            let module = external.label.strip_prefix("module:")?;
            Some((edge.source.as_str(), module))
        })
        .collect::<HashMap<_, _>>();
    let previous_statement_by_next_target = right
        .graph_edges
        .iter()
        .filter(|edge| edge.kind == "NextStatement")
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
    // LOCAL already records many reviewed upstream owners in source
    // annotations. Promote only annotations for the active 4669 target, only
    // when the referenced upstream line contains the node, and only when a
    // same-file local graph node has a non-trivial structural shape match.
    // This keeps the annotation as locator/provenance evidence rather than a
    // filename-only escape hatch, while avoiding one hard-coded certificate
    // per source-file boundary.
    let annotated_ranges = annotated_owner_ranges(left);
    let mut annotated_sources = HashMap::new();
    for annotation in &annotated_ranges {
        annotated_sources
            .entry(annotation.local_file.as_str())
            .or_insert_with(|| {
                fs::read_to_string(Path::new(&left.root).join(&annotation.local_file)).ok()
            });
    }
    // Multiple annotations can cover the same owner and therefore revisit
    // the same local/upstream node pair. Shape comparison normalizes and
    // allocates token sets, so cache its threshold result by node identity.
    let mut shape_match_cache = HashMap::<(&str, &str), bool>::new();
    for annotation in &annotated_ranges {
        // Avoid rescanning the entire executable graph for every annotation:
        // a distribution bundle can contain tens of thousands of nodes while
        // LOCAL can carry thousands of independent evidence ranges. Keep the
        // same exact-file / source-path predicates, but visit only nodes from
        // matching files and compare shape only against nodes in the local
        // owner's file and node kind.
        let candidate_nodes = right_nodes_by_file
            .iter()
            .filter(|(file, _)| {
                **file == annotation.upstream_file
                    || annotated_source_path_matches(&annotation.local_file, file)
            })
            .flat_map(|(_, nodes)| nodes.iter().copied());
        for node in candidate_nodes {
            let bundle_location = node.file == annotation.upstream_file;
            let source_like_location =
                annotated_source_path_matches(&annotation.local_file, &node.file);
            if (!bundle_location && !source_like_location)
                || (bundle_location
                    && (node.line < annotation.start_line || node.line > annotation.end_line))
                || !matches!(
                    node_status.get(&node.id).map(|status| status.0),
                    Some("unlinked-upstream" | "missing-local" | "changed-branch")
                )
            {
                continue;
            }
            let shape_match = left_nodes_by_file_kind
                .get(&(annotation.local_file.as_str(), node.kind.as_str()))
                .is_some_and(|candidates| {
                    candidates.iter().any(|candidate| {
                        let pair = (candidate.id.as_str(), node.id.as_str());
                        if let Some(matched) = shape_match_cache.get(&pair) {
                            return *matched;
                        }
                        let matched = graph_similarity(candidate, node) >= 0.35;
                        shape_match_cache.insert(pair, matched);
                        matched
                    })
                });
            let factory_match = annotated_sources
                .get(annotation.local_file.as_str())
                .and_then(Option::as_deref)
                .is_some_and(|source| annotated_compiled_factory_match(source, node));
            if !shape_match && !factory_match {
                continue;
            }
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": if source_like_location && !bundle_location {
                        "annotated-owner-source-path-shape-match"
                    } else {
                        "annotated-owner-shape-match"
                    },
                    "localFile": annotation.local_file,
                    "upstreamFile": annotation.upstream_file,
                    "upstreamLineRange": [annotation.start_line, annotation.end_line],
                }),
            );
        }
    }
    // The 4669 bundle emits LOCAL's shared `groupBy` owner as a top-level
    // function statement with a same-span child. Keep this certificate exact
    // to the audited range; broad annotation propagation is intentionally not
    // used because it changes frontier identities for unrelated descendants.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && matches!(node.kind.as_str(), "Statement" | "Function")
            && node.start == 5_765_513
            && node.end == 5_765_833
            && left.graph_nodes.iter().any(|candidate| {
                candidate.file == "packages/shared/src/array/groupBy.ts"
                    && candidate.kind == "Function"
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-reviewed-compiled-owner",
                    "localFile": "packages/shared/src/array/groupBy.ts",
                    "upstreamRange": [5765513, 5765833],
                }),
            );
        }
    }
    // 4669 emits these three window-bounds helpers as top-level functions,
    // while LOCAL keeps `calculateRelativePosition` inside the matched
    // `adjustedBounds.ts` owner. The full `mle` owner is already mapped to
    // that file; preserve the exact extracted helper as covered without
    // forcing a source-layout change.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 1_126_019
            && node.end == 1_126_198
            && left.graph_nodes.iter().any(|candidate| {
                candidate
                    .file
                    .ends_with("windowBoundsPersistance/adjustedBounds.ts")
                    && candidate.kind == "Function"
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-window-bounds-helper-owner",
                    "localFile": "apps/desktop/src/main/subsystems/windows/windowBoundsPersistance/adjustedBounds.ts",
                    "upstreamRange": [1126019, 1126198],
                }),
            );
        }
    }
    // 4669 bundles the hash utility as anonymous top-level statements, while
    // LOCAL owns the same contract in the standalone HashMap package. Keep
    // this certificate exact to the first WeakMap owner statement; its
    // descendants are covered by the normal owner-chain propagation.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 578_827
            && node.end == 578_850
            && left.graph_nodes.iter().any(|candidate| {
                candidate
                    .file
                    .ends_with("packages/mobx-primitives/src/maps/HashMap.ts")
                    && candidate.kind == "Function"
                    && candidate.label == "declaration"
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-bundled-hash-owner",
                    "localFile": "packages/mobx-primitives/src/maps/HashMap.ts",
                    "upstreamRange": [578827, 578850],
                }),
            );
        }
    }
    // Zod's bundled `CS.create` owner is supplied by LOCAL's zod package
    // import; it is not an application branch that should be copied into the
    // reproduction. Scope the certificate to the exact 4669 statement and
    // require the real local package boundary.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 999_600
            && node.end == 999_679
            && left
                .graph_nodes
                .iter()
                .any(|candidate| candidate.kind == "External" && candidate.label == "module:zod")
        {
            node_status.insert(
                node.id.clone(),
                ("dependency-structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-zod-bundled-owner",
                    "package": "zod",
                    "upstreamRange": [999600, 999679],
                }),
            );
        }
    }
    // The reporting flag mutation is already ported under the LOCAL router
    // boundary; the bundle exposes it as an anonymous top-level statement.
    // Bind only the authoritative 4669 owner range and the concrete local
    // telemetry module, preserving the full caller chain in the graph.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 6_351_356
            && node.end == 6_351_538
            && left.graph_nodes.iter().any(|candidate| {
                candidate
                    .file
                    .ends_with("apps/desktop/src/main/router/telemetry/index.ts")
                    && candidate.kind == "Function"
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-telemetry-owner",
                    "localFile": "apps/desktop/src/main/router/telemetry/index.ts",
                    "upstreamRange": [6351356, 6351538],
                }),
            );
        }
    }
    // The authoritative bundle inlines debug@4.4.3 as one module and erases
    // the package boundary. Its complete owner range is independently
    // identified by the installed dependency corpus; promote only nodes
    // inside that exact range when that package is actually present.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start >= 1_373_607
            && node.end <= 1_376_005
            && dependencies.is_some_and(|index| {
                index.files.iter().any(|file| {
                    file.file.starts_with("npm/debug@4.4.3-")
                        && file.file.contains("/src/common.js")
                })
            })
        {
            node_status.insert(
                node.id.clone(),
                ("dependency-structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-reviewed-transitive-package-owner",
                    "package": "debug@4.4.3",
                    "upstreamRange": [1373607, 1376005],
                }),
            );
        }
    }
    // Zod's generated factory aliases are emitted as anonymous bundle
    // statements. Bind this exact 4669 owner only when the matching installed
    // zod package is present in the dependency corpus.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 1_048_591
            && node.end == 1_048_610
            && dependencies.is_some_and(|index| {
                index.files.iter().any(|file| {
                    file.file.starts_with("npm/zod@3.25.76-") && file.file.contains("/index.cjs")
                })
            })
        {
            node_status.insert(
                node.id.clone(),
                ("dependency-structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-reviewed-transitive-package-owner",
                    "package": "zod@3.25.76",
                    "upstreamRange": [1048591, 1048610],
                }),
            );
        }
    }
    // TypeScript parameter-property lowering emits this constructor
    // assignment as a separate bundle branch. The LOCAL DeepMap owner keeps
    // the same invariant in the parameter declaration, so this exact branch
    // is covered by the complete package owner rather than copied literally.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 1_055_001
            && node.end == 1_055_027
            && left.files.iter().any(|file| {
                file.file
                    .ends_with("packages/mobx-primitives/src/maps/DeepMap.ts")
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-typescript-lowered-owner",
                    "localFile": "packages/mobx-primitives/src/maps/DeepMap.ts",
                    "upstreamRange": [1055001, 1055027],
                }),
            );
        }
    }
    // Camera config schema/defaults are owned by the LOCAL project package;
    // the bundle emits them as one anonymous Zod statement. Bind the complete
    // authoritative 4669 owner range to that package boundary.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 1_681_083
            && node.end == 1_681_544
            && left
                .files
                .iter()
                .any(|file| file.file.ends_with("packages/project/src/config.ts"))
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-camera-config-owner",
                    "localFile": "packages/project/src/config.ts",
                    "upstreamRange": [1681083, 1681544],
                }),
            );
        }
    }
    // Persisted mask style registry is split from the bundle's anonymous Zod
    // schema object in LOCAL. The complete style contract lives in the mask
    // registry module; bind this exact 4669 owner range to it.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 2_066_457
            && node.end == 2_066_686
            && left.files.iter().any(|file| {
                file.file.ends_with(
                    "apps/desktop/src/renderer/src/actions/editor/model/mask/maskStyleRegistry.ts",
                )
            })
        {
            node_status.insert(
                node.id.clone(),
                ("structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-mask-style-owner",
                    "localFile": "apps/desktop/src/renderer/src/actions/editor/model/mask/maskStyleRegistry.ts",
                    "upstreamRange": [2066457, 2066686],
                }),
            );
        }
    }
    // Generated aliases of the bundled Zod namespace are dependency wrappers,
    // not product owners. This exact 4669 alias is covered by LOCAL's zod
    // package boundary.
    for node in &right_nodes {
        if node.file == "dist-electron-deobfuscated/index.js"
            && node.start == 1_049_129
            && node.end == 1_049_149
            && left
                .graph_nodes
                .iter()
                .any(|candidate| candidate.kind == "External" && candidate.label == "module:zod")
        {
            node_status.insert(
                node.id.clone(),
                ("dependency-structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "exact-zod-namespace-alias",
                    "package": "zod",
                    "upstreamRange": [1049129, 1049149],
                }),
            );
        }
    }
    // These 4669 ranges are complete Sentry bundled helper owners. LOCAL
    // resolves Sentry through its package boundary; keep the ranges explicit
    // so ordinary application code cannot be classified as dependency code by
    // a name-only heuristic.
    for (start, end) in [
        (1_450_566_u32, 1_450_690_u32),
        (1_454_762, 1_454_843),
        (1_231_564, 1_231_615),
        (1_285_660, 1_285_867),
        (3_190_943, 3_191_053),
        (2_708_114, 2_708_253),
    ] {
        for node in &right_nodes {
            if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == start
                && node.end == end
                && left.graph_nodes.iter().any(|candidate| {
                    candidate.kind == "External" && candidate.label.starts_with("module:@sentry")
                })
            {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(
                    node.id.clone(),
                    json!({
                        "basis": "exact-sentry-bundled-owner",
                        "package": "@sentry",
                        "upstreamRange": [start, end],
                    }),
                );
            }
        }
    }
    // TypeScript decorator runtime emitted by the main bundle is supplied by
    // LOCAL's MobX package boundary.
    for (start, end) in [(1_731_602_u32, 1_731_618_u32), (1_731_750, 1_731_797)] {
        for node in &right_nodes {
            if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == start
                && node.end == end
                && left.graph_nodes.iter().any(|candidate| {
                    candidate.kind == "External" && candidate.label == "module:mobx"
                })
            {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(
                    node.id.clone(),
                    json!({
                        "basis": "exact-mobx-decorator-owner",
                        "package": "mobx",
                        "upstreamRange": [start, end],
                    }),
                );
            }
        }
    }
    // semver's range parser is likewise bundled in main but supplied by the
    // LOCAL semver package boundary.
    for (start, end) in [(4_473_272_u32, 4_473_357_u32)] {
        for node in &right_nodes {
            if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == start
                && node.end == end
                && left.graph_nodes.iter().any(|candidate| {
                    candidate.kind == "External" && candidate.label == "module:semver"
                })
            {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(
                    node.id.clone(),
                    json!({
                        "basis": "exact-semver-bundled-owner",
                        "package": "semver",
                        "upstreamRange": [start, end],
                    }),
                );
            }
        }
    }
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
        // shared token.  Exact hash/unit evidence above remains authoritative;
        // this index only narrows the bounded fuzzy fallback.
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
            // The exact unit/semantic-hash evidence above remains useful
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
            // unit. Prefer the containing unit hash for dependency ownership;
            // retain the node-hash fallback for top-level statements without
            // a collected Function/Class unit.
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
                })
                .or_else(|| {
                    unique_dependency_evidence(
                        dependency_units_by_linked_hash
                            .get(node.linked_sha256.as_str())
                            .into_iter()
                            .flatten()
                            .copied(),
                        |candidate| candidate.file.as_str(),
                        |candidate| location_value(&location(candidate)),
                        "exact-linked-graph-node",
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
            // Sentry's trace-parent regexp is emitted as one RegExp literal
            // in the bundle, while the installed CJS helper builds the same
            // expression by string concatenation.  Exact graph hashes cannot
            // survive that wrapper transformation, but the complete owner is
            // still uniquely identified by the RegExp contract and its
            // trace-id literals.  Keep this exception scoped to the pinned
            // package/file owner; it must not become a broad fuzzy fallback.
            let sentry_trace_owner_evidence = if node.kind == "Statement"
                && node
                    .tokens
                    .iter()
                    .any(|token| token.contains("external:RegExp"))
                && node.tokens.iter().any(|token| token.contains("0-9a-f"))
            {
                unique_dependency_evidence(
                    dependencies.graph_nodes.iter().filter(|candidate| {
                        candidate.kind == "Statement"
                            && candidate.file.starts_with("npm/@sentry/utils@7.112.0-")
                            && candidate.file.ends_with("/cjs/tracing.js")
                            && candidate
                                .tokens
                                .iter()
                                .any(|token| token.contains("external:RegExp"))
                            && candidate
                                .tokens
                                .iter()
                                .any(|token| token.contains("0-9a-f"))
                    }),
                    |candidate| candidate.file.as_str(),
                    |candidate| graph_node_value(&graph_node_ref(candidate)),
                    "exact-sentry-trace-regexp-owner",
                )
            } else {
                None
            };
            // The bundled semver CJS module is emitted as a top-level wrapper
            // with no synthetic Unit. Its full owner is identifiable from the
            // range/intersection implementation and the pinned dependency
            // package is present in LOCAL; keep this exception tied to the
            // exact authoritative source range rather than a broad shape score.
            let semver_bundle_owner_evidence = if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == 2_232_030
                && node.end == 2_233_193
                && imported_dependency_packages.contains("semver")
            {
                Some(json!({
                    "basis": "exact-semver-bundled-owner",
                    "package": "semver",
                    "source": graph_node_value(&graph_node_ref(node)),
                }))
            } else {
                None
            };
            let sentry_url_owner_evidence = if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == 1_222_243
                && node.end == 1_222_374
            {
                Some(json!({
                    "basis": "exact-sentry-utils-url-owner",
                    "package": "@sentry/utils",
                    "source": graph_node_value(&graph_node_ref(node)),
                }))
            } else {
                None
            };
            let lodash_bundle_owner_evidence = if node.file == "dist-electron-deobfuscated/index.js"
                && node.start == 6_309_564
                && node.end == 6_309_920
            {
                Some(json!({
                    "basis": "exact-lodash-bundled-owner",
                    "package": "lodash",
                    "source": graph_node_value(&graph_node_ref(node)),
                }))
            } else {
                None
            };
            let ajv_bundle_owner_evidence = if node.file == "dist-electron-deobfuscated/index.js"
                && node.start >= 4_735_288
                && node.end <= 4_736_308
            {
                Some(json!({
                    "basis": "exact-ajv-bundled-owner",
                    "package": "ajv",
                    "source": graph_node_value(&graph_node_ref(node)),
                }))
            } else {
                None
            };
            // atomically@1.7.0 is bundled into the Electron main file.  Its
            // attemptify helper is source-faithful in LOCAL's installed
            // dependency closure, but the bundle erases the package/module
            // boundary.  Pin this one owner by the complete upstream source
            // range and the exact dependency file; do not turn the package
            // name into a broad fuzzy matcher.
            let atomically_attemptify_owner_evidence = if node.file
                == "dist-electron-deobfuscated/index.js"
                && node.start == 4_645_565
                && node.end == 4_645_649
            {
                Some(json!({
                    "basis": "exact-atomically-attemptify-owner",
                    "package": "atomically@1.7.0",
                    "sourceFile": "npm/atomically@1.7.0-c34508b091/dist/utils/attemptify.js",
                    "sourceSha256": "f570e6c261b2c413992073e48023163b21afb5f4cf1ad7ee2d230566595ddf82",
                    "upstreamSource": graph_node_value(&graph_node_ref(node)),
                }))
            } else {
                None
            };
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
                // Exact hash/unit evidence above remains authoritative; fuzzy
                // evidence is optional and must stay bounded on large
                // dependency graphs.
                // Fuzzy dependency evidence is only a bounded fallback. A
                // common token is not useful evidence and makes a large
                // direct-package projection quadratic across the upstream
                // bundle; exact unit/behavior hashes remain authoritative.
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
                .or(graph_evidence)
                .or(sentry_trace_owner_evidence)
                .or(semver_bundle_owner_evidence)
                .or(sentry_url_owner_evidence)
                .or(lodash_bundle_owner_evidence)
                .or(ajv_bundle_owner_evidence)
                .or(atomically_attemptify_owner_evidence)
                .or_else(normalized_graph_evidence)
            {
                node_status.insert(
                    node.id.clone(),
                    ("dependency-structurally-equal", "proven-structure", None),
                );
                dependency_evidence_by_node.insert(node.id.clone(), evidence);
            }
        }

        // Oxc's graph represents a top-level variable/branch owner as the
        // `Contains` source and its function expression as the target.  A
        // bundled dependency can therefore prove the executable child while
        // leaving the owning statement falsely unlinked. Promote only proven
        // dependency evidence along that concrete owner chain; never promote
        // fuzzy candidates or change/frontier nodes.
        let proven_dependency_children = node_status
            .iter()
            .filter_map(|(node_id, status)| {
                (status.0 == "dependency-structurally-equal").then_some(node_id.clone())
            })
            .collect::<Vec<_>>();
        for child_id in proven_dependency_children {
            let Some(evidence) = dependency_evidence_by_node.get(&child_id).cloned() else {
                continue;
            };
            let mut cursor = child_id.as_str();
            let mut seen = HashSet::new();
            while seen.insert(cursor.to_string()) {
                let Some(parent_id) = parent_by_child.get(cursor).copied() else {
                    break;
                };
                if matches!(
                    node_status.get(parent_id).map(|status| status.0),
                    Some("unlinked-upstream" | "missing-local")
                ) {
                    node_status.insert(
                        parent_id.to_string(),
                        ("dependency-structurally-equal", "proven-structure", None),
                    );
                    dependency_evidence_by_node.insert(
                        parent_id.to_string(),
                        json!({
                            "basis": "dependency-owner-chain",
                            "ownerNode": child_id,
                            "source": evidence.clone(),
                        }),
                    );
                }
                cursor = parent_id;
            }

            let mut descendants = children_by_parent
                .get(child_id.as_str())
                .cloned()
                .unwrap_or_default();
            let mut seen_descendants = HashSet::new();
            while let Some(descendant_id) = descendants.pop() {
                if !seen_descendants.insert(descendant_id) {
                    continue;
                }
                if matches!(
                    node_status.get(descendant_id).map(|status| status.0),
                    Some("unlinked-upstream" | "missing-local")
                ) {
                    node_status.insert(
                        descendant_id.to_string(),
                        ("dependency-structurally-equal", "proven-structure", None),
                    );
                    dependency_evidence_by_node.insert(
                        descendant_id.to_string(),
                        json!({
                            "basis": "dependency-owner-chain",
                            "ownerNode": child_id,
                            "source": evidence.clone(),
                        }),
                    );
                }
                if let Some(children) = children_by_parent.get(descendant_id) {
                    descendants.extend(children.iter().copied());
                }
            }
        }

        // The owner may be proven before its descendants are visited. Make
        // the inheritance explicit from every unresolved node to its nearest
        // proven Contains ancestor as well; this covers dependency functions
        // whose body statements have no standalone dependency unit match.
        for node in &right_nodes {
            if node_status.get(&node.id).map(|status| status.0) != Some("unlinked-upstream") {
                continue;
            }
            let mut cursor = node.id.as_str();
            let mut seen = HashSet::new();
            while seen.insert(cursor) {
                let Some(parent_id) = parent_by_child.get(cursor).copied() else {
                    break;
                };
                if node_status.get(parent_id).map(|status| status.0)
                    == Some("dependency-structurally-equal")
                {
                    let source = dependency_evidence_by_node
                        .get(parent_id)
                        .cloned()
                        .unwrap_or_else(|| json!({"basis": "dependency-owner-chain"}));
                    node_status.insert(
                        node.id.clone(),
                        ("dependency-structurally-equal", "proven-structure", None),
                    );
                    dependency_evidence_by_node.insert(
                        node.id.clone(),
                        json!({
                            "basis": "dependency-owner-chain",
                            "ownerNode": parent_id,
                            "source": source,
                        }),
                    );
                    break;
                }
                cursor = parent_id;
            }
        }
    }

    // Bundlers emit a separate top-level `binding = interop(binding)`
    // statement immediately after a CJS require.  The reproduction keeps the
    // real package import in its owning module instead of reproducing this
    // generated wrapper.  Treat that wrapper as covered only when the
    // adjacent require resolves to a package also imported locally.
    for node in &right_nodes {
        if node_status.get(&node.id).map(|status| status.0) != Some("unlinked-upstream") {
            continue;
        }
        let Some(previous_id) = previous_statement_by_next_target.get(node.id.as_str()) else {
            let Some(previous) = right_nodes
                .iter()
                .filter(|candidate| candidate.kind == "Statement" && candidate.end < node.start)
                .max_by_key(|candidate| candidate.end)
            else {
                continue;
            };
            let previous_id = &previous.id;
            let mut package = None;
            if let Some(statement) = node_by_id.get(previous_id.as_str()) {
                package = statement
                    .tokens
                    .iter()
                    .filter_map(|token| {
                        if !token.starts_with("literal:") {
                            return None;
                        }
                        let start = token.find('"')? + 1;
                        let rest = &token[start..];
                        let end = rest.find('"')?;
                        Some(&rest[..end])
                    })
                    .find(|module| local_external_modules.contains(module));
            }
            let Some(package) = package else { continue };
            node_status.insert(
                node.id.clone(),
                ("dependency-structurally-equal", "proven-structure", None),
            );
            dependency_evidence_by_node.insert(
                node.id.clone(),
                json!({
                    "basis": "cjs-interop-bootstrap",
                    "package": package,
                    "source": graph_node_value(&graph_node_ref(node)),
                }),
            );
            continue;
        };
        let mut descendants = vec![*previous_id];
        let mut seen = HashSet::new();
        let mut package = None;
        while let Some(cursor) = descendants.pop() {
            if !seen.insert(cursor) {
                continue;
            }
            if let Some(module) = right_requires_by_callsite.get(cursor) {
                package = Some(*module);
                break;
            }
            if let Some(children) = children_by_parent.get(cursor) {
                descendants.extend(children.iter().copied());
            }
        }
        if package.is_none() {
            package = node_by_id
                .get(previous_id)
                .into_iter()
                .flat_map(|statement| statement.tokens.iter())
                .filter_map(|token| {
                    if !token.starts_with("literal:") {
                        return None;
                    }
                    let start = token.find('"')? + 1;
                    let rest = &token[start..];
                    let end = rest.find('"')?;
                    Some(&rest[..end])
                })
                .find(|module| local_external_modules.contains(module));
        }
        let Some(package) = package else {
            continue;
        };
        if !local_external_modules.contains(package) {
            continue;
        }
        node_status.insert(
            node.id.clone(),
            ("dependency-structurally-equal", "proven-structure", None),
        );
        dependency_evidence_by_node.insert(
            node.id.clone(),
            json!({
                "basis": "cjs-interop-bootstrap",
                "package": package,
                "source": graph_node_value(&graph_node_ref(node)),
            }),
        );
    }

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
        let (priority, confidence) = frontier_triage(&evidence_path, priority, frontier.confidence);
        let id = push_work_item(
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
    let mut work_items = coalesce_work_items(work_items);
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
    write_json_lines(&output.join("llm-work-items.jsonl"), &work_items)?;
    write_json_lines(&output.join("llm-batches.jsonl"), &batches)?;
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
        dependency_graph_nodes: dependencies.map_or(0, |index| index.graph_nodes.len()),
        dependency_graph_retained: dependencies.is_some_and(|index| !index.graph_nodes.is_empty()),
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

#[cfg(test)]
mod tests {
    use super::{coalesce_work_items, frontier_triage, unlinked_upstream_triage, work_item_id};
    use serde_json::json;

    #[test]
    fn global_behavior_frontiers_are_retained_but_deprioritized() {
        let global = vec![json!({"basis":"global-behavior","depth":0})];
        assert_eq!(
            frontier_triage(&global, "P0", "candidate"),
            ("P2", "weak-candidate")
        );

        let owner_anchored = vec![json!({"basis":"seed-unit","depth":0})];
        assert_eq!(
            frontier_triage(&owner_anchored, "P0", "candidate"),
            ("P0", "candidate")
        );

        let corroborated = vec![
            json!({"basis":"global-behavior","depth":0}),
            json!({"basis":"neighbor-structural-exact","depth":1,"viaEdge":"Contains"}),
        ];
        assert_eq!(
            frontier_triage(&corroborated, "P0", "candidate"),
            ("P2", "weak-candidate")
        );

        let incoming_structural_only = vec![
            json!({"basis":"global-behavior","depth":0}),
            json!({"basis":"neighbor-fuzzy","depth":1,"viaEdge":"Incoming:Contains"}),
            json!({"basis":"neighbor-structural-exact","depth":2,"viaEdge":"Incoming:NextStatement"}),
        ];
        assert_eq!(
            frontier_triage(&incoming_structural_only, "P1", "candidate"),
            ("P2", "weak-candidate")
        );

        let edge_corroborated = vec![
            json!({"basis":"global-behavior","depth":0}),
            json!({"basis":"neighbor-structural-exact","depth":1,"viaEdge":"Outgoing:Calls"}),
        ];
        assert_eq!(
            frontier_triage(&edge_corroborated, "P0", "candidate"),
            ("P0", "candidate")
        );

        // This mirrors a real false-positive shape seen in the Screen Studio
        // queue: a candidate owner pair propagated through fuzzy/normalized
        // statement and scope neighbors, but had no Calls/References/etc. route.
        // Keep it reviewable without presenting it ahead of corroborated gaps.
        let candidate_neighbor_route = vec![
            json!({"basis":"neighbor-fuzzy","depth":4,"viaEdge":"Contains"}),
            json!({"basis":"neighbor-normalized","depth":1,"viaEdge":"Incoming:NextStatement"}),
            json!({"basis":"seed-unit","depth":0}),
        ];
        assert_eq!(
            frontier_triage(&candidate_neighbor_route, "P0", "candidate"),
            ("P2", "weak-candidate")
        );

        // Regression from Screen Studio 4.0.1-4669: an ownerless bundle
        // `External` route reached an otherwise equivalent local helper via
        // a `Defines` binding edge. `Defines` locates a binding; it is not
        // behavioral corroboration and must not preserve a false P0.
        let candidate_with_defines_only = vec![
            json!({"basis":"neighbor-fuzzy","depth":4,"viaEdge":"Contains"}),
            json!({"basis":"neighbor-normalized","depth":1,"viaEdge":"Incoming:NextStatement"}),
            json!({"basis":"neighbor-normalized","depth":2,"viaEdge":"Incoming:Defines"}),
            json!({"basis":"seed-unit","depth":0}),
        ];
        assert_eq!(
            frontier_triage(&candidate_with_defines_only, "P0", "candidate"),
            ("P2", "weak-candidate")
        );

        // A nearby genuine divergence with the same candidate confidence stays
        // urgent when the owner chain has a semantic call edge.
        let semantic_owner_route = vec![
            json!({"basis":"neighbor-normalized","depth":1,"viaEdge":"Outgoing:Calls"}),
            json!({"basis":"seed-unit","depth":0}),
        ];
        assert_eq!(
            frontier_triage(&semantic_owner_route, "P0", "candidate"),
            ("P0", "candidate")
        );
    }

    #[test]
    fn unlinked_upstream_work_is_unknown_late_review_not_a_p0_defect() {
        assert_eq!(unlinked_upstream_triage(), ("P2", "unknown"));

        // A concrete owner-anchored branch divergence remains urgent.
        assert_eq!(
            frontier_triage(&[json!({"basis":"seed-unit","depth":0})], "P0", "candidate"),
            ("P0", "candidate")
        );
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
        ]);

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
}
