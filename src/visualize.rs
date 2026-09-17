use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

const MAX_SNIPPET_BYTES: usize = 24_000;
const MAX_GRAPH_SNIPPET_BYTES: usize = 8_000;
const GRAPH_OVERLAY_ARTIFACT: &str = "graph-overlay.json";

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct FilePairSummary {
    left_file: String,
    right_file: String,
    relations: usize,
    exact: usize,
    candidates: usize,
}

#[derive(Default)]
struct UnmatchedAccumulator {
    count: usize,
    top_candidate_files: BTreeMap<String, usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UnmatchedFileSummary {
    file: String,
    count: usize,
    top_candidate_files: Vec<(String, usize)>,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemFileSummary {
    file: String,
    bytes: u64,
    units: usize,
    promoted_units: usize,
    graph_relations: usize,
    missing_frontiers: usize,
    extra_frontiers: usize,
    changed_frontiers: usize,
    linked_files: usize,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemFileLink {
    left_file: String,
    right_file: String,
    promoted_units: usize,
    graph_relations: usize,
}

fn truncate_utf8(value: &str, limit: usize) -> (&str, bool) {
    let mut boundary = value.len().min(limit);
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    (&value[..boundary], boundary < value.len())
}

fn line_window(source: &str, line: usize) -> &str {
    if source.is_empty() {
        return source;
    }

    let mut starts = vec![0];
    starts.extend(
        source
            .match_indices('\n')
            .map(|(index, _)| index + 1)
            .filter(|start| *start < source.len()),
    );
    let target = line.saturating_sub(1).min(starts.len() - 1);
    let first = target.saturating_sub(2);
    let after_last = (target + 3).min(starts.len());
    let start = starts[first];
    let end = starts.get(after_last).copied().unwrap_or(source.len());
    &source[start..end]
}

fn location_source_with_limit(root: &Path, location: &Value, limit: usize) -> Value {
    let Some(relative) = location.get("file").and_then(Value::as_str) else {
        return json!({"error": "location has no file"});
    };
    let Some(start) = location.get("start").and_then(Value::as_u64) else {
        return json!({"error": "location has no start"});
    };
    let Some(end) = location.get("end").and_then(Value::as_u64) else {
        return json!({"error": "location has no end"});
    };
    let path = root.join(relative);
    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => return json!({"error": format!("read {}: {error}", path.display())}),
    };
    let start = start as usize;
    let end = end as usize;
    let span = source.get(start..end).filter(|snippet| !snippet.is_empty());
    let snippet = span.unwrap_or_else(|| {
        line_window(
            &source,
            location.get("line").and_then(Value::as_u64).unwrap_or(1) as usize,
        )
    });
    let (snippet, truncated) = truncate_utf8(snippet, limit);
    json!({
        "text": snippet,
        "truncated": truncated,
        "fallback": span.is_none().then_some("line-window"),
        "path": path,
    })
}

fn location_source(root: &Path, location: &Value) -> Value {
    location_source_with_limit(root, location, MAX_SNIPPET_BYTES)
}

fn read_json_lines(path: &Path) -> Result<Vec<Value>> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    source
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn collect_graph_node(nodes: &mut BTreeMap<String, Value>, root: &Path, node: &Value) {
    let Some(id) = node.get("id").and_then(Value::as_str) else {
        return;
    };
    if nodes.contains_key(id) {
        return;
    }
    let mut enriched = node.clone();
    enriched["source"] = location_source_with_limit(root, node, MAX_GRAPH_SNIPPET_BYTES);
    nodes.insert(id.to_string(), enriched);
}

fn system_files(side: &Value) -> BTreeMap<String, SystemFileSummary> {
    side["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file["file"].as_str()?.to_string();
            Some((
                path.clone(),
                SystemFileSummary {
                    file: path,
                    bytes: file["bytes"].as_u64().unwrap_or_default(),
                    units: file["units"].as_u64().unwrap_or_default() as usize,
                    ..SystemFileSummary::default()
                },
            ))
        })
        .collect()
}

fn build_system_map(report: &Value, relations: &[Value], frontiers: &[Value]) -> Value {
    let mut left_files = system_files(&report["left"]);
    let mut right_files = system_files(&report["right"]);
    let mut links = BTreeMap::<(String, String), SystemFileLink>::new();

    for relation in report["matches"].as_array().into_iter().flatten() {
        let (Some(left), Some(right)) = (
            relation["left"]["file"].as_str(),
            relation["right"]["file"].as_str(),
        ) else {
            continue;
        };
        left_files
            .entry(left.to_string())
            .or_default()
            .promoted_units += 1;
        right_files
            .entry(right.to_string())
            .or_default()
            .promoted_units += 1;
        let link = links
            .entry((left.to_string(), right.to_string()))
            .or_insert_with(|| SystemFileLink {
                left_file: left.to_string(),
                right_file: right.to_string(),
                ..SystemFileLink::default()
            });
        link.promoted_units += 1;
    }

    for relation in relations {
        let (Some(left), Some(right)) = (
            relation["left"]["file"].as_str(),
            relation["right"]["file"].as_str(),
        ) else {
            continue;
        };
        left_files
            .entry(left.to_string())
            .or_default()
            .graph_relations += 1;
        right_files
            .entry(right.to_string())
            .or_default()
            .graph_relations += 1;
        let link = links
            .entry((left.to_string(), right.to_string()))
            .or_insert_with(|| SystemFileLink {
                left_file: left.to_string(),
                right_file: right.to_string(),
                ..SystemFileLink::default()
            });
        link.graph_relations += 1;
    }

    for frontier in frontiers {
        match frontier["classification"].as_str() {
            Some("missing-local-branch") => {
                if let Some(file) = frontier["rightEdge"]["target"]["file"].as_str() {
                    right_files
                        .entry(file.to_string())
                        .or_default()
                        .missing_frontiers += 1;
                }
            }
            Some("extra-local-branch") => {
                if let Some(file) = frontier["leftEdge"]["target"]["file"].as_str() {
                    left_files
                        .entry(file.to_string())
                        .or_default()
                        .extra_frontiers += 1;
                }
            }
            Some("changed-branch") => {
                if let Some(file) = frontier["leftEdge"]["target"]["file"].as_str() {
                    left_files
                        .entry(file.to_string())
                        .or_default()
                        .changed_frontiers += 1;
                }
                if let Some(file) = frontier["rightEdge"]["target"]["file"].as_str() {
                    right_files
                        .entry(file.to_string())
                        .or_default()
                        .changed_frontiers += 1;
                }
            }
            _ => {}
        }
    }

    let mut linked_left = BTreeMap::<String, usize>::new();
    let mut linked_right = BTreeMap::<String, usize>::new();
    for link in links.values() {
        *linked_left.entry(link.left_file.clone()).or_default() += 1;
        *linked_right.entry(link.right_file.clone()).or_default() += 1;
    }
    for (file, count) in linked_left {
        left_files.entry(file).or_default().linked_files = count;
    }
    for (file, count) in linked_right {
        right_files.entry(file).or_default().linked_files = count;
    }

    json!({
        "orientation": "upstream-led",
        "leftFiles": left_files.into_values().collect::<Vec<_>>(),
        "rightFiles": right_files.into_values().collect::<Vec<_>>(),
        "links": links.into_values().collect::<Vec<_>>(),
    })
}

fn write_graph_overlay_artifact(output: &Path, report: &Value) -> Result<()> {
    let left_root = PathBuf::from(report["left"]["root"].as_str().unwrap_or_default());
    let right_root = PathBuf::from(report["right"]["root"].as_str().unwrap_or_default());
    let relations = read_json_lines(&output.join("graph-relations.jsonl"))?;
    let frontiers = read_json_lines(&output.join("divergence-frontiers.jsonl"))?;
    let mut nodes = BTreeMap::<String, Value>::new();
    for relation in &relations {
        collect_graph_node(&mut nodes, &left_root, &relation["left"]);
        collect_graph_node(&mut nodes, &right_root, &relation["right"]);
        if relation.get("source").is_some_and(Value::is_object) {
            collect_graph_node(&mut nodes, &left_root, &relation["source"]["left"]);
            collect_graph_node(&mut nodes, &right_root, &relation["source"]["right"]);
        }
    }
    for frontier in &frontiers {
        collect_graph_node(&mut nodes, &left_root, &frontier["sourceLeft"]);
        collect_graph_node(&mut nodes, &right_root, &frontier["sourceRight"]);
        if frontier.get("leftEdge").is_some_and(Value::is_object) {
            collect_graph_node(&mut nodes, &left_root, &frontier["leftEdge"]["target"]);
        }
        if frontier.get("rightEdge").is_some_and(Value::is_object) {
            collect_graph_node(&mut nodes, &right_root, &frontier["rightEdge"]["target"]);
        }
    }
    let system_map = build_system_map(report, &relations, &frontiers);
    let overlay = json!({
        "schema": "project-parity/overlay-v1",
        "nodes": nodes,
        "relations": relations,
        "frontiers": frontiers,
        "systemMap": system_map,
    });
    fs::write(
        output.join(GRAPH_OVERLAY_ARTIFACT),
        serde_json::to_vec(&overlay)?,
    )
    .with_context(|| format!("write {}", output.join(GRAPH_OVERLAY_ARTIFACT).display()))
}

fn aggregate_unmatched(path: &Path) -> Result<Vec<UnmatchedFileSummary>> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut by_file = BTreeMap::<String, UnmatchedAccumulator>::new();
    for line in source.lines().filter(|line| !line.is_empty()) {
        let record: Value = serde_json::from_str(line)?;
        let Some(file) = record["location"]["file"].as_str() else {
            continue;
        };
        let accumulator = by_file.entry(file.to_string()).or_default();
        accumulator.count += 1;
        if let Some(candidate_file) = record["candidates"]
            .as_array()
            .and_then(|candidates| candidates.first())
            .and_then(|candidate| candidate["location"]["file"].as_str())
        {
            *accumulator
                .top_candidate_files
                .entry(candidate_file.to_string())
                .or_default() += 1;
        }
    }
    let mut summaries = by_file
        .into_iter()
        .map(|(file, accumulator)| {
            let mut top_candidate_files = accumulator
                .top_candidate_files
                .into_iter()
                .collect::<Vec<_>>();
            top_candidate_files
                .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            top_candidate_files.truncate(3);
            UnmatchedFileSummary {
                file,
                count: accumulator.count,
                top_candidate_files,
            }
        })
        .collect::<Vec<_>>();
    summaries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.file.cmp(&right.file))
    });
    Ok(summaries)
}

fn build_view_model(output: &Path, report: &Value) -> Result<Value> {
    let left_root = PathBuf::from(report["left"]["root"].as_str().unwrap_or_default());
    let right_root = PathBuf::from(report["right"]["root"].as_str().unwrap_or_default());
    let mut relations = Vec::new();
    let mut pair_summaries = BTreeMap::<(String, String), FilePairSummary>::new();
    for relation in report["matches"].as_array().into_iter().flatten() {
        let mut enriched = relation.clone();
        enriched["leftSource"] = location_source(&left_root, &relation["left"]);
        enriched["rightSource"] = location_source(&right_root, &relation["right"]);
        let left_file = relation["left"]["file"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let right_file = relation["right"]["file"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let summary = pair_summaries
            .entry((left_file.clone(), right_file.clone()))
            .or_insert_with(|| FilePairSummary {
                left_file,
                right_file,
                ..FilePairSummary::default()
            });
        summary.relations += 1;
        if relation["confidence"] == "proven-structure" {
            summary.exact += 1;
        } else {
            summary.candidates += 1;
        }
        relations.push(enriched);
    }
    let mut file_pairs = pair_summaries.into_values().collect::<Vec<_>>();
    file_pairs.sort_by(|left, right| {
        right
            .relations
            .cmp(&left.relations)
            .then_with(|| left.left_file.cmp(&right.left_file))
            .then_with(|| left.right_file.cmp(&right.right_file))
    });
    Ok(json!({
        "schema": "project-parity/visual-v1",
        "report": {
            "schema": report["schema"],
            "engine": report["engine"],
            "evidenceBoundary": report["evidenceBoundary"],
            "summary": report["summary"],
            "graphSummary": report["graphSummary"],
            "graphRelationsArtifact": report["graphRelationsArtifact"],
            "divergenceFrontiersArtifact": report["divergenceFrontiersArtifact"],
            "graphOverlayArtifact": GRAPH_OVERLAY_ARTIFACT,
            "left": {"root": report["left"]["root"], "corpus": report["left"]["corpus"]},
            "right": {"root": report["right"]["root"], "corpus": report["right"]["corpus"]},
        },
        "relations": relations,
        "filePairs": file_pairs,
        "fileGraphCandidates": report["fileGraphCandidates"],
        "ambiguousGroups": report["ambiguousGroups"],
        "groupCandidates": report["groupCandidates"],
        "unmatchedLeftByFile": aggregate_unmatched(&output.join("unmatched-left.jsonl"))?,
        "unmatchedRightByFile": aggregate_unmatched(&output.join("unmatched-right.jsonl"))?,
    }))
}

pub fn write_visual_report(output: &Path, report: &Value) -> Result<()> {
    write_graph_overlay_artifact(output, report)?;
    let mut data = serde_json::to_string(&build_view_model(output, report)?)?;
    data = data.replace('<', "\\u003c").replace('&', "\\u0026");
    let html = include_str!("visualize.html").replace("__REPORT_DATA__", &data);
    fs::write(output.join("report.html"), html)
        .with_context(|| format!("write {}", output.join("report.html").display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn zero_length_location_uses_non_empty_line_window() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("owner.ts"),
            "const alpha = 1;\nconst beta = 2;\nconst gamma = 3;\n",
        )
        .unwrap();
        let location = json!({
            "file": "owner.ts",
            "line": 2,
            "start": 0,
            "end": 0,
        });

        let excerpt = location_source_with_limit(root.path(), &location, 8_000);

        assert_eq!(excerpt["fallback"], "line-window");
        assert!(excerpt["text"]
            .as_str()
            .is_some_and(|text| text.contains("const beta = 2;")));
    }
}
