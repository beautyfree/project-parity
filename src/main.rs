use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    env, fs,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    thread,
    time::Duration,
};

use anyhow::{bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    ArrowFunctionExpression, Class, Function, ParenthesizedExpression, TSAsExpression,
    TSInstantiationExpression, TSNonNullExpression, TSSatisfiesExpression, TSTypeAnnotation,
    TSTypeAssertion, TSTypeParameterDeclaration, TSTypeParameterInstantiation,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::{walk, Visit};
use oxc_codegen::Codegen;
use oxc_parser::Parser;
use oxc_semantic::{ScopeId, Scoping, SemanticBuilder, SymbolId};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_str::Ident;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use sourcemap::DecodedMap;
use walkdir::{DirEntry, WalkDir};

mod llm_context;
mod semantic_graph;
mod state;
mod visualize;

use semantic_graph::{GraphEdge, GraphNode, SemanticGraph};

const CODE_EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];
const ENGINE_VERSION: &str = "rust-oxc-0.126.0/v38";
// Graph extraction is cache material: change this whenever semantic nodes or
// edges change, otherwise an old cache silently erases newly added ownership
// links from a report.
const INDEX_CACHE_VERSION: &str = "rust-oxc-0.126.0/v29";
const SKIP_DIRECTORIES: &[&str] = &[
    ".git",
    ".cache",
    ".output",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "reports",
    "scripts",
    "target",
    "tools",
];
type BestGroup<'a> = (Vec<&'a Unit>, (f64, f64, f64));
type FileAffinities = HashMap<String, Vec<String>>;

struct Discovery {
    root: PathBuf,
    files: Vec<(PathBuf, String)>,
    skipped: Vec<String>,
    corpus: CorpusSelection,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Unit {
    id: String,
    file: String,
    kind: String,
    name: Option<String>,
    start: u32,
    end: u32,
    line: usize,
    origin: Option<SourceOrigin>,
    nodes_approx: usize,
    strict_sha256: String,
    linked_sha256: String,
    tokens: BTreeSet<String>,
    features: FeatureChannels,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceOrigin {
    file: String,
    line: u32,
    column: u32,
    name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct FeatureChannels {
    shape: BTreeMap<String, u32>,
    ordered: BTreeMap<String, u32>,
    literals: BTreeMap<String, u32>,
    operators: BTreeMap<String, u32>,
    properties: BTreeMap<String, u32>,
    externals: BTreeMap<String, u32>,
    #[serde(skip)]
    last_event: Option<String>,
    #[serde(skip)]
    local_slots: HashMap<String, usize>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelScores {
    shape: f64,
    ordered: f64,
    literals: f64,
    operators: f64,
    operators_active: bool,
    properties: f64,
    externals: f64,
    size: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileRecord {
    file: String,
    bytes: usize,
    source_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_map_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_map_error: Option<String>,
    units: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct IndexedFile {
    record: FileRecord,
    units: Vec<Unit>,
    graph: SemanticGraph,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Failure {
    file: String,
    error: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CorpusSelection {
    mode: &'static str,
    roots: Vec<String>,
    excluded_derivative_roots: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    projection_tool: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectIndex {
    root: String,
    corpus: CorpusSelection,
    project_sha256: String,
    files: Vec<FileRecord>,
    #[serde(skip_serializing)]
    units: Vec<Unit>,
    #[serde(skip_serializing)]
    graph_nodes: Vec<GraphNode>,
    #[serde(skip_serializing)]
    graph_edges: Vec<GraphEdge>,
    /// Complete per-file graph stream. The in-memory graph may be compacted
    /// for large bundles, while this lossless stream remains available for
    /// artifact generation and bounded inspection.
    #[serde(skip)]
    graph_artifact: Option<PathBuf>,
    failures: Vec<Failure>,
    skipped: Vec<String>,
}

/// Resolution evidence for an import edge.  The matcher deliberately records
/// uncertainty instead of inferring package identity from a callee/property
/// name: two unrelated packages may both export `debounce` (or any other
/// identifier).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyProvenance {
    side: String,
    edge_kind: String,
    importer_file: String,
    specifier: String,
    imported_export: String,
    binding_symbol_id: Option<String>,
    module_node_id: String,
    resolution: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_runtime_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_resolution: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_sha256: Option<String>,
    /// All statically visible package export branches.  `entry_path` remains
    /// the unique proven entry; this list prevents conditional alternatives
    /// from disappearing from the LLM-facing evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entry_candidates: Vec<String>,
}

/// A binding correspondence is promoted only when the graph has already
/// paired both lexical bindings and both resolved package runtime surfaces are
/// byte-identical.  Rows without those facts remain actionable evidence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DependencyBindingContract {
    disposition: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    left: Option<DependencyProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    right: Option<DependencyProvenance>,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location {
    id: String,
    file: String,
    kind: String,
    name: Option<String>,
    line: usize,
    start: u32,
    end: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    origin: Option<SourceOrigin>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MatchRecord {
    confidence: &'static str,
    status: &'static str,
    basis: &'static str,
    score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    channels: Option<ChannelScores>,
    left: Location,
    right: Location,
}

/// Optional, hash-pinned external review evidence. The engine never ships a
/// project-specific certificate; callers may supply one for any project.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BundleEquivalenceCertificate {
    left: CertifiedOwner,
    right: CertifiedOwner,
    bindings: Vec<CertifiedBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertifiedOwner {
    file: String,
    name: String,
    source_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertifiedBinding {
    left: String,
    right: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    score: f64,
    basis: &'static str,
    channels: ChannelScores,
    location: Location,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileGraphCandidate {
    source_file: String,
    target_file: String,
    anchor_relations: usize,
    supporting_units: usize,
    average_score: f64,
    graph_score: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphNodeRef {
    id: String,
    file: String,
    kind: String,
    label: String,
    line: usize,
    start: u32,
    end: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphRelation {
    confidence: &'static str,
    basis: &'static str,
    depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    via_edge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<GraphRelationSource>,
    left: GraphNodeRef,
    right: GraphNodeRef,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphRelationSource {
    left: GraphNodeRef,
    right: GraphNodeRef,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdgeRef {
    kind: String,
    dynamic: bool,
    label: Option<String>,
    target: GraphNodeRef,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DivergenceFrontier {
    classification: &'static str,
    confidence: &'static str,
    depth: usize,
    source_left: GraphNodeRef,
    source_right: GraphNodeRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    left_edge: Option<GraphEdgeRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    right_edge: Option<GraphEdgeRef>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphSummary {
    left_nodes: usize,
    right_nodes: usize,
    left_edges: usize,
    right_edges: usize,
    seeded_relations: usize,
    expanded_relations: usize,
    divergence_frontiers: usize,
    edge_layers: BTreeMap<String, usize>,
    behavior_refinement: BehaviorRefinementSummary,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct BehaviorRefinementSummary {
    left_iterations: usize,
    right_iterations: usize,
    left_converged: bool,
    right_converged: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Unmatched {
    location: Location,
    candidates: Vec<Candidate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AmbiguousGroup {
    confidence: &'static str,
    basis: &'static str,
    left: Vec<Location>,
    right: Vec<Location>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupCandidate {
    confidence: &'static str,
    relation: &'static str,
    score: f64,
    coverage: f64,
    precision: f64,
    left: Vec<Location>,
    right: Vec<Location>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    left_files: usize,
    right_files: usize,
    left_units: usize,
    right_units: usize,
    left_failures: usize,
    right_failures: usize,
    alpha_equal: usize,
    linked_candidates: usize,
    mutual_best_candidates: usize,
    ambiguous_groups: usize,
    extraction_inline_candidates: usize,
    unmatched_left: usize,
    unmatched_right: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Report<'a> {
    schema: &'static str,
    engine: &'static str,
    evidence_boundary: &'static str,
    confidence_contract: BTreeMap<&'static str, &'static str>,
    thresholds: BTreeMap<&'static str, f64>,
    summary: Summary,
    left: &'a ProjectIndex,
    right: &'a ProjectIndex,
    matches: Vec<MatchRecord>,
    ambiguous_groups: Vec<AmbiguousGroup>,
    group_candidates: Vec<GroupCandidate>,
    file_graph_candidates: Vec<FileGraphCandidate>,
    graph_summary: GraphSummary,
    llm_summary: llm_context::LlmSummary,
    graph_relations_artifact: &'static str,
    divergence_frontiers_artifact: &'static str,
    unmatched_left_artifact: &'static str,
    unmatched_right_artifact: &'static str,
    upstream_executable_ledger_artifact: &'static str,
    upstream_semantic_ledger_artifact: &'static str,
    upstream_semantic_edge_ledger_artifact: &'static str,
    llm_work_items_artifact: &'static str,
    llm_batches_artifact: &'static str,
    llm_manifest_artifact: &'static str,
    llm_task_brief_artifact: &'static str,
    dependency_evidence_corpus_artifact: &'static str,
    dependency_provenance_artifact: &'static str,
    dependency_binding_contracts_artifact: &'static str,
    semantic_graph_artifact: &'static str,
    semantic_graph_summary: SemanticGraphArtifactSummary,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SemanticGraphArtifactSummary {
    schema: &'static str,
    compression: &'static str,
    left_nodes: usize,
    right_nodes: usize,
    left_edges: usize,
    right_edges: usize,
    left_compact_nodes: usize,
    right_compact_nodes: usize,
    left_compact_edges: usize,
    right_compact_edges: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Oracle {
    #[serde(default = "default_top_k")]
    top_k: usize,
    #[serde(default)]
    expected: Vec<OraclePair>,
    #[serde(default)]
    forbidden: Vec<OraclePair>,
}

#[derive(Debug, Deserialize)]
struct OraclePair {
    left: OracleLocator,
    right: OracleLocator,
}

#[derive(Debug, Deserialize)]
struct OracleLocator {
    file: String,
    name: Option<String>,
    line: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OracleMetrics {
    schema: &'static str,
    top_k: usize,
    expected: usize,
    forbidden: usize,
    promoted_correct: usize,
    top_one_recovered: usize,
    top_k_recovered: usize,
    abstained_expected: usize,
    false_promotions: usize,
    promoted_precision: f64,
    promoted_recall: f64,
    top_k_recall: f64,
}

fn default_top_k() -> usize {
    5
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}

fn scope_depth(scoping: &Scoping, mut scope_id: ScopeId) -> usize {
    let mut depth = 0;
    while let Some(parent) = scoping.scope_parent_id(scope_id) {
        depth += 1;
        scope_id = parent;
    }
    depth
}

fn collision_free_prefix(scoping: &Scoping) -> String {
    let occupied: BTreeSet<&str> = scoping
        .symbol_names()
        .chain(
            scoping
                .root_unresolved_references()
                .keys()
                .map(Ident::as_str),
        )
        .collect();
    let mut prefix = "__astp_".to_string();
    while occupied.iter().any(|name| name.starts_with(&prefix)) {
        prefix.push('_');
    }
    prefix
}

fn canonicalize(
    source: &str,
    source_type: SourceType,
    file: &str,
    side: &str,
) -> Result<(String, Vec<RawUnit>, SemanticGraph)> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, source_type).parse();
    if !parsed.errors.is_empty() {
        bail!(
            "parse failed: {}",
            parsed
                .errors
                .iter()
                .map(|e| e.message.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let program = parsed.program;
    let mut original_units = UnitCollector::default();
    original_units.visit_program(&program);
    original_units
        .units
        .sort_by_key(|unit| (unit.span.start, unit.span.end));
    let built = SemanticBuilder::new().build(&program);
    if !built.errors.is_empty() {
        bail!(
            "semantic analysis failed: {}",
            built
                .errors
                .iter()
                .map(|e| e.message.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let mut semantic = built.semantic;
    let graph = semantic_graph::extract(&program, &semantic, source, file, side);
    let prefix = collision_free_prefix(semantic.scoping());
    let mut by_scope = BTreeMap::<usize, Vec<SymbolId>>::new();
    for symbol_id in semantic.scoping().symbol_ids() {
        let scope_id = semantic.scoping().symbol_scope_id(symbol_id);
        by_scope
            .entry(scope_id.index())
            .or_default()
            .push(symbol_id);
    }
    for symbols in by_scope.values_mut() {
        symbols.sort_by_key(|symbol_id| {
            let span = semantic.scoping().symbol_span(*symbol_id);
            (span.start, span.end, symbol_id.index())
        });
    }
    let mut plan = Vec::new();
    for symbols in by_scope.values() {
        for (ordinal, symbol_id) in symbols.iter().copied().enumerate() {
            let scope_id = semantic.scoping().symbol_scope_id(symbol_id);
            let depth = scope_depth(semantic.scoping(), scope_id);
            plan.push((symbol_id, scope_id, format!("{prefix}s{depth}b{ordinal}")));
        }
    }
    for (symbol_id, scope_id, name) in plan {
        let canonical = Ident::from(allocator.alloc_str(&name));
        semantic
            .scoping_mut()
            .rename_symbol(symbol_id, scope_id, canonical);
    }
    Ok((
        Codegen::new()
            .with_scoping(Some(semantic.into_scoping()))
            .build(&program)
            .code,
        original_units.units,
        graph,
    ))
}

#[derive(Debug)]
struct RawUnit {
    span: Span,
    kind: &'static str,
    name: Option<String>,
}

#[derive(Default)]
struct UnitCollector {
    units: Vec<RawUnit>,
}

impl<'a> Visit<'a> for UnitCollector {
    fn visit_function(&mut self, function: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        self.units.push(RawUnit {
            span: function.span(),
            kind: "Function",
            name: function.id.as_ref().map(|id| id.name.to_string()),
        });
        walk::walk_function(self, function, flags);
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        self.units.push(RawUnit {
            span: function.span(),
            kind: "Function",
            name: None,
        });
        walk::walk_arrow_function_expression(self, function);
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        self.units.push(RawUnit {
            span: class.span(),
            kind: "Class",
            name: class.id.as_ref().map(|id| id.name.to_string()),
        });
        walk::walk_class(self, class);
    }
}

impl FeatureChannels {
    fn increment(channel: &mut BTreeMap<String, u32>, value: impl Into<String>) {
        *channel.entry(value.into()).or_default() += 1;
    }

    fn token_set(&self) -> BTreeSet<String> {
        let mut tokens = BTreeSet::new();
        for (channel, values) in [
            ("shape", &self.shape),
            ("ordered", &self.ordered),
            ("literal", &self.literals),
            ("operator", &self.operators),
            ("property", &self.properties),
            ("external", &self.externals),
        ] {
            tokens.extend(
                values
                    .iter()
                    .map(|(value, count)| format!("{channel}:{value}:{count}")),
            );
        }
        tokens
    }

    fn signature(&self, include_externals: bool) -> String {
        let mut parts = Vec::new();
        for (channel, values) in [
            ("shape", &self.shape),
            ("ordered", &self.ordered),
            ("literal", &self.literals),
            ("operator", &self.operators),
            ("property", &self.properties),
        ] {
            parts.extend(
                values
                    .iter()
                    .map(|(value, count)| format!("{channel}\0{value}\0{count}")),
            );
        }
        if include_externals {
            parts.extend(
                self.externals
                    .iter()
                    .map(|(value, count)| format!("external\0{value}\0{count}")),
            );
        }
        parts.join("\n")
    }

    fn node_count(&self) -> usize {
        self.shape.values().map(|count| *count as usize).sum()
    }

    fn record_event(&mut self, event: impl Into<String>) {
        let event = event.into();
        if let Some(previous) = self.last_event.replace(event.clone()) {
            Self::increment(&mut self.ordered, format!("{previous}\u{1f}{event}"));
        }
    }

    fn bind_local(&mut self, canonical_name: &str) -> usize {
        let next = self.local_slots.len();
        *self
            .local_slots
            .entry(canonical_name.to_string())
            .or_insert(next)
    }

    fn local_slot(&mut self, canonical_name: &str) -> usize {
        self.bind_local(canonical_name)
    }
}

fn record_ast_feature(features: &mut FeatureChannels, source: &str, kind: AstKind<'_>) {
    let node = format!("{:?}", kind.ty());
    FeatureChannels::increment(&mut features.shape, &node);
    features.record_event(format!("node:{node}"));
    match kind {
        AstKind::BindingIdentifier(identifier) => {
            let name = identifier.name.as_str();
            if name.starts_with("__astp_") {
                features.bind_local(name);
            }
        }
        AstKind::IdentifierReference(identifier) => {
            let name = identifier.name.as_str();
            if name.starts_with("__astp_") {
                let slot = features.local_slot(name);
                features.record_event(format!("local:{slot}"));
            } else {
                FeatureChannels::increment(&mut features.externals, name);
                features.record_event("external");
            }
        }
        AstKind::IdentifierName(identifier) => {
            FeatureChannels::increment(&mut features.properties, identifier.name.as_str());
            features.record_event(format!("property:{}", identifier.name));
        }
        AstKind::StringLiteral(_)
        | AstKind::NumericLiteral(_)
        | AstKind::BooleanLiteral(_)
        | AstKind::NullLiteral(_)
        | AstKind::BigIntLiteral(_)
        | AstKind::RegExpLiteral(_)
        | AstKind::TemplateElement(_) => {
            let span = kind.span();
            FeatureChannels::increment(
                &mut features.literals,
                &source[span.start as usize..span.end as usize],
            );
            features.record_event(format!(
                "literal:{}",
                &source[span.start as usize..span.end as usize]
            ));
        }
        AstKind::UpdateExpression(expression) => {
            let operator = format!("{:?}", expression.operator);
            FeatureChannels::increment(&mut features.operators, &operator);
            features.record_event(format!("operator:{operator}"));
        }
        AstKind::UnaryExpression(expression) => {
            let operator = format!("{:?}", expression.operator);
            FeatureChannels::increment(&mut features.operators, &operator);
            features.record_event(format!("operator:{operator}"));
        }
        AstKind::BinaryExpression(expression) => {
            let operator = format!("{:?}", expression.operator);
            FeatureChannels::increment(&mut features.operators, &operator);
            features.record_event(format!("operator:{operator}"));
        }
        AstKind::LogicalExpression(expression) => {
            let operator = format!("{:?}", expression.operator);
            FeatureChannels::increment(&mut features.operators, &operator);
            features.record_event(format!("operator:{operator}"));
        }
        AstKind::AssignmentExpression(expression) => {
            let operator = format!("{:?}", expression.operator);
            FeatureChannels::increment(&mut features.operators, &operator);
            features.record_event(format!("operator:{operator}"));
        }
        _ => {}
    }
}

#[derive(Debug)]
struct CanonicalUnit {
    span: Span,
    features: FeatureChannels,
}

struct CanonicalUnitCollector<'s> {
    source: &'s str,
    units: Vec<CanonicalUnit>,
    active_units: Vec<usize>,
}

impl<'s> CanonicalUnitCollector<'s> {
    fn new(source: &'s str) -> Self {
        Self {
            source,
            units: Vec::new(),
            active_units: Vec::new(),
        }
    }

    fn begin_unit(&mut self, span: Span) {
        let index = self.units.len();
        self.units.push(CanonicalUnit {
            span,
            features: FeatureChannels::default(),
        });
        self.active_units.push(index);
    }

    fn end_unit(&mut self) {
        self.active_units.pop();
    }
}

impl<'a> Visit<'a> for CanonicalUnitCollector<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        for index in self.active_units.iter().copied() {
            record_ast_feature(&mut self.units[index].features, self.source, kind);
        }
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        self.begin_unit(function.span());
        walk::walk_function(self, function, flags);
        self.end_unit();
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        self.begin_unit(function.span());
        walk::walk_arrow_function_expression(self, function);
        self.end_unit();
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        self.begin_unit(class.span());
        walk::walk_class(self, class);
        self.end_unit();
    }

    fn visit_parenthesized_expression(&mut self, expression: &ParenthesizedExpression<'a>) {
        self.visit_expression(&expression.expression);
    }

    // TypeScript syntax has no runtime behavior. Local sources are TS,
    // while upstream bundles are JS, so retaining these nodes makes identical
    // executable owners look structurally different. Type-only subtrees are
    // omitted and runtime-transparent wrappers visit only their expression.
    fn visit_ts_type_annotation(&mut self, _annotation: &TSTypeAnnotation<'a>) {}

    fn visit_ts_type_parameter_declaration(
        &mut self,
        _parameters: &TSTypeParameterDeclaration<'a>,
    ) {
    }

    fn visit_ts_type_parameter_instantiation(
        &mut self,
        _parameters: &TSTypeParameterInstantiation<'a>,
    ) {
    }

    fn visit_ts_as_expression(&mut self, expression: &TSAsExpression<'a>) {
        self.visit_expression(&expression.expression);
    }

    fn visit_ts_satisfies_expression(&mut self, expression: &TSSatisfiesExpression<'a>) {
        self.visit_expression(&expression.expression);
    }

    fn visit_ts_type_assertion(&mut self, expression: &TSTypeAssertion<'a>) {
        self.visit_expression(&expression.expression);
    }

    fn visit_ts_non_null_expression(&mut self, expression: &TSNonNullExpression<'a>) {
        self.visit_expression(&expression.expression);
    }

    fn visit_ts_instantiation_expression(&mut self, expression: &TSInstantiationExpression<'a>) {
        self.visit_expression(&expression.expression);
    }
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

fn generated_position(source: &str, offset: usize) -> (u32, u32) {
    let mut line = 0_u32;
    let mut utf16_column = 0_u32;
    for character in source[..offset.min(source.len())].chars() {
        if character == '\n' {
            line += 1;
            utf16_column = 0;
        } else {
            utf16_column += character.len_utf16() as u32;
        }
    }
    (line, utf16_column)
}

fn source_origin(
    source_map: Option<&DecodedMap>,
    generated_source: &str,
    generated_offset: usize,
) -> Option<SourceOrigin> {
    let source_map = source_map?;
    let (line, column) = generated_position(generated_source, generated_offset);
    let token = source_map.lookup_token(line, column)?;
    if token.get_dst_line() != line
        || token.get_src_line() == u32::MAX
        || token.get_src_col() == u32::MAX
    {
        return None;
    }
    Some(SourceOrigin {
        file: token.get_source()?.to_string(),
        line: token.get_src_line() + 1,
        column: token.get_src_col(),
        name: token.get_name().map(str::to_string),
    })
}

fn collect_units(
    canonical: &str,
    original_source: &str,
    source_type: SourceType,
    file: &str,
    side: &str,
    original_units: Vec<RawUnit>,
    source_map: Option<&DecodedMap>,
) -> Result<Vec<Unit>> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, canonical, source_type).parse();
    if !parsed.errors.is_empty() {
        bail!("canonical reparse failed");
    }
    let mut collector = CanonicalUnitCollector::new(canonical);
    collector.visit_program(&parsed.program);
    collector
        .units
        .sort_by_key(|unit| (unit.span.start, unit.span.end));
    if collector.units.len() != original_units.len() {
        bail!(
            "canonical unit count changed: original {}, canonical {}",
            original_units.len(),
            collector.units.len()
        );
    }
    Ok(collector
        .units
        .into_iter()
        .zip(original_units)
        .enumerate()
        .map(|(ordinal, (canonical_unit, original_unit))| {
            let fragment =
                &canonical[canonical_unit.span.start as usize..canonical_unit.span.end as usize];
            let features = canonical_unit.features;
            let tokens = features.token_set();
            Unit {
                id: format!(
                    "{side}:{file}:{}:{}:{ordinal}",
                    original_unit.span.start, original_unit.span.end
                ),
                file: file.to_string(),
                kind: original_unit.kind.to_string(),
                name: original_unit.name,
                start: original_unit.span.start,
                end: original_unit.span.end,
                line: line_at(original_source, original_unit.span.start as usize),
                origin: source_origin(
                    source_map,
                    original_source,
                    original_unit.span.start as usize,
                ),
                nodes_approx: features.node_count(),
                strict_sha256: sha256(fragment),
                linked_sha256: sha256(features.signature(false)),
                tokens,
                features,
            }
        })
        .collect())
}

fn should_skip(entry: &DirEntry, selected_root: &Path) -> bool {
    entry.file_type().is_dir()
        && entry.path() != selected_root
        && SKIP_DIRECTORIES.contains(&entry.file_name().to_string_lossy().as_ref())
}

fn discover(input: &Path) -> Result<Discovery> {
    let root = input
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", input.display()))?;
    // Keep the standalone tool build-system agnostic. A caller can point it
    // at source trees or at pre-processed bundle/projection directories; the
    // matcher itself never assumes Electron, a specific unpacker, or a
    // product-specific layout.
    let selected = vec![root.clone()];
    let corpus = CorpusSelection {
        mode: "recursive-source-project",
        roots: vec![".".to_string()],
        excluded_derivative_roots: Vec::new(),
        source_root: None,
        projection_tool: None,
    };
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for selected_root in selected {
        for entry in WalkDir::new(&selected_root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| {
                let skip = should_skip(entry, &selected_root);
                if skip {
                    skipped.push(
                        entry
                            .path()
                            .strip_prefix(&root)
                            .unwrap_or(entry.path())
                            .display()
                            .to_string(),
                    );
                }
                !skip
            })
        {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !CODE_EXTENSIONS.contains(&extension) {
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            if relative.contains("/__tests__/")
                || [".test.", ".spec.", ".stories."]
                    .iter()
                    .any(|needle| relative.contains(needle))
            {
                continue;
            }
            files.push((path.to_path_buf(), relative));
        }
    }
    files.sort_by(|left, right| left.1.cmp(&right.1));
    skipped.sort();
    skipped.dedup();
    Ok(Discovery {
        root,
        files,
        skipped,
        corpus,
    })
}

#[derive(Debug, Deserialize)]
struct PackageManifest {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    main: Option<String>,
    #[serde(default)]
    exports: Option<JsonValue>,
    #[serde(default)]
    imports: Option<JsonValue>,
    #[serde(default)]
    dependencies: BTreeMap<String, String>,
    #[serde(default)]
    optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    peer_dependencies: BTreeMap<String, String>,
}

fn manifest_dependency_names(manifest: &PackageManifest) -> BTreeSet<String> {
    manifest
        .dependencies
        .keys()
        .chain(manifest.optional_dependencies.keys())
        .chain(manifest.peer_dependencies.keys())
        .cloned()
        .collect()
}

fn read_package_manifest(path: &Path) -> Option<PackageManifest> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TsConfig {
    #[serde(default)]
    compiler_options: TsCompilerOptions,
    #[serde(default)]
    extends: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct TsCompilerOptions {
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    paths: BTreeMap<String, Vec<String>>,
}

#[derive(Debug)]
struct TsConfigPathEntry {
    resolution: &'static str,
    path: Option<PathBuf>,
}

fn read_tsconfig(path: &Path) -> Option<TsConfig> {
    let source = fs::read_to_string(path).ok()?;
    jsonc_parser::parse_to_serde_value(&source, &Default::default()).ok()
}

fn config_file_path(base: &Path, reference: &str) -> Option<PathBuf> {
    let paths = if reference.starts_with('.') || reference.starts_with('/') {
        vec![base.join(reference)]
    } else {
        // TypeScript permits package-based `extends` (for example
        // `@tsconfig/node16/tsconfig.json`).  It follows normal Node ancestor
        // lookup, not merely a path relative to the importing config.
        let mut paths = Vec::new();
        let mut cursor = Some(base);
        while let Some(directory) = cursor {
            paths.push(directory.join("node_modules").join(reference));
            cursor = directory.parent();
        }
        paths
    };
    paths.into_iter().find_map(|path| {
        [
            path.clone(),
            path.with_extension("json"),
            path.join("tsconfig.json"),
        ]
        .into_iter()
        .find(|candidate| candidate.is_file())
    })
}

/// Returns only the inheritance chain for the importing project. TypeScript
/// project references are separate compilation projects, not inherited
/// compiler options; treating them as a flat union made unrelated aliases
/// resolve to arbitrary files.
fn tsconfig_tree(root_config: &Path) -> Vec<(PathBuf, TsConfig)> {
    let mut queue = VecDeque::from([root_config.to_path_buf()]);
    let mut seen = HashSet::new();
    let mut configs = Vec::new();
    while let Some(config_path) = queue.pop_front() {
        let Ok(config_path) = config_path.canonicalize() else {
            continue;
        };
        if !seen.insert(config_path.clone()) {
            continue;
        }
        let Some(config) = read_tsconfig(&config_path) else {
            continue;
        };
        let directory = config_path.parent().unwrap_or(&config_path);
        if let Some(extends) = &config.extends {
            if let Some(path) = config_file_path(directory, extends) {
                queue.push_back(path);
            }
        }
        configs.push((config_path, config));
    }
    configs.reverse();
    configs
}

type TsConfigTree = Vec<(PathBuf, TsConfig)>;
type TsConfigTreeCache = HashMap<PathBuf, TsConfigTree>;

static TSCONFIG_TREE_CACHE: OnceLock<Mutex<TsConfigTreeCache>> = OnceLock::new();

fn cached_tsconfig_tree(root_config: &Path) -> Vec<(PathBuf, TsConfig)> {
    let key = root_config
        .canonicalize()
        .unwrap_or_else(|_| root_config.to_path_buf());
    let cache = TSCONFIG_TREE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(configs) = cache.lock().expect("tsconfig cache poisoned").get(&key) {
        return configs.clone();
    }
    let configs = tsconfig_tree(&key);
    cache
        .lock()
        .expect("tsconfig cache poisoned")
        .insert(key, configs.clone());
    configs
}

fn nearest_tsconfig(importer: &Path, project_root: &Path) -> Option<PathBuf> {
    let mut cursor = importer.parent();
    while let Some(directory) = cursor {
        let config = directory.join("tsconfig.json");
        if config.is_file() {
            return Some(config);
        }
        if directory == project_root {
            break;
        }
        cursor = directory.parent();
    }
    None
}

fn resolve_installed_package(from: &Path, project_root: &Path, name: &str) -> Option<PathBuf> {
    let mut cursor = Some(from);
    while let Some(directory) = cursor {
        // Node package self-reference: a package may import its own public
        // name/subpaths without passing through node_modules.
        if read_package_manifest(&directory.join("package.json"))
            .and_then(|manifest| manifest.name)
            .as_deref()
            == Some(name)
        {
            return directory.canonicalize().ok();
        }
        let candidate = directory.join("node_modules").join(name);
        if let Ok(resolved) = candidate.canonicalize() {
            return Some(resolved);
        }
        if directory == project_root {
            break;
        }
        cursor = directory.parent();
    }
    None
}

fn package_name_from_specifier(specifier: &str) -> Option<&str> {
    if specifier.starts_with('.')
        || specifier.starts_with('/')
        || [
            "node:", "data:", "file:", "http:", "https:", "bun:", "deno:",
        ]
        .iter()
        .any(|scheme| specifier.starts_with(scheme))
    {
        return None;
    }
    if let Some(rest) = specifier.strip_prefix('@') {
        let mut parts = rest.split('/');
        let scope = parts.next()?;
        let package = parts.next()?;
        let length = 1 + scope.len() + 1 + package.len();
        return specifier.get(..length);
    }
    specifier.split('/').next()
}

#[derive(Debug)]
struct PackageEntry {
    resolution: &'static str,
    path: Option<PathBuf>,
    /// Every branch visible in an `exports` condition map.  `path` is set
    /// only when this set has one unblocked member; callers still retain the
    /// alternatives for an actionable graph rather than erasing them.
    candidates: BTreeSet<PathBuf>,
}

/// Resolution of Node's `package.json#imports` aliases. The map is scoped to
/// the nearest containing package, unlike a TypeScript compiler path alias.
/// Only a literal `#name -> ./relative-file` entry is statically exact without
/// choosing environment conditions or expanding patterns.
#[derive(Debug)]
struct PackageImportEntry {
    resolution: &'static str,
    path: Option<PathBuf>,
    candidates: BTreeSet<PathBuf>,
}

fn resolve_package_import(
    importer: &Path,
    project_root: &Path,
    specifier: &str,
) -> PackageImportEntry {
    if !specifier.starts_with('#') {
        return PackageImportEntry {
            resolution: "invalid-package-import-specifier",
            path: None,
            candidates: BTreeSet::new(),
        };
    }
    let mut cursor = importer.parent();
    while let Some(directory) = cursor {
        let manifest_path = directory.join("package.json");
        if manifest_path.is_file() {
            let Some(manifest) = read_package_manifest(&manifest_path) else {
                return PackageImportEntry {
                    resolution: "invalid-package-import-manifest",
                    path: None,
                    candidates: BTreeSet::new(),
                };
            };
            let Some(imports) = manifest.imports else {
                return PackageImportEntry {
                    resolution: "unresolved-package-import",
                    path: None,
                    candidates: BTreeSet::new(),
                };
            };
            let target = match &imports {
                JsonValue::Object(entries) => {
                    let mut candidates = entries
                        .iter()
                        .filter_map(|(pattern, value)| {
                            export_pattern_capture(pattern, specifier).map(|capture| {
                                let specificity = pattern
                                    .len()
                                    .saturating_sub(usize::from(pattern.contains('*')));
                                (specificity, pattern.as_str(), value, capture)
                            })
                        })
                        .collect::<Vec<_>>();
                    candidates.sort_by(|left, right| {
                        right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1))
                    });
                    candidates
                        .into_iter()
                        .next()
                        .map(|(_, _, value, capture)| (value, capture))
                }
                _ => None,
            };
            return match target {
                Some((target, capture)) => {
                    let paths = package_export_paths(directory, target, &capture);
                    match (paths.paths.len(), paths.blocked_or_unresolved) {
                        (1, false) => PackageImportEntry {
                            resolution: "exact-package-import-map",
                            path: paths.paths.iter().next().cloned(),
                            candidates: paths.paths,
                        },
                        _ => PackageImportEntry {
                            resolution: "conditional-or-unresolved-package-import-map",
                            path: None,
                            candidates: paths.paths,
                        },
                    }
                }
                None => PackageImportEntry {
                    resolution: "unresolved-package-import",
                    path: None,
                    candidates: BTreeSet::new(),
                },
            };
        }
        if directory == project_root {
            break;
        }
        cursor = directory.parent();
    }
    PackageImportEntry {
        resolution: "unresolved-package-import",
        path: None,
        candidates: BTreeSet::new(),
    }
}

fn resolve_package_file(package_root: &Path, target: &str) -> Option<PathBuf> {
    let package_root = package_root.canonicalize().ok()?;
    let target = target.strip_prefix("./").unwrap_or(target);
    let base = package_root.join(target);
    let candidates = std::iter::once(base.clone())
        .chain(
            CODE_EXTENSIONS
                .iter()
                .map(|extension| base.with_extension(extension)),
        )
        .chain(
            CODE_EXTENSIONS
                .iter()
                .map(|extension| base.join(format!("index.{extension}"))),
        );
    candidates
        .filter(|candidate| candidate.is_file())
        .find_map(|candidate| candidate.canonicalize().ok())
        .filter(|path| path.starts_with(&package_root))
}

fn package_subpath<'a>(specifier: &'a str, package_name: &str) -> Option<&'a str> {
    specifier
        .strip_prefix(package_name)
        .filter(|rest| rest.is_empty() || rest.starts_with('/'))
        .map(|rest| rest.trim_start_matches('/'))
}

fn export_pattern_capture(pattern: &str, key: &str) -> Option<String> {
    match pattern.matches('*').count() {
        0 => (pattern == key).then(String::new),
        1 => {
            let (prefix, suffix) = pattern.split_once('*')?;
            key.strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .map(str::to_string)
        }
        _ => None,
    }
}

/// Returns the selected export-map value and a pattern capture. Node resolves
/// the longest matching subpath key; condition objects are deliberately left
/// intact for the caller to prove convergence instead of selecting `import`,
/// `require`, or `default` arbitrarily.
fn package_export_value<'a>(exports: &'a JsonValue, key: &str) -> Option<(&'a JsonValue, String)> {
    let JsonValue::Object(map) = exports else {
        return (key == ".").then_some((exports, String::new()));
    };
    if !map.keys().any(|candidate| candidate.starts_with('.')) {
        return (key == ".").then_some((exports, String::new()));
    }
    let mut candidates = map
        .iter()
        .filter_map(|(pattern, value)| {
            export_pattern_capture(pattern, key).map(|capture| {
                let specificity = pattern
                    .len()
                    .saturating_sub(usize::from(pattern.contains('*')));
                (specificity, pattern.as_str(), value, capture)
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    candidates
        .into_iter()
        .next()
        .map(|(_, _, value, capture)| (value, capture))
}

/// Resolve every statically visible branch of a package export. Only callers
/// seeing exactly one resulting path may call it exact; zero/multiple paths
/// remain blocked/conditional evidence rather than a guessed condition.
#[derive(Default)]
struct PackageExportPaths {
    paths: BTreeSet<PathBuf>,
    blocked_or_unresolved: bool,
}

fn package_export_paths(
    package_root: &Path,
    value: &JsonValue,
    capture: &str,
) -> PackageExportPaths {
    match value {
        JsonValue::String(target) => {
            let target = target.replace('*', capture);
            match resolve_package_file(package_root, &target) {
                Some(path) => PackageExportPaths {
                    paths: BTreeSet::from([path]),
                    blocked_or_unresolved: false,
                },
                None => PackageExportPaths {
                    paths: BTreeSet::new(),
                    blocked_or_unresolved: true,
                },
            }
        }
        JsonValue::Object(map) => {
            map.values()
                .fold(PackageExportPaths::default(), |mut all, branch| {
                    let resolved = package_export_paths(package_root, branch, capture);
                    all.paths.extend(resolved.paths);
                    all.blocked_or_unresolved |= resolved.blocked_or_unresolved;
                    all
                })
        }
        // `null` deliberately contributes no path: it is an explicit blocked
        // export branch, not an empty/default candidate.
        _ => PackageExportPaths {
            paths: BTreeSet::new(),
            blocked_or_unresolved: true,
        },
    }
}

fn resolve_installed_package_entry(
    package_root: &Path,
    manifest: &PackageManifest,
    specifier: &str,
    package_name: &str,
) -> PackageEntry {
    let Some(subpath) = package_subpath(specifier, package_name) else {
        return PackageEntry {
            resolution: "invalid-package-specifier",
            path: None,
            candidates: BTreeSet::new(),
        };
    };
    let export_key = if subpath.is_empty() {
        ".".to_string()
    } else {
        format!("./{subpath}")
    };
    if let Some(exports) = &manifest.exports {
        let Some((target, capture)) = package_export_value(exports, &export_key) else {
            return PackageEntry {
                resolution: "conditional-or-unexported-package-export",
                path: None,
                candidates: BTreeSet::new(),
            };
        };
        let paths = package_export_paths(package_root, target, &capture);
        return match (paths.paths.len(), paths.blocked_or_unresolved) {
            (1, false) => PackageEntry {
                resolution: "exact-package-export",
                path: paths.paths.iter().next().cloned(),
                candidates: paths.paths,
            },
            _ => PackageEntry {
                // A condition map (for example import/require/browser/default)
                // has no universally correct branch without the caller's
                // runtime conditions. Preserve that uncertainty explicitly.
                resolution: "conditional-or-unexported-package-export",
                path: None,
                candidates: paths.paths,
            },
        };
    }
    if !subpath.is_empty() {
        return match resolve_package_file(package_root, subpath) {
            Some(path) => PackageEntry {
                resolution: "exact-package-subpath",
                candidates: BTreeSet::from([path.clone()]),
                path: Some(path),
            },
            None => PackageEntry {
                resolution: "unresolved-package-subpath",
                path: None,
                candidates: BTreeSet::new(),
            },
        };
    }
    let main = manifest.main.as_deref().unwrap_or("index.js");
    match resolve_package_file(package_root, main) {
        Some(path) => PackageEntry {
            resolution: "legacy-package-main",
            candidates: BTreeSet::from([path.clone()]),
            path: Some(path),
        },
        None => PackageEntry {
            resolution: "unresolved-package-main",
            path: None,
            candidates: BTreeSet::new(),
        },
    }
}

fn resolve_relative_source_with_declarations(
    importer: &Path,
    specifier: &str,
    include_declarations: bool,
) -> Option<PathBuf> {
    let base = importer.parent()?.join(specifier);
    let candidates = resolve_source_candidates(base, include_declarations);
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

/// Extensionless source resolution is only exact when its candidate set has
/// one physical file. Choosing the first `js/ts/...` extension is a tool
/// preference, not a Node/TypeScript proof, and can falsely cover divergent
/// dependency behavior.
fn resolve_source_candidates(base: PathBuf, include_declarations: bool) -> BTreeSet<PathBuf> {
    let mut candidates = vec![base.clone()];
    candidates.extend(
        CODE_EXTENSIONS
            .iter()
            .map(|extension| base.with_extension(extension)),
    );
    candidates.extend(
        CODE_EXTENSIONS
            .iter()
            .map(|extension| base.join(format!("index.{extension}"))),
    );
    if include_declarations {
        candidates.push(base.with_extension("d.ts"));
        candidates.push(base.join("index.d.ts"));
    }
    candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .filter_map(|path| path.canonicalize().ok())
        .collect()
}

fn resolve_relative_source(importer: &Path, specifier: &str) -> Option<PathBuf> {
    resolve_relative_source_with_declarations(importer, specifier, false)
}

fn resolve_relative_type_source(importer: &Path, specifier: &str) -> Option<PathBuf> {
    resolve_relative_source_with_declarations(importer, specifier, true)
}

fn resolve_source_from_base(
    base: &Path,
    target: &str,
    include_declarations: bool,
) -> Option<PathBuf> {
    let candidates = resolve_source_candidates(base.join(target), include_declarations);
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn tsconfig_path_target(pattern: &str, target: &str, specifier: &str) -> Option<String> {
    match pattern.matches('*').count() {
        0 if pattern == specifier => (target.matches('*').count() == 0).then(|| target.to_string()),
        1 => {
            let (prefix, suffix) = pattern.split_once('*')?;
            let matched = specifier
                .strip_prefix(prefix)?
                .strip_suffix(suffix)
                .unwrap_or_default();
            (target.matches('*').count() == 1).then(|| target.replacen('*', matched, 1))
        }
        _ => None,
    }
}

/// Resolves aliases from the effective `extends` chain of the importing
/// project. A child overrides a matching path key from its parent; project
/// references deliberately do not participate. Among patterns, TypeScript
/// selects the most specific match, then tries its declared targets in order.
fn resolve_tsconfig_path(
    importer: &Path,
    project_root: &Path,
    specifier: &str,
    include_declarations: bool,
) -> Option<TsConfigPathEntry> {
    if specifier.starts_with('.') || specifier.starts_with('/') || specifier.starts_with('#') {
        return None;
    }
    let root_config = nearest_tsconfig(importer, project_root)?;
    let canonical_project_root = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
    let mut rules = BTreeMap::<String, (PathBuf, Vec<String>)>::new();
    for (config_path, config) in cached_tsconfig_tree(&root_config) {
        let config_dir = config_path.parent().unwrap_or(&config_path);
        let base_url = config
            .compiler_options
            .base_url
            .as_deref()
            .map(|base_url| config_dir.join(base_url))
            .unwrap_or_else(|| config_dir.to_path_buf());
        for (pattern, targets) in config.compiler_options.paths {
            rules.insert(pattern, (base_url.clone(), targets));
        }
    }
    let mut matching = rules
        .iter()
        .filter_map(|(pattern, rule)| {
            tsconfig_path_target(pattern, pattern, specifier).map(|_| {
                let specificity = if pattern.contains('*') {
                    pattern.len() - 1
                } else {
                    usize::MAX
                };
                (specificity, pattern, rule)
            })
        })
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));
    let (_, pattern, (base_url, targets)) = matching.first()?;
    for target in targets {
        let Some(target) = tsconfig_path_target(pattern, target, specifier) else {
            continue;
        };
        if let Some(path) = resolve_source_from_base(base_url, &target, include_declarations)
            .filter(|path| path.starts_with(&canonical_project_root))
        {
            return Some(TsConfigPathEntry {
                resolution: "exact-tsconfig-path",
                path: Some(path),
            });
        }
    }
    Some(TsConfigPathEntry {
        resolution: "unresolved-tsconfig-path",
        path: None,
    })
}

fn package_runtime_sha256(package_root: &Path) -> Option<String> {
    let selected_root = package_root.canonicalize().ok()?;
    let mut files = Vec::new();
    for entry in WalkDir::new(&selected_root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "node_modules")
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".d.ts"))
        {
            continue;
        }
        let name = path.file_name().and_then(|name| name.to_str());
        let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
            continue;
        };
        if !CODE_EXTENSIONS.contains(&extension) && name != Some("package.json") {
            continue;
        }
        let relative = path.strip_prefix(&selected_root).ok()?.to_string_lossy();
        let contents = fs::read(path).ok()?;
        files.push(format!("{relative}\0{}", sha256(contents)));
    }
    (!files.is_empty()).then(|| sha256(files.join("\n")))
}

fn dependency_provenance(index: &ProjectIndex, side: &str) -> Vec<DependencyProvenance> {
    let project_root = Path::new(&index.root);
    let nodes = index
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    let mut runtime_hashes = HashMap::<PathBuf, Option<String>>::new();
    for edge in &index.graph_edges {
        if !matches!(
            edge.kind.as_str(),
            "ImportsBinding"
                | "Imports"
                | "TypeImportsBinding"
                | "TypeImports"
                | "RequiresBinding"
                | "Requires"
                | "DynamicImports"
                | "DynamicImportsBinding"
                | "ReExportsBinding"
                | "TypeReExportsBinding"
        ) {
            continue;
        }
        let Some(module) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        let Some(specifier) = module.label.strip_prefix("module:") else {
            continue;
        };
        let binding = matches!(
            edge.kind.as_str(),
            "ImportsBinding" | "TypeImportsBinding" | "RequiresBinding" | "DynamicImportsBinding"
        )
        .then(|| edge.source.clone());
        let importer_file = nodes
            .get(edge.source.as_str())
            .map(|node| node.file.clone())
            .unwrap_or_else(|| module.file.clone());
        let imported_export = if matches!(
            edge.kind.as_str(),
            "ImportsBinding"
                | "TypeImportsBinding"
                | "RequiresBinding"
                | "DynamicImportsBinding"
                | "ReExportsBinding"
                | "TypeReExportsBinding"
        ) {
            edge.label
                .clone()
                .unwrap_or_else(|| "<unknown-module-contract>".to_string())
        } else if edge.kind == "Requires" {
            "<commonjs-require>".to_string()
        } else if edge.kind == "DynamicImports" {
            "<dynamic-import>".to_string()
        } else if matches!(edge.kind.as_str(), "TypeImports" | "TypeReExportsBinding") {
            "<type-only>".to_string()
        } else {
            "<side-effect>".to_string()
        };
        let key = (
            importer_file.clone(),
            specifier.to_string(),
            imported_export.clone(),
            binding.clone(),
        );
        if !seen.insert(key) {
            continue;
        }
        let importer = project_root.join(&importer_file);
        let mut entry_candidates = Vec::new();
        let (
            resolution,
            resolved_path,
            package,
            version,
            package_runtime_sha256,
            entry_resolution,
            entry_path,
            entry_sha256,
        ) = if specifier.starts_with('.') || specifier.starts_with('/') {
            let type_only = matches!(
                edge.kind.as_str(),
                "TypeImportsBinding" | "TypeImports" | "TypeReExportsBinding"
            );
            match resolve_project_module_path(project_root, &importer, specifier, type_only) {
                Some(path) => (
                    "resolved-local-source",
                    Some(
                        path.strip_prefix(project_root)
                            .unwrap_or(&path)
                            .display()
                            .to_string(),
                    ),
                    None,
                    None,
                    None,
                    Some("exact-relative-source"),
                    Some(
                        path.strip_prefix(project_root)
                            .unwrap_or(&path)
                            .display()
                            .to_string(),
                    ),
                    fs::read(&path).ok().map(sha256),
                ),
                None => (
                    "unresolved-or-local",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            }
        } else if specifier.starts_with('#') {
            let entry = resolve_package_import(&importer, project_root, specifier);
            entry_candidates.extend(entry.candidates.iter().map(|path| {
                path.strip_prefix(project_root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            }));
            let entry_sha256 = entry
                .path
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .map(sha256);
            let entry_path = entry.path.as_ref().map(|path| {
                path.strip_prefix(project_root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            });
            (
                if entry.path.is_some() {
                    "resolved-package-import-map"
                } else {
                    entry.resolution
                },
                entry_path.clone(),
                None,
                None,
                None,
                Some(entry.resolution),
                entry_path,
                entry_sha256,
            )
        } else if let Some(entry) = resolve_tsconfig_path(
            &importer,
            project_root,
            specifier,
            matches!(
                edge.kind.as_str(),
                "TypeImportsBinding" | "TypeImports" | "TypeReExportsBinding"
            ),
        ) {
            let entry_sha256 = entry
                .path
                .as_ref()
                .and_then(|path| fs::read(path).ok())
                .map(sha256);
            let entry_path = entry.path.as_ref().map(|path| {
                path.strip_prefix(project_root)
                    .unwrap_or(path)
                    .display()
                    .to_string()
            });
            (
                if entry.path.is_some() {
                    "resolved-tsconfig-path"
                } else {
                    entry.resolution
                },
                entry_path.clone(),
                None,
                None,
                None,
                Some(entry.resolution),
                entry_path,
                entry_sha256,
            )
        } else if let Some(package_name) = package_name_from_specifier(specifier) {
            match resolve_installed_package(
                importer.parent().unwrap_or(project_root),
                project_root,
                package_name,
            ) {
                Some(root) => match read_package_manifest(&root.join("package.json")) {
                    Some(manifest) => {
                        let runtime_hash = runtime_hashes
                            .entry(root.clone())
                            .or_insert_with(|| package_runtime_sha256(&root))
                            .clone();
                        let entry = resolve_installed_package_entry(
                            &root,
                            &manifest,
                            specifier,
                            package_name,
                        );
                        entry_candidates.extend(entry.candidates.iter().map(|path| {
                            path.strip_prefix(&root)
                                .unwrap_or(path)
                                .display()
                                .to_string()
                        }));
                        let entry_sha256 = entry
                            .path
                            .as_ref()
                            .and_then(|path| fs::read(path).ok())
                            .map(sha256);
                        let entry_path = entry.path.as_ref().map(|path| {
                            path.strip_prefix(&root)
                                .unwrap_or(path)
                                .display()
                                .to_string()
                        });
                        (
                            "resolved-installed-package",
                            Some(root.display().to_string()),
                            manifest.name.or_else(|| Some(package_name.to_string())),
                            manifest.version,
                            runtime_hash,
                            Some(entry.resolution),
                            entry_path,
                            entry_sha256,
                        )
                    }
                    None => (
                        "ambiguous-installed-package",
                        Some(root.display().to_string()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                },
                None => (
                    "unresolved-or-local",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            }
        } else {
            (
                "unresolved-or-local",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };
        rows.push(DependencyProvenance {
            side: side.to_string(),
            edge_kind: edge.kind.clone(),
            importer_file,
            specifier: specifier.to_string(),
            imported_export,
            binding_symbol_id: binding,
            module_node_id: module.id.clone(),
            resolution,
            resolved_path,
            package,
            version,
            package_runtime_sha256,
            entry_resolution,
            entry_path,
            entry_sha256,
            entry_candidates,
        });
    }
    rows.sort_by(|left, right| {
        left.side
            .cmp(&right.side)
            .then_with(|| left.importer_file.cmp(&right.importer_file))
            .then_with(|| left.specifier.cmp(&right.specifier))
            .then_with(|| left.imported_export.cmp(&right.imported_export))
            .then_with(|| left.edge_kind.cmp(&right.edge_kind))
            .then_with(|| left.binding_symbol_id.cmp(&right.binding_symbol_id))
    });
    rows
}

fn equivalent_package_contract(left: &DependencyProvenance, right: &DependencyProvenance) -> bool {
    left.resolution == "resolved-installed-package"
        && right.resolution == "resolved-installed-package"
        && left.package == right.package
        && left.version == right.version
        && left.package_runtime_sha256.is_some()
        && left.package_runtime_sha256 == right.package_runtime_sha256
        && left.entry_resolution.is_some()
        && left.entry_resolution == right.entry_resolution
        && left.entry_sha256.is_some()
        && left.entry_sha256 == right.entry_sha256
        && left.specifier == right.specifier
        && left.imported_export == right.imported_export
}

/// Pair import bindings only after the semantic graph has identified their
/// lexical relationship.  This deliberately leaves a matched package contract
/// at candidate level: graph correspondence is static evidence, not a claim
/// that the imported API is exercised identically at runtime.
fn dependency_binding_contracts(
    provenance: &[DependencyProvenance],
    relations: &[GraphRelation],
) -> Vec<DependencyBindingContract> {
    let mut right_by_binding = HashMap::<&str, Vec<(usize, &DependencyProvenance)>>::new();
    for (index, row) in provenance
        .iter()
        .enumerate()
        .filter(|(_, row)| row.side == "right")
    {
        if let Some(binding) = &row.binding_symbol_id {
            right_by_binding
                .entry(binding)
                .or_default()
                .push((index, row));
        }
    }
    let mut related_right = HashMap::<&str, Vec<&str>>::new();
    for relation in relations {
        related_right
            .entry(relation.left.id.as_str())
            .or_default()
            .push(relation.right.id.as_str());
    }
    let mut used_right = BTreeSet::new();
    let mut contracts = Vec::new();
    for left in provenance.iter().filter(|row| row.side == "left") {
        let candidates = left
            .binding_symbol_id
            .as_deref()
            .and_then(|binding| related_right.get(binding))
            .into_iter()
            .flatten()
            .flat_map(|binding| right_by_binding.get(binding).into_iter().flatten())
            .collect::<Vec<_>>();
        if candidates.len() == 1 {
            let (right_index, right) = *candidates[0];
            // `module_node_id` is shared by every named import from a module;
            // it cannot identify a consumed binding. Preserve row identity so
            // `{ a, b } from "pkg"` cannot hide an unpaired contract.
            used_right.insert(right_index);
            let (disposition, reason) = if equivalent_package_contract(left, right) {
                (
                    "candidate-identical-package-contract",
                    "Lexical bindings are graph-related; package name, version, runtime fingerprint, specifier and imported export are identical. Static graph evidence still requires behavior review.".to_string(),
                )
            } else {
                (
                    "changed-or-unresolved-package-contract",
                    "Lexical bindings are graph-related, but package identity, runtime fingerprint, specifier or imported export is changed or unresolved.".to_string(),
                )
            };
            contracts.push(DependencyBindingContract {
                disposition,
                left: Some(left.clone()),
                right: Some(right.clone()),
                reason,
            });
        } else {
            contracts.push(DependencyBindingContract {
                disposition: "unpaired-local-import-binding",
                left: Some(left.clone()),
                right: None,
                reason: if candidates.is_empty() {
                    "No unique graph-related upstream import binding exists.".to_string()
                } else {
                    "Multiple graph-related upstream import bindings exist; choosing one would be unsound."
                        .to_string()
                },
            });
        }
    }
    for (right_index, right) in provenance
        .iter()
        .enumerate()
        .filter(|(_, row)| row.side == "right")
    {
        if used_right.contains(&right_index) {
            continue;
        }
        contracts.push(DependencyBindingContract {
            disposition: "unpaired-upstream-import-binding",
            left: None,
            right: Some(right.clone()),
            reason: "No unique graph-related local import binding exists.".to_string(),
        });
    }
    contracts.sort_by(|left, right| {
        let left_id = left
            .left
            .as_ref()
            .or(left.right.as_ref())
            .map(|row| row.module_node_id.as_str())
            .unwrap_or("");
        let right_id = right
            .left
            .as_ref()
            .or(right.right.as_ref())
            .map(|row| row.module_node_id.as_str())
            .unwrap_or("");
        left.disposition
            .cmp(right.disposition)
            .then_with(|| left_id.cmp(right_id))
    });
    contracts
}

struct DependencyContextEntry {
    start: u32,
    end: u32,
    context: Option<String>,
}

type DependencyContextIndex = HashMap<String, Vec<DependencyContextEntry>>;

fn build_dependency_context_index(
    index: &ProjectIndex,
    provenance: &[DependencyProvenance],
) -> DependencyContextIndex {
    let provenance_by_binding = provenance
        .iter()
        .filter_map(|row| row.binding_symbol_id.as_deref().map(|id| (id, row)))
        .collect::<HashMap<_, _>>();
    let nodes = index
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut contexts = HashMap::<String, Vec<DependencyContextEntry>>::new();
    for edge in &index.graph_edges {
        if !matches!(
            edge.kind.as_str(),
            "References" | "Calls" | "Instantiates" | "Renders"
        ) {
            continue;
        }
        let Some(owner) = nodes.get(edge.source.as_str()) else {
            continue;
        };
        let Some(binding) = provenance_by_binding.get(edge.target.as_str()) else {
            continue;
        };
        let context = {
            // A matching spelling for an unresolved or conditional import is not
            // evidence that two units execute the same dependency. Do not promote
            // a strict AST match to proven structure until this edge has one exact
            // source/entry identity on both sides.
            if !matches!(
                binding.resolution,
                "resolved-local-source"
                    | "resolved-tsconfig-path"
                    | "resolved-package-import-map"
                    | "resolved-installed-package"
            ) || binding.entry_resolution.is_none()
                || binding.entry_sha256.is_none()
            {
                None
            } else {
                Some(format!(
                    "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                    binding.resolution,
                    binding.specifier,
                    binding.imported_export,
                    binding.package.as_deref().unwrap_or(""),
                    binding.version.as_deref().unwrap_or(""),
                    binding.package_runtime_sha256.as_deref().unwrap_or(""),
                    binding.resolved_path.as_deref().unwrap_or(""),
                    binding.entry_resolution.unwrap_or(""),
                    binding.entry_path.as_deref().unwrap_or(""),
                    binding.entry_sha256.as_deref().unwrap_or(""),
                ))
            }
        };
        contexts
            .entry(owner.file.clone())
            .or_default()
            .push(DependencyContextEntry {
                start: owner.start,
                end: owner.end,
                context,
            });
    }
    contexts
}

fn units_have_equivalent_dependency_context(
    left_contexts: &DependencyContextIndex,
    right_contexts: &DependencyContextIndex,
    left_unit: &Unit,
    right_unit: &Unit,
) -> bool {
    fn context_for(index: &DependencyContextIndex, unit: &Unit) -> Option<BTreeSet<String>> {
        let mut result = BTreeSet::new();
        for entry in index.get(&unit.file).into_iter().flatten() {
            if entry.start < unit.start || entry.end > unit.end {
                continue;
            }
            let Some(context) = &entry.context else {
                return None;
            };
            result.insert(context.clone());
        }
        Some(result)
    }
    matches!(
        (context_for(left_contexts, left_unit), context_for(right_contexts, right_unit)),
        (Some(left), Some(right)) if left == right
    )
}

fn discover_dependencies(
    input: &Path,
    observed: Option<&ProjectIndex>,
) -> Result<Option<Discovery>> {
    let root = input
        .canonicalize()
        .with_context(|| format!("cannot resolve {}", input.display()))?;
    let mut manifest_paths = Vec::new();
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !should_skip(entry, &root))
    {
        let entry = entry?;
        if entry.file_type().is_file() && entry.file_name() == "package.json" {
            manifest_paths.push(entry.path().to_path_buf());
        }
    }

    let mut queue = VecDeque::<(PathBuf, String)>::new();
    // The application import graph is the authoritative runtime boundary.
    // Scanning every manifest dependency first drags in dev/build tooling and
    // can materialize hundreds of thousands of irrelevant AST nodes.  Use the
    // manifest-wide fallback only when no observed graph is available.
    if observed.is_none() {
        for manifest_path in manifest_paths {
            let Some(manifest) = read_package_manifest(&manifest_path) else {
                continue;
            };
            let Some(parent) = manifest_path.parent() else {
                continue;
            };
            for name in manifest_dependency_names(&manifest) {
                if let Some(package_root) = resolve_installed_package(parent, &root, &name) {
                    if package_root.to_string_lossy().contains("/node_modules/")
                        || package_root.to_string_lossy().contains("/.pnpm/")
                    {
                        queue.push_back((package_root, name));
                    }
                }
            }
        }
    }

    // Manifests are not a complete runtime boundary: bundled/projection trees
    // often import an installed package that is absent from the root manifest
    // (or is injected by a workspace/toolchain). Seed the same closure from
    // observed import edges whenever an index is available.
    if let Some(observed) = observed {
        let nodes = observed
            .graph_nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        for edge in &observed.graph_edges {
            if !matches!(
                edge.kind.as_str(),
                "Imports"
                    | "ImportsBinding"
                    | "Requires"
                    | "RequiresBinding"
                    | "DynamicImports"
                    | "DynamicImportsBinding"
                    | "ReExportsBinding"
                    | "TypeImports"
                    | "TypeImportsBinding"
                    | "TypeReExportsBinding"
            ) {
                continue;
            }
            let Some(module) = nodes.get(edge.target.as_str()) else {
                continue;
            };
            let Some(specifier) = module.label.strip_prefix("module:") else {
                continue;
            };
            let Some(package_name) = package_name_from_specifier(specifier) else {
                continue;
            };
            let importer = root.join(&module.file);
            if let Some(package_root) =
                resolve_installed_package(importer.parent().unwrap_or(&root), &root, package_name)
            {
                queue.push_back((package_root, package_name.to_string()));
            }
        }
    }

    let mut packages = BTreeMap::<PathBuf, (String, String)>::new();
    while let Some((package_root, requested_name)) = queue.pop_front() {
        if packages.contains_key(&package_root) {
            continue;
        }
        let Some(manifest) = read_package_manifest(&package_root.join("package.json")) else {
            continue;
        };
        let name = manifest.name.clone().unwrap_or(requested_name);
        let version = manifest
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        packages.insert(package_root.clone(), (name, version));
        for dependency in manifest_dependency_names(&manifest) {
            if let Some(dependency_root) =
                resolve_installed_package(&package_root, &root, &dependency)
            {
                queue.push_back((dependency_root, dependency.clone()));
            }
        }
    }
    if packages.is_empty() {
        return Ok(None);
    }

    let mut files = Vec::new();
    let mut skipped = Vec::new();
    for (package_root, (name, version)) in &packages {
        let package_key = format!(
            "{}@{}-{}",
            name,
            version,
            &sha256(package_root.to_string_lossy().as_bytes())[..10]
        );
        let selected_root = ["dist", "lib", "cjs", "esm", "build"]
            .into_iter()
            .map(|relative| package_root.join(relative))
            .find(|candidate| candidate.is_dir())
            .unwrap_or_else(|| package_root.clone());
        for entry in WalkDir::new(&selected_root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|entry| {
                let skip = entry.file_type().is_dir()
                    && entry.path() != selected_root
                    && matches!(
                        entry.file_name().to_string_lossy().as_ref(),
                        ".git"
                            | ".history"
                            | "bin"
                            | "coverage"
                            | "docs"
                            | "examples"
                            | "node_modules"
                            | "test"
                            | "tests"
                    );
                if skip {
                    skipped.push(format!(
                        "npm/{}/{}",
                        package_key,
                        entry
                            .path()
                            .strip_prefix(&selected_root)
                            .unwrap_or(entry.path())
                            .display()
                    ));
                }
                !skip
            })
        {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".d.ts"))
            {
                continue;
            }
            let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
                continue;
            };
            if !CODE_EXTENSIONS.contains(&extension) {
                continue;
            }
            let package_relative = path.strip_prefix(&selected_root).unwrap_or(path);
            if [".test.", ".spec.", ".stories."]
                .iter()
                .any(|needle| package_relative.to_string_lossy().contains(needle))
            {
                continue;
            }
            files.push((
                path.to_path_buf(),
                format!(
                    "npm/{package_key}/{}/{}",
                    selected_root
                        .strip_prefix(package_root)
                        .unwrap_or(&selected_root)
                        .display(),
                    package_relative.display()
                ),
            ));
        }
    }
    files.sort_by(|left, right| left.1.cmp(&right.1));
    files.dedup_by(|left, right| left.1 == right.1);
    skipped.sort();
    skipped.dedup();
    Ok(Some(Discovery {
        root,
        files,
        skipped,
        corpus: CorpusSelection {
            mode: "installed-runtime-dependencies",
            roots: packages
                .values()
                .map(|(name, version)| format!("{name}@{version}"))
                .collect(),
            excluded_derivative_roots: Vec::new(),
            source_root: None,
            projection_tool: None,
        },
    }))
}

fn cache_root() -> PathBuf {
    env::var_os("PROJECT_AST_MATCH_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("project-parity-cache-v3"))
}

struct LoadedSourceMap {
    sha256: Option<String>,
    decoded: Option<DecodedMap>,
    error: Option<String>,
}

fn adjacent_source_map_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".map");
    PathBuf::from(value)
}

fn load_adjacent_source_map(path: &Path) -> Option<LoadedSourceMap> {
    let map_path = adjacent_source_map_path(path);
    if !map_path.exists() {
        return None;
    }
    let bytes = match fs::read(&map_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Some(LoadedSourceMap {
                sha256: None,
                decoded: None,
                error: Some(format!("read {}: {error}", map_path.display())),
            });
        }
    };
    let source_map_sha256 = sha256(&bytes);
    match sourcemap::decode_slice(&bytes) {
        Ok(decoded) => Some(LoadedSourceMap {
            sha256: Some(source_map_sha256),
            decoded: Some(decoded),
            error: None,
        }),
        Err(error) => Some(LoadedSourceMap {
            sha256: Some(source_map_sha256),
            decoded: None,
            error: Some(format!("decode {}: {error}", map_path.display())),
        }),
    }
}

fn index_file(
    path: &Path,
    relative: &str,
    side: &str,
    cache_dir: &Path,
) -> Result<(IndexedFile, bool)> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let source_sha256 = sha256(&source);
    let source_map = load_adjacent_source_map(path);
    let source_map_fingerprint = match source_map.as_ref() {
        None => "absent",
        Some(source_map) => source_map.sha256.as_deref().unwrap_or("unreadable"),
    };
    let cache_key = sha256(format!(
        "{INDEX_CACHE_VERSION}\0{}\0{side}\0{relative}\0{source_sha256}\0{source_map_fingerprint}",
        path.display()
    ));
    let cache_path = cache_dir.join(format!("{cache_key}.json.zst"));
    if let Ok(cached) = fs::read(&cache_path) {
        if let Ok(decoded) = zstd::stream::decode_all(cached.as_slice()) {
            if let Ok(indexed) = serde_json::from_slice::<IndexedFile>(&decoded) {
                return Ok((indexed, true));
            }
        }
    }
    let source_type =
        SourceType::from_path(path).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (canonical, original_units, graph) = canonicalize(&source, source_type, relative, side)?;
    let units = collect_units(
        &canonical,
        &source,
        source_type,
        relative,
        side,
        original_units,
        source_map
            .as_ref()
            .and_then(|source_map| source_map.decoded.as_ref()),
    )?;
    let indexed = IndexedFile {
        record: FileRecord {
            file: relative.to_string(),
            bytes: source.len(),
            source_sha256,
            source_map_sha256: source_map
                .as_ref()
                .and_then(|source_map| source_map.sha256.clone()),
            source_map_error: source_map
                .as_ref()
                .and_then(|source_map| source_map.error.clone()),
            units: units.len(),
        },
        units,
        graph,
    };
    if let Ok(serialized) = serde_json::to_vec(&indexed) {
        if let Ok(compressed) = zstd::stream::encode_all(serialized.as_slice(), 3) {
            let _ = fs::write(&cache_path, compressed);
        }
    }
    Ok((indexed, false))
}

fn compact_semantic_graph(graph: &mut SemanticGraph) {
    for node in &mut graph.nodes {
        node.tokens.clear();
    }
    let retained = graph
        .nodes
        .iter()
        .filter(|node| !node.kind.ends_with("Site") && node.kind != "MemberAccess")
        .map(|node| node.id.clone())
        .collect::<HashSet<_>>();
    graph.nodes.retain(|node| retained.contains(&node.id));
    graph
        .edges
        .retain(|edge| retained.contains(&edge.source) && retained.contains(&edge.target));
}

fn index_discovery(discovery: Discovery, side: &str) -> Result<ProjectIndex> {
    let Discovery {
        root,
        files: discovered,
        skipped,
        corpus,
    } = discovery;
    let cache_dir = cache_root();
    let _ = fs::create_dir_all(&cache_dir);
    let graph_artifact = cache_dir.join(format!(
        "project-graph-{}-{side}.jsonl",
        sha256(root.to_string_lossy().as_bytes())
    ));
    let graph_file = fs::File::create(&graph_artifact)
        .with_context(|| format!("create {}", graph_artifact.display()))?;
    let mut graph_output = io::BufWriter::new(graph_file);
    let mut files = Vec::new();
    let mut units = Vec::new();
    let mut graph_nodes = Vec::new();
    let mut graph_edges = Vec::new();
    let mut failures = Vec::new();
    let mut cache_hits = 0;
    let mut cache_misses = 0;
    // File count is a conservative proxy for bundle scale. A single emitted
    // chunk can contain hundreds of thousands of nodes, so a 100-file
    // projection must use the same compact correspondence tier as a large
    // multi-chunk renderer tree.
    let compact_large_graph = discovered.len() > 100;
    // Process one file at a time instead of collecting every `IndexedFile`
    // into a temporary vector.  A production renderer corpus can contain
    // thousands of chunks; retaining both the per-file AST graphs and the
    // flattened project graph briefly doubled peak RSS and caused the cold
    // report to be killed by the OS before publication.
    for (path, relative) in discovered {
        let file = relative.clone();
        let result = index_file(&path, &relative, side, &cache_dir);
        match result {
            Ok((mut indexed, cache_hit)) => {
                if cache_hit {
                    cache_hits += 1;
                } else {
                    cache_misses += 1;
                }
                files.push(indexed.record);
                for node in &indexed.graph.nodes {
                    serde_json::to_writer(
                        &mut graph_output,
                        &serde_json::json!({"recordType":"node","side":side,"node":node}),
                    )?;
                    graph_output.write_all(b"\n")?;
                }
                for edge in &indexed.graph.edges {
                    serde_json::to_writer(
                        &mut graph_output,
                        &serde_json::json!({"recordType":"edge","side":side,"edge":edge}),
                    )?;
                    graph_output.write_all(b"\n")?;
                }
                if compact_large_graph {
                    compact_semantic_graph(&mut indexed.graph);
                }
                units.extend(indexed.units);
                graph_nodes.extend(indexed.graph.nodes);
                graph_edges.extend(indexed.graph.edges);
            }
            Err(error) => failures.push(Failure {
                file,
                error: format!("{error:#}"),
            }),
        }
    }
    files.sort_by(|left, right| left.file.cmp(&right.file));
    graph_output.flush()?;
    units.sort_by(|left, right| left.id.cmp(&right.id));
    graph_nodes.sort_by(|left, right| left.id.cmp(&right.id));
    graph_edges.sort();
    failures.sort_by(|left, right| left.file.cmp(&right.file));
    let project_sha256 = sha256(
        files
            .iter()
            .map(|file| {
                format!(
                    "{}\0{}\0{}",
                    file.file,
                    file.source_sha256,
                    file.source_map_sha256.as_deref().unwrap_or_else(|| {
                        if file.source_map_error.is_some() {
                            "unreadable"
                        } else {
                            "absent"
                        }
                    })
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    );
    eprintln!("indexed {side}: cache hits {cache_hits}, misses {cache_misses}");
    let mut project = ProjectIndex {
        root: root.display().to_string(),
        corpus,
        project_sha256,
        files,
        units,
        graph_nodes,
        graph_edges,
        graph_artifact: Some(graph_artifact),
        failures,
        skipped,
    };
    link_relative_module_owners(&mut project);
    Ok(project)
}

fn index_project(input: &Path, side: &str) -> Result<ProjectIndex> {
    let mut index = index_discovery(discover(input)?, side)?;
    link_installed_package_entries(&mut index);
    Ok(index)
}

/// Build dependency evidence without retaining a second full semantic graph.
/// Large node_modules trees are still represented completely by file records,
/// hashes and package provenance; AST indexing is reserved for small closures
/// where exact dependency-unit evidence is affordable.
fn index_dependency_evidence(discovery: Discovery) -> Result<ProjectIndex> {
    if discovery.files.len() <= 200 {
        return index_discovery(discovery, "dependency");
    }
    let Discovery {
        root,
        files: discovered,
        skipped,
        corpus,
    } = discovery;
    let mut files = Vec::with_capacity(discovered.len());
    for (path, relative) in discovered {
        let source = fs::read_to_string(&path)
            .with_context(|| format!("read dependency {}", path.display()))?;
        files.push(FileRecord {
            file: relative,
            bytes: source.len(),
            source_sha256: sha256(&source),
            source_map_sha256: None,
            source_map_error: None,
            units: 0,
        });
    }
    files.sort_by(|left, right| left.file.cmp(&right.file));
    let project_sha256 = sha256(
        files
            .iter()
            .map(|file| format!("{}\0{}", file.file, file.source_sha256))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    Ok(ProjectIndex {
        root: root.display().to_string(),
        corpus,
        project_sha256,
        files,
        units: Vec::new(),
        graph_nodes: Vec::new(),
        graph_edges: Vec::new(),
        graph_artifact: None,
        failures: Vec::new(),
        skipped,
    })
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct ProjectModuleResolutionKey {
    root: PathBuf,
    importer: PathBuf,
    specifier: String,
    type_only: bool,
}

type ProjectModuleResolutionCache = HashMap<ProjectModuleResolutionKey, Option<PathBuf>>;

static PROJECT_MODULE_RESOLUTION_CACHE: OnceLock<Mutex<ProjectModuleResolutionCache>> =
    OnceLock::new();

/// Materialize installed package boundaries in the same graph as the project
/// source.  The dependency corpus remains useful for broad package analysis,
/// but a source import must not terminate at an opaque `module:lodash` node:
/// it has a resolved package/version/entry contract, or an explicit set of
/// conditional entry candidates.  We intentionally model package boundaries
/// here rather than pretending that every installed package file is part of
/// the application's own source tree.
fn link_installed_package_entries(index: &mut ProjectIndex) {
    let root = Path::new(&index.root);
    let nodes = index
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut additions = BTreeSet::new();
    let mut nodes_to_add = BTreeMap::<String, GraphNode>::new();
    for edge in &index.graph_edges {
        if !matches!(
            edge.kind.as_str(),
            "Imports"
                | "ImportsBinding"
                | "TypeImports"
                | "TypeImportsBinding"
                | "Requires"
                | "RequiresBinding"
                | "DynamicImports"
                | "DynamicImportsBinding"
                | "ReExportsBinding"
                | "TypeReExportsBinding"
        ) {
            continue;
        }
        let Some(module) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        let Some(specifier) = module.label.strip_prefix("module:") else {
            continue;
        };
        let Some(package_name) = package_name_from_specifier(specifier) else {
            continue;
        };
        let importer = root.join(&module.file);
        let Some(package_root) =
            resolve_installed_package(importer.parent().unwrap_or(root), root, package_name)
        else {
            continue;
        };
        let Some(manifest) = read_package_manifest(&package_root.join("package.json")) else {
            continue;
        };
        let package = manifest
            .name
            .clone()
            .unwrap_or_else(|| package_name.to_string());
        let version = manifest
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let entry =
            resolve_installed_package_entry(&package_root, &manifest, specifier, package_name);
        let candidates = if entry.candidates.is_empty() {
            Vec::new()
        } else {
            entry.candidates.into_iter().collect::<Vec<_>>()
        };
        for candidate in candidates {
            let relative = candidate
                .strip_prefix(&package_root)
                .unwrap_or(&candidate)
                .to_string_lossy()
                .to_string();
            let label = format!("{package}@{version}:{relative}");
            let id = format!(
                "{}:package-entry:{}",
                index.root,
                sha256(format!("{package}\0{version}\0{relative}"))
            );
            nodes_to_add.entry(id.clone()).or_insert_with(|| GraphNode {
                id: id.clone(),
                file: format!("npm/{package}@{version}/{relative}"),
                kind: "PackageEntry".to_string(),
                label: label.clone(),
                start: 0,
                end: 0,
                line: 1,
                scope: None,
                linked_sha256: fs::read(&candidate)
                    .ok()
                    .map(sha256)
                    .unwrap_or_else(|| sha256(&label)),
                tokens: BTreeSet::from([
                    "PackageEntry".to_string(),
                    package.clone(),
                    version.clone(),
                    relative,
                ]),
            });
            additions.insert(GraphEdge {
                source: module.id.clone(),
                target: id,
                kind: if entry.path.is_some() {
                    "ResolvesToPackage"
                } else {
                    "ResolvesToPackageCandidate"
                }
                .to_string(),
                dynamic: edge.dynamic,
                label: Some(specifier.to_string()),
            });
        }
    }
    index.graph_nodes.extend(nodes_to_add.into_values());
    index
        .graph_nodes
        .sort_by(|left, right| left.id.cmp(&right.id));
    index
        .graph_nodes
        .dedup_by(|left, right| left.id == right.id);
    index.graph_edges.extend(additions);
    index.graph_edges.sort();
    index.graph_edges.dedup();
}

/// Attach the parsed dependency source graph to the owning project graph.
/// Dependency units are intentionally not added to the owner matcher (they
/// are evidence, not application owners), but every dependency node/edge is
/// retained under a collision-free namespace and connected to the package
/// entry that caused it to be reachable.
#[allow(dead_code)]
fn merge_dependency_graph(project: &mut ProjectIndex, dependencies: &ProjectIndex) {
    let dependency_ids = dependencies
        .graph_nodes
        .iter()
        .map(|node| (node.id.clone(), format!("dependency:{id}", id = node.id)))
        .collect::<HashMap<_, _>>();
    let mut dependency_nodes = Vec::with_capacity(dependencies.graph_nodes.len());
    for node in &dependencies.graph_nodes {
        let Some(id) = dependency_ids.get(&node.id) else {
            continue;
        };
        let mut node = node.clone();
        node.id = id.clone();
        dependency_nodes.push(node);
    }
    let mut dependency_edges = Vec::with_capacity(dependencies.graph_edges.len());
    for edge in &dependencies.graph_edges {
        let (Some(source), Some(target)) = (
            dependency_ids.get(&edge.source),
            dependency_ids.get(&edge.target),
        ) else {
            continue;
        };
        let mut edge = edge.clone();
        edge.source = source.clone();
        edge.target = target.clone();
        dependency_edges.push(edge);
    }
    project.graph_nodes.extend(dependency_nodes);
    project.graph_edges.extend(dependency_edges);

    let package_entries = project
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "PackageEntry")
        .cloned()
        .collect::<Vec<_>>();
    let dependency_files = project
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "File" && node.file.starts_with("npm/"))
        .cloned()
        .collect::<Vec<_>>();
    let mut links = BTreeSet::new();
    for entry in package_entries {
        let Some((package_version, relative)) = entry.label.split_once(':') else {
            continue;
        };
        let prefix = format!("npm/{package_version}-");
        for file in &dependency_files {
            if file.file.starts_with(&prefix) && file.file.ends_with(&format!("/{relative}")) {
                links.insert(GraphEdge {
                    source: entry.id.clone(),
                    target: file.id.clone(),
                    kind: "ResolvesToDependencySource".to_string(),
                    dynamic: false,
                    label: Some(relative.to_string()),
                });
            }
        }
    }
    project.graph_edges.extend(links);
    project
        .graph_nodes
        .sort_by(|left, right| left.id.cmp(&right.id));
    project.graph_edges.sort();
    project.graph_edges.dedup();
}

/// Link only resolved package-entry nodes to their dependency source file.
/// The complete dependency AST remains in the separate evidence corpus; the
/// primary graph carries this bounded boundary edge for provenance queries.
fn link_dependency_entry_sources(project: &mut ProjectIndex, dependencies: &ProjectIndex) {
    let dependency_files = dependencies
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "File")
        .collect::<Vec<_>>();
    let entries = project
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "PackageEntry")
        .cloned()
        .collect::<Vec<_>>();
    let mut additions = Vec::new();
    for entry in entries {
        let Some((_, relative)) = entry.label.split_once(':') else {
            continue;
        };
        let Some(source) = dependency_files
            .iter()
            .find(|node| node.file.ends_with(relative) || node.label.ends_with(relative))
        else {
            continue;
        };
        additions.push(GraphEdge {
            source: entry.id.clone(),
            target: format!("dependency:{}", source.id),
            kind: "ResolvesToDependencySource".to_string(),
            dynamic: false,
            label: Some(relative.to_string()),
        });
    }
    project.graph_edges.extend(additions);
    project.graph_edges.sort();
    project.graph_edges.dedup();
}

/// Resolve an in-project module through every project-level mechanism the
/// parser records.  Keeping this selection in one place matters: provenance,
/// module ownership and re-export propagation must never disagree about
/// whether an import points at a project file.
fn resolve_project_module_path(
    root: &Path,
    importer: &Path,
    specifier: &str,
    type_only: bool,
) -> Option<PathBuf> {
    let key = ProjectModuleResolutionKey {
        root: root.canonicalize().unwrap_or_else(|_| root.to_path_buf()),
        importer: importer
            .canonicalize()
            .unwrap_or_else(|_| importer.to_path_buf()),
        specifier: specifier.to_string(),
        type_only,
    };
    let cache = PROJECT_MODULE_RESOLUTION_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(resolved) = cache
        .lock()
        .expect("project resolver cache poisoned")
        .get(&key)
    {
        return resolved.clone();
    }
    let resolved = if specifier.starts_with('.') || specifier.starts_with('/') {
        if type_only {
            resolve_relative_type_source(importer, specifier)
        } else {
            resolve_relative_source(importer, specifier)
        }
    } else if specifier.starts_with('#') {
        resolve_package_import(importer, root, specifier).path
    } else {
        resolve_tsconfig_path(importer, root, specifier, type_only).and_then(|entry| entry.path)
    };
    cache
        .lock()
        .expect("project resolver cache poisoned")
        .insert(key, resolved.clone());
    resolved
}

/// Preserve the local-module leg of an import in the semantic graph.  Bundles
/// frequently erase file boundaries, so this edge is only emitted for an
/// exact on-disk Node-style relative resolution; package and unknown imports
/// stay external until their own provenance can be proven.
fn link_relative_module_owners(index: &mut ProjectIndex) {
    let root = Path::new(&index.root);
    let file_nodes = index
        .graph_nodes
        .iter()
        .filter(|node| node.kind == "File")
        .map(|node| (node.file.clone(), node.id.clone()))
        .collect::<HashMap<_, _>>();
    let nodes = index
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut additions = BTreeSet::new();
    let mut exports = HashMap::<(String, String), Vec<String>>::new();
    let mut type_exports = HashMap::<(String, String), Vec<String>>::new();
    // Semantic extraction deliberately keeps a barrel's public-name edge so
    // the raw graph is lossless.  It is not, however, a declaration owner.
    // Record those names before building the owner map; otherwise the barrel
    // placeholder makes an otherwise exact re-export look ambiguous.
    let mut reexported_values = HashSet::<(String, String)>::new();
    let mut reexported_types = HashSet::<(String, String)>::new();
    for edge in &index.graph_edges {
        let destination = match edge.kind.as_str() {
            "ReExportsBinding" => &mut reexported_values,
            "TypeReExportsBinding" => &mut reexported_types,
            _ => continue,
        };
        let Some(module) = nodes.get(edge.source.as_str()) else {
            continue;
        };
        let Some(label) = &edge.label else {
            continue;
        };
        if let Some((exported, _)) = label.split_once(" <- ") {
            destination.insert((module.file.clone(), exported.to_string()));
        }
    }
    for edge in &index.graph_edges {
        let destination = match edge.kind.as_str() {
            "ExportsBinding" => {
                let Some(module) = nodes.get(edge.target.as_str()) else {
                    continue;
                };
                let Some(exported) = &edge.label else {
                    continue;
                };
                if module.label == "module:<current>"
                    && reexported_values.contains(&(module.file.clone(), exported.clone()))
                {
                    continue;
                }
                &mut exports
            }
            "TypeExportsBinding" => {
                let Some(module) = nodes.get(edge.target.as_str()) else {
                    continue;
                };
                let Some(exported) = &edge.label else {
                    continue;
                };
                if module.label == "module:<current>"
                    && reexported_types.contains(&(module.file.clone(), exported.clone()))
                {
                    continue;
                }
                &mut type_exports
            }
            _ => continue,
        };
        let Some(module) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        if module.label != "module:<current>" {
            continue;
        }
        let Some(exported) = &edge.label else {
            continue;
        };
        destination
            .entry((module.file.clone(), exported.clone()))
            .or_default()
            .push(edge.source.clone());
    }

    // Resolve every project-local module leg once.  This table is reused for
    // ordinary imports *and* re-export fixed-point propagation below; the old
    // implementation only joined direct exports and therefore silently lost
    // aliases and barrels such as `a -> b -> c`.
    let mut resolved_modules = HashMap::<String, String>::new();
    for edge in &index.graph_edges {
        let Some(module) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        let Some(specifier) = module.label.strip_prefix("module:") else {
            continue;
        };
        let type_only = matches!(
            edge.kind.as_str(),
            "TypeImports" | "TypeImportsBinding" | "TypeReExportsBinding"
        );
        let importer = root.join(&module.file);
        let Some(resolved) = resolve_project_module_path(root, &importer, specifier, type_only)
        else {
            continue;
        };
        let Ok(relative) = resolved.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().to_string();
        if file_nodes.contains_key(&relative) {
            resolved_modules.insert(module.id.clone(), relative);
        }
    }

    // A named `export { remote as public } from './owner'` is an alias, not
    // an implementation owned by the barrel.  Resolve aliases to a fixed
    // point so imports through arbitrary local barrel chains bind to their
    // concrete declaration.  `export *` is necessarily conservative: default
    // is excluded by the ESM contract, while every known named export remains
    // represented.  Unknown stars stay explicit on their original edge.
    for _ in 0..64 {
        let mut changed = false;
        for edge in &index.graph_edges {
            let (map, reexport_kind) = match edge.kind.as_str() {
                "ReExportsBinding" => (&mut exports, "ReExportsTo"),
                "TypeReExportsBinding" => (&mut type_exports, "TypeReExportsTo"),
                _ => continue,
            };
            let Some(current_module) = nodes.get(edge.source.as_str()) else {
                continue;
            };
            let Some(source_file) = resolved_modules.get(&edge.target) else {
                continue;
            };
            let Some(label) = &edge.label else {
                continue;
            };
            let Some((exported, imported)) = label.split_once(" <- ") else {
                continue;
            };
            let current_file = current_module.file.clone();
            // Collect before mutating `map`: wildcard re-exports preserve the
            // public name of each known source export, while named aliases
            // replace it with the explicit exported name.
            let owners = if imported == "*" {
                map.iter()
                    .filter(|((file, name), _)| file == source_file && name != "default")
                    .flat_map(|((_, name), owners)| {
                        owners
                            .iter()
                            .cloned()
                            .map(|owner| (name.clone(), owner))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            } else {
                map.get(&(source_file.clone(), imported.to_string()))
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|owner| (exported.to_string(), owner))
                    .collect::<Vec<_>>()
            };
            if owners.is_empty() {
                continue;
            }
            for (public_name, owner) in owners {
                let destination = map
                    .entry((current_file.clone(), public_name.clone()))
                    .or_default();
                if !destination.contains(&owner) {
                    destination.push(owner.clone());
                    changed = true;
                    additions.insert(GraphEdge {
                        source: current_module.id.clone(),
                        target: owner,
                        kind: reexport_kind.to_string(),
                        dynamic: false,
                        label: Some(if imported == "*" {
                            format!("{public_name} <- {public_name}")
                        } else {
                            label.clone()
                        }),
                    });
                }
            }
        }
        if !changed {
            break;
        }
    }

    for edge in &index.graph_edges {
        if !matches!(
            edge.kind.as_str(),
            "Imports"
                | "ImportsBinding"
                | "TypeImports"
                | "TypeImportsBinding"
                | "RequiresBinding"
                | "Requires"
                | "DynamicImports"
                | "DynamicImportsBinding"
                | "ReExportsBinding"
                | "TypeReExportsBinding"
        ) {
            continue;
        }
        let Some(module) = nodes.get(edge.target.as_str()) else {
            continue;
        };
        let Some(specifier) = module.label.strip_prefix("module:") else {
            continue;
        };
        let Some(relative) = resolved_modules.get(&module.id) else {
            continue;
        };
        let Some(target) = file_nodes.get(relative) else {
            continue;
        };
        additions.insert(GraphEdge {
            source: module.id.clone(),
            target: target.clone(),
            kind: "ResolvesTo".to_string(),
            dynamic: false,
            label: Some(specifier.to_string()),
        });
        let (binding_kind, export_map) = match edge.kind.as_str() {
            "ImportsBinding" | "RequiresBinding" | "DynamicImportsBinding" => ("BindsTo", &exports),
            "TypeImportsBinding" => ("TypeBindsTo", &type_exports),
            _ => continue,
        };
        let Some(imported) = &edge.label else {
            continue;
        };
        let Some(export_owners) = export_map.get(&(relative.clone(), imported.clone())) else {
            continue;
        };
        if export_owners.len() == 1 {
            additions.insert(GraphEdge {
                source: edge.source.clone(),
                target: export_owners[0].clone(),
                kind: binding_kind.to_string(),
                dynamic: false,
                label: Some(imported.clone()),
            });
        }
    }
    index.graph_edges.extend(additions);
    index.graph_edges.sort();
    index.graph_edges.dedup();
}

fn location(unit: &Unit) -> Location {
    Location {
        id: unit.id.clone(),
        file: unit.file.clone(),
        kind: unit.kind.clone(),
        name: unit.name.clone(),
        line: unit.line,
        start: unit.start,
        end: unit.end,
        origin: unit.origin.clone(),
    }
}

fn multiset_similarity(left: &BTreeMap<String, u32>, right: &BTreeMap<String, u32>) -> f64 {
    let mut left = left.iter().peekable();
    let mut right = right.iter().peekable();
    let mut intersection = 0_u64;
    let mut union = 0_u64;
    loop {
        match (left.peek(), right.peek()) {
            (Some((left_key, left_count)), Some((right_key, right_count))) => {
                match left_key.cmp(right_key) {
                    std::cmp::Ordering::Less => {
                        union += **left_count as u64;
                        left.next();
                    }
                    std::cmp::Ordering::Greater => {
                        union += **right_count as u64;
                        right.next();
                    }
                    std::cmp::Ordering::Equal => {
                        intersection += (**left_count).min(**right_count) as u64;
                        union += (**left_count).max(**right_count) as u64;
                        left.next();
                        right.next();
                    }
                }
            }
            (Some((_, count)), None) => {
                union += **count as u64;
                left.next();
            }
            (None, Some((_, count))) => {
                union += **count as u64;
                right.next();
            }
            (None, None) => break,
        }
    }
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn similarity(left: &Unit, right: &Unit) -> (f64, ChannelScores) {
    let channels = ChannelScores {
        shape: multiset_similarity(&left.features.shape, &right.features.shape),
        ordered: multiset_similarity(&left.features.ordered, &right.features.ordered),
        literals: multiset_similarity(&left.features.literals, &right.features.literals),
        operators: multiset_similarity(&left.features.operators, &right.features.operators),
        operators_active: !left.features.operators.is_empty()
            || !right.features.operators.is_empty(),
        properties: multiset_similarity(&left.features.properties, &right.features.properties),
        externals: multiset_similarity(&left.features.externals, &right.features.externals),
        size: left.nodes_approx.min(right.nodes_approx) as f64
            / left.nodes_approx.max(right.nodes_approx).max(1) as f64,
    };
    let weighted = [
        (0.30, channels.shape, true),
        (0.20, channels.ordered, true),
        (
            0.16,
            channels.literals,
            !left.features.literals.is_empty() || !right.features.literals.is_empty(),
        ),
        (
            0.12,
            channels.operators,
            !left.features.operators.is_empty() || !right.features.operators.is_empty(),
        ),
        (
            0.10,
            channels.properties,
            !left.features.properties.is_empty() || !right.features.properties.is_empty(),
        ),
        (
            0.07,
            channels.externals,
            !left.features.externals.is_empty() || !right.features.externals.is_empty(),
        ),
        (0.05, channels.size, true),
    ];
    let denominator = weighted
        .iter()
        .filter(|(_, _, active)| *active)
        .map(|(weight, _, _)| weight)
        .sum::<f64>();
    let score = weighted
        .iter()
        .filter(|(_, _, active)| *active)
        .map(|(weight, value, _)| weight * value)
        .sum::<f64>()
        / denominator;
    (score, channels)
}

fn unique_matches<'a>(
    left: &'a [Unit],
    right: &'a [Unit],
    key: impl Fn(&Unit) -> &str,
) -> Vec<(&'a Unit, &'a Unit)> {
    let mut left_groups = HashMap::<(String, String), Vec<&Unit>>::new();
    let mut right_groups = HashMap::<(String, String), Vec<&Unit>>::new();
    for unit in left {
        left_groups
            .entry((unit.kind.clone(), key(unit).to_string()))
            .or_default()
            .push(unit);
    }
    for unit in right {
        right_groups
            .entry((unit.kind.clone(), key(unit).to_string()))
            .or_default()
            .push(unit);
    }
    left_groups
        .into_iter()
        .filter_map(|(key, left)| {
            let right = right_groups.get(&key)?;
            (left.len() == 1 && right.len() == 1).then_some((left[0], right[0]))
        })
        .collect()
}

fn ambiguous_groups(
    left: &[Unit],
    right: &[Unit],
    basis: &'static str,
    key: impl Fn(&Unit) -> &str,
) -> Vec<AmbiguousGroup> {
    let mut left_groups = HashMap::<(String, String), Vec<&Unit>>::new();
    let mut right_groups = HashMap::<(String, String), Vec<&Unit>>::new();
    for unit in left {
        left_groups
            .entry((unit.kind.clone(), key(unit).to_string()))
            .or_default()
            .push(unit);
    }
    for unit in right {
        right_groups
            .entry((unit.kind.clone(), key(unit).to_string()))
            .or_default()
            .push(unit);
    }
    left_groups
        .into_iter()
        .filter_map(|(key, left)| {
            let right = right_groups.get(&key)?;
            (left.len() > 1 || right.len() > 1).then(|| AmbiguousGroup {
                confidence: "ambiguous",
                basis,
                left: left.into_iter().map(location).collect(),
                right: right.iter().map(|unit| location(unit)).collect(),
            })
        })
        .collect()
}

fn coarse_tokens(unit: &Unit) -> Vec<String> {
    let mut tokens = Vec::new();
    for (channel, values) in [
        ("shape", &unit.features.shape),
        ("ordered", &unit.features.ordered),
        ("literal", &unit.features.literals),
        ("operator", &unit.features.operators),
        ("property", &unit.features.properties),
        ("external", &unit.features.externals),
    ] {
        tokens.extend(values.keys().map(|value| format!("{channel}:{value}")));
    }
    tokens
}

fn coarse_token_count(unit: &Unit) -> usize {
    unit.features.shape.len()
        + unit.features.ordered.len()
        + unit.features.literals.len()
        + unit.features.operators.len()
        + unit.features.properties.len()
        + unit.features.externals.len()
}

fn rank_candidates(targets: &[&Unit], candidates: &[&Unit]) -> Vec<Unmatched> {
    rank_candidates_with_affinity(targets, candidates, None)
}

fn rank_candidates_with_affinity(
    targets: &[&Unit],
    candidates: &[&Unit],
    affinities: Option<&FileAffinities>,
) -> Vec<Unmatched> {
    let use_postings = candidates.len() <= 20_000;
    let mut postings = HashMap::<String, Vec<&Unit>>::new();
    let mut candidates_by_kind = HashMap::<String, Vec<&Unit>>::new();
    let mut candidates_by_file_kind = HashMap::<(String, String), Vec<&Unit>>::new();
    for unit in candidates {
        candidates_by_kind
            .entry(unit.kind.clone())
            .or_default()
            .push(unit);
        candidates_by_file_kind
            .entry((unit.file.clone(), unit.kind.clone()))
            .or_default()
            .push(unit);
        // Keep the inverted index bounded for minified/vendor-sized units.
        // Similarity still uses the complete feature channels below; the
        // posting list is only a shortlist accelerator and must not retain
        // unbounded formatted token strings for every AST node.
        if !use_postings {
            continue;
        }
        for token in coarse_tokens(unit).into_iter().take(64) {
            postings
                .entry(format!("{}:{token}", unit.kind))
                .or_default()
                .push(unit);
        }
    }
    for values in candidates_by_kind.values_mut() {
        values.sort_by(|left, right| {
            left.nodes_approx
                .cmp(&right.nodes_approx)
                .then_with(|| left.id.cmp(&right.id))
        });
    }
    for values in candidates_by_file_kind.values_mut() {
        values.sort_by(|left, right| {
            left.nodes_approx
                .cmp(&right.nodes_approx)
                .then_with(|| left.id.cmp(&right.id))
        });
    }
    // Candidate records retain source locations and feature channels.  Global
    // Rayon parallelism is capped to two workers in `main`, so peak RSS stays
    // bounded while retaining useful throughput on large corpora.
    targets
        .par_iter()
        .map(|target| {
            let mut votes = HashMap::<String, (&Unit, usize)>::new();
            let target_coarse_tokens = coarse_tokens(target);
            let mut discriminative_tokens = target_coarse_tokens
                .iter()
                .filter_map(|token| {
                    let key = format!("{}:{token}", target.kind);
                    let values = postings.get(&key)?;
                    (values.len() <= 256).then_some((key, values.len()))
                })
                .collect::<Vec<_>>();
            discriminative_tokens
                .sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
            discriminative_tokens.truncate(8);
            for (key, _) in discriminative_tokens {
                if let Some(values) = postings.get(&key) {
                    for candidate in values {
                        votes
                            .entry(candidate.id.clone())
                            .and_modify(|entry| entry.1 += 1)
                            .or_insert((candidate, 1));
                    }
                }
            }
            let mut strongest_votes = votes.into_values().collect::<Vec<_>>();
            strongest_votes.sort_by(|(left_unit, left_votes), (right_unit, right_votes)| {
                right_votes
                    .cmp(left_votes)
                    .then_with(|| left_unit.id.cmp(&right_unit.id))
            });
            strongest_votes.truncate(128);
            let mut candidate_pool = strongest_votes
                .into_iter()
                .map(|(candidate, votes)| (candidate.id.clone(), (candidate, votes, false)))
                .collect::<HashMap<_, _>>();
            if let Some(same_kind) = candidates_by_kind.get(&target.kind) {
                let center = same_kind
                    .partition_point(|candidate| candidate.nodes_approx < target.nodes_approx);
                let start = center.saturating_sub(48);
                let end = (center + 48).min(same_kind.len());
                for candidate in &same_kind[start..end] {
                    candidate_pool
                        .entry(candidate.id.clone())
                        .or_insert((*candidate, 0, false));
                }
            }
            if let Some(preferred_files) = affinities.and_then(|files| files.get(&target.file)) {
                for preferred_file in preferred_files {
                    let key = (preferred_file.clone(), target.kind.clone());
                    let Some(same_file_kind) = candidates_by_file_kind.get(&key) else {
                        continue;
                    };
                    let center = same_file_kind
                        .partition_point(|candidate| candidate.nodes_approx < target.nodes_approx);
                    let start = center.saturating_sub(32);
                    let end = (center + 32).min(same_file_kind.len());
                    for candidate in &same_file_kind[start..end] {
                        candidate_pool
                            .entry(candidate.id.clone())
                            .and_modify(|entry| entry.2 = true)
                            .or_insert((*candidate, 0, true));
                    }
                }
            }
            let mut shortlist = candidate_pool
                .into_values()
                .filter_map(|(candidate, intersection, graph_supported)| {
                    let candidate_token_count = coarse_token_count(candidate);
                    let union = target_coarse_tokens.len() + candidate_token_count - intersection;
                    let jaccard = if union == 0 {
                        0.0
                    } else {
                        intersection as f64 / union as f64
                    };
                    let size = target.nodes_approx.min(candidate.nodes_approx) as f64
                        / target.nodes_approx.max(candidate.nodes_approx).max(1) as f64;
                    let coarse_score = jaccard * 0.65 + size * 0.35;
                    (coarse_score >= if graph_supported { 0.05 } else { 0.10 }).then_some((
                        candidate,
                        coarse_score,
                        graph_supported,
                    ))
                })
                .collect::<Vec<_>>();
            shortlist.sort_by(
                |(left_unit, left_score, left_graph), (right_unit, right_score, right_graph)| {
                    let left_rank = left_score + if *left_graph { 0.05 } else { 0.0 };
                    let right_rank = right_score + if *right_graph { 0.05 } else { 0.0 };
                    right_rank
                        .total_cmp(&left_rank)
                        .then_with(|| left_unit.id.cmp(&right_unit.id))
                },
            );
            shortlist.truncate(48);
            let mut ranked = shortlist
                .into_iter()
                .map(|(candidate, _, graph_supported)| {
                    let (score, channels) = similarity(candidate, target);
                    (score, graph_supported, channels, candidate)
                })
                .filter(|(score, graph_supported, _, _)| {
                    *score >= if *graph_supported { 0.20 } else { 0.30 }
                })
                .map(|(score, graph_supported, channels, candidate)| Candidate {
                    score,
                    basis: if graph_supported {
                        "containment-graph"
                    } else {
                        "feature"
                    },
                    channels,
                    location: location(candidate),
                })
                .collect::<Vec<_>>();
            ranked.sort_by(|a, b| {
                b.score
                    .total_cmp(&a.score)
                    .then_with(|| a.location.id.cmp(&b.location.id))
            });
            ranked.truncate(6);
            Unmatched {
                location: location(target),
                candidates: ranked,
            }
        })
        .collect()
}

fn merge_reverse_candidates(primary: &mut [Unmatched], reverse: &[Unmatched]) {
    let primary_by_id = primary
        .iter()
        .enumerate()
        .map(|(index, record)| (record.location.id.clone(), index))
        .collect::<HashMap<_, _>>();
    for reverse_record in reverse {
        for reverse_candidate in &reverse_record.candidates {
            let Some(index) = primary_by_id.get(&reverse_candidate.location.id).copied() else {
                continue;
            };
            let record = &mut primary[index];
            if record
                .candidates
                .iter()
                .any(|candidate| candidate.location.id == reverse_record.location.id)
            {
                continue;
            }
            record.candidates.push(Candidate {
                score: reverse_candidate.score,
                basis: reverse_candidate.basis,
                channels: reverse_candidate.channels,
                location: reverse_record.location.clone(),
            });
        }
    }
    for record in primary {
        record.candidates.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.location.id.cmp(&right.location.id))
        });
        record.candidates.truncate(6);
    }
}

fn best_is_distinct(record: &Unmatched) -> bool {
    record.candidates.first().is_some_and(|best| {
        best.score >= 0.72
            && best.channels.ordered >= 0.60
            && (!best.channels.operators_active
                || (best.channels.operators == 1.0 && best.channels.ordered >= 0.90))
            && record
                .candidates
                .get(1)
                .is_none_or(|second| best.score - second.score >= 0.05)
    })
}

#[derive(Default)]
struct FileGraphEvidence {
    anchor_relations: usize,
    supporting_units: usize,
    score_sum: f64,
}

fn infer_file_graph(
    matches: &[MatchRecord],
    ranked: &[Unmatched],
    target_is_left: bool,
) -> (Vec<FileGraphCandidate>, FileAffinities) {
    let mut evidence = HashMap::<(String, String), FileGraphEvidence>::new();
    for matched in matches {
        let (source, target) = if target_is_left {
            (&matched.left.file, &matched.right.file)
        } else {
            (&matched.right.file, &matched.left.file)
        };
        evidence
            .entry((source.clone(), target.clone()))
            .or_default()
            .anchor_relations += 1;
    }
    for record in ranked {
        let Some(best) = record.candidates.first() else {
            continue;
        };
        if best.score < 0.45 {
            continue;
        }
        let item = evidence
            .entry((record.location.file.clone(), best.location.file.clone()))
            .or_default();
        item.supporting_units += 1;
        item.score_sum += best.score;
    }
    let mut by_source = HashMap::<String, Vec<FileGraphCandidate>>::new();
    for ((source_file, target_file), item) in evidence {
        let average_score = if item.supporting_units == 0 {
            0.0
        } else {
            item.score_sum / item.supporting_units as f64
        };
        if item.anchor_relations == 0
            && item.supporting_units < 2
            && !(item.supporting_units == 1 && average_score >= 0.70)
        {
            continue;
        }
        let graph_score =
            item.anchor_relations as f64 * 2.0 + item.supporting_units as f64 * average_score;
        by_source
            .entry(source_file.clone())
            .or_default()
            .push(FileGraphCandidate {
                source_file,
                target_file,
                anchor_relations: item.anchor_relations,
                supporting_units: item.supporting_units,
                average_score,
                graph_score,
            });
    }
    let mut selected = Vec::new();
    let mut affinities = FileAffinities::new();
    for (source, mut candidates) in by_source {
        candidates.sort_by(|left, right| {
            right
                .graph_score
                .total_cmp(&left.graph_score)
                .then_with(|| left.target_file.cmp(&right.target_file))
        });
        candidates.truncate(3);
        affinities.insert(
            source,
            candidates
                .iter()
                .map(|candidate| candidate.target_file.clone())
                .collect(),
        );
        selected.extend(candidates);
    }
    selected.sort_by(|left, right| {
        left.source_file
            .cmp(&right.source_file)
            .then_with(|| right.graph_score.total_cmp(&left.graph_score))
            .then_with(|| left.target_file.cmp(&right.target_file))
    });
    (selected, affinities)
}

fn group_metrics(target: &Unit, members: &[&Unit]) -> Option<(f64, f64, f64)> {
    let union = members
        .iter()
        .flat_map(|unit| unit.tokens.iter().cloned())
        .collect::<BTreeSet<_>>();
    if target.tokens.is_empty() || union.is_empty() {
        return None;
    }
    let intersection = target.tokens.intersection(&union).count() as f64;
    let coverage = intersection / target.tokens.len() as f64;
    let precision = intersection / union.len() as f64;
    let member_size = members.iter().map(|unit| unit.nodes_approx).sum::<usize>();
    let size_ratio = target.nodes_approx.min(member_size) as f64
        / target.nodes_approx.max(member_size).max(1) as f64;
    let score = coverage * 0.55 + precision * 0.25 + size_ratio * 0.2;
    (coverage >= 0.78 && precision >= 0.55 && size_ratio >= 0.5 && score >= 0.74)
        .then_some((score, coverage, precision))
}

fn consider_group<'a>(target: &Unit, selection: Vec<&'a Unit>, best: &mut Option<BestGroup<'a>>) {
    if selection
        .iter()
        .any(|member| member.file != selection[0].file)
    {
        return;
    }
    let Some(metrics) = group_metrics(target, &selection) else {
        return;
    };
    if best
        .as_ref()
        .is_none_or(|(_, current)| metrics.0 > current.0)
    {
        *best = Some((selection, metrics));
    }
}

fn group_candidates(
    records: &[Unmatched],
    targets: &HashMap<String, &Unit>,
    members: &HashMap<String, &Unit>,
    relation: &'static str,
) -> Vec<GroupCandidate> {
    let mut groups = Vec::new();
    for record in records {
        let Some(target) = targets.get(&record.location.id) else {
            continue;
        };
        if target.nodes_approx < 12 {
            continue;
        }
        let pool = record
            .candidates
            .iter()
            .filter(|candidate| candidate.score >= 0.55)
            .filter_map(|candidate| members.get(&candidate.location.id).copied())
            .filter(|member| member.nodes_approx >= 6)
            .take(6)
            .collect::<Vec<_>>();
        let mut best: Option<BestGroup<'_>> = None;
        for first in 0..pool.len() {
            for second in first + 1..pool.len() {
                consider_group(target, vec![pool[first], pool[second]], &mut best);
                for third in second + 1..pool.len() {
                    consider_group(
                        target,
                        vec![pool[first], pool[second], pool[third]],
                        &mut best,
                    );
                }
            }
        }
        if let Some((selected, (score, coverage, precision))) = best {
            let target_location = location(target);
            let member_locations = selected.into_iter().map(location).collect::<Vec<_>>();
            groups.push(if relation == "left-one-to-right-many" {
                GroupCandidate {
                    confidence: "candidate",
                    relation,
                    score,
                    coverage,
                    precision,
                    left: vec![target_location],
                    right: member_locations,
                }
            } else {
                GroupCandidate {
                    confidence: "candidate",
                    relation,
                    score,
                    coverage,
                    precision,
                    left: member_locations,
                    right: vec![target_location],
                }
            });
        }
    }
    groups
}

fn write_json_lines(path: &Path, records: &[Unmatched]) -> Result<()> {
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut output = io::BufWriter::new(file);
    for record in records {
        serde_json::to_writer(&mut output, record)?;
        output.write_all(b"\n")?;
    }
    output
        .flush()
        .with_context(|| format!("write {}", path.display()))
}

fn write_serialized_json_lines<T: Serialize>(path: &Path, records: &[T]) -> Result<()> {
    let file = fs::File::create(path).with_context(|| format!("create {}", path.display()))?;
    let mut output = io::BufWriter::new(file);
    for record in records {
        serde_json::to_writer(&mut output, record)?;
        output.write_all(b"\n")?;
    }
    output
        .flush()
        .with_context(|| format!("write {}", path.display()))
}

fn write_lossless_semantic_graph(
    output: &Path,
    left: &ProjectIndex,
    right: &ProjectIndex,
) -> Result<SemanticGraphArtifactSummary> {
    let mut summary = SemanticGraphArtifactSummary {
        schema: "project-parity/semantic-graph-v1",
        compression: "zstd-jsonl",
        left_nodes: left.graph_nodes.len(),
        right_nodes: right.graph_nodes.len(),
        left_edges: left.graph_edges.len(),
        right_edges: right.graph_edges.len(),
        left_compact_nodes: left.graph_nodes.len(),
        right_compact_nodes: right.graph_nodes.len(),
        left_compact_edges: left.graph_edges.len(),
        right_compact_edges: right.graph_edges.len(),
    };
    let path = output.join("semantic-graph.jsonl.zst");
    let mut file = fs::File::create(&path).with_context(|| format!("create {}", path.display()))?;
    let header = serde_json::json!({
        "recordType": "header",
        "schema": summary.schema,
        "leftProjectSha256": left.project_sha256,
        "rightProjectSha256": right.project_sha256,
        "summaryScope": "compact-correspondence; report.semanticGraphSummary is lossless",
        "summary": summary,
    });
    // Independent zstd frames make the otherwise streaming JSONL artifact
    // addressable.  Concatenated frames remain valid input to `decode_all`,
    // preserving the v1 artifact contract for existing consumers.
    let mut chunk = Vec::new();
    let mut chunk_node_ids = BTreeSet::<String>::new();
    let mut emitted_nodes = HashSet::<String>::new();
    let mut emitted_edges = BTreeSet::<GraphEdge>::new();
    let mut lossless_nodes = [0usize; 2];
    let mut lossless_edges = [0usize; 2];
    let mut index = BTreeMap::<String, Vec<usize>>::new();
    let mut chunks_meta = Vec::new();
    let mut flush = |chunk: &mut Vec<u8>, ids: &mut BTreeSet<String>| -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        let compressed = zstd::stream::encode_all(chunk.as_slice(), 3)?;
        let offset = file.stream_position()?;
        file.write_all(&compressed)?;
        let chunk_index = chunks_meta.len();
        for id in ids.iter() {
            index.entry(id.clone()).or_default().push(chunk_index);
        }
        chunks_meta.push(serde_json::json!({
            "offset": offset,
            "length": compressed.len(),
        }));
        chunk.clear();
        ids.clear();
        Ok(())
    };
    let mut append_record = |record: serde_json::Value,
                             ids: &mut BTreeSet<String>,
                             chunk: &mut Vec<u8>|
     -> Result<()> {
        let line = serde_json::to_vec(&record)?;
        chunk.extend_from_slice(&line);
        chunk.push(b'\n');
        if let Some(id) = record["node"]["id"].as_str() {
            ids.insert(id.to_string());
        }
        if let Some(source) = record["edge"]["source"].as_str() {
            ids.insert(source.to_string());
        }
        if let Some(target) = record["edge"]["target"].as_str() {
            ids.insert(target.to_string());
        }
        if chunk.len() >= 64 * 1024 {
            flush(chunk, ids)?;
        }
        Ok(())
    };
    append_record(header, &mut chunk_node_ids, &mut chunk)?;
    for (side, project) in [("left", left), ("right", right)] {
        if let Some(path) = &project.graph_artifact {
            let input = fs::File::open(path)
                .with_context(|| format!("open graph stream {}", path.display()))?;
            for line in BufReader::new(input).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: serde_json::Value = serde_json::from_str(&line)?;
                match record["recordType"].as_str() {
                    Some("node") => {
                        lossless_nodes[usize::from(side == "right")] += 1;
                        if let Some(id) = record["node"]["id"].as_str() {
                            if !emitted_nodes.insert(id.to_string()) {
                                continue;
                            }
                        }
                    }
                    Some("edge") => {
                        lossless_edges[usize::from(side == "right")] += 1;
                        let edge: GraphEdge = serde_json::from_value(record["edge"].clone())?;
                        if !emitted_edges.insert(edge) {
                            continue;
                        }
                    }
                    _ => continue,
                }
                append_record(record, &mut chunk_node_ids, &mut chunk)?;
            }
        }
        // Package-entry and resolver edges are added after per-file indexing;
        // append only those records not already covered by the lossless stream.
        for node in &project.graph_nodes {
            if emitted_nodes.insert(node.id.clone()) {
                lossless_nodes[usize::from(side == "right")] += 1;
                let record = serde_json::json!({"recordType": "node", "side": side, "node": node});
                append_record(record, &mut chunk_node_ids, &mut chunk)?;
            }
        }
        for edge in &project.graph_edges {
            if emitted_edges.insert(edge.clone()) {
                lossless_edges[usize::from(side == "right")] += 1;
                let record = serde_json::json!({"recordType": "edge", "side": side, "edge": edge});
                append_record(record, &mut chunk_node_ids, &mut chunk)?;
            }
        }
    }
    summary.left_nodes = lossless_nodes[0];
    summary.right_nodes = lossless_nodes[1];
    summary.left_edges = lossless_edges[0];
    summary.right_edges = lossless_edges[1];
    flush(&mut chunk, &mut chunk_node_ids)?;
    let index_artifact = serde_json::json!({
        "schema": "project-parity/semantic-graph-index-v1",
        "projectHashes": {
            "left": left.project_sha256,
            "right": right.project_sha256,
        },
        "chunks": chunks_meta,
        "nodes": index,
    });
    fs::write(
        output.join("semantic-graph.index.json"),
        format!("{}\n", serde_json::to_string_pretty(&index_artifact)?),
    )?;
    Ok(summary)
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

fn graph_edge_ref(edge: &GraphEdge, nodes: &HashMap<&str, &GraphNode>) -> Option<GraphEdgeRef> {
    Some(GraphEdgeRef {
        kind: edge.kind.clone(),
        dynamic: edge.dynamic,
        label: edge.label.clone(),
        target: graph_node_ref(nodes.get(edge.target.as_str())?),
    })
}

/// A graph relation is semantic only when its complete edge contract agrees.
/// Kind alone is not enough: `import { a }` and `import { b }` have the same
/// edge kind but different observable module contracts.
fn same_graph_edge_contract(left: &GraphEdge, right: &GraphEdge) -> bool {
    left.kind == right.kind && left.dynamic == right.dynamic && left.label == right.label
}

fn graph_similarity(left: &GraphNode, right: &GraphNode) -> f64 {
    if left.kind != right.kind {
        return 0.0;
    }
    if left.linked_sha256 == right.linked_sha256 {
        return 1.0;
    }
    let intersection = left.tokens.intersection(&right.tokens).count();
    let union = left.tokens.union(&right.tokens).count();
    let token_score = if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    };
    let label_score = if left.label == right.label { 1.0 } else { 0.0 };
    0.8 * token_score + 0.2 * label_score
}

fn graph_location_node<'a>(
    project: &'a ProjectIndex,
    location: &Location,
) -> Option<&'a GraphNode> {
    project.graph_nodes.iter().find(|node| {
        node.file == location.file
            && node.kind == location.kind
            && node.start == location.start
            && node.end == location.end
    })
}

fn insert_graph_pair(
    pair_meta: &mut BTreeMap<(String, String), PairMeta>,
    left_to_right: &mut HashMap<String, String>,
    right_to_left: &mut HashMap<String, String>,
    queue: &mut VecDeque<(String, String)>,
    conflicts: &mut BTreeSet<(String, String)>,
    key: (String, String),
    candidate: PairMeta,
) {
    if let Some(existing) = pair_meta.get_mut(&key) {
        let candidate_key = (
            candidate.depth,
            candidate.basis,
            candidate.via_edge.as_deref().unwrap_or(""),
            candidate
                .source
                .as_ref()
                .map(|item| item.0.as_str())
                .unwrap_or(""),
            candidate
                .source
                .as_ref()
                .map(|item| item.1.as_str())
                .unwrap_or(""),
        );
        let existing_key = (
            existing.depth,
            existing.basis,
            existing.via_edge.as_deref().unwrap_or(""),
            existing
                .source
                .as_ref()
                .map(|item| item.0.as_str())
                .unwrap_or(""),
            existing
                .source
                .as_ref()
                .map(|item| item.1.as_str())
                .unwrap_or(""),
        );
        if candidate_key < existing_key {
            *existing = candidate;
        }
        return;
    }
    // Correspondence is a partial bijection. Greedy graph expansion may find
    // several plausible neighbors; silently accepting all of them creates a
    // false proof. Keep the first deterministic seed/route and leave the
    // competing branch visible as a frontier.
    if left_to_right
        .get(&key.0)
        .is_some_and(|mapped| mapped != &key.1)
        || right_to_left
            .get(&key.1)
            .is_some_and(|mapped| mapped != &key.0)
    {
        conflicts.insert(key);
        return;
    }
    left_to_right.insert(key.0.clone(), key.1.clone());
    right_to_left.insert(key.1.clone(), key.0.clone());
    pair_meta.insert(key.clone(), candidate);
    queue.push_back(key);
}

struct PairMeta {
    basis: &'static str,
    depth: usize,
    via_edge: Option<String>,
    source: Option<(String, String)>,
}

struct BehaviorHashes {
    hashes: HashMap<String, String>,
    iterations: usize,
    converged: bool,
}

impl BehaviorHashes {
    fn get(&self, node_id: &str) -> Option<&String> {
        self.hashes.get(node_id)
    }
}

fn graph_behavior_hashes(project: &ProjectIndex) -> BehaviorHashes {
    let mut hashes = project
        .graph_nodes
        .iter()
        .map(|node| {
            (
                node.id.clone(),
                sha256(format!("{}\0{}", node.kind, node.linked_sha256)),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut outgoing = HashMap::<&str, Vec<&GraphEdge>>::new();
    for edge in &project.graph_edges {
        outgoing.entry(edge.source.as_str()).or_default().push(edge);
    }
    // Weisfeiler-Lehman refinement can need more than six hops in a real
    // module/call graph. Refine up to 64 hops (or the graph size for smaller
    // inputs) before the explicit resource bound; this routine only seeds
    // candidates, never upgrades a relation to structural proof on its own.
    // Large bundle graphs do not benefit from dozens of full-hash rounds:
    // each round allocates one hash per node.  Keep deep refinement for
    // ordinary projects, but bound production-scale graphs and report
    // `converged: false` when the budget is exhausted.
    if project.graph_nodes.len() > 100_000 {
        return BehaviorHashes {
            hashes,
            iterations: 0,
            converged: false,
        };
    }
    let max_iterations = project.graph_nodes.len().clamp(1, 64);
    let mut iterations = 0;
    let mut converged = false;
    for _ in 0..max_iterations {
        iterations += 1;
        let next = project
            .graph_nodes
            .iter()
            .map(|node| {
                let mut neighborhood = outgoing
                    .get(node.id.as_str())
                    .into_iter()
                    .flatten()
                    // Execution ordering is preserved as a graph edge and is
                    // compared in frontiers. It is intentionally excluded
                    // from identity hashes: bundling two independent files
                    // into one chunk must not make either side-effectful
                    // statement structurally unmatchable.
                    .filter(|edge| edge.kind != "NextStatement")
                    .map(|edge| {
                        format!(
                            "{}\0{}\0{}\0{}",
                            edge.kind,
                            edge.dynamic,
                            edge.label.as_deref().unwrap_or(""),
                            hashes
                                .get(&edge.target)
                                .map(String::as_str)
                                .unwrap_or("unknown")
                        )
                    })
                    .collect::<Vec<_>>();
                neighborhood.sort();
                (
                    node.id.clone(),
                    sha256(format!(
                        "{}\0{}\n{}",
                        node.kind,
                        node.linked_sha256,
                        neighborhood.join("\n")
                    )),
                )
            })
            .collect::<HashMap<_, _>>();
        if next == hashes {
            converged = true;
            break;
        }
        hashes = next;
    }
    BehaviorHashes {
        hashes,
        iterations,
        converged,
    }
}

fn is_global_behavior_seed(node: &GraphNode) -> bool {
    !matches!(node.kind.as_str(), "File" | "Dynamic" | "External")
        && !(node.kind == "Scope" && node.label.starts_with("depth-0:"))
}

fn analyze_semantic_graph(
    left: &ProjectIndex,
    right: &ProjectIndex,
    matches: &[MatchRecord],
    _file_graph_candidates: &[FileGraphCandidate],
) -> (GraphSummary, Vec<GraphRelation>, Vec<DivergenceFrontier>) {
    let left_nodes = left
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let right_nodes = right
        .graph_nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<HashMap<_, _>>();
    let mut left_outgoing = HashMap::<&str, Vec<&GraphEdge>>::new();
    let mut right_outgoing = HashMap::<&str, Vec<&GraphEdge>>::new();
    let mut left_incoming = HashMap::<&str, Vec<&GraphEdge>>::new();
    let mut right_incoming = HashMap::<&str, Vec<&GraphEdge>>::new();
    for edge in &left.graph_edges {
        left_outgoing
            .entry(edge.source.as_str())
            .or_default()
            .push(edge);
        left_incoming
            .entry(edge.target.as_str())
            .or_default()
            .push(edge);
    }
    for edge in &right.graph_edges {
        right_outgoing
            .entry(edge.source.as_str())
            .or_default()
            .push(edge);
        right_incoming
            .entry(edge.target.as_str())
            .or_default()
            .push(edge);
    }

    let mut pair_meta = BTreeMap::<(String, String), PairMeta>::new();
    let mut left_to_right = HashMap::<String, String>::new();
    let mut right_to_left = HashMap::<String, String>::new();
    let mut queue = VecDeque::<(String, String)>::new();
    let mut correspondence_conflicts = BTreeSet::<(String, String)>::new();
    let left_behavior_result = graph_behavior_hashes(left);
    let right_behavior_result = graph_behavior_hashes(right);
    let left_behavior = left_behavior_result.hashes;
    let right_behavior = right_behavior_result.hashes;
    let mut left_groups = HashMap::<(&str, &str), Vec<&GraphNode>>::new();
    let mut right_groups = HashMap::<(&str, &str), Vec<&GraphNode>>::new();
    for node in &left.graph_nodes {
        if !is_global_behavior_seed(node) {
            continue;
        }
        left_groups
            .entry((
                node.kind.as_str(),
                left_behavior
                    .get(&node.id)
                    .map(String::as_str)
                    .unwrap_or(""),
            ))
            .or_default()
            .push(node);
    }
    for node in &right.graph_nodes {
        if !is_global_behavior_seed(node) {
            continue;
        }
        right_groups
            .entry((
                node.kind.as_str(),
                right_behavior
                    .get(&node.id)
                    .map(String::as_str)
                    .unwrap_or(""),
            ))
            .or_default()
            .push(node);
    }
    for (key, left_group) in left_groups {
        let Some(right_group) = right_groups.get(&key) else {
            continue;
        };
        if left_group.len() == 1 && right_group.len() == 1 {
            insert_graph_pair(
                &mut pair_meta,
                &mut left_to_right,
                &mut right_to_left,
                &mut queue,
                &mut correspondence_conflicts,
                (left_group[0].id.clone(), right_group[0].id.clone()),
                PairMeta {
                    basis: "global-behavior",
                    depth: 0,
                    via_edge: None,
                    source: None,
                },
            );
        }
    }
    for matched in matches {
        if let (Some(left_node), Some(right_node)) = (
            graph_location_node(left, &matched.left),
            graph_location_node(right, &matched.right),
        ) {
            insert_graph_pair(
                &mut pair_meta,
                &mut left_to_right,
                &mut right_to_left,
                &mut queue,
                &mut correspondence_conflicts,
                (left_node.id.clone(), right_node.id.clone()),
                PairMeta {
                    basis: "seed-unit",
                    depth: 0,
                    via_edge: None,
                    source: None,
                },
            );
        }
    }

    while let Some((left_id, right_id)) = queue.pop_front() {
        let depth = pair_meta
            .get(&(left_id.clone(), right_id.clone()))
            .map(|meta| meta.depth)
            .unwrap_or(0);
        let left_edges = left_outgoing
            .get(left_id.as_str())
            .cloned()
            .unwrap_or_default();
        let right_edges = right_outgoing
            .get(right_id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut proposed = Vec::<(String, String, &'static str, String)>::new();
        for left_edge in &left_edges {
            let Some(left_target) = left_nodes.get(left_edge.target.as_str()) else {
                continue;
            };
            let exact = right_edges
                .iter()
                .filter(|right_edge| same_graph_edge_contract(left_edge, right_edge))
                .filter_map(|right_edge| {
                    let right_target = right_nodes.get(right_edge.target.as_str())?;
                    (left_target.kind == right_target.kind
                        && left_target.linked_sha256 == right_target.linked_sha256)
                        .then_some((*right_edge, *right_target))
                })
                .collect::<Vec<_>>();
            let reverse_exact_count = exact.first().map_or(0, |(_, right_target)| {
                left_edges
                    .iter()
                    .filter(|candidate| same_graph_edge_contract(candidate, left_edge))
                    .filter_map(|candidate| left_nodes.get(candidate.target.as_str()))
                    .filter(|candidate| {
                        candidate.kind == right_target.kind
                            && candidate.linked_sha256 == right_target.linked_sha256
                    })
                    .count()
            });
            if exact.len() == 1 && reverse_exact_count == 1 {
                proposed.push((
                    left_target.id.clone(),
                    exact[0].1.id.clone(),
                    "neighbor-exact",
                    left_edge.kind.clone(),
                ));
                continue;
            }
            let mut scored = right_edges
                .iter()
                .filter(|right_edge| same_graph_edge_contract(left_edge, right_edge))
                .filter_map(|right_edge| {
                    let right_target = right_nodes.get(right_edge.target.as_str())?;
                    (left_target.kind == right_target.kind)
                        .then_some((graph_similarity(left_target, right_target), *right_target))
                })
                .collect::<Vec<_>>();
            scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
            if scored.first().is_some_and(|best| {
                best.0 >= 0.72
                    && best.0 - scored.get(1).map(|second| second.0).unwrap_or(0.0) >= 0.08
            }) {
                proposed.push((
                    left_target.id.clone(),
                    scored[0].1.id.clone(),
                    "neighbor-fuzzy",
                    left_edge.kind.clone(),
                ));
            }
        }
        let left_parent_edges = left_incoming
            .get(left_id.as_str())
            .cloned()
            .unwrap_or_default();
        let right_parent_edges = right_incoming
            .get(right_id.as_str())
            .cloned()
            .unwrap_or_default();
        for left_edge in &left_parent_edges {
            let Some(left_parent) = left_nodes.get(left_edge.source.as_str()) else {
                continue;
            };
            if left_parent.kind == "File"
                || (left_parent.kind == "Scope" && left_parent.label.starts_with("depth-0:"))
            {
                continue;
            }
            let mut scored = right_parent_edges
                .iter()
                .filter(|right_edge| same_graph_edge_contract(left_edge, right_edge))
                .filter_map(|right_edge| {
                    let right_parent = right_nodes.get(right_edge.source.as_str())?;
                    (left_parent.kind == right_parent.kind).then_some((
                        if left_behavior.get(&left_parent.id)
                            == right_behavior.get(&right_parent.id)
                        {
                            1.0
                        } else {
                            graph_similarity(left_parent, right_parent)
                        },
                        *right_parent,
                    ))
                })
                .collect::<Vec<_>>();
            scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
            if scored.first().is_some_and(|best| {
                best.0 >= 0.72
                    && best.0 - scored.get(1).map(|second| second.0).unwrap_or(0.0) >= 0.08
            }) {
                proposed.push((
                    left_parent.id.clone(),
                    scored[0].1.id.clone(),
                    if scored[0].0 == 1.0 {
                        "neighbor-exact"
                    } else {
                        "neighbor-fuzzy"
                    },
                    format!("Incoming:{}", left_edge.kind),
                ));
            }
        }
        for (left_target, right_target, basis, edge_kind) in proposed {
            insert_graph_pair(
                &mut pair_meta,
                &mut left_to_right,
                &mut right_to_left,
                &mut queue,
                &mut correspondence_conflicts,
                (left_target, right_target),
                PairMeta {
                    basis,
                    depth: depth + 1,
                    via_edge: Some(edge_kind),
                    source: Some((left_id.clone(), right_id.clone())),
                },
            );
        }
    }

    let relation_pairs = pair_meta.keys().cloned().collect::<BTreeSet<_>>();
    let mut frontiers = Vec::new();
    let mut frontier_keys = BTreeSet::new();
    for ((left_id, right_id), meta) in &pair_meta {
        let depth = meta.depth;
        let Some(left_source) = left_nodes.get(left_id.as_str()) else {
            continue;
        };
        let Some(right_source) = right_nodes.get(right_id.as_str()) else {
            continue;
        };
        let left_edges = left_outgoing
            .get(left_id.as_str())
            .cloned()
            .unwrap_or_default();
        let right_edges = right_outgoing
            .get(right_id.as_str())
            .cloned()
            .unwrap_or_default();
        let mut used_left = HashSet::new();
        let mut used_right = HashSet::new();
        for (left_index, left_edge) in left_edges.iter().enumerate() {
            if let Some((right_index, _)) =
                right_edges.iter().enumerate().find(|(_, right_edge)| {
                    same_graph_edge_contract(left_edge, right_edge)
                        && relation_pairs
                            .contains(&(left_edge.target.clone(), right_edge.target.clone()))
                })
            {
                used_left.insert(left_index);
                used_right.insert(right_index);
            }
        }
        for (left_index, left_edge) in left_edges.iter().enumerate() {
            if used_left.contains(&left_index) {
                continue;
            }
            let Some(left_target) = left_nodes.get(left_edge.target.as_str()) else {
                continue;
            };
            let changed = right_edges
                .iter()
                .enumerate()
                .filter(|(right_index, _)| !used_right.contains(right_index))
                .filter(|(_, right_edge)| same_graph_edge_contract(left_edge, right_edge))
                .filter_map(|(right_index, right_edge)| {
                    let right_target = right_nodes.get(right_edge.target.as_str())?;
                    (left_target.kind == right_target.kind).then_some((
                        graph_similarity(left_target, right_target),
                        right_index,
                        right_edge,
                    ))
                })
                .max_by(|a, b| a.0.total_cmp(&b.0));
            if let Some((score, right_index, right_edge)) = changed.filter(|item| item.0 >= 0.35) {
                used_left.insert(left_index);
                used_right.insert(right_index);
                let key = format!(
                    "changed:{left_id}:{right_id}:{}:{}",
                    left_edge.target, right_edge.target
                );
                if frontier_keys.insert(key) {
                    frontiers.push(DivergenceFrontier {
                        classification: "changed-branch",
                        confidence: if score >= 0.72 {
                            "candidate"
                        } else {
                            "weak-candidate"
                        },
                        depth: depth + 1,
                        source_left: graph_node_ref(left_source),
                        source_right: graph_node_ref(right_source),
                        left_edge: graph_edge_ref(left_edge, &left_nodes),
                        right_edge: graph_edge_ref(right_edge, &right_nodes),
                    });
                }
            }
        }
        for (left_index, left_edge) in left_edges.iter().enumerate() {
            if used_left.contains(&left_index) {
                continue;
            }
            let key = format!("extra:{left_id}:{right_id}:{}", left_edge.target);
            if frontier_keys.insert(key) {
                frontiers.push(DivergenceFrontier {
                    classification: "extra-local-branch",
                    confidence: "candidate",
                    depth: depth + 1,
                    source_left: graph_node_ref(left_source),
                    source_right: graph_node_ref(right_source),
                    left_edge: graph_edge_ref(left_edge, &left_nodes),
                    right_edge: None,
                });
            }
        }
        for (right_index, right_edge) in right_edges.iter().enumerate() {
            if used_right.contains(&right_index) {
                continue;
            }
            let key = format!("missing:{left_id}:{right_id}:{}", right_edge.target);
            if frontier_keys.insert(key) {
                frontiers.push(DivergenceFrontier {
                    classification: "missing-local-branch",
                    confidence: "candidate",
                    depth: depth + 1,
                    source_left: graph_node_ref(left_source),
                    source_right: graph_node_ref(right_source),
                    left_edge: None,
                    right_edge: graph_edge_ref(right_edge, &right_nodes),
                });
            }
        }
    }
    // A partial bijection is intentionally strict: a competing route is not
    // silently accepted, but it also must not vanish from the actionable
    // result.  Surface it as an ambiguity frontier rather than mislabeling it
    // as a missing branch or a proven correspondence.
    for (left_id, right_id) in correspondence_conflicts {
        let (Some(left_node), Some(right_node)) = (
            left_nodes.get(left_id.as_str()),
            right_nodes.get(right_id.as_str()),
        ) else {
            continue;
        };
        frontiers.push(DivergenceFrontier {
            classification: "ambiguous-correspondence",
            confidence: "candidate",
            depth: 0,
            source_left: graph_node_ref(left_node),
            source_right: graph_node_ref(right_node),
            left_edge: None,
            right_edge: None,
        });
    }
    frontiers.sort_by(|left, right| {
        left.source_left
            .id
            .cmp(&right.source_left.id)
            .then_with(|| left.source_right.id.cmp(&right.source_right.id))
            .then_with(|| left.classification.cmp(right.classification))
    });
    let relations = pair_meta
        .iter()
        .filter_map(|((left_id, right_id), meta)| {
            Some(GraphRelation {
                confidence: "candidate",
                basis: meta.basis,
                depth: meta.depth,
                via_edge: meta.via_edge.clone(),
                source: meta
                    .source
                    .as_ref()
                    .and_then(|(source_left, source_right)| {
                        Some(GraphRelationSource {
                            left: graph_node_ref(left_nodes.get(source_left.as_str())?),
                            right: graph_node_ref(right_nodes.get(source_right.as_str())?),
                        })
                    }),
                left: graph_node_ref(left_nodes.get(left_id.as_str())?),
                right: graph_node_ref(right_nodes.get(right_id.as_str())?),
            })
        })
        .collect::<Vec<_>>();
    let mut edge_layers = BTreeMap::new();
    for edge in left.graph_edges.iter().chain(&right.graph_edges) {
        *edge_layers.entry(edge.kind.clone()).or_default() += 1;
    }
    let seeded_relations = relations
        .iter()
        .filter(|relation| relation.depth == 0)
        .count();
    let summary = GraphSummary {
        left_nodes: left.graph_nodes.len(),
        right_nodes: right.graph_nodes.len(),
        left_edges: left.graph_edges.len(),
        right_edges: right.graph_edges.len(),
        seeded_relations,
        expanded_relations: relations.len().saturating_sub(seeded_relations),
        divergence_frontiers: frontiers.len(),
        edge_layers,
        behavior_refinement: BehaviorRefinementSummary {
            left_iterations: left_behavior_result.iterations,
            right_iterations: right_behavior_result.iterations,
            left_converged: left_behavior_result.converged,
            right_converged: right_behavior_result.converged,
        },
    };
    (summary, relations, frontiers)
}

fn apply_bundle_equivalence_certificates(
    matches: &mut [MatchRecord],
    left: &ProjectIndex,
    right: &ProjectIndex,
    certificates: &[BundleEquivalenceCertificate],
) -> Result<()> {
    let left_hashes = left
        .files
        .iter()
        .map(|file| (file.file.as_str(), file.source_sha256.as_str()))
        .collect::<HashMap<_, _>>();
    let right_hashes = right
        .files
        .iter()
        .map(|file| (file.file.as_str(), file.source_sha256.as_str()))
        .collect::<HashMap<_, _>>();

    for certificate in certificates {
        if certificate.bindings.is_empty()
            || certificate
                .bindings
                .iter()
                .any(|binding| binding.left.trim().is_empty() || binding.right.trim().is_empty())
        {
            bail!("bundle-equivalence certificate needs at least one complete binding");
        }
        if left_hashes.get(certificate.left.file.as_str())
            != Some(&certificate.left.source_sha256.as_str())
            || right_hashes.get(certificate.right.file.as_str())
                != Some(&certificate.right.source_sha256.as_str())
        {
            bail!(
                "stale bundle-equivalence certificate for {} -> {}",
                certificate.left.file,
                certificate.right.file
            );
        }
        let record = matches
            .iter_mut()
            .find(|record| {
                record.left.file == certificate.left.file
                    && record.left.name.as_deref() == Some(certificate.left.name.as_str())
                    && record.right.file == certificate.right.file
                    && record.right.name.as_deref() == Some(certificate.right.name.as_str())
            })
            .with_context(|| {
                format!(
                    "bundle-equivalence certificate has no reciprocal candidate {}:{} -> {}:{}",
                    certificate.left.file,
                    certificate.left.name,
                    certificate.right.file,
                    certificate.right.name
                )
            })?;
        if record.confidence != "candidate" {
            bail!("bundle-equivalence certificate may only promote a candidate relation");
        }
        record.confidence = "proven-bundle-normalized";
        record.status = "bundle-normalized-equal";
        record.basis = "hash-pinned-reviewed-bundle-equivalence";
        record.score = 1.0;
    }
    Ok(())
}

fn run_with_certificates(
    left_path: &Path,
    right_path: &Path,
    output: &Path,
    certificates: &[BundleEquivalenceCertificate],
) -> Result<Summary> {
    let mut left = index_project(left_path, "left")?;
    let right = index_project(right_path, "right")?;
    let mut dependencies = discover_dependencies(left_path, Some(&left))?
        .map(index_dependency_evidence)
        .transpose()?;
    // Keep the heavy dependency AST out of the primary matching lifetime.
    // Provenance and package-entry links are computed below; LLM routing only
    // needs the dependency file inventory and parse status after that point.
    let dependency_summary = dependencies.as_ref().map(|index| {
        if index.graph_nodes.len() < 10_000 {
            return ProjectIndex {
                root: index.root.clone(),
                corpus: CorpusSelection {
                    mode: index.corpus.mode,
                    roots: index.corpus.roots.clone(),
                    excluded_derivative_roots: index.corpus.excluded_derivative_roots.clone(),
                    source_root: index.corpus.source_root.clone(),
                    projection_tool: index.corpus.projection_tool.clone(),
                },
                project_sha256: index.project_sha256.clone(),
                files: index.files.clone(),
                units: index.units.clone(),
                graph_nodes: index.graph_nodes.clone(),
                graph_edges: index.graph_edges.clone(),
                graph_artifact: index.graph_artifact.clone(),
                failures: index.failures.clone(),
                skipped: index.skipped.clone(),
            };
        }
        ProjectIndex {
            root: index.root.clone(),
            corpus: CorpusSelection {
                mode: index.corpus.mode,
                roots: index.corpus.roots.clone(),
                excluded_derivative_roots: index.corpus.excluded_derivative_roots.clone(),
                source_root: index.corpus.source_root.clone(),
                projection_tool: index.corpus.projection_tool.clone(),
            },
            project_sha256: index.project_sha256.clone(),
            files: index.files.clone(),
            units: Vec::new(),
            graph_nodes: Vec::new(),
            graph_edges: Vec::new(),
            graph_artifact: index.graph_artifact.clone(),
            failures: index.failures.clone(),
            skipped: index.skipped.clone(),
        }
    });
    let left_provenance = dependency_provenance(&left, "left");
    if let Some(dependencies) = &dependencies {
        // Dependency source is retained in its own evidence corpus and linked
        // through PackageEntry nodes/provenance.  Do not merge the complete
        // node_modules AST into the application graph: large workspaces can
        // contain millions of dependency nodes and would make the primary
        // correspondence graph exceed the process memory ceiling.
        // Include its corpus hash in report identity so package updates still
        // invalidate prior evidence.
        left.project_sha256 = sha256(format!(
            "{}\0dependency\0{}",
            left.project_sha256, dependencies.project_sha256
        ));
        link_dependency_entry_sources(&mut left, dependencies);
    }
    // Release the full dependency AST before the expensive correspondence
    // phase; only the bounded summary is needed for output/routing below.
    dependencies = dependency_summary;
    let right_provenance = dependency_provenance(&right, "right");
    let left_dependency_contexts = build_dependency_context_index(&left, &left_provenance);
    let right_dependency_contexts = build_dependency_context_index(&right, &right_provenance);
    let mut used_left = HashSet::new();
    let mut used_right = HashSet::new();
    let mut matches = Vec::new();
    // A byte-identical source file is already a deterministic correspondence
    // boundary.  Pair its units by source coordinates before global fuzzy
    // matching; otherwise repeated identical statements become ambiguous and
    // are incorrectly emitted as LLM repair tasks (notably when a project is
    // audited against itself).
    let identical_files = left
        .files
        .iter()
        .filter_map(|left_file| {
            right
                .files
                .iter()
                .find(|right_file| {
                    right_file.file == left_file.file
                        && right_file.source_sha256 == left_file.source_sha256
                        && right_file.source_map_sha256 == left_file.source_map_sha256
                })
                .map(|_| left_file.file.as_str())
        })
        .collect::<HashSet<_>>();
    for old in left
        .units
        .iter()
        .filter(|unit| identical_files.contains(unit.file.as_str()))
    {
        let Some(new) = right.units.iter().find(|candidate| {
            candidate.file == old.file
                && candidate.kind == old.kind
                && candidate.start == old.start
                && candidate.end == old.end
                && candidate.name == old.name
                && !used_right.contains(&candidate.id)
        }) else {
            continue;
        };
        used_left.insert(old.id.clone());
        used_right.insert(new.id.clone());
        matches.push(MatchRecord {
            confidence: "proven-structure",
            status: "alpha-equal",
            basis: "identical-file",
            score: 1.0,
            channels: None,
            left: location(old),
            right: location(new),
        });
    }
    for (old, new) in unique_matches(&left.units, &right.units, |unit| &unit.strict_sha256) {
        if used_left.contains(&old.id) || used_right.contains(&new.id) {
            continue;
        }
        used_left.insert(old.id.clone());
        used_right.insert(new.id.clone());
        if units_have_equivalent_dependency_context(
            &left_dependency_contexts,
            &right_dependency_contexts,
            old,
            new,
        ) {
            matches.push(MatchRecord {
                confidence: "proven-structure",
                status: "alpha-equal",
                basis: "strict",
                score: 1.0,
                channels: None,
                left: location(old),
                right: location(new),
            });
        } else {
            matches.push(MatchRecord {
                confidence: "candidate",
                status: "dependency-context-changed",
                basis: "strict-dependency-context",
                score: 1.0,
                channels: None,
                left: location(old),
                right: location(new),
            });
        }
    }
    let linked_left = left
        .units
        .iter()
        .filter(|unit| !used_left.contains(&unit.id))
        .cloned()
        .collect::<Vec<_>>();
    let linked_right = right
        .units
        .iter()
        .filter(|unit| !used_right.contains(&unit.id))
        .cloned()
        .collect::<Vec<_>>();
    for (old, new) in unique_matches(&linked_left, &linked_right, |unit| &unit.linked_sha256) {
        used_left.insert(old.id.clone());
        used_right.insert(new.id.clone());
        matches.push(MatchRecord {
            confidence: "candidate",
            status: "changed-candidate",
            basis: "linked",
            score: 1.0,
            channels: None,
            left: location(old),
            right: location(new),
        });
    }
    let mut ambiguous = ambiguous_groups(&left.units, &right.units, "strict", |unit| {
        &unit.strict_sha256
    });
    ambiguous.extend(ambiguous_groups(
        &linked_left,
        &linked_right,
        "linked",
        |unit| &unit.linked_sha256,
    ));
    ambiguous.sort_by(|left, right| {
        left.basis
            .cmp(right.basis)
            .then_with(|| {
                left.left
                    .first()
                    .map(|item| &item.id)
                    .cmp(&right.left.first().map(|item| &item.id))
            })
            .then_with(|| {
                left.right
                    .first()
                    .map(|item| &item.id)
                    .cmp(&right.right.first().map(|item| &item.id))
            })
    });
    let remaining_left = left
        .units
        .iter()
        .filter(|unit| !used_left.contains(&unit.id))
        .collect::<Vec<_>>();
    let remaining_right = right
        .units
        .iter()
        .filter(|unit| !used_right.contains(&unit.id))
        .collect::<Vec<_>>();
    let ranked_right = rank_candidates(&remaining_right, &remaining_left);
    let ranked_left = rank_candidates(&remaining_left, &remaining_right);
    let left_ranked_by_id = ranked_left
        .iter()
        .map(|record| (record.location.id.clone(), record))
        .collect::<HashMap<_, _>>();
    let mut mutual_left = HashSet::new();
    let mut mutual_right = HashSet::new();
    for right_record in &ranked_right {
        if !best_is_distinct(right_record) {
            continue;
        }
        let best_left = &right_record.candidates[0];
        let Some(left_record) = left_ranked_by_id.get(&best_left.location.id) else {
            continue;
        };
        if !best_is_distinct(left_record)
            || left_record.candidates[0].location.id != right_record.location.id
        {
            continue;
        }
        mutual_left.insert(left_record.location.id.clone());
        mutual_right.insert(right_record.location.id.clone());
        matches.push(MatchRecord {
            confidence: "candidate",
            status: "changed-candidate",
            basis: "mutual-best-fuzzy",
            score: best_left.score,
            channels: Some(best_left.channels),
            left: left_record.location.clone(),
            right: right_record.location.clone(),
        });
    }
    apply_bundle_equivalence_certificates(&mut matches, &left, &right, certificates)?;
    let (file_graph_candidates, left_affinities) = infer_file_graph(&matches, &ranked_left, true);
    let (_, right_affinities) = infer_file_graph(&matches, &ranked_right, false);
    let final_remaining_left = remaining_left
        .iter()
        .copied()
        .filter(|unit| !mutual_left.contains(&unit.id))
        .collect::<Vec<_>>();
    let final_remaining_right = remaining_right
        .iter()
        .copied()
        .filter(|unit| !mutual_right.contains(&unit.id))
        .collect::<Vec<_>>();
    let mut unmatched_left = rank_candidates_with_affinity(
        &final_remaining_left,
        &final_remaining_right,
        Some(&left_affinities),
    );
    let mut unmatched_right = rank_candidates_with_affinity(
        &final_remaining_right,
        &final_remaining_left,
        Some(&right_affinities),
    );
    merge_reverse_candidates(&mut unmatched_left, &unmatched_right);
    merge_reverse_candidates(&mut unmatched_right, &unmatched_left);
    let left_units_by_id = final_remaining_left
        .iter()
        .map(|unit| (unit.id.clone(), *unit))
        .collect::<HashMap<_, _>>();
    let right_units_by_id = final_remaining_right
        .iter()
        .map(|unit| (unit.id.clone(), *unit))
        .collect::<HashMap<_, _>>();
    let mut groups = group_candidates(
        &unmatched_left,
        &left_units_by_id,
        &right_units_by_id,
        "left-one-to-right-many",
    );
    groups.extend(group_candidates(
        &unmatched_right,
        &right_units_by_id,
        &left_units_by_id,
        "left-many-to-right-one",
    ));
    groups.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.relation.cmp(right.relation))
            .then_with(|| {
                left.left
                    .first()
                    .map(|item| &item.id)
                    .cmp(&right.left.first().map(|item| &item.id))
            })
            .then_with(|| {
                left.right
                    .first()
                    .map(|item| &item.id)
                    .cmp(&right.right.first().map(|item| &item.id))
            })
    });
    matches.sort_by(|a, b| a.left.id.cmp(&b.left.id));
    let (graph_summary, graph_relations, divergence_frontiers) =
        analyze_semantic_graph(&left, &right, &matches, &file_graph_candidates);
    let alpha_equal = matches
        .iter()
        .filter(|record| record.status == "alpha-equal")
        .count();
    let linked_candidates = matches
        .iter()
        .filter(|record| record.basis == "linked")
        .count();
    let mutual_best_candidates = matches
        .iter()
        .filter(|record| record.basis == "mutual-best-fuzzy")
        .count();
    let summary = Summary {
        left_files: left.files.len(),
        right_files: right.files.len(),
        left_units: left.units.len(),
        right_units: right.units.len(),
        left_failures: left.failures.len(),
        right_failures: right.failures.len(),
        alpha_equal,
        linked_candidates,
        mutual_best_candidates,
        ambiguous_groups: ambiguous.len(),
        extraction_inline_candidates: groups.len(),
        unmatched_left: unmatched_left.len(),
        unmatched_right: unmatched_right.len(),
    };
    fs::create_dir_all(output)?;
    let mut provenance = left_provenance;
    provenance.extend(right_provenance);
    provenance.sort_by(|left, right| {
        left.side
            .cmp(&right.side)
            .then_with(|| left.importer_file.cmp(&right.importer_file))
            .then_with(|| left.specifier.cmp(&right.specifier))
            .then_with(|| left.imported_export.cmp(&right.imported_export))
            .then_with(|| left.edge_kind.cmp(&right.edge_kind))
            .then_with(|| left.binding_symbol_id.cmp(&right.binding_symbol_id))
    });
    write_serialized_json_lines(&output.join("dependency-provenance.jsonl"), &provenance)?;
    write_json_lines(&output.join("unmatched-left.jsonl"), &unmatched_left)?;
    write_json_lines(&output.join("unmatched-right.jsonl"), &unmatched_right)?;
    write_serialized_json_lines(&output.join("graph-relations.jsonl"), &graph_relations)?;
    write_serialized_json_lines(
        &output.join("divergence-frontiers.jsonl"),
        &divergence_frontiers,
    )?;
    let binding_contracts = dependency_binding_contracts(&provenance, &graph_relations);
    write_serialized_json_lines(
        &output.join("dependency-binding-contracts.jsonl"),
        &binding_contracts,
    )?;
    let semantic_graph_summary = write_lossless_semantic_graph(output, &left, &right)?;
    let llm_summary = llm_context::write_llm_context(
        output,
        &left,
        &right,
        &matches,
        &ambiguous,
        &groups,
        &graph_relations,
        &divergence_frontiers,
        &unmatched_left,
        &unmatched_right,
        dependencies.as_ref(),
    )?;
    let report = Report {
        schema: "project-parity/v10",
        engine: ENGINE_VERSION,
        evidence_boundary:
            "Static bundler-agnostic candidate discovery only. Chunk layout and wrappers are not parity evidence; source maps are optional locator evidence. A relation is not behavioral or runtime parity.",
        confidence_contract: BTreeMap::from([
            (
                "proven-structure",
                "Unique alpha-equivalent normalized structure only; dependencies and behavior remain outside proof.",
            ),
            (
                "candidate",
                "Ranked correspondence requiring owner review; never consumed as parity evidence.",
            ),
            (
                "ambiguous",
                "Multiplicity or insufficient margin forbids an automatic choice.",
            ),
            (
                "unknown",
                "Unmatched, skipped or failed input retained explicitly.",
            ),
        ]),
        thresholds: BTreeMap::from([
            ("coarseMinimum", 0.10),
            ("coarseShortlistLimit", 48.0),
            ("coarsePostingMaximum", 256.0),
            ("coarseRareTokenLimit", 8.0),
            ("coarseVotePoolLimit", 128.0),
            ("fuzzyMinimum", 0.30),
            ("mutualBestMinimum", 0.72),
            ("mutualBestOrderedMinimum", 0.60),
            ("mutualBestMargin", 0.05),
            ("groupMinimum", 0.74),
            ("groupCoverageMinimum", 0.78),
            ("groupPrecisionMinimum", 0.55),
        ]),
        summary: Summary { ..summary },
        left: &left,
        right: &right,
        matches,
        ambiguous_groups: ambiguous,
        group_candidates: groups,
        file_graph_candidates,
        graph_summary,
        llm_summary,
        graph_relations_artifact: "graph-relations.jsonl",
        divergence_frontiers_artifact: "divergence-frontiers.jsonl",
        unmatched_left_artifact: "unmatched-left.jsonl",
        unmatched_right_artifact: "unmatched-right.jsonl",
        upstream_executable_ledger_artifact: "upstream-executable-ledger.jsonl",
        upstream_semantic_ledger_artifact: "upstream-semantic-ledger.jsonl.zst",
        upstream_semantic_edge_ledger_artifact: "upstream-semantic-edge-ledger.jsonl.zst",
        llm_work_items_artifact: "llm-work-items.jsonl",
        llm_batches_artifact: "llm-batches.jsonl",
        llm_manifest_artifact: "llm-manifest.json",
        llm_task_brief_artifact: "LLM_TASK_BRIEF.md",
        dependency_evidence_corpus_artifact: "dependency-evidence-corpus.json",
        dependency_provenance_artifact: "dependency-provenance.jsonl",
        dependency_binding_contracts_artifact: "dependency-binding-contracts.jsonl",
        semantic_graph_artifact: "semantic-graph.jsonl.zst",
        semantic_graph_summary,
    };
    let report_value = serde_json::to_value(&report)?;
    fs::write(
        output.join("report.json"),
        format!("{}\n", serde_json::to_string_pretty(&report_value)?),
    )?;
    visualize::write_visual_report(output, &report_value)?;
    Ok(summary)
}

fn oracle_location_matches(locator: &OracleLocator, location: &serde_json::Value) -> bool {
    location.get("file").and_then(serde_json::Value::as_str) == Some(locator.file.as_str())
        && locator.name.as_ref().is_none_or(|name| {
            location.get("name").and_then(serde_json::Value::as_str) == Some(name.as_str())
        })
        && locator.line.is_none_or(|line| {
            location.get("line").and_then(serde_json::Value::as_u64) == Some(line as u64)
        })
}

fn oracle_pair_is_promoted(pair: &OraclePair, report: &serde_json::Value) -> bool {
    report["matches"].as_array().is_some_and(|matches| {
        matches.iter().any(|record| {
            oracle_location_matches(&pair.left, &record["left"])
                && oracle_location_matches(&pair.right, &record["right"])
        })
    })
}

fn oracle_pair_group_rank(pair: &OraclePair, report: &serde_json::Value) -> Option<usize> {
    report["groupCandidates"]
        .as_array()
        .and_then(|groups| {
            groups.iter().position(|group| {
                group["left"].as_array().is_some_and(|locations| {
                    locations
                        .iter()
                        .any(|location| oracle_location_matches(&pair.left, location))
                }) && group["right"].as_array().is_some_and(|locations| {
                    locations
                        .iter()
                        .any(|location| oracle_location_matches(&pair.right, location))
                })
            })
        })
        .map(|index| index + 1)
}

fn oracle_pair_candidate_rank(pair: &OraclePair, output: &Path) -> Result<Option<usize>> {
    let unmatched = fs::read_to_string(output.join("unmatched-left.jsonl"))?;
    for line in unmatched.lines().filter(|line| !line.is_empty()) {
        let record: serde_json::Value = serde_json::from_str(line)?;
        if !oracle_location_matches(&pair.left, &record["location"]) {
            continue;
        }
        return Ok(record["candidates"].as_array().and_then(|candidates| {
            candidates
                .iter()
                .position(|candidate| oracle_location_matches(&pair.right, &candidate["location"]))
                .map(|index| index + 1)
        }));
    }
    Ok(None)
}

fn evaluate_oracle(output: &Path, oracle_path: &Path) -> Result<OracleMetrics> {
    let oracle: Oracle = serde_json::from_slice(
        &fs::read(oracle_path).with_context(|| format!("read {}", oracle_path.display()))?,
    )
    .with_context(|| format!("parse {}", oracle_path.display()))?;
    let report: serde_json::Value = serde_json::from_slice(&fs::read(output.join("report.json"))?)?;
    let mut promoted_correct = 0;
    let mut top_one_recovered = 0;
    let mut top_k_recovered = 0;
    for pair in &oracle.expected {
        if oracle_pair_is_promoted(pair, &report) {
            promoted_correct += 1;
            top_one_recovered += 1;
            top_k_recovered += 1;
            continue;
        }
        let rank = oracle_pair_candidate_rank(pair, output)?
            .or_else(|| oracle_pair_group_rank(pair, &report));
        if rank == Some(1) {
            top_one_recovered += 1;
        }
        if rank.is_some_and(|rank| rank <= oracle.top_k) {
            top_k_recovered += 1;
        }
    }
    let false_promotions = oracle
        .forbidden
        .iter()
        .filter(|pair| oracle_pair_is_promoted(pair, &report))
        .count();
    let precision_denominator = promoted_correct + false_promotions;
    let metrics = OracleMetrics {
        schema: "project-parity/oracle-v1",
        top_k: oracle.top_k,
        expected: oracle.expected.len(),
        forbidden: oracle.forbidden.len(),
        promoted_correct,
        top_one_recovered,
        top_k_recovered,
        abstained_expected: oracle.expected.len().saturating_sub(promoted_correct),
        false_promotions,
        promoted_precision: if precision_denominator == 0 {
            1.0
        } else {
            promoted_correct as f64 / precision_denominator as f64
        },
        promoted_recall: if oracle.expected.is_empty() {
            1.0
        } else {
            promoted_correct as f64 / oracle.expected.len() as f64
        },
        top_k_recall: if oracle.expected.is_empty() {
            1.0
        } else {
            top_k_recovered as f64 / oracle.expected.len() as f64
        },
    };
    fs::write(
        output.join("oracle-report.json"),
        format!("{}\n", serde_json::to_string_pretty(&metrics)?),
    )?;
    Ok(metrics)
}

fn json_contains_unit_id(value: &serde_json::Value, unit_id: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => {
            map.get("id").and_then(serde_json::Value::as_str) == Some(unit_id)
                || map
                    .values()
                    .any(|value| json_contains_unit_id(value, unit_id))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| json_contains_unit_id(value, unit_id)),
        _ => false,
    }
}

fn find_location<'a>(value: &'a serde_json::Value, unit_id: &str) -> Option<&'a serde_json::Value> {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("id").and_then(serde_json::Value::as_str) == Some(unit_id)
                && map.contains_key("file")
                && map.contains_key("start")
                && map.contains_key("end")
            {
                return Some(value);
            }
            map.values().find_map(|value| find_location(value, unit_id))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_location(value, unit_id)),
        _ => None,
    }
}

#[allow(dead_code)]
fn run(left_path: &Path, right_path: &Path, output: &Path) -> Result<Summary> {
    run_with_certificates(left_path, right_path, output, &[])
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangedFile {
    side: String,
    file: String,
    change: String,
    before: Option<String>,
    after: Option<String>,
}

type FileSnapshot = BTreeMap<String, String>;

fn file_snapshot(root: &Path) -> Result<FileSnapshot> {
    let discovery = discover(root)?;
    discovery
        .files
        .into_iter()
        .map(|(path, relative)| {
            let source = fs::read(&path)
                .with_context(|| format!("read snapshot source {}", path.display()))?;
            let source_map = load_adjacent_source_map(&path);
            let map_fingerprint = source_map
                .as_ref()
                .and_then(|map| map.sha256.as_deref())
                .unwrap_or(if source_map.is_some() {
                    "unreadable"
                } else {
                    "absent"
                });
            Ok((
                relative,
                sha256(format!("{}\0{}", sha256(source), map_fingerprint)),
            ))
        })
        .collect()
}

fn changed_files(before: &FileSnapshot, after: &FileSnapshot, side: &str) -> Vec<ChangedFile> {
    let keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    keys.into_iter()
        .filter_map(|file| {
            let old = before.get(&file);
            let new = after.get(&file);
            if old == new {
                return None;
            }
            let change = match (old, new) {
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                (Some(_), Some(_)) => "modified",
                (None, None) => return None,
            };
            Some(ChangedFile {
                side: side.to_string(),
                file,
                change: change.to_string(),
                before: old.cloned(),
                after: new.cloned(),
            })
        })
        .collect()
}

fn write_change_set(output: &Path, files: &[ChangedFile], initial: bool) -> Result<()> {
    let value = serde_json::json!({
        "schema": "project-parity/change-set-v1",
        "initial": initial,
        "changedFiles": files,
        "count": files.len(),
        "resyncMode": "component-impact-plan; content-addressed-index-cache; global-correspondence-phase",
    });
    fs::write(
        output.join("change-set.json"),
        format!("{}\n", serde_json::to_string_pretty(&value)?),
    )?;
    Ok(())
}

fn write_resync_plan(output: &Path, changes: &[ChangedFile]) -> Result<()> {
    let mut impacted = changes
        .iter()
        .map(|change| format!("{}:{}", change.side, change.file))
        .collect::<BTreeSet<_>>();
    let graph_path = output.join("semantic-graph.jsonl.zst");
    if graph_path.is_file() {
        let decoded = zstd::stream::decode_all(fs::File::open(&graph_path)?)?;
        let mut node_files = HashMap::<String, String>::new();
        let mut reverse = HashMap::<String, BTreeSet<String>>::new();
        for line in std::str::from_utf8(&decoded)?
            .lines()
            .filter(|line| !line.is_empty())
        {
            let record: serde_json::Value = serde_json::from_str(line)?;
            if record["recordType"] == "node" {
                if let (Some(id), Some(file)) = (
                    record["node"]["id"].as_str(),
                    record["node"]["file"].as_str(),
                ) {
                    let side = id.split(':').next().unwrap_or_default();
                    node_files.insert(id.to_string(), format!("{side}:{file}"));
                }
            }
            if record["recordType"] == "edge" {
                let source = record["edge"]["source"].as_str();
                let target = record["edge"]["target"].as_str();
                if let (Some(source), Some(target)) = (source, target) {
                    if let (Some(source_file), Some(target_file)) =
                        (node_files.get(source), node_files.get(target))
                    {
                        reverse
                            .entry(target_file.clone())
                            .or_default()
                            .insert(source_file.clone());
                    }
                }
            }
        }
        let mut queue = impacted.iter().cloned().collect::<VecDeque<_>>();
        while let Some(file) = queue.pop_front() {
            for dependent in reverse.get(&file).into_iter().flatten() {
                if impacted.insert(dependent.clone()) {
                    queue.push_back(dependent.clone());
                }
            }
        }
    }
    let value = serde_json::json!({
        "schema": "project-parity/resync-plan-v1",
        "changedFiles": changes,
        "impactedFiles": impacted,
        "indexing": "only changed files miss the content-addressed Oxc cache",
        "correspondence": "global; required to preserve cross-file matches",
    });
    fs::write(
        output.join("resync-plan.json"),
        format!("{}\n", serde_json::to_string_pretty(&value)?),
    )?;
    Ok(())
}

fn write_service_status(output: &Path, phase: &str, changes: usize) -> Result<()> {
    let value = serde_json::json!({
        "schema": "project-parity/service-status-v1",
        "service": "serve",
        "phase": phase,
        "pid": std::process::id(),
        "updatedAt": format!("{:?}", std::time::SystemTime::now()),
        "lastChangeCount": changes,
        "correspondence": "global",
        "indexing": "content-addressed-cache; component-impact-plan",
    });
    fs::write(
        output.join("serve-status.json"),
        format!("{}\n", serde_json::to_string_pretty(&value)?),
    )?;
    Ok(())
}

fn watch(
    left_path: &Path,
    right_path: &Path,
    output: &Path,
    state_db: Option<&Path>,
    interval: Duration,
    debounce: Duration,
) -> Result<()> {
    let mut left_snapshot = file_snapshot(left_path)?;
    let mut right_snapshot = file_snapshot(right_path)?;
    run(left_path, right_path, output)?;
    write_change_set(output, &[], true)?;
    write_resync_plan(output, &[])?;
    if let Some(state_db) = state_db {
        state::sync(state_db, output)?;
    }
    let _ = write_service_status(output, "running", 0);
    eprintln!("watching for source changes; press Ctrl-C to stop");
    loop {
        thread::sleep(interval);
        let next_left = file_snapshot(left_path)?;
        let next_right = file_snapshot(right_path)?;
        let mut changes = changed_files(&left_snapshot, &next_left, "local");
        changes.extend(changed_files(&right_snapshot, &next_right, "upstream"));
        if changes.is_empty() {
            continue;
        }
        // Coalesce an editor's save/rename burst before starting an expensive
        // correspondence pass. The content snapshots are still taken again,
        // so no intermediate event can be mistaken for the final source.
        thread::sleep(debounce);
        let settled_left = file_snapshot(left_path)?;
        let settled_right = file_snapshot(right_path)?;
        changes = changed_files(&left_snapshot, &settled_left, "local");
        changes.extend(changed_files(&right_snapshot, &settled_right, "upstream"));
        if changes.is_empty() {
            left_snapshot = settled_left;
            right_snapshot = settled_right;
            continue;
        }
        write_resync_plan(output, &changes)?;
        run(left_path, right_path, output)?;
        write_change_set(output, &changes, false)?;
        if let Some(state_db) = state_db {
            state::sync(state_db, output)?;
        }
        let _ = write_service_status(output, "running", changes.len());
        left_snapshot = settled_left;
        right_snapshot = settled_right;
        eprintln!("resynced {} changed file(s)", changes.len());
    }
}

/// Long-running service entry point used by agent integrations.  The service
/// intentionally reuses the safe watcher: indexing is incremental, while
/// cross-file correspondence remains global for correctness.
fn serve(
    left_path: &Path,
    right_path: &Path,
    output: &Path,
    state_db: Option<&Path>,
    interval: Duration,
    debounce: Duration,
) -> Result<()> {
    fs::create_dir_all(output)?;
    write_service_status(output, "starting", 0)?;
    let result = watch(left_path, right_path, output, state_db, interval, debounce);
    let phase = if result.is_ok() { "stopped" } else { "failed" };
    let _ = write_service_status(output, phase, 0);
    result
}

fn mcp_text_result(value: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())}],
        "structuredContent": value,
    })
}

fn mcp_error(message: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "isError": true,
        "content": [{"type": "text", "text": message.into()}],
    })
}

fn mcp_tool_result(
    name: &str,
    arguments: &serde_json::Value,
    output: &Path,
    state_db: Option<&Path>,
    left: &Path,
    right: &Path,
) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        match name {
            "parity_status" => {
                let status = output.join("serve-status.json");
                let report = output.join("report.json");
                Ok(serde_json::json!({
                    "status": if status.is_file() { Some(serde_json::from_slice::<serde_json::Value>(&fs::read(status)?)?) } else { None::<serde_json::Value> },
                    "report": if report.is_file() { Some(serde_json::from_slice::<serde_json::Value>(&fs::read(report)?)?) } else { None::<serde_json::Value> },
                    "left": left,
                    "right": right,
                }))
            }
            "state_next" => {
                let db = state_db.context("serve was started without --state")?;
                let limit = arguments["limit"].as_u64().unwrap_or(10) as usize;
                if limit == 0 {
                    bail!("limit must be greater than zero");
                }
                Ok(state::next(db, limit)?)
            }
            "show_work" => Ok(show_work(
                output,
                arguments["id"].as_str().context("id is required")?,
            )?),
            "inspect" => Ok(inspect_unit(
                output,
                arguments["id"].as_str().context("id is required")?,
            )?),
            "graph_node" => {
                let id = arguments["id"].as_str().context("id is required")?;
                let limit = arguments["limit"].as_u64().unwrap_or(100) as usize;
                let offset = arguments["offset"].as_u64().unwrap_or(0) as usize;
                Ok(graph_node(output, id, limit, offset)?)
            }
            "resync" => {
                let summary = run(left, right, output)?;
                let sync = state_db.map(|db| state::sync(db, output)).transpose()?;
                Ok(serde_json::json!({"summary": summary, "stateSync": sync}))
            }
            _ => bail!("unknown project-parity tool: {name}"),
        }
    })();
    match result {
        Ok(value) => mcp_text_result(value),
        Err(error) => mcp_error(error.to_string()),
    }
}

fn serve_mcp(
    left_path: &Path,
    right_path: &Path,
    output: &Path,
    state_db: Option<&Path>,
    interval: Duration,
    debounce: Duration,
) -> Result<()> {
    fs::create_dir_all(output)?;
    let left = left_path.to_path_buf();
    let right = right_path.to_path_buf();
    let report = output.to_path_buf();
    let state = state_db.map(Path::to_path_buf);
    thread::spawn(move || {
        if let Err(error) = serve(&left, &right, &report, state.as_deref(), interval, debounce) {
            eprintln!("project-parity serve failed: {error:#}");
        }
    });
    // Do not answer MCP requests against an empty report while the initial
    // authoritative index is being built.  This also makes the first
    // `parity_status` call deterministic for agent hosts.
    for _ in 0..600 {
        if let Ok(bytes) = fs::read(output.join("serve-status.json")) {
            if let Ok(status) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                if matches!(status["phase"].as_str(), Some("running" | "failed")) {
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut line = String::new();
    while input.read_line(&mut line)? != 0 {
        let request: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(value) => value,
            Err(error) => {
                print_mcp(
                    &serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":error.to_string()}}),
                )?;
                line.clear();
                continue;
            }
        };
        line.clear();
        let id = request
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let method = request["method"].as_str().unwrap_or_default();
        let response = match method {
            "initialize" => serde_json::json!({
                "jsonrpc":"2.0", "id":id,
                "result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"project-parity","version":env!("CARGO_PKG_VERSION")}}
            }),
            "notifications/initialized" => continue,
            "tools/list" => serde_json::json!({
                "jsonrpc":"2.0", "id":id,
                "result":{"tools":[
                    {"name":"parity_status","description":"Read current parity service status and latest report.","inputSchema":{"type":"object","properties":{}}},
                    {"name":"state_next","description":"Get the next unresolved upstream-led repair tasks.","inputSchema":{"type":"object","properties":{"limit":{"type":"integer","minimum":1}}}},
                    {"name":"show_work","description":"Load complete evidence for one repair task.","inputSchema":{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}},
                    {"name":"inspect","description":"Load source-backed evidence for one semantic unit.","inputSchema":{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}},
                    {"name":"graph_node","description":"Page incoming and outgoing semantic graph edges.","inputSchema":{"type":"object","required":["id"],"properties":{"id":{"type":"string"},"limit":{"type":"integer","minimum":1},"offset":{"type":"integer","minimum":0}}}},
                    {"name":"resync","description":"Run a fresh authoritative parity analysis and sync the state queue.","inputSchema":{"type":"object","properties":{}}}
                ]}
            }),
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or_default();
                let arguments = &request["params"]["arguments"];
                serde_json::json!({"jsonrpc":"2.0","id":id,"result":mcp_tool_result(name, arguments, output, state_db, left_path, right_path)})
            }
            _ => {
                serde_json::json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("method not found: {method}")}})
            }
        };
        print_mcp(&response)?;
    }
    Ok(())
}

fn inspect_unit(output: &Path, unit_id: &str) -> Result<serde_json::Value> {
    let report_path = output.join("report.json");
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(&report_path).with_context(|| format!("read {}", report_path.display()))?,
    )?;
    let mut relations = Vec::new();
    for key in ["matches", "ambiguousGroups", "groupCandidates"] {
        if let Some(records) = report[key].as_array() {
            relations.extend(
                records
                    .iter()
                    .filter(|record| json_contains_unit_id(record, unit_id))
                    .cloned(),
            );
        }
    }
    for artifact in [
        "unmatched-left.jsonl",
        "unmatched-right.jsonl",
        "graph-relations.jsonl",
        "divergence-frontiers.jsonl",
        "llm-work-items.jsonl",
        "upstream-executable-ledger.jsonl",
    ] {
        let path = output.join(artifact);
        if !path.exists() {
            continue;
        }
        for line in fs::read_to_string(&path)?
            .lines()
            .filter(|line| !line.is_empty())
        {
            let record: serde_json::Value = serde_json::from_str(line)?;
            if json_contains_unit_id(&record, unit_id) {
                relations.push(record);
            }
        }
    }
    let semantic_ledger = output.join("upstream-semantic-ledger.jsonl.zst");
    if semantic_ledger.exists() {
        if let Some(record) = read_indexed_json_record(&semantic_ledger, unit_id)? {
            relations.push(record);
        } else {
            let decoded = zstd::stream::decode_all(
                fs::File::open(&semantic_ledger)
                    .with_context(|| format!("read {}", semantic_ledger.display()))?,
            )?;
            for line in std::str::from_utf8(&decoded)
                .context("decode upstream semantic ledger as UTF-8")?
                .lines()
                .filter(|line| !line.is_empty())
            {
                let record: serde_json::Value = serde_json::from_str(line)?;
                if json_contains_unit_id(&record, unit_id) {
                    relations.push(record);
                }
            }
        }
    }
    let location = relations
        .iter()
        .find_map(|relation| find_location(relation, unit_id))
        .cloned()
        .with_context(|| format!("unit id not found: {unit_id}"))?;
    let side = if unit_id.starts_with("left:") {
        "left"
    } else if unit_id.starts_with("right:") {
        "right"
    } else {
        bail!("unit id must start with left: or right:");
    };
    let relative = location["file"].as_str().context("location has no file")?;
    let root = report[side]["root"]
        .as_str()
        .context("report has no project root")?;
    let file_record = report[side]["files"]
        .as_array()
        .and_then(|files| {
            files
                .iter()
                .find(|file| file["file"].as_str() == Some(relative))
        })
        .context("source file is absent from report inventory")?;
    let expected_sha = file_record["sourceSha256"]
        .as_str()
        .context("source file has no SHA in report inventory")?;
    let source_path = Path::new(root).join(relative);
    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("read source locator {}", source_path.display()))?;
    let actual_sha = sha256(&source);
    if actual_sha != expected_sha {
        bail!(
            "stale report: {} changed (expected {}, got {})",
            source_path.display(),
            expected_sha,
            actual_sha
        );
    }
    let source_map_path = adjacent_source_map_path(&source_path);
    if let Some(error) = file_record["sourceMapError"].as_str() {
        bail!(
            "report contains unusable source-map evidence for {}: {}",
            source_map_path.display(),
            error
        );
    }
    let expected_source_map_sha = file_record["sourceMapSha256"].as_str();
    match (expected_source_map_sha, source_map_path.exists()) {
        (Some(expected), true) => {
            let actual = sha256(
                fs::read(&source_map_path)
                    .with_context(|| format!("read source map {}", source_map_path.display()))?,
            );
            if actual != expected {
                bail!(
                    "stale report: {} changed (expected {}, got {})",
                    source_map_path.display(),
                    expected,
                    actual
                );
            }
        }
        (Some(_), false) => bail!(
            "stale report: source map {} was removed",
            source_map_path.display()
        ),
        (None, true) => bail!(
            "stale report: source map {} was added",
            source_map_path.display()
        ),
        (None, false) => {}
    }
    let start = location["start"]
        .as_u64()
        .context("location has no start")? as usize;
    let end = location["end"].as_u64().context("location has no end")? as usize;
    let snippet = source
        .get(start..end)
        .context("location span is not a valid UTF-8 boundary")?;
    Ok(serde_json::json!({
        "schema": "project-parity/inspection-v1",
        "unitId": unit_id,
        "sourceSha256": actual_sha,
        "location": location,
        "source": snippet,
        "relations": relations
    }))
}

fn graph_node(
    output: &Path,
    node_id: &str,
    limit: usize,
    offset: usize,
) -> Result<serde_json::Value> {
    let report: serde_json::Value = serde_json::from_slice(&fs::read(output.join("report.json"))?)?;
    if let Some(indexed) = graph_node_from_index(output, &report, node_id, limit, offset)? {
        return Ok(indexed);
    }
    let path = output.join("semantic-graph.jsonl.zst");
    let decoder = zstd::stream::read::Decoder::new(
        fs::File::open(&path).with_context(|| format!("open {}", path.display()))?,
    )?;
    let reader = BufReader::new(decoder);
    let mut header_checked = false;
    let mut node = None;
    let mut edges = Vec::new();
    let mut total_edges = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(&line)?;
        match record["recordType"].as_str() {
            Some("header") => {
                let left = report["left"]["projectSha256"].as_str();
                let right = report["right"]["projectSha256"].as_str();
                if record["leftProjectSha256"].as_str() != left
                    || record["rightProjectSha256"].as_str() != right
                {
                    bail!("stale semantic graph artifact: project hashes do not match report.json");
                }
                header_checked = true;
            }
            Some("node") if record["node"]["id"].as_str() == Some(node_id) => {
                node = Some(record["node"].clone());
            }
            Some("edge") => {
                let edge = &record["edge"];
                if edge["source"].as_str() == Some(node_id)
                    || edge["target"].as_str() == Some(node_id)
                {
                    if total_edges >= offset && edges.len() < limit {
                        edges.push(record);
                    }
                    total_edges += 1;
                }
            }
            _ => {}
        }
    }
    if !header_checked {
        bail!("semantic graph artifact has no header");
    }
    let node = node.with_context(|| format!("graph node not found: {node_id}"))?;
    let returned = edges.len();
    Ok(serde_json::json!({
        "schema": "project-parity/graph-node-v1",
        "node": node,
        "totalEdges": total_edges,
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "remaining": total_edges.saturating_sub(offset.saturating_add(returned)),
        "nextOffset": (offset + returned < total_edges).then_some(offset + returned),
        "edges": edges,
    }))
}

fn usage() -> &'static str {
    concat!(
        "Usage:\n",
        "  project-parity init LOCAL_DIR UPSTREAM_DIR\n",
        "  project-parity sync LOCAL_DIR UPSTREAM_DIR\n",
        "  project-parity LEFT_DIR RIGHT_DIR --out DIRECTORY [--oracle FILE] [--bundle-certificates FILE]\n",
        "  project-parity watch LEFT_DIR RIGHT_DIR --out DIRECTORY [--state STATE_DB] [--interval MS] [--debounce MS]\n",
        "  project-parity serve LEFT_DIR RIGHT_DIR --out DIRECTORY [--state STATE_DB] [--interval MS] [--debounce MS] [--mcp]\n",
        "  project-parity inspect REPORT_DIRECTORY UNIT_ID\n",
        "  project-parity graph-node REPORT_DIRECTORY NODE_ID [LIMIT] [OFFSET]\n",
        "  project-parity show-work REPORT_DIRECTORY WORK_ITEM_ID\n",
        "  project-parity show-batch REPORT_DIRECTORY BATCH_ID [LIMIT] [OFFSET]\n",
        "  project-parity state-sync STATE_DB REPORT_DIRECTORY\n",
        "  project-parity state-next STATE_DB [LIMIT]\n",
        "  project-parity state-runs STATE_DB [LIMIT]\n",
        "  project-parity graph-import STATE_DB SEMANTIC_GRAPH\n",
        "  project-parity codegraph-import STATE_DB CODEGRAPH_DB SIDE",
    )
}

fn read_bundle_equivalence_certificates(path: &Path) -> Result<Vec<BundleEquivalenceCertificate>> {
    let value = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&value).with_context(|| format!("parse {}", path.display()))
}

fn read_json_lines(path: &Path) -> Result<Vec<serde_json::Value>> {
    fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn jsonl_index_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if let Some(stem) = name.strip_suffix(".jsonl.zst") {
        return path.with_file_name(format!("{stem}.index.json"));
    }
    path.with_extension("index.json")
}

fn read_indexed_json_record(path: &Path, id: &str) -> Result<Option<serde_json::Value>> {
    let index_path = jsonl_index_path(path);
    if !index_path.is_file() {
        return Ok(None);
    }
    let index: serde_json::Value = serde_json::from_slice(&fs::read(&index_path)?)?;
    let Some(record) = index["records"].get(id) else {
        return Ok(None);
    };
    if let Some(chunk_ids) = record.as_array() {
        let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
        for chunk_id in chunk_ids {
            let chunk_id = chunk_id
                .as_u64()
                .context("compressed ledger index chunk is not an integer")?
                as usize;
            let chunk = index["chunks"]
                .get(chunk_id)
                .context("compressed ledger index chunk is absent")?;
            let offset = chunk["offset"]
                .as_u64()
                .context("compressed ledger chunk offset is not an integer")?;
            let length = chunk["length"]
                .as_u64()
                .context("compressed ledger chunk length is not an integer")?;
            file.seek(SeekFrom::Start(offset))?;
            let mut compressed = vec![0; length as usize];
            file.read_exact(&mut compressed)?;
            let decoded = zstd::stream::decode_all(compressed.as_slice())?;
            let values = std::str::from_utf8(&decoded)
                .context("decode compressed ledger chunk as UTF-8")?
                .lines()
                .filter(|line| !line.is_empty())
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if let Some(value) = values
                .into_iter()
                .find(|value| value["id"].as_str() == Some(id))
            {
                return Ok(Some(value));
            }
        }
        return Ok(None);
    }
    let offset = record["offset"]
        .as_u64()
        .context("index offset is not an integer")?;
    let length = record["length"]
        .as_u64()
        .context("index length is not an integer")?;
    let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes)?;
    Ok(Some(serde_json::from_slice(bytes.trim_ascii())?))
}

fn read_indexed_json_group(path: &Path, group: &str) -> Result<Option<Vec<serde_json::Value>>> {
    let index_path = jsonl_index_path(path);
    if !index_path.is_file() {
        return Ok(None);
    }
    let index: serde_json::Value = serde_json::from_slice(&fs::read(&index_path)?)?;
    let Some(records) = index["groups"]
        .get(group)
        .and_then(|value| value.as_array())
    else {
        return Ok(Some(Vec::new()));
    };
    let mut file = fs::File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut values = Vec::with_capacity(records.len());
    for record in records {
        let offset = record["offset"]
            .as_u64()
            .context("index offset is not an integer")?;
        let length = record["length"]
            .as_u64()
            .context("index length is not an integer")?;
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; length as usize];
        file.read_exact(&mut bytes)?;
        values.push(serde_json::from_slice(bytes.trim_ascii())?);
    }
    Ok(Some(values))
}

fn show_work(output: &Path, id: &str) -> Result<serde_json::Value> {
    let path = output.join("llm-work-items.jsonl");
    if let Some(item) = read_indexed_json_record(&path, id)? {
        return Ok(item);
    }
    read_json_lines(&path)?
        .into_iter()
        .find(|item| item["id"].as_str() == Some(id))
        .with_context(|| format!("work item not found: {id}"))
}

fn show_batch(output: &Path, id: &str, limit: usize, offset: usize) -> Result<serde_json::Value> {
    let batch_path = output.join("llm-batches.jsonl");
    let batch = if let Some(batch) = read_indexed_json_record(&batch_path, id)? {
        batch
    } else {
        read_json_lines(&batch_path)?
            .into_iter()
            .find(|batch| batch["id"].as_str() == Some(id))
            .with_context(|| format!("batch not found: {id}"))?
    };
    let total = batch["workItemCount"]
        .as_u64()
        .context("batch has no workItemCount")? as usize;
    let items_path = output.join("llm-work-items.jsonl");
    let indexed_items = read_indexed_json_group(&items_path, id)?;
    let items = indexed_items
        .unwrap_or(read_json_lines(&items_path)?)
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let returned = items.len();
    Ok(serde_json::json!({
        "schema": "project-parity/llm-batch-view-v2",
        "batch": batch,
        "total": total,
        "offset": offset,
        "returned": returned,
        "limit": limit,
        "remaining": total.saturating_sub(offset.saturating_add(returned)),
        "nextOffset": (offset + returned < total).then_some(offset + returned),
        "items": items,
    }))
}

fn graph_node_from_index(
    output: &Path,
    report: &serde_json::Value,
    node_id: &str,
    limit: usize,
    offset: usize,
) -> Result<Option<serde_json::Value>> {
    let index_path = output.join("semantic-graph.index.json");
    if !index_path.is_file() {
        return Ok(None);
    }
    let index: serde_json::Value = serde_json::from_slice(&fs::read(&index_path)?)?;
    let left_hash = report["left"]["projectSha256"].as_str();
    let right_hash = report["right"]["projectSha256"].as_str();
    if index["projectHashes"]["left"].as_str() != left_hash
        || index["projectHashes"]["right"].as_str() != right_hash
    {
        bail!("stale semantic graph index: project hashes do not match report.json");
    }
    let Some(chunk_ids) = index["nodes"][node_id].as_array() else {
        return Ok(None);
    };
    let graph_path = output.join("semantic-graph.jsonl.zst");
    let mut file =
        fs::File::open(&graph_path).with_context(|| format!("open {}", graph_path.display()))?;
    let mut records = Vec::new();
    let mut seen_chunks = BTreeSet::new();
    for chunk_id in chunk_ids {
        let chunk_id = chunk_id
            .as_u64()
            .context("semantic graph index chunk is not an integer")?
            as usize;
        if !seen_chunks.insert(chunk_id) {
            continue;
        }
        let chunk = index["chunks"]
            .get(chunk_id)
            .context("semantic graph index chunk is absent")?;
        let chunk_offset = chunk["offset"]
            .as_u64()
            .context("semantic graph chunk offset is not an integer")?;
        let chunk_length = chunk["length"]
            .as_u64()
            .context("semantic graph chunk length is not an integer")?;
        file.seek(SeekFrom::Start(chunk_offset))?;
        let mut compressed = vec![0; chunk_length as usize];
        file.read_exact(&mut compressed)?;
        let decoded = zstd::stream::decode_all(compressed.as_slice())?;
        records.extend(
            std::str::from_utf8(&decoded)
                .context("decode indexed semantic graph chunk as UTF-8")?
                .lines()
                .filter(|line| !line.is_empty())
                .map(serde_json::from_str::<serde_json::Value>)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
    }
    let node = records
        .iter()
        .find(|record| record["recordType"] == "node" && record["node"]["id"] == node_id)
        .map(|record| record["node"].clone())
        .with_context(|| format!("graph node not found: {node_id}"))?;
    let mut edges = records
        .into_iter()
        .filter(|record| {
            record["recordType"] == "edge"
                && (record["edge"]["source"] == node_id || record["edge"]["target"] == node_id)
        })
        .collect::<Vec<_>>();
    edges.sort_by_key(|left| left.to_string());
    let total_edges = edges.len();
    let edges = edges
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let returned = edges.len();
    Ok(Some(serde_json::json!({
        "schema": "project-parity/graph-node-v1",
        "node": node,
        "totalEdges": total_edges,
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "remaining": total_edges.saturating_sub(offset.saturating_add(returned)),
        "nextOffset": (offset + returned < total_edges).then_some(offset + returned),
        "edges": edges,
    })))
}

fn print_stdout(value: impl AsRef<str>) -> Result<()> {
    let mut stdout = io::stdout().lock();
    match writeln!(stdout, "{}", value.as_ref()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn print_json(value: &impl Serialize) -> Result<()> {
    print_stdout(serde_json::to_string_pretty(value)?)
}

fn print_mcp(value: &impl Serialize) -> Result<()> {
    print_stdout(serde_json::to_string(value)?)
}

fn sync_project(local: &Path, upstream: &Path, command: &'static str) -> Result<serde_json::Value> {
    let parity = local.join(".parity");
    let report = parity.join("report");
    let state_db = parity.join("state.sqlite");
    if command == "sync" && !parity.is_dir() {
        bail!(
            "{} is not initialized; run `project-parity init LOCAL_DIR UPSTREAM_DIR` first",
            local.display()
        );
    }
    fs::create_dir_all(&parity)?;
    let summary = run(local, upstream, &report)?;
    let sync = state::sync(&state_db, &report)?;
    Ok(serde_json::json!({
        "schema": format!("project-parity/{command}-v1"),
        "local": local,
        "upstream": upstream,
        "report": report,
        "state": state_db,
        "summary": summary,
        "stateSync": sync,
    }))
}

fn main() -> Result<()> {
    // Keep matcher parallelism bounded on large upstream bundles.  Two
    // workers retain throughput while avoiding the multi-gigabyte peaks from
    // one shortlist hashmap per CPU core.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build_global();
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.iter().any(|arg| arg == "--help") {
        print_stdout(usage())?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "init") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&sync_project(
            Path::new(&args[1]),
            Path::new(&args[2]),
            "init",
        )?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "sync") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&sync_project(
            Path::new(&args[1]),
            Path::new(&args[2]),
            "sync",
        )?)?;
        return Ok(());
    }
    if args
        .first()
        .is_some_and(|arg| arg == "watch" || arg == "serve")
    {
        let service_mode = args.first().is_some_and(|arg| arg == "serve");
        if args.len() < 5 || args[3] != "--out" {
            bail!(usage());
        }
        let mut state_db = None;
        let mut interval_ms = 1_000u64;
        let mut debounce_ms = 750u64;
        let mut mcp_mode = false;
        let mut index = 5;
        while index < args.len() {
            if args[index] == "--mcp" {
                if mcp_mode {
                    bail!(usage());
                }
                mcp_mode = true;
                index += 1;
                continue;
            }
            let Some(value) = args.get(index + 1) else {
                bail!(usage());
            };
            match args[index].as_str() {
                "--state" if state_db.is_none() => state_db = Some(PathBuf::from(value)),
                "--interval" if interval_ms == 1_000 => interval_ms = value.parse()?,
                "--debounce" if debounce_ms == 750 => debounce_ms = value.parse()?,
                _ => bail!(usage()),
            }
            index += 2;
        }
        if interval_ms == 0 || debounce_ms == 0 {
            bail!("--interval and --debounce must be greater than zero");
        }
        let left = Path::new(&args[1]);
        let right = Path::new(&args[2]);
        let output = Path::new(&args[4]);
        let interval = Duration::from_millis(interval_ms);
        let debounce = Duration::from_millis(debounce_ms);
        if mcp_mode && !service_mode {
            bail!("--mcp is only supported with `serve`");
        }
        if mcp_mode {
            serve_mcp(left, right, output, state_db.as_deref(), interval, debounce)?;
        } else if service_mode {
            serve(left, right, output, state_db.as_deref(), interval, debounce)?;
        } else {
            watch(left, right, output, state_db.as_deref(), interval, debounce)?;
        }
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "state-sync") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&state::sync(Path::new(&args[1]), Path::new(&args[2]))?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "state-next") {
        if !(2..=3).contains(&args.len()) {
            bail!(usage());
        }
        let limit = args
            .get(2)
            .map(|value| value.parse::<usize>())
            .transpose()?
            .unwrap_or(10);
        if limit == 0 {
            bail!("LIMIT must be greater than zero");
        }
        print_json(&state::next(Path::new(&args[1]), limit)?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "state-runs") {
        if !(2..=3).contains(&args.len()) {
            bail!(usage());
        }
        let limit = args
            .get(2)
            .map(|value| value.parse::<usize>())
            .transpose()?
            .unwrap_or(20);
        if limit == 0 {
            bail!("LIMIT must be greater than zero");
        }
        print_json(&state::runs(Path::new(&args[1]), limit)?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "graph-import") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&state::import_graph(
            Path::new(&args[1]),
            Path::new(&args[2]),
        )?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "codegraph-import") {
        if args.len() != 4 {
            bail!(usage());
        }
        if args[3].is_empty() {
            bail!("SIDE must not be empty");
        }
        print_json(&state::import_codegraph(
            Path::new(&args[1]),
            Path::new(&args[2]),
            &args[3],
        )?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "inspect") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&inspect_unit(Path::new(&args[1]), &args[2])?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "show-work") {
        if args.len() != 3 {
            bail!(usage());
        }
        print_json(&show_work(Path::new(&args[1]), &args[2])?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "graph-node") {
        if !matches!(args.len(), 3..=5) {
            bail!(usage());
        }
        let limit = args
            .get(3)
            .map(|value| value.parse::<usize>())
            .transpose()
            .context("LIMIT must be a positive integer")?
            .unwrap_or(100);
        if limit == 0 {
            bail!("LIMIT must be greater than zero");
        }
        let offset = args
            .get(4)
            .map(|value| value.parse::<usize>())
            .transpose()
            .context("OFFSET must be a non-negative integer")?
            .unwrap_or(0);
        print_json(&graph_node(Path::new(&args[1]), &args[2], limit, offset)?)?;
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "show-batch") {
        if !matches!(args.len(), 3..=5) {
            bail!(usage());
        }
        let limit = args
            .get(3)
            .map(|value| value.parse::<usize>())
            .transpose()
            .context("LIMIT must be a positive integer")?
            .unwrap_or(25);
        if limit == 0 {
            bail!("LIMIT must be greater than zero");
        }
        let offset = args
            .get(4)
            .map(|value| value.parse::<usize>())
            .transpose()
            .context("OFFSET must be a non-negative integer")?
            .unwrap_or(0);
        print_json(&show_batch(Path::new(&args[1]), &args[2], limit, offset)?)?;
        return Ok(());
    }
    if args.len() < 4 || args[2] != "--out" {
        bail!(usage());
    }
    let mut oracle = None;
    let mut certificate_path = None;
    let mut index = 4;
    while index < args.len() {
        let Some(value) = args.get(index + 1) else {
            bail!(usage())
        };
        match args[index].as_str() {
            "--oracle" if oracle.replace(value.as_str()).is_none() => {}
            "--bundle-certificates" if certificate_path.replace(value.as_str()).is_none() => {}
            _ => bail!(usage()),
        }
        index += 2;
    }
    let output = Path::new(&args[3]);
    let certificates = certificate_path
        .map(|path| read_bundle_equivalence_certificates(Path::new(path)))
        .transpose()?
        .unwrap_or_default();
    let summary = run_with_certificates(
        Path::new(&args[0]),
        Path::new(&args[1]),
        output,
        &certificates,
    )?;
    print_stdout(serde_json::to_string_pretty(&summary)?)?;
    if summary.left_failures > 0 || summary.right_failures > 0 {
        std::process::exit(2);
    }
    if let Some(oracle) = oracle {
        let metrics = evaluate_oracle(output, Path::new(oracle))?;
        print_stdout(serde_json::to_string_pretty(&metrics)?)?;
        if metrics.false_promotions > 0 {
            std::process::exit(3);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn unit(id: &str, tokens: &[&str]) -> Unit {
        let mut features = FeatureChannels::default();
        for token in tokens {
            FeatureChannels::increment(&mut features.shape, *token);
            features.record_event(*token);
        }
        Unit {
            id: id.to_string(),
            file: format!("{id}.js"),
            kind: "Function".to_string(),
            name: Some(id.to_string()),
            start: 0,
            end: 1,
            line: 1,
            origin: None,
            nodes_approx: tokens.len(),
            strict_sha256: id.to_string(),
            linked_sha256: id.to_string(),
            tokens: tokens.iter().map(|token| (*token).to_string()).collect(),
            features,
        }
    }

    #[test]
    fn renamed_bindings_match_but_operand_order_does_not() {
        let left_source = "function add(a,b){return a-b}";
        let renamed_source = "function x(y,z){return y-z}";
        let reordered_source = "function x(y,z){return z-y}";
        let (left, left_original, _) =
            canonicalize(left_source, SourceType::mjs(), "left.js", "left").unwrap();
        let (renamed, renamed_original, _) =
            canonicalize(renamed_source, SourceType::mjs(), "right.js", "right").unwrap();
        let (reordered, reordered_original, _) =
            canonicalize(reordered_source, SourceType::mjs(), "right.js", "right").unwrap();
        let left = collect_units(
            &left,
            left_source,
            SourceType::mjs(),
            "left.js",
            "left",
            left_original,
            None,
        )
        .unwrap();
        let renamed = collect_units(
            &renamed,
            renamed_source,
            SourceType::mjs(),
            "right.js",
            "right",
            renamed_original,
            None,
        )
        .unwrap();
        let reordered = collect_units(
            &reordered,
            reordered_source,
            SourceType::mjs(),
            "right.js",
            "right",
            reordered_original,
            None,
        )
        .unwrap();
        assert_eq!(left[0].strict_sha256, renamed[0].strict_sha256);
        assert_ne!(left[0].strict_sha256, reordered[0].strict_sha256);
        assert_eq!(
            &left_source[left[0].start as usize..left[0].end as usize],
            left_source
        );
    }

    #[test]
    fn typescript_types_and_transparent_wrappers_do_not_change_runtime_signature() {
        let typed_source = r#"
            function owner<T>(value: number | null): number {
                const current = value! as number satisfies number;
                return current + 1;
            }
        "#;
        let javascript_source = "function renamed(input){const result=input;return result+1}";
        let (typed, typed_original, _) =
            canonicalize(typed_source, SourceType::ts(), "typed.ts", "left").unwrap();
        let (javascript, javascript_original, _) =
            canonicalize(javascript_source, SourceType::mjs(), "bundle.js", "right").unwrap();
        let typed = collect_units(
            &typed,
            typed_source,
            SourceType::ts(),
            "typed.ts",
            "left",
            typed_original,
            None,
        )
        .unwrap();
        let javascript = collect_units(
            &javascript,
            javascript_source,
            SourceType::mjs(),
            "bundle.js",
            "right",
            javascript_original,
            None,
        )
        .unwrap();

        assert_eq!(typed[0].linked_sha256, javascript[0].linked_sha256);
        assert_eq!(similarity(&typed[0], &javascript[0]).0, 1.0);
    }

    #[test]
    fn reverse_candidate_is_retained_when_forward_shortlist_misses_it() {
        let left = unit("left-owner", &["Function", "Call"]);
        let right = unit("right-owner", &["Function", "Call"]);
        let channels = similarity(&left, &right).1;
        let mut forward = vec![Unmatched {
            location: location(&left),
            candidates: Vec::new(),
        }];
        let reverse = vec![Unmatched {
            location: location(&right),
            candidates: vec![Candidate {
                score: 0.9,
                basis: "feature",
                channels,
                location: location(&left),
            }],
        }];

        merge_reverse_candidates(&mut forward, &reverse);

        assert_eq!(forward[0].candidates.len(), 1);
        assert_eq!(forward[0].candidates[0].location.id, right.id);
        assert_eq!(forward[0].candidates[0].score, 0.9);
    }

    #[test]
    fn graph_pair_conflicts_are_retained_as_ambiguity_evidence() {
        let mut pairs = BTreeMap::new();
        let mut left_to_right = HashMap::new();
        let mut right_to_left = HashMap::new();
        let mut queue = VecDeque::new();
        let mut conflicts = BTreeSet::new();
        let meta = || PairMeta {
            basis: "seed-unit",
            depth: 0,
            via_edge: None,
            source: None,
        };
        insert_graph_pair(
            &mut pairs,
            &mut left_to_right,
            &mut right_to_left,
            &mut queue,
            &mut conflicts,
            ("left-a".to_string(), "right-a".to_string()),
            meta(),
        );
        insert_graph_pair(
            &mut pairs,
            &mut left_to_right,
            &mut right_to_left,
            &mut queue,
            &mut conflicts,
            ("left-a".to_string(), "right-b".to_string()),
            meta(),
        );
        assert_eq!(pairs.len(), 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(
            conflicts,
            BTreeSet::from([("left-a".to_string(), "right-b".to_string())])
        );
    }

    #[test]
    fn semantic_graph_preserves_scopes_side_effects_iifes_and_typed_edges() {
        let source = r#"
            import { boot as importedBoot } from 'pkg';
            const required = require('required-package');
            const directNamed = require('required-package').directNamed;
            const { named: legacyNamed, 'string-key': stringKey, ...legacyRest } = require('required-package');
            const loaded = import('dynamic-package');
            const lazyNamespace = import('lazy-package');
            async function loadNamespace() {
              const awaitedNamespace = await import('awaited-package');
              const { awaitedNamed: awaitedRenamed } = await import('awaited-destructured-package');
              return [awaitedNamespace, awaitedRenamed];
            }
            console.log('top-level');
            (function () { importedBoot(); })();
            class Widget {}
            new Widget();
            function Child() { return <span />; }
            function Parent() { return <Child />; }
            function shadow(value) {
                { let value = 1; console.log(value); }
                return value;
            }
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::tsx(), "fixture.tsx", "left").unwrap();
        let node_by_id = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        for kind in ["File", "Scope", "Statement", "Function", "Class", "Symbol"] {
            assert!(
                graph.nodes.iter().any(|node| node.kind == kind),
                "missing {kind}"
            );
        }
        for kind in [
            "Contains",
            "NextStatement",
            "Calls",
            "References",
            "Imports",
            "Requires",
            "RequiresBinding",
            "DynamicImports",
            "DynamicImportsBinding",
            "Instantiates",
            "Renders",
        ] {
            assert!(
                graph.edges.iter().any(|edge| edge.kind == kind),
                "missing {kind}"
            );
        }
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "Calls"
                && !edge.dynamic
                && node_by_id
                    .get(edge.target.as_str())
                    .is_some_and(|node| node.kind == "Function")
        }));
        let commonjs_exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "RequiresBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert!(commonjs_exports.contains("named"));
        assert!(commonjs_exports.contains("directNamed"));
        assert!(commonjs_exports.contains("string-key"));
        assert!(commonjs_exports.contains("*"));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "DynamicImportsBinding" && edge.label.as_deref() == Some("*")
        }));
        let dynamic_binding_modules = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "DynamicImportsBinding")
            .filter_map(|edge| node_by_id.get(edge.target.as_str()))
            .map(|node| node.label.as_str())
            .collect::<BTreeSet<_>>();
        assert!(dynamic_binding_modules.contains("module:awaited-package"));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "DynamicImportsBinding"
                && edge.label.as_deref() == Some("awaitedNamed")
                && node_by_id
                    .get(edge.target.as_str())
                    .is_some_and(|node| node.label == "module:awaited-destructured-package")
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "Renders"
                && edge.label.as_deref() == Some("Child")
                && node_by_id
                    .get(edge.target.as_str())
                    .is_some_and(|node| node.kind == "Symbol")
        }));
        let referenced_symbols = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "References")
            .filter_map(|edge| node_by_id.get(edge.target.as_str()))
            .filter(|node| node.kind == "Symbol")
            .map(|node| node.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(referenced_symbols.len() >= 3);
    }

    #[test]
    fn semantic_graph_preserves_import_binding_provenance() {
        let source = r#"
            import { debounce as wait } from 'lodash';
            import type { Config } from 'types-package';
            import { type Shape } from 'types-package';
            import fallback from 'fallback-package';
            import * as namespace from 'namespace-package';
            function run() { wait(() => {}); fallback(); namespace.run(); }
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::ts(), "fixture.ts", "left").unwrap();
        let imported = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ImportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(imported, BTreeSet::from(["*", "debounce", "default"]));
        let type_imported = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "TypeImportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(type_imported, BTreeSet::from(["Config", "Shape"]));
        assert!(graph.edges.iter().any(|edge| edge.kind == "TypeImports"));
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == "External" && node.label == "module:lodash"));
    }

    #[test]
    fn semantic_graph_keeps_each_read_and_call_occurrence() {
        let source = r#"
            function target() {}
            function use(value) {
                target();
                target();
                return value + value;
            }
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::mjs(), "fixture.js", "left").unwrap();
        let call_sites = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "CallSite")
            .collect::<Vec<_>>();
        let reference_sites = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "ReferenceSite")
            .collect::<Vec<_>>();
        assert_eq!(call_sites.len(), 2);
        assert!(reference_sites.len() >= 4);
        let calls = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "Calls")
            .collect::<Vec<_>>();
        assert_eq!(calls.len(), 2);
        assert_ne!(calls[0].source, calls[1].source);
    }

    #[test]
    fn semantic_graph_models_static_optional_and_computed_member_calls() {
        let source = r#"
            import * as api from 'api';
            function run(object, key) {
                api.start();
                object?.stop();
                object[key]();
            }
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::mjs(), "fixture.js", "left").unwrap();
        let members = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "MemberAccess")
            .map(|node| node.label.as_str())
            .collect::<BTreeSet<_>>();
        assert!(members.contains("start"));
        assert!(members.contains("stop?"));
        assert!(members.contains("key"));
        let member_ids = graph
            .nodes
            .iter()
            .filter(|node| node.kind == "MemberAccess")
            .map(|node| node.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.kind == "Calls" && member_ids.contains(edge.target.as_str()) }));
        assert!(graph.edges.iter().any(|edge| edge.kind == "Accesses"));
    }

    #[test]
    fn semantic_graph_distinguishes_identifier_writes_from_reads() {
        let source = "let value = 0; function update(){ value = value + 1; }";
        let (_, _, graph) = canonicalize(source, SourceType::mjs(), "fixture.js", "left").unwrap();
        assert_eq!(
            graph
                .nodes
                .iter()
                .filter(|node| node.kind == "WriteSite")
                .count(),
            1
        );
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.kind == "Writes")
                .count(),
            1
        );
        assert!(graph.edges.iter().any(|edge| edge.kind == "References"));
    }

    #[test]
    fn semantic_graph_keeps_type_exports_out_of_runtime_contracts() {
        let source = r#"
            export type { Model as PublicModel } from './types';
            export { type Shape as PublicShape, run as publicRun } from './mixed';
            export type * as TypeNamespace from './types';
            export interface PublicInterface { id: string }
            export type PublicAlias = string;
            export const runtime = 1;
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::ts(), "barrel.ts", "left").unwrap();
        let runtime_exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(runtime_exports, BTreeSet::from(["publicRun", "runtime"]));
        let type_exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "TypeExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            type_exports,
            BTreeSet::from([
                "PublicAlias",
                "PublicInterface",
                "PublicModel",
                "PublicShape",
                "TypeNamespace",
            ])
        );
        let runtime_reexports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ReExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(runtime_reexports, BTreeSet::from(["publicRun <- run"]));
        let type_reexports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "TypeReExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            type_reexports,
            BTreeSet::from([
                "PublicModel <- Model",
                "PublicShape <- Shape",
                "TypeNamespace <- *",
            ])
        );
        assert!(graph.edges.iter().any(|edge| edge.kind == "TypeExports"));
        assert!(!graph.edges.iter().any(|edge| {
            edge.kind == "ExportsBinding"
                && matches!(
                    edge.label.as_deref(),
                    Some(
                        "PublicModel"
                            | "PublicShape"
                            | "TypeNamespace"
                            | "PublicInterface"
                            | "PublicAlias"
                    )
                )
        }));
    }

    #[test]
    fn semantic_graph_preserves_typescript_import_equals_and_export_assignment() {
        let source = r#"
            import runtime = require('./runtime');
            import type Types = require('./types');
            export = runtime;
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::ts(), "legacy.ts", "left").unwrap();
        let requires = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "RequiresBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(requires, BTreeSet::from(["*"]));
        let type_imports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "TypeImportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(type_imports, BTreeSet::from(["*"]));
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.kind == "Requires" && edge.label.as_deref() == Some("./runtime") }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "TypeImports" && edge.label.as_deref() == Some("./types")
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "ExportsBinding" && edge.label.as_deref() == Some("default")
        }));
    }

    #[test]
    fn semantic_graph_preserves_static_commonjs_export_ownership() {
        let source = r#"
            const value = 1;
            module.exports = value;
            module.exports.foo = value;
            exports.bar = value;
            module.exports = require('./forwarded');
            exports.alias = require('./forwarded').named;
            exports['computed'] = value;
            function shadow(exports, module) {
                exports.hidden = value;
                module.exports.hidden = value;
            }
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::cjs(), "fixture.cjs", "left").unwrap();
        let exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(exports, BTreeSet::from(["alias", "bar", "default", "foo"]));
        let reexports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ReExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            reexports,
            BTreeSet::from(["alias <- named", "default <- *"])
        );
    }

    #[test]
    fn semantic_graph_exports_only_declared_symbols_and_keeps_local_owners() {
        let source = r#"
            const local = 1;
            export { local as publicLocal };
            export default local;
            export function api(parameter) {
                const implementationDetail = parameter + local;
                return implementationDetail;
            }
            export const publicValue = 2;
            module.exports.legacy = local;
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::mjs(), "fixture.ts", "left").unwrap();
        let exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            exports,
            BTreeSet::from(["api", "default", "legacy", "publicLocal", "publicValue"])
        );

        let nodes = graph
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let owners = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.kind == "ExportsBinding"
                    && matches!(
                        edge.label.as_deref(),
                        Some("publicLocal" | "default" | "legacy")
                    )
            })
            .filter_map(|edge| nodes.get(edge.source.as_str()))
            .map(|node| node.kind.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(owners, BTreeSet::from(["Symbol"]));
    }

    #[test]
    fn semantic_graph_preserves_named_and_wildcard_reexport_contracts() {
        let source = r#"
            export { implementation as publicApi } from './implementation';
            export * as plugins from './plugins';
            export * from './wildcard';
        "#;
        let (_, _, graph) = canonicalize(source, SourceType::mjs(), "barrel.js", "left").unwrap();
        let exports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(exports, BTreeSet::from(["plugins", "publicApi"]));
        let reexports = graph
            .edges
            .iter()
            .filter(|edge| edge.kind == "ReExportsBinding")
            .filter_map(|edge| edge.label.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            reexports,
            BTreeSet::from(["* <- *", "plugins <- *", "publicApi <- implementation",])
        );
    }

    #[test]
    fn type_only_local_contracts_bind_without_runtime_provenance() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("src")).unwrap();
        fs::write(
            left.path().join("src/types.d.ts"),
            "export interface Model { id: string }",
        )
        .unwrap();
        fs::write(
            left.path().join("src/runtime.ts"),
            "export const runtime = 1;",
        )
        .unwrap();
        fs::write(
            left.path().join("src/consumer.ts"),
            "import type { Model } from './types'; import { runtime } from './runtime'; export type { Model }; export { runtime };",
        )
        .unwrap();
        fs::write(
            right.path().join("placeholder.js"),
            "export const placeholder = true;",
        )
        .unwrap();

        let indexed = index_project(left.path(), "left").unwrap();
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| { edge.kind == "TypeBindsTo" && edge.label.as_deref() == Some("Model") }));
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| edge.kind == "BindsTo" && edge.label.as_deref() == Some("runtime")));

        run(left.path(), right.path(), output.path()).unwrap();
        let provenance =
            fs::read_to_string(output.path().join("dependency-provenance.jsonl")).unwrap();
        assert!(provenance.lines().any(|line| {
            let row = serde_json::from_str::<serde_json::Value>(line).unwrap();
            row["specifier"] == "./types"
                && row["importedExport"] == "Model"
                && row["edgeKind"] == "TypeImportsBinding"
                && row["entryPath"] == "src/types.d.ts"
        }));
        assert!(provenance.lines().any(|line| {
            let row = serde_json::from_str::<serde_json::Value>(line).unwrap();
            row["specifier"] == "./runtime" && row["importedExport"] == "runtime"
        }));
    }

    #[test]
    fn package_import_maps_are_exact_or_explicitly_unresolved() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("src")).unwrap();
        fs::write(
            left.path().join("package.json"),
            r##"{
                "name":"package-import-fixture",
                "imports": {
                    "#runtime":"./src/runtime.js",
                    "#types":"./src/types.ts",
                    "#alias/*":"./src/*.js",
                    "#convergent":{"import":"./src/runtime.js","require":"./src/runtime.js"},
                    "#conditional":{"import":"./src/runtime.js","require":"./src/types.ts"}
                }
            }"##,
        )
        .unwrap();
        fs::write(
            left.path().join("src/runtime.js"),
            "export const runtime = 1;",
        )
        .unwrap();
        fs::write(
            left.path().join("src/types.ts"),
            "export interface Model { id: string }",
        )
        .unwrap();
        fs::write(
            left.path().join("src/main.ts"),
            "import { runtime } from '#runtime'; import type { Model } from '#types'; import '#conditional'; runtime;",
        )
        .unwrap();
        fs::write(
            right.path().join("placeholder.js"),
            "export const placeholder = true;",
        )
        .unwrap();

        let indexed = index_project(left.path(), "left").unwrap();
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesTo" && edge.label.as_deref() == Some("#runtime")
        }));
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| { edge.kind == "BindsTo" && edge.label.as_deref() == Some("runtime") }));
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| { edge.kind == "TypeBindsTo" && edge.label.as_deref() == Some("Model") }));

        run(left.path(), right.path(), output.path()).unwrap();
        let rows = fs::read_to_string(output.path().join("dependency-provenance.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(rows.iter().any(|row| {
            row["specifier"] == "#runtime"
                && row["resolution"] == "resolved-package-import-map"
                && row["entryResolution"] == "exact-package-import-map"
                && row["resolvedPath"] == "src/runtime.js"
                && row["entrySha256"].as_str().is_some()
        }));
        assert!(rows.iter().any(|row| {
            row["specifier"] == "#conditional"
                && row["resolution"] == "conditional-or-unresolved-package-import-map"
                && row["entryResolution"] == "conditional-or-unresolved-package-import-map"
                && row["resolvedPath"].is_null()
                && row["entryCandidates"].as_array().is_some_and(|paths| {
                    paths.iter().any(|path| path == "src/runtime.js")
                        && paths.iter().any(|path| path == "src/types.ts")
                })
        }));
        assert_eq!(
            resolve_package_import(
                &left.path().join("src/main.ts"),
                left.path(),
                "#alias/runtime"
            )
            .resolution,
            "exact-package-import-map"
        );
        assert_eq!(
            resolve_package_import(&left.path().join("src/main.ts"), left.path(), "#convergent")
                .resolution,
            "exact-package-import-map"
        );
    }

    #[test]
    fn tsconfig_paths_resolve_local_value_and_type_bindings() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("src")).unwrap();
        fs::write(
            left.path().join("tsconfig.json"),
            r#"{
                // JSONC comments and trailing commas are valid tsconfig syntax.
                "compilerOptions": {
                    "baseUrl": ".",
                    "paths": { "@app/*": ["src/*",], },
                },
            }"#,
        )
        .unwrap();
        fs::write(
            left.path().join("src/runtime.ts"),
            "export const runtime = 1; export interface Model { id: string }",
        )
        .unwrap();
        fs::write(
            left.path().join("src/consumer.ts"),
            "import { runtime } from '@app/runtime'; import type { Model } from '@app/runtime'; async function load() { const { runtime: dynamicRuntime } = await import('@app/runtime'); return dynamicRuntime; } runtime; type Local = Model;",
        )
        .unwrap();
        fs::write(
            right.path().join("placeholder.js"),
            "export const placeholder = true;",
        )
        .unwrap();

        let indexed = index_project(left.path(), "left").unwrap();
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesTo" && edge.label.as_deref() == Some("@app/runtime")
        }));
        assert!(
            indexed
                .graph_edges
                .iter()
                .filter(|edge| edge.kind == "BindsTo" && edge.label.as_deref() == Some("runtime"))
                .count()
                >= 2
        );
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| { edge.kind == "TypeBindsTo" && edge.label.as_deref() == Some("Model") }));

        run(left.path(), right.path(), output.path()).unwrap();
        let rows = fs::read_to_string(output.path().join("dependency-provenance.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(rows.iter().any(|row| {
            row["specifier"] == "@app/runtime"
                && row["resolution"] == "resolved-tsconfig-path"
                && row["entryResolution"] == "exact-tsconfig-path"
                && row["resolvedPath"] == "src/runtime.ts"
        }));
    }

    #[test]
    fn tsconfig_package_extends_contributes_effective_paths() {
        let project = tempdir().unwrap();
        fs::create_dir_all(project.path().join("src")).unwrap();
        fs::create_dir_all(project.path().join("node_modules/@fixture/config")).unwrap();
        fs::write(
            project
                .path()
                .join("node_modules/@fixture/config/tsconfig.json"),
            r#"{"compilerOptions":{"baseUrl":"../../..","paths":{"@shared/*":["src/*"]}}}"#,
        )
        .unwrap();
        fs::write(
            project.path().join("tsconfig.json"),
            r#"{"extends":"@fixture/config/tsconfig.json"}"#,
        )
        .unwrap();
        fs::write(
            project.path().join("src/value.ts"),
            "export const value = 1;",
        )
        .unwrap();
        fs::write(
            project.path().join("src/main.ts"),
            "import { value } from '@shared/value'; value;",
        )
        .unwrap();

        let indexed = index_project(project.path(), "left").unwrap();
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesTo" && edge.label.as_deref() == Some("@shared/value")
        }));
        let entry = resolve_tsconfig_path(
            &project.path().join("src/main.ts"),
            project.path(),
            "@shared/value",
            false,
        )
        .expect("path rule");
        assert_eq!(entry.resolution, "exact-tsconfig-path");
        assert_eq!(
            entry.path.unwrap(),
            project.path().join("src/value.ts").canonicalize().unwrap()
        );
    }

    #[test]
    fn tsconfig_project_references_do_not_become_inherited_aliases() {
        let project = tempdir().unwrap();
        fs::create_dir_all(project.path().join("src")).unwrap();
        fs::create_dir_all(project.path().join("alternative")).unwrap();
        fs::write(
            project.path().join("tsconfig.json"),
            r#"{ "references": [{ "path": "./tsconfig.web.json" }, { "path": "./tsconfig.node.json" }] }"#,
        )
        .unwrap();
        fs::write(
            project.path().join("tsconfig.web.json"),
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@app/*": ["src/*"] } } }"#,
        )
        .unwrap();
        fs::write(
            project.path().join("tsconfig.node.json"),
            r#"{ "compilerOptions": { "baseUrl": ".", "paths": { "@app/*": ["alternative/*"] } } }"#,
        )
        .unwrap();
        fs::write(
            project.path().join("src/runtime.ts"),
            "export const runtime = 1;",
        )
        .unwrap();
        fs::write(
            project.path().join("alternative/runtime.ts"),
            "export const runtime = 2;",
        )
        .unwrap();
        fs::write(
            project.path().join("consumer.ts"),
            "import { runtime } from '@app/runtime'; runtime;",
        )
        .unwrap();

        let entry = resolve_tsconfig_path(
            &project.path().join("consumer.ts"),
            project.path(),
            "@app/runtime",
            false,
        );
        assert!(entry.is_none());
        let indexed = index_project(project.path(), "left").unwrap();
        assert!(!indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesTo" && edge.label.as_deref() == Some("@app/runtime")
        }));
    }

    #[test]
    fn extensionless_source_resolution_refuses_multiple_runtime_candidates() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(root.path().join("src/entry.ts"), "import './helper';").unwrap();
        fs::write(root.path().join("src/helper.js"), "export const js = 1;").unwrap();
        fs::write(root.path().join("src/helper.ts"), "export const ts = 1;").unwrap();
        assert!(resolve_relative_source(&root.path().join("src/entry.ts"), "./helper").is_none());
        assert_eq!(
            resolve_source_candidates(root.path().join("src/helper"), false).len(),
            2
        );
    }

    #[test]
    fn runtime_url_specifiers_are_not_misclassified_as_packages() {
        for specifier in [
            "node:fs",
            "data:text/javascript,export%20default%201",
            "file:///tmp/module.js",
            "https://example.test/module.js",
            "bun:sqlite",
            "deno:runtime",
        ] {
            assert_eq!(package_name_from_specifier(specifier), None, "{specifier}");
        }
        assert_eq!(
            package_name_from_specifier("@scope/package/subpath"),
            Some("@scope/package")
        );
    }

    #[test]
    fn package_self_reference_resolves_before_node_modules_lookup() {
        let package = tempdir().unwrap();
        fs::create_dir_all(package.path().join("src")).unwrap();
        fs::write(
            package.path().join("package.json"),
            r#"{"name":"self-reference-fixture"}"#,
        )
        .unwrap();
        let resolved = resolve_installed_package(
            &package.path().join("src"),
            package.path(),
            "self-reference-fixture",
        )
        .unwrap();
        assert_eq!(resolved, package.path().canonicalize().unwrap());
    }

    #[test]
    fn dependency_provenance_resolves_exact_package_version_and_keeps_local_edges() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("node_modules/lodash")).unwrap();
        fs::create_dir_all(left.path().join("src")).unwrap();
        fs::write(
            left.path().join("node_modules/lodash/package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        )
        .unwrap();
        fs::write(
            left.path().join("node_modules/lodash/index.js"),
            "export const debounce = value => value;",
        )
        .unwrap();
        fs::write(
            left.path().join("src/helper.js"),
            "export const helper = 1;",
        )
        .unwrap();
        fs::write(
            left.path().join("src/cjs-helper.cjs"),
            "const value = 1; module.exports.foo = value;",
        )
        .unwrap();
        fs::write(
            left.path().join("src/barrel.js"),
            "export { helper as api } from './helper';",
        )
        .unwrap();
        fs::write(
            left.path().join("src/main.ts"),
            "import { debounce as wait } from 'lodash'; import legacyPackage = require('lodash'); import { helper } from './helper'; import { api } from './barrel'; const { helper: legacyHelper } = require('./helper'); const { foo: legacyFoo } = require('./cjs-helper'); const directDebounce = require('lodash').debounce; const dynamicPackage = import('lodash'); wait(helper); legacyPackage; directDebounce; dynamicPackage; api;",
        )
        .unwrap();
        fs::write(right.path().join("main.js"), "export const ready = true;").unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let rows = fs::read_to_string(output.path().join("dependency-provenance.jsonl")).unwrap();
        let rows = rows
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "lodash"
                && row["importedExport"] == "debounce"
                && row["resolution"] == "resolved-installed-package"
                && row["package"] == "lodash"
                && row["version"] == "4.17.21"
                && row["packageRuntimeSha256"].as_str().is_some()
                && row["entryResolution"] == "legacy-package-main"
                && row["entryPath"] == "index.js"
                && row["entrySha256"].as_str().is_some()
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "lodash"
                && row["edgeKind"] == "RequiresBinding"
                && row["importedExport"] == "*"
                && row["resolution"] == "resolved-installed-package"
                && row["package"] == "lodash"
                && row["version"] == "4.17.21"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "lodash"
                && row["edgeKind"] == "RequiresBinding"
                && row["importedExport"] == "debounce"
                && row["resolution"] == "resolved-installed-package"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "lodash"
                && row["edgeKind"] == "DynamicImportsBinding"
                && row["importedExport"] == "*"
                && row["bindingSymbolId"].is_string()
                && row["resolution"] == "resolved-installed-package"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "./helper"
                && row["resolution"] == "resolved-local-source"
                && row["resolvedPath"] == "src/helper.js"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "./helper"
                && row["edgeKind"] == "RequiresBinding"
                && row["importedExport"] == "helper"
                && row["resolution"] == "resolved-local-source"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "./helper"
                && row["edgeKind"] == "Requires"
                && row["importedExport"] == "<commonjs-require>"
                && row["resolution"] == "resolved-local-source"
        }));
        assert!(rows.iter().any(|row| {
            row["side"] == "left"
                && row["specifier"] == "./helper"
                && row["edgeKind"] == "ReExportsBinding"
                && row["importedExport"] == "api <- helper"
                && row["resolution"] == "resolved-local-source"
        }));
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        assert!(report["left"]["files"].as_array().is_some_and(|files| {
            files
                .iter()
                .any(|file| file["file"].as_str() == Some("src/helper.js"))
        }));
        let indexed = index_project(left.path(), "left").unwrap();
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesTo" && edge.label.as_deref() == Some("./helper")
        }));
        assert!(
            indexed
                .graph_edges
                .iter()
                .filter(|edge| edge.kind == "BindsTo" && edge.label.as_deref() == Some("helper"))
                .count()
                >= 2
        );
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| edge.kind == "BindsTo" && edge.label.as_deref() == Some("foo")));
        assert!(indexed
            .graph_edges
            .iter()
            .any(|edge| edge.kind == "BindsTo" && edge.label.as_deref() == Some("api")));
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ReExportsBinding" && edge.label.as_deref() == Some("api <- helper")
        }));
        assert!(indexed.graph_nodes.iter().any(|node| {
            node.kind == "PackageEntry" && node.label == "lodash@4.17.21:index.js"
        }));
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "ResolvesToPackage" && edge.label.as_deref() == Some("lodash")
        }));
    }

    #[test]
    fn local_reexport_chain_binds_to_the_concrete_owner() {
        let project = tempdir().unwrap();
        fs::create_dir_all(project.path().join("src")).unwrap();
        fs::write(
            project.path().join("src/owner.js"),
            "export function implementation() { return 1; }",
        )
        .unwrap();
        fs::write(
            project.path().join("src/first.js"),
            "export { implementation as intermediate } from './owner';",
        )
        .unwrap();
        fs::write(
            project.path().join("src/second.js"),
            "export { intermediate as publicApi } from './first';",
        )
        .unwrap();
        fs::write(
            project.path().join("src/use.js"),
            "import { publicApi } from './second'; publicApi();",
        )
        .unwrap();

        let indexed = index_project(project.path(), "left").unwrap();
        let nodes = indexed
            .graph_nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let implementation = indexed
            .graph_edges
            .iter()
            .find(|edge| {
                edge.kind == "ExportsBinding"
                    && edge.label.as_deref() == Some("implementation")
                    && nodes
                        .get(edge.source.as_str())
                        .is_some_and(|node| node.file == "src/owner.js")
            })
            .map(|edge| edge.source.as_str())
            .expect("owner export");
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "BindsTo"
                && edge.label.as_deref() == Some("publicApi")
                && edge.target == implementation
        }));
        assert_eq!(
            indexed
                .graph_edges
                .iter()
                .filter(|edge| {
                    edge.kind == "ReExportsTo"
                        && edge.label.as_deref() == Some("publicApi <- intermediate")
                })
                .count(),
            1
        );
    }

    #[test]
    fn wildcard_reexport_propagates_known_named_exports_but_not_default() {
        let project = tempdir().unwrap();
        fs::write(
            project.path().join("owner.js"),
            "export const named = 1; export default 2;",
        )
        .unwrap();
        fs::write(project.path().join("barrel.js"), "export * from './owner';").unwrap();
        fs::write(
            project.path().join("use.js"),
            "import { named } from './barrel'; named();",
        )
        .unwrap();

        let indexed = index_project(project.path(), "left").unwrap();
        let nodes = indexed
            .graph_nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let owner = indexed
            .graph_edges
            .iter()
            .find(|edge| {
                edge.kind == "ExportsBinding"
                    && edge.label.as_deref() == Some("named")
                    && nodes
                        .get(edge.source.as_str())
                        .is_some_and(|node| node.file == "owner.js")
            })
            .map(|edge| edge.source.as_str())
            .expect("named owner");
        assert!(indexed.graph_edges.iter().any(|edge| {
            edge.kind == "BindsTo" && edge.label.as_deref() == Some("named") && edge.target == owner
        }));
        assert!(!indexed
            .graph_edges
            .iter()
            .any(|edge| { edge.kind == "BindsTo" && edge.label.as_deref() == Some("default") }));
    }

    #[test]
    fn package_runtime_fingerprint_changes_with_executable_source() {
        let package = tempdir().unwrap();
        fs::write(package.path().join("index.js"), "export const value = 1;").unwrap();
        fs::create_dir_all(package.path().join("esm")).unwrap();
        fs::write(
            package.path().join("esm/secondary.js"),
            "export const secondary = 1;",
        )
        .unwrap();
        fs::write(
            package.path().join("package.json"),
            "{\"name\":\"fixture\"}",
        )
        .unwrap();
        let first = package_runtime_sha256(package.path()).unwrap();
        fs::write(
            package.path().join("esm/secondary.js"),
            "export const secondary = 2;",
        )
        .unwrap();
        let second = package_runtime_sha256(package.path()).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn package_entry_resolution_is_exact_or_explicitly_conditional() {
        let package = tempdir().unwrap();
        fs::create_dir_all(package.path().join("src")).unwrap();
        fs::write(package.path().join("src/root.js"), "export const root = 1;").unwrap();
        fs::write(
            package.path().join("src/feature.js"),
            "export const feature = 1;",
        )
        .unwrap();
        fs::write(
            package.path().join("package.json"),
            r#"{
                "name":"entry-fixture",
                "version":"1.0.0",
                "exports": {
                    ".":"./src/root.js",
                    "./feature":"./src/feature.js",
                    "./feature/*":"./src/*.js",
                    "./convergent":{"import":"./src/root.js","require":"./src/root.js"},
                    "./blocked":{"import":"./src/root.js","browser":null},
                    "./conditional":{"import":"./src/root.js","require":"./src/feature.js"}
                }
            }"#,
        )
        .unwrap();
        let manifest = read_package_manifest(&package.path().join("package.json")).unwrap();
        let root = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture",
            "entry-fixture",
        );
        assert_eq!(root.resolution, "exact-package-export");
        let canonical_package = package.path().canonicalize().unwrap();
        assert_eq!(
            root.path.unwrap().strip_prefix(&canonical_package).unwrap(),
            Path::new("src/root.js")
        );
        let subpath = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture/feature",
            "entry-fixture",
        );
        assert_eq!(subpath.resolution, "exact-package-export");
        let wildcard = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture/feature/root",
            "entry-fixture",
        );
        assert_eq!(wildcard.resolution, "exact-package-export");
        let convergent = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture/convergent",
            "entry-fixture",
        );
        assert_eq!(convergent.resolution, "exact-package-export");
        let blocked = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture/blocked",
            "entry-fixture",
        );
        assert_eq!(
            blocked.resolution,
            "conditional-or-unexported-package-export"
        );
        let conditional = resolve_installed_package_entry(
            package.path(),
            &manifest,
            "entry-fixture/conditional",
            "entry-fixture",
        );
        assert_eq!(
            conditional.resolution,
            "conditional-or-unexported-package-export"
        );
        assert!(conditional.path.is_none());
    }

    #[test]
    fn conditional_package_exports_remain_graph_candidates() {
        let project = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(project.path().join("node_modules/conditional-package/dist")).unwrap();
        fs::write(
            project
                .path()
                .join("node_modules/conditional-package/package.json"),
            r#"{
                "name":"conditional-package",
                "version":"1.2.3",
                "exports":{".":{"import":"./dist/esm.js","require":"./dist/cjs.js"}}
            }"#,
        )
        .unwrap();
        fs::write(
            project
                .path()
                .join("node_modules/conditional-package/dist/esm.js"),
            "export const mode = 'esm';",
        )
        .unwrap();
        fs::write(
            project
                .path()
                .join("node_modules/conditional-package/dist/cjs.js"),
            "module.exports = { mode: 'cjs' };",
        )
        .unwrap();
        fs::write(
            project.path().join("main.js"),
            "import { mode } from 'conditional-package'; console.log(mode);",
        )
        .unwrap();
        fs::write(
            right.path().join("placeholder.js"),
            "export const ok = true;",
        )
        .unwrap();

        let indexed = index_project(project.path(), "left").unwrap();
        let discovery = discover_dependencies(project.path(), Some(&indexed))
            .unwrap()
            .expect("observed package closure");
        assert!(discovery
            .corpus
            .roots
            .iter()
            .any(|root| root == "conditional-package@1.2.3"));
        let candidates = indexed
            .graph_edges
            .iter()
            .filter(|edge| {
                edge.kind == "ResolvesToPackageCandidate"
                    && edge.label.as_deref() == Some("conditional-package")
            })
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 2);
        let target_labels = indexed
            .graph_nodes
            .iter()
            .map(|node| (node.id.as_str(), node.label.as_str()))
            .collect::<HashMap<_, _>>();
        assert!(candidates.iter().any(|edge| {
            target_labels.get(edge.target.as_str())
                == Some(&"conditional-package@1.2.3:dist/esm.js")
        }));
        assert!(candidates.iter().any(|edge| {
            target_labels.get(edge.target.as_str())
                == Some(&"conditional-package@1.2.3:dist/cjs.js")
        }));
        run(project.path(), right.path(), output.path()).unwrap();
        let rows = fs::read_to_string(output.path().join("dependency-provenance.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(rows.iter().any(|row| {
            row["specifier"] == "conditional-package"
                && row["entryCandidates"].as_array().is_some_and(|paths| {
                    paths.iter().any(|path| path == "dist/esm.js")
                        && paths.iter().any(|path| path == "dist/cjs.js")
                })
        }));
    }

    #[test]
    fn binding_contract_requires_graph_identity_and_runtime_package_fingerprint() {
        let row = |side: &str, binding: &str, fingerprint: &str| DependencyProvenance {
            side: side.to_string(),
            edge_kind: "ImportsBinding".to_string(),
            importer_file: "src/main.js".to_string(),
            specifier: "lodash".to_string(),
            imported_export: "debounce".to_string(),
            binding_symbol_id: Some(binding.to_string()),
            module_node_id: format!("{side}-module"),
            resolution: "resolved-installed-package",
            resolved_path: Some(format!("/{side}/node_modules/lodash")),
            package: Some("lodash".to_string()),
            version: Some("4.17.21".to_string()),
            package_runtime_sha256: Some(fingerprint.to_string()),
            entry_resolution: Some("legacy-package-main"),
            entry_path: Some("index.js".to_string()),
            entry_sha256: Some(fingerprint.to_string()),
            entry_candidates: Vec::new(),
        };
        let relation = GraphRelation {
            confidence: "candidate",
            basis: "neighbor-exact",
            depth: 1,
            via_edge: Some("ImportsBinding".to_string()),
            source: None,
            left: GraphNodeRef {
                id: "left-binding".to_string(),
                file: "src/main.js".to_string(),
                kind: "Symbol".to_string(),
                label: "local".to_string(),
                line: 1,
                start: 0,
                end: 1,
            },
            right: GraphNodeRef {
                id: "right-binding".to_string(),
                file: "src/main.js".to_string(),
                kind: "Symbol".to_string(),
                label: "local".to_string(),
                line: 1,
                start: 0,
                end: 1,
            },
        };
        let contracts = dependency_binding_contracts(
            &[
                row("left", "left-binding", "same"),
                row("right", "right-binding", "same"),
            ],
            &[relation],
        );
        assert!(contracts
            .iter()
            .any(|contract| contract.disposition == "candidate-identical-package-contract"));

        let contracts = dependency_binding_contracts(
            &[
                row("left", "left-binding", "before"),
                row("right", "right-binding", "after"),
            ],
            &[GraphRelation {
                confidence: "candidate",
                basis: "neighbor-exact",
                depth: 1,
                via_edge: Some("ImportsBinding".to_string()),
                source: None,
                left: GraphNodeRef {
                    id: "left-binding".to_string(),
                    file: "src/main.js".to_string(),
                    kind: "Symbol".to_string(),
                    label: "local".to_string(),
                    line: 1,
                    start: 0,
                    end: 1,
                },
                right: GraphNodeRef {
                    id: "right-binding".to_string(),
                    file: "src/main.js".to_string(),
                    kind: "Symbol".to_string(),
                    label: "local".to_string(),
                    line: 1,
                    start: 0,
                    end: 1,
                },
            }],
        );
        assert!(contracts
            .iter()
            .any(|contract| contract.disposition == "changed-or-unresolved-package-contract"));
    }

    #[test]
    fn alpha_equal_owner_with_different_import_provenance_is_not_proven_structure() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("main.js"),
            "import { run as target } from 'first-package'; export function caller(){ return target(); }",
        )
        .unwrap();
        fs::write(
            right.path().join("main.js"),
            "import { run as target } from 'second-package'; export function caller(){ return target(); }",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        assert!(report["matches"].as_array().is_some_and(|matches| {
            matches.iter().any(|record| {
                record["basis"] == "strict-dependency-context"
                    && record["status"] == "dependency-context-changed"
                    && record["confidence"] == "candidate"
            })
        }));
        assert!(!report["matches"].as_array().is_some_and(|matches| {
            matches.iter().any(|record| {
                record["basis"] == "strict"
                    && record["left"]["name"] == "caller"
                    && record["confidence"] == "proven-structure"
            })
        }));
    }

    #[test]
    fn divergence_frontier_reports_a_deleted_branch() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("owner.js"),
            "export function anchor(v){return v+1}export function render(flag){base();if(flag){extra()}return 1}",
        )
        .unwrap();
        fs::write(
            right.path().join("chunk.js"),
            "export function stable(x){return x+1}export function x(value){base();return 1}",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let frontiers =
            fs::read_to_string(output.path().join("divergence-frontiers.jsonl")).unwrap();
        assert!(frontiers.lines().any(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            matches!(
                value["classification"].as_str(),
                Some("extra-local-branch" | "changed-branch")
            )
        }));
        let relations = fs::read_to_string(output.path().join("graph-relations.jsonl")).unwrap();
        assert!(relations.lines().any(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["depth"].as_u64().is_some_and(|depth| depth > 0)
                && value["source"]["left"]["id"].is_string()
                && value["source"]["right"]["id"].is_string()
        }));
        let overlay: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(output.path().join("graph-overlay.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(overlay["schema"], "project-parity/overlay-v1");
        assert!(overlay["nodes"]
            .as_object()
            .is_some_and(|nodes| !nodes.is_empty()));
        assert_eq!(overlay["systemMap"]["orientation"], "upstream-led");
        assert_eq!(
            overlay["systemMap"]["leftFiles"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            overlay["systemMap"]["rightFiles"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(overlay["systemMap"]["links"]
            .as_array()
            .is_some_and(|links| !links.is_empty()));
    }

    #[test]
    fn global_behavior_matching_ignores_file_and_chunk_boundaries() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("feature")).unwrap();
        fs::write(
            left.path().join("feature/first.js"),
            "console.log('first-side-effect')",
        )
        .unwrap();
        fs::write(
            left.path().join("feature/second.js"),
            "console.log('second-side-effect')",
        )
        .unwrap();
        fs::create_dir_all(right.path().join("bundle")).unwrap();
        fs::write(
            right.path().join("bundle/chunk.js"),
            "console.log('first-side-effect');console.log('second-side-effect')",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let relations = fs::read_to_string(output.path().join("graph-relations.jsonl")).unwrap();
        let matched_files = relations
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|relation| relation["basis"] == "global-behavior")
            .filter(|relation| relation["left"]["kind"] == "Statement")
            .filter_map(|relation| {
                Some((
                    relation["left"]["file"].as_str()?.to_string(),
                    relation["right"]["file"].as_str()?.to_string(),
                ))
            })
            .collect::<BTreeSet<_>>();
        assert!(matched_files.contains(&(
            "feature/first.js".to_string(),
            "bundle/chunk.js".to_string()
        )));
        assert!(matched_files.contains(&(
            "feature/second.js".to_string(),
            "bundle/chunk.js".to_string()
        )));
    }

    #[test]
    fn project_match_crosses_file_boundaries() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("feature")).unwrap();
        fs::create_dir_all(right.path().join("chunk")).unwrap();
        fs::write(
            left.path().join("feature/a.js"),
            "export function add(a){return a+1}",
        )
        .unwrap();
        fs::write(
            right.path().join("chunk/z.js"),
            "export function x(y){return y+1}",
        )
        .unwrap();
        let summary = run(left.path(), right.path(), output.path()).unwrap();
        assert_eq!(summary.left_failures, 0);
        assert_eq!(summary.right_failures, 0);
        assert_eq!(summary.alpha_equal, 1);
    }

    #[test]
    fn llm_bundle_is_upstream_led_exhaustive_and_inspectable() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("source.js"),
            "export function same(value){return value+1}",
        )
        .unwrap();
        fs::write(
            right.path().join("bundle.js"),
            "export function a(input){return input+1}export function missing(){return upstreamOnly()}",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("llm-manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["orientation"], "upstream-led");
        assert!(manifest["summary"]["upstreamExecutableNodes"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert!(manifest["summary"]["workItems"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert!(manifest["summary"]["batches"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(
            manifest["artifacts"]["semanticGraph"],
            "semantic-graph.jsonl.zst"
        );
        assert_eq!(
            manifest["artifacts"]["semanticGraphIndex"],
            "semantic-graph.index.json"
        );
        assert!(output.path().join("semantic-graph.index.json").is_file());
        assert!(output
            .path()
            .join("upstream-semantic-ledger.index.json")
            .is_file());
        assert!(output
            .path()
            .join("upstream-semantic-edge-ledger.index.json")
            .is_file());

        let ledger = fs::read_to_string(output.path().join("upstream-executable-ledger.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            ledger.len() as u64,
            manifest["summary"]["upstreamExecutableNodes"]
                .as_u64()
                .unwrap()
        );
        assert!(ledger
            .iter()
            .all(|row| row["disposition"].is_string() && row["upstream"]["id"].is_string()));
        assert!(ledger
            .iter()
            .any(|row| row["disposition"] == "structurally-equal"));
        assert!(ledger.iter().any(|row| {
            row["disposition"] == "unlinked-upstream" && row["workItemId"].is_string()
        }));

        assert_eq!(
            manifest["artifacts"]["upstreamSemanticLedger"],
            "upstream-semantic-ledger.jsonl.zst"
        );
        assert_eq!(
            manifest["artifacts"]["upstreamSemanticEdgeLedger"],
            "upstream-semantic-edge-ledger.jsonl.zst"
        );
        let semantic_ledger = zstd::stream::decode_all(
            fs::File::open(output.path().join("upstream-semantic-ledger.jsonl.zst")).unwrap(),
        )
        .unwrap();
        let semantic_ledger = std::str::from_utf8(&semantic_ledger)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            semantic_ledger.len() as u64,
            manifest["summary"]["upstreamSemanticNodes"]
                .as_u64()
                .unwrap()
        );
        assert!(semantic_ledger
            .iter()
            .all(|row| row["id"].is_string() && row["disposition"].is_string()));
        assert!(semantic_ledger.iter().all(|row| {
            matches!(
                row["disposition"].as_str(),
                Some("structurally-equal" | "dependency-structurally-equal")
            ) || row["workItemId"].is_string()
        }));
        assert!(semantic_ledger.iter().any(|row| {
            row["disposition"] == "unresolved-graph-context" && row["workItemId"].is_string()
        }));
        let edge_ledger = zstd::stream::decode_all(
            fs::File::open(
                output
                    .path()
                    .join("upstream-semantic-edge-ledger.jsonl.zst"),
            )
            .unwrap(),
        )
        .unwrap();
        let edge_ledger = std::str::from_utf8(&edge_ledger)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let indexed = index_project(right.path(), "right").unwrap();
        assert_eq!(edge_ledger.len(), indexed.graph_edges.len());
        assert!(edge_ledger.iter().all(|row| {
            row["id"].is_string()
                && row["source"]["id"].is_string()
                && row["target"]["id"].is_string()
                && row["kind"].is_string()
        }));

        let graph_node_id = ledger[0]["upstream"]["id"].as_str().unwrap();
        let inspection = inspect_unit(output.path(), graph_node_id).unwrap();
        assert_eq!(inspection["unitId"], graph_node_id);
        assert!(inspection["source"].is_string());
        let graph = graph_node(output.path(), graph_node_id, 10, 0).unwrap();
        assert_eq!(graph["node"]["id"], graph_node_id);
        assert!(graph["totalEdges"].as_u64().is_some());

        let work_items = fs::read_to_string(output.path().join("llm-work-items.jsonl")).unwrap();
        assert!(work_items.contains("locate-unlinked-upstream-branch"));
        assert!(!work_items.contains("structurally-equal"));
        assert!(output.path().join("llm-work-items.index.json").is_file());
        let work_id = read_json_lines(&output.path().join("llm-work-items.jsonl")).unwrap()[0]
            ["id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(show_work(output.path(), &work_id).unwrap()["id"], work_id);
        let batches = read_json_lines(&output.path().join("llm-batches.jsonl")).unwrap();
        let batch_id = batches[0]["id"].as_str().unwrap();
        assert!(output.path().join("llm-batches.index.json").is_file());
        let batch = show_batch(output.path(), batch_id, 1, 0).unwrap();
        assert_eq!(batch["returned"], 1);
        assert_eq!(batch["offset"], 0);
        assert_eq!(batch["items"].as_array().map(Vec::len), Some(1));
        assert!(batch["batch"].get("workItemIds").is_none());
    }

    #[test]
    fn semantic_graph_index_pages_records_across_multiple_compressed_chunks() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        let source = (0..700)
            .map(|index| format!("function owner{index}(value){{return value+{index};}}\n"))
            .collect::<String>();
        fs::write(left.path().join("large.js"), source).unwrap();
        fs::write(right.path().join("small.js"), "export const ok = true;").unwrap();
        run(left.path(), right.path(), output.path()).unwrap();

        let graph_index: serde_json::Value = serde_json::from_slice(
            &fs::read(output.path().join("semantic-graph.index.json")).unwrap(),
        )
        .unwrap();
        assert!(graph_index["chunks"]
            .as_array()
            .is_some_and(|chunks| chunks.len() > 1));
        let node_id = graph_index["nodes"]
            .as_object()
            .and_then(|nodes| nodes.keys().next())
            .expect("indexed graph node")
            .clone();
        let page = graph_node(output.path(), &node_id, 5, 0).unwrap();
        assert_eq!(page["node"]["id"], node_id);
    }

    #[test]
    fn installed_dependency_code_is_covered_by_exact_evidence() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(left.path().join("node_modules/example-runtime")).unwrap();
        fs::write(
            left.path().join("package.json"),
            r#"{"name":"fixture","dependencies":{"example-runtime":"1.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            left.path()
                .join("node_modules/example-runtime/package.json"),
            r#"{"name":"example-runtime","version":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            left.path().join("node_modules/example-runtime/index.js"),
            "export function runtimeHelper(value){if(value==null){return 'missing'}return value.map(item=>item+1).join(',')}" ,
        )
        .unwrap();
        fs::write(
            left.path().join("app.js"),
            "import { runtimeHelper } from 'example-runtime'; export const app=()=>runtimeHelper([1]);",
        )
        .unwrap();
        fs::write(
            right.path().join("bundle.js"),
            "export function a(x){if(x==null){return 'missing'}return x.map(y=>y+1).join(',')}",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("llm-manifest.json")).unwrap())
                .unwrap();
        assert!(manifest["summary"]["dependencyCoveredNodes"]
            .as_u64()
            .is_some_and(|count| count > 0));
        let ledger =
            read_json_lines(&output.path().join("upstream-executable-ledger.jsonl")).unwrap();
        assert!(ledger.iter().any(|row| {
            row["disposition"] == "dependency-structurally-equal"
                && row["dependencyEvidence"]["package"]
                    .as_str()
                    .is_some_and(|package| package.starts_with("example-runtime@1.0.0"))
        }));
        let dependency_corpus: serde_json::Value = serde_json::from_slice(
            &fs::read(output.path().join("dependency-evidence-corpus.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            dependency_corpus["schema"],
            "project-parity/dependency-evidence-corpus-v1"
        );
        assert!(dependency_corpus["files"]
            .as_array()
            .is_some_and(|files| !files.is_empty()));
        let semantic_graph = zstd::stream::decode_all(
            fs::File::open(output.path().join("semantic-graph.jsonl.zst")).unwrap(),
        )
        .unwrap();
        assert!(std::str::from_utf8(&semantic_graph)
            .unwrap()
            .lines()
            .any(|line| line.contains("ResolvesToDependencySource")));
    }

    #[test]
    fn report_ranks_regex_template_and_unicode_by_ast_features() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("left.js"),
            "export function regexFoo(v){return /foo/u.test(`${v}-α`)}\n\
             export function regexBar(v){return /bar/u.test(`${v}-β`)}",
        )
        .unwrap();
        fs::write(
            right.path().join("right.js"),
            "export function changed(x){if(x==null)return false;return /foo/u.test(`${x}-α`)}",
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();

        let unmatched = fs::read_to_string(output.path().join("unmatched-right.jsonl")).unwrap();
        let record: serde_json::Value =
            serde_json::from_str(unmatched.lines().next().unwrap()).unwrap();
        let best = &record["candidates"][0];
        assert_eq!(best["location"]["name"], "regexFoo");
        assert!(best["channels"]["literals"].as_f64().unwrap() > 0.5);
        assert!(best["channels"]["shape"].as_f64().unwrap() > 0.5);
    }

    #[test]
    fn identical_project_audit_has_no_false_repair_queue() {
        let project = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::create_dir_all(project.path().join("src")).unwrap();
        fs::write(
            project.path().join("src/app.ts"),
            "export const value = 1;\nexport function read(){ return value; }\n",
        )
        .unwrap();
        run(project.path(), project.path(), output.path()).unwrap();
        let work_items = read_json_lines(&output.path().join("llm-work-items.jsonl")).unwrap();
        assert!(
            work_items.is_empty(),
            "identical inputs produced false tasks"
        );
    }

    #[test]
    fn oracle_evaluation_measures_recovery_and_false_promotions() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        let oracle_path = output.path().join("oracle.json");
        fs::write(
            left.path().join("left.js"),
            "export function expected(a){return a+1}\nexport function forbidden(a){return a-1}",
        )
        .unwrap();
        fs::write(
            right.path().join("right.js"),
            "export function renamed(x){return x+1}",
        )
        .unwrap();
        fs::write(
            &oracle_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "topK": 5,
                "expected": [{
                    "left": {"file": "left.js", "name": "expected"},
                    "right": {"file": "right.js", "name": "renamed"}
                }],
                "forbidden": [{
                    "left": {"file": "left.js", "name": "forbidden"},
                    "right": {"file": "right.js", "name": "renamed"}
                }]
            }))
            .unwrap(),
        )
        .unwrap();

        run(left.path(), right.path(), output.path()).unwrap();
        let metrics = evaluate_oracle(output.path(), &oracle_path).unwrap();

        assert_eq!(metrics.expected, 1);
        assert_eq!(metrics.promoted_correct, 1);
        assert_eq!(metrics.top_k_recovered, 1);
        assert_eq!(metrics.false_promotions, 0);
    }

    #[test]
    fn bundled_oracle_fixture_has_perfect_labeled_precision_and_recall() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/oracle-basic");
        let output = tempdir().unwrap();
        run(&fixture.join("left"), &fixture.join("right"), output.path()).unwrap();
        let metrics = evaluate_oracle(output.path(), &fixture.join("oracle.json")).unwrap();
        assert_eq!(metrics.promoted_precision, 1.0);
        assert_eq!(metrics.top_k_recall, 1.0);
        assert_eq!(metrics.abstained_expected, 0);
        assert_eq!(metrics.false_promotions, 0);
    }

    #[test]
    fn inspector_returns_exact_source_and_rejects_stale_reports() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("left.js"),
            "export function sourceOwner(value){return value+1}",
        )
        .unwrap();
        fs::write(
            right.path().join("right.js"),
            "export function bundledOwner(input){return input+1}",
        )
        .unwrap();
        run(left.path(), right.path(), output.path()).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        let unit_id = report["matches"][0]["left"]["id"].as_str().unwrap();

        let inspection = inspect_unit(output.path(), unit_id).unwrap();
        assert_eq!(
            inspection["source"],
            "function sourceOwner(value){return value+1}"
        );

        fs::write(
            left.path().join("left.js"),
            "export function sourceOwner(value){return value+2}",
        )
        .unwrap();
        assert!(inspect_unit(output.path(), unit_id)
            .unwrap_err()
            .to_string()
            .contains("stale report"));
    }

    #[test]
    fn inspector_rejects_stale_source_map_evidence() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        let bundle = left.path().join("bundle.js");
        fs::write(
            &bundle,
            "export function bundledName(value){return value+1}",
        )
        .unwrap();
        fs::write(
            adjacent_source_map_path(&bundle),
            r#"{"version":3,"file":"bundle.js","sources":["original.ts"],"names":["firstName"],"mappings":"OAAGA"}"#,
        )
        .unwrap();
        fs::write(
            right.path().join("source.js"),
            "export function sourceName(value){return value+1}",
        )
        .unwrap();
        run(left.path(), right.path(), output.path()).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        let unit_id = report["matches"][0]["left"]["id"].as_str().unwrap();
        inspect_unit(output.path(), unit_id).unwrap();

        fs::write(
            adjacent_source_map_path(&bundle),
            r#"{"version":3,"file":"bundle.js","sources":["original.ts"],"names":["otherName"],"mappings":"OAAGA"}"#,
        )
        .unwrap();
        assert!(inspect_unit(output.path(), unit_id)
            .unwrap_err()
            .to_string()
            .contains("stale report"));
    }

    #[test]
    fn repeated_runs_write_byte_identical_artifacts() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let first_output = tempdir().unwrap();
        let second_output = tempdir().unwrap();
        let mut left_source = String::new();
        let mut right_source = String::new();
        for index in 0..32 {
            left_source.push_str(&format!(
                "export const left{index}a=()=>{index};export const left{index}b=()=>{index};"
            ));
            right_source.push_str(&format!(
                "export const right{index}a=()=>{index};export const right{index}b=()=>{index};"
            ));
        }
        fs::write(left.path().join("left.js"), left_source).unwrap();
        fs::write(right.path().join("right.js"), right_source).unwrap();

        run(left.path(), right.path(), first_output.path()).unwrap();
        run(left.path(), right.path(), second_output.path()).unwrap();

        for artifact in [
            "report.json",
            "report.html",
            "unmatched-left.jsonl",
            "unmatched-right.jsonl",
            "graph-relations.jsonl",
            "divergence-frontiers.jsonl",
            "graph-overlay.json",
            "semantic-graph.jsonl.zst",
            "upstream-executable-ledger.jsonl",
            "llm-work-items.jsonl",
            "llm-batches.jsonl",
            "llm-manifest.json",
            "LLM_TASK_BRIEF.md",
        ] {
            assert_eq!(
                fs::read(first_output.path().join(artifact)).unwrap(),
                fs::read(second_output.path().join(artifact)).unwrap(),
                "{artifact} changed across identical runs"
            );
        }
    }

    #[test]
    fn generated_directories_are_not_discovered_from_project_root() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::create_dir_all(root.path().join("dist")).unwrap();
        fs::write(root.path().join("src/a.js"), "export const a=1").unwrap();
        fs::write(
            root.path().join("src/contracts.d.ts"),
            "export interface Contract { id: string }",
        )
        .unwrap();
        fs::write(root.path().join("dist/copied.js"), "export const copied=1").unwrap();
        let discovery = discover(root.path()).unwrap();
        assert_eq!(discovery.files.len(), 2);
        assert_eq!(
            discovery
                .files
                .iter()
                .map(|(_, relative)| relative.as_str())
                .collect::<Vec<_>>(),
            ["src/a.js", "src/contracts.d.ts"]
        );
        assert_eq!(discovery.corpus.mode, "recursive-source-project");
    }

    #[test]
    fn changed_file_snapshot_reports_added_modified_and_deleted() {
        let before = BTreeMap::from([
            ("a.ts".to_string(), "a".to_string()),
            ("deleted.ts".to_string(), "d".to_string()),
        ]);
        let after = BTreeMap::from([
            ("a.ts".to_string(), "b".to_string()),
            ("added.ts".to_string(), "n".to_string()),
        ]);
        let changes = changed_files(&before, &after, "local");
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].file, "a.ts");
        assert_eq!(changes[0].change, "modified");
        assert_eq!(changes[1].change, "added");
        assert_eq!(changes[2].change, "deleted");
    }

    #[test]
    fn adjacent_source_map_projects_origin_and_invalidates_cache() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/source-map");
        let cache = tempdir().unwrap();
        let bundle = fixture.join("bundle.js");
        let first = index_file(&bundle, "bundle.js", "left", cache.path()).unwrap();
        let owner = first
            .0
            .units
            .iter()
            .find(|unit| unit.name.as_deref() == Some("bundledName"))
            .unwrap();
        assert_eq!(owner.origin.as_ref().unwrap().file, "../src/original.ts");
        assert_eq!(owner.origin.as_ref().unwrap().line, 1);
        assert_eq!(owner.origin.as_ref().unwrap().column, 3);
        assert_eq!(
            owner.origin.as_ref().unwrap().name.as_deref(),
            Some("originalFunction")
        );
        assert!(!first.1);

        let second = index_file(&bundle, "bundle.js", "left", cache.path()).unwrap();
        assert!(second.1);

        let temporary = tempdir().unwrap();
        let temporary_bundle = temporary.path().join("bundle.js");
        fs::copy(&bundle, &temporary_bundle).unwrap();
        let first_map = fs::read(adjacent_source_map_path(&bundle)).unwrap();
        fs::write(adjacent_source_map_path(&temporary_bundle), &first_map).unwrap();
        let first = index_file(&temporary_bundle, "bundle.js", "left", cache.path()).unwrap();
        assert!(!first.1);
        let changed_map = String::from_utf8(first_map)
            .unwrap()
            .replace("originalFunction", "renamedFunction");
        fs::write(adjacent_source_map_path(&temporary_bundle), changed_map).unwrap();
        let changed = index_file(&temporary_bundle, "bundle.js", "left", cache.path()).unwrap();
        assert!(
            !changed.1,
            "source-map SHA must participate in the cache key"
        );
        assert_eq!(
            changed.0.units[0].origin.as_ref().unwrap().name.as_deref(),
            Some("renamedFunction")
        );
    }

    #[test]
    fn generated_columns_use_utf16_code_units() {
        assert_eq!(generated_position("😀x", "😀".len()), (0, 2));
        assert_eq!(generated_position("😀x\ny", "😀x\n".len()), (1, 0));
    }

    #[test]
    fn parse_failures_remain_explicit_without_hiding_valid_files() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(left.path().join("broken.js"), "export function {").unwrap();
        fs::write(
            left.path().join("valid.js"),
            "export function valid(value){return value}",
        )
        .unwrap();
        fs::write(
            right.path().join("bundle.js"),
            "export function bundled(input){return input}",
        )
        .unwrap();

        let summary = run(left.path(), right.path(), output.path()).unwrap();

        assert_eq!(summary.left_failures, 1);
        assert_eq!(summary.alpha_equal, 1);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.path().join("report.json")).unwrap()).unwrap();
        assert_eq!(report["left"]["failures"][0]["file"], "broken.js");
    }

    #[test]
    fn filename_source_types_cover_tsx_and_unicode_bindings() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(
            left.path().join("component.tsx"),
            "export function Компонент(props:{label:string}){return <span>{props.label}</span>}",
        )
        .unwrap();
        fs::write(
            right.path().join("chunk.tsx"),
            "export function x(p:{label:string}){return <span>{p.label}</span>}",
        )
        .unwrap();

        let summary = run(left.path(), right.path(), output.path()).unwrap();

        assert_eq!(summary.left_failures, 0);
        assert_eq!(summary.right_failures, 0);
        assert_eq!(summary.alpha_equal, 1);
    }

    #[test]
    fn relationship_layers_preserve_ambiguity_and_find_split_candidates() {
        let mut duplicate_left = vec![unit("l1", &["a"]), unit("l2", &["a"])];
        let mut duplicate_right = vec![unit("r1", &["a"]), unit("r2", &["a"])];
        for item in duplicate_left.iter_mut().chain(duplicate_right.iter_mut()) {
            item.strict_sha256 = "same".to_string();
        }
        assert_eq!(
            ambiguous_groups(&duplicate_left, &duplicate_right, "strict", |item| {
                &item.strict_sha256
            })
            .len(),
            1
        );

        let target = unit("combined", &["a", "b", "c", "d"]);
        let first = unit("first", &["a", "b"]);
        let second = unit("second", &["c", "d"]);
        let metrics = group_metrics(&target, &[&first, &second]).unwrap();
        assert!(metrics.0 >= 0.9);

        let changed = unit("changed", &["a", "b", "c", "d", "e"]);
        let distractor = unit("distractor", &["a"]);
        let ranked = rank_candidates(&[&target], &[&changed, &distractor]);
        assert!(best_is_distinct(&ranked[0]));
        assert_eq!(ranked[0].candidates[0].location.id, "changed");
    }

    #[test]
    fn candidate_generation_survives_feature_count_drift() {
        let mut target = unit("target", &["CallExpression", "ReturnStatement"]);
        FeatureChannels::increment(&mut target.features.shape, "CallExpression");
        target.nodes_approx = target.features.node_count();
        target.tokens = target.features.token_set();

        let mut wrapped = unit(
            "wrapped",
            &["CallExpression", "CallExpression", "ReturnStatement"],
        );
        FeatureChannels::increment(&mut wrapped.features.shape, "CallExpression");
        wrapped.nodes_approx = wrapped.features.node_count();
        wrapped.tokens = wrapped.features.token_set();

        let distractor = unit(
            "distractor",
            &["Class", "MethodDefinition", "ThrowStatement"],
        );
        let ranked = rank_candidates(&[&target], &[&wrapped, &distractor]);

        assert_eq!(ranked[0].candidates[0].location.id, "wrapped");
    }

    #[test]
    fn containment_graph_aggregates_unit_support_into_file_affinity() {
        let mut local_a = unit("local-a", &["alpha", "return"]);
        let mut local_b = unit("local-b", &["beta", "call"]);
        let mut bundled_a = unit("bundled-a", &["alpha", "return", "wrapper"]);
        let mut bundled_b = unit("bundled-b", &["beta", "call", "wrapper"]);
        local_a.file = "src/feature.ts".to_string();
        local_b.file = "src/feature.ts".to_string();
        bundled_a.file = "dist/chunk.js".to_string();
        bundled_b.file = "dist/chunk.js".to_string();

        let ranked = rank_candidates(&[&local_a, &local_b], &[&bundled_a, &bundled_b]);
        let (file_candidates, affinities) = infer_file_graph(&[], &ranked, true);

        assert_eq!(file_candidates.len(), 1);
        assert_eq!(file_candidates[0].supporting_units, 2);
        assert_eq!(
            affinities["src/feature.ts"],
            vec!["dist/chunk.js".to_string()]
        );
    }
}
