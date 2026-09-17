use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use oxc_ast::ast::ImportOrExportKind;
use oxc_ast::{
    ast::{
        ArrowFunctionExpression, AssignmentExpression, AssignmentTarget, CallExpression, Class,
        ComputedMemberExpression, Declaration, ExportAllDeclaration, ExportDefaultDeclaration,
        ExportNamedDeclaration, Function, IdentifierReference, ImportDeclaration,
        ImportDeclarationSpecifier, ImportExpression, JSXElement, JSXElementName, ModuleExportName,
        NewExpression, Program, PropertyKey, Statement, StaticMemberExpression, TSExportAssignment,
        TSImportEqualsDeclaration, TSModuleReference, VariableDeclarator,
    },
    AstKind,
};
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};
use oxc_syntax::{scope::ScopeId, symbol::SymbolId};
use serde::{Deserialize, Serialize};

use super::{line_at, record_ast_feature, sha256, FeatureChannels};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GraphNode {
    pub id: String,
    pub file: String,
    pub kind: String,
    pub label: String,
    pub start: u32,
    pub end: u32,
    pub line: usize,
    pub scope: Option<String>,
    pub linked_sha256: String,
    pub tokens: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GraphEdge {
    pub source: String,
    pub target: String,
    pub kind: String,
    pub dynamic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SemanticGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

struct PendingNode {
    node: GraphNode,
    features: FeatureChannels,
}

struct GraphCollector<'a, 's> {
    source: &'s str,
    file: &'s str,
    side: &'s str,
    semantic: &'a Semantic<'a>,
    nodes: Vec<PendingNode>,
    edges: BTreeSet<GraphEdge>,
    scope_stack: Vec<String>,
    owner_stack: Vec<String>,
    active_feature_nodes: Vec<usize>,
    last_statement_by_container: HashMap<String, String>,
    scope_nodes: HashMap<usize, String>,
    symbol_nodes: HashMap<usize, String>,
    external_nodes: BTreeMap<String, String>,
    span_nodes: HashMap<(String, u32, u32), String>,
    write_reference_ids: HashSet<usize>,
    // Export wrappers do not carry a reference id for declarations such as
    // `export const value`.  Record *exact declared symbols*, not the wrapper
    // span: a wrapper also encloses function parameters and nested locals,
    // none of which are public module contracts.
    direct_export_symbols: Vec<(SymbolId, String, bool)>,
    ordinal: usize,
}

impl<'a, 's> GraphCollector<'a, 's> {
    fn new(source: &'s str, file: &'s str, side: &'s str, semantic: &'a Semantic<'a>) -> Self {
        let mut collector = Self {
            source,
            file,
            side,
            semantic,
            nodes: Vec::new(),
            edges: BTreeSet::new(),
            scope_stack: Vec::new(),
            owner_stack: Vec::new(),
            active_feature_nodes: Vec::new(),
            last_statement_by_container: HashMap::new(),
            scope_nodes: HashMap::new(),
            symbol_nodes: HashMap::new(),
            external_nodes: BTreeMap::new(),
            span_nodes: HashMap::new(),
            write_reference_ids: HashSet::new(),
            direct_export_symbols: Vec::new(),
            ordinal: 0,
        };
        let file_id =
            collector.add_node("File", "Program", Span::new(0, source.len() as u32), None);
        collector.owner_stack.push(file_id);
        collector
    }

    fn current_container(&self) -> String {
        self.owner_stack
            .last()
            .or_else(|| self.scope_stack.last())
            .expect("file owner exists")
            .clone()
    }

    fn add_node(&mut self, kind: &str, label: &str, span: Span, scope: Option<String>) -> String {
        let ordinal = self.ordinal;
        self.ordinal += 1;
        let id = format!(
            "{}:{}:graph:{}:{}:{}:{}",
            self.side, self.file, kind, span.start, span.end, ordinal
        );
        self.nodes.push(PendingNode {
            node: GraphNode {
                id: id.clone(),
                file: self.file.to_string(),
                kind: kind.to_string(),
                label: label.to_string(),
                start: span.start,
                end: span.end,
                line: line_at(self.source, span.start as usize),
                scope,
                linked_sha256: String::new(),
                tokens: BTreeSet::new(),
            },
            features: FeatureChannels::default(),
        });
        self.span_nodes
            .insert((kind.to_string(), span.start, span.end), id.clone());
        id
    }

    fn add_edge(
        &mut self,
        source: impl Into<String>,
        target: impl Into<String>,
        kind: &str,
        dynamic: bool,
        label: Option<String>,
    ) {
        self.edges.insert(GraphEdge {
            source: source.into(),
            target: target.into(),
            kind: kind.to_string(),
            dynamic,
            label,
        });
    }

    fn begin_owned_node(&mut self, kind: &str, label: &str, span: Span) -> (String, usize) {
        let container = self.current_container();
        let scope = self.scope_stack.last().cloned();
        let id = self.add_node(kind, label, span, scope);
        self.add_edge(container, id.clone(), "Contains", false, None);
        let index = self.nodes.len() - 1;
        self.owner_stack.push(id.clone());
        self.active_feature_nodes.push(index);
        (id, index)
    }

    /// Preserve source-level occurrences instead of collapsing every use of a
    /// symbol into one owner→target edge. The containing function still gives
    /// a compact summary through `Contains`, while each read/call/render has
    /// its own span, order and target contract for matching and review.
    fn occurrence_node(&mut self, kind: &str, label: &str, span: Span) -> String {
        let owner = self.current_container();
        let scope = self.scope_stack.last().cloned();
        let id = self.add_node(kind, label, span, scope);
        self.add_edge(owner, id.clone(), "Contains", false, None);
        id
    }

    fn end_owned_node(&mut self, expected_index: usize) {
        debug_assert_eq!(self.active_feature_nodes.pop(), Some(expected_index));
        self.owner_stack.pop();
    }

    fn external_node(&mut self, label: &str, dynamic: bool) -> String {
        let key = format!("{}:{label}", if dynamic { "dynamic" } else { "external" });
        if let Some(id) = self.external_nodes.get(&key) {
            return id.clone();
        }
        let kind = if dynamic { "Dynamic" } else { "External" };
        let id = self.add_node(kind, label, Span::new(0, 0), None);
        self.external_nodes.insert(key, id.clone());
        id
    }

    fn symbol_node(&mut self, symbol_id: SymbolId) -> String {
        if let Some(id) = self.symbol_nodes.get(&symbol_id.index()) {
            return id.clone();
        }
        let span = self.semantic.scoping().symbol_span(symbol_id);
        let scope_id = self.semantic.scoping().symbol_scope_id(symbol_id);
        let scope = self.scope_node_id(scope_id);
        let id = self.add_node("Symbol", "local", span, Some(scope.clone()));
        self.add_edge(scope, id.clone(), "Contains", false, None);
        self.symbol_nodes.insert(symbol_id.index(), id.clone());
        id
    }

    fn scope_node_id(&mut self, scope_id: ScopeId) -> String {
        if let Some(id) = self.scope_nodes.get(&scope_id.index()) {
            return id.clone();
        }
        // This fallback is only used for symbol metadata encountered before the scope visitor.
        let id = self.add_node(
            "Scope",
            &format!("scope-depth-{}", self.scope_depth(scope_id)),
            Span::new(0, 0),
            None,
        );
        self.scope_nodes.insert(scope_id.index(), id.clone());
        id
    }

    fn scope_depth(&self, mut scope_id: ScopeId) -> usize {
        let mut depth = 0;
        while let Some(parent) = self.semantic.scoping().scope_parent_id(scope_id) {
            depth += 1;
            scope_id = parent;
        }
        depth
    }

    fn reference_target(&mut self, identifier: &IdentifierReference<'a>) -> (String, bool) {
        let reference = self
            .semantic
            .scoping()
            .get_reference(identifier.reference_id());
        if let Some(symbol_id) = reference.symbol_id() {
            (self.symbol_node(symbol_id), false)
        } else {
            (self.external_node(identifier.name.as_str(), false), false)
        }
    }

    fn expression_target(
        &mut self,
        expression: &oxc_ast::ast::Expression<'a>,
    ) -> (String, bool, Option<String>) {
        if let Some(identifier) = expression.get_identifier_reference() {
            let label = identifier.name.to_string();
            let (target, dynamic) = self.reference_target(identifier);
            return (target, dynamic, Some(label));
        }
        let inner = expression.get_inner_expression();
        match inner {
            oxc_ast::ast::Expression::StaticMemberExpression(member) => {
                let target = self.member_access_node(
                    member.span,
                    &member.object,
                    member.property.name.as_str(),
                    member.optional,
                );
                return (target, false, Some(member.property.name.to_string()));
            }
            oxc_ast::ast::Expression::ComputedMemberExpression(member) => {
                let property = self
                    .source
                    .get(
                        member.expression.span().start as usize
                            ..member.expression.span().end as usize,
                    )
                    .unwrap_or("<computed>")
                    .to_string();
                let target = self.member_access_node(
                    member.span,
                    &member.object,
                    &property,
                    member.optional,
                );
                return (target, true, Some(property));
            }
            _ => {}
        }
        let span = inner.span();
        for kind in ["Function", "Class"] {
            if let Some(id) = self
                .span_nodes
                .get(&(kind.to_string(), span.start, span.end))
            {
                return (id.clone(), false, Some(kind.to_string()));
            }
        }
        let label = self
            .source
            .get(span.start as usize..span.end as usize)
            .unwrap_or("<dynamic>")
            .chars()
            .take(160)
            .collect::<String>();
        let target = self.external_node(&label, true);
        (target, true, Some(label))
    }

    fn member_access_node(
        &mut self,
        span: Span,
        object: &oxc_ast::ast::Expression<'a>,
        property: &str,
        optional: bool,
    ) -> String {
        if let Some(id) = self
            .span_nodes
            .get(&(String::from("MemberAccess"), span.start, span.end))
        {
            return id.clone();
        }
        let label = if optional {
            format!("{property}?")
        } else {
            property.to_string()
        };
        let access = self.occurrence_node("MemberAccess", &label, span);
        let (target, dynamic, object_label) = self.expression_target(object);
        self.add_edge(access.clone(), target, "Accesses", dynamic, object_label);
        access
    }

    fn add_module_edge(&mut self, kind: &str, module: &str) {
        let owner = self.current_container();
        let target = self.external_node(&format!("module:{module}"), false);
        self.add_edge(owner, target, kind, false, Some(module.to_string()));
    }

    fn add_dynamic_module_edge(&mut self, kind: &str, module: &str) {
        let owner = self.current_container();
        let target = self.external_node(&format!("module:{module}"), true);
        self.add_edge(owner, target, kind, true, Some(module.to_string()));
    }

    fn module_export_name(name: &ModuleExportName<'a>) -> String {
        match name {
            ModuleExportName::IdentifierName(name) => name.name.to_string(),
            ModuleExportName::IdentifierReference(name) => name.name.to_string(),
            ModuleExportName::StringLiteral(name) => name.value.to_string(),
        }
    }

    fn binding_symbols(pattern: &oxc_ast::ast::BindingPattern<'a>) -> Vec<(SymbolId, String)> {
        pattern
            .get_binding_identifiers()
            .into_iter()
            .filter_map(|binding| {
                binding
                    .symbol_id
                    .get()
                    .map(|id| (id, binding.name.to_string()))
            })
            .collect()
    }

    fn declaration_symbols(declaration: &Declaration<'a>) -> Vec<(SymbolId, String)> {
        match declaration {
            Declaration::VariableDeclaration(declaration) => declaration
                .declarations
                .iter()
                .flat_map(|declarator| Self::binding_symbols(&declarator.id))
                .collect(),
            _ => declaration
                .id()
                .and_then(|binding| {
                    binding
                        .symbol_id
                        .get()
                        .map(|id| (id, binding.name.to_string()))
                })
                .into_iter()
                .collect(),
        }
    }

    fn export_symbol_for_local(&mut self, name: &ModuleExportName<'a>) -> Option<String> {
        let ModuleExportName::IdentifierReference(identifier) = name else {
            return None;
        };
        let reference = self
            .semantic
            .scoping()
            .get_reference(identifier.reference_id());
        reference.symbol_id().map(|symbol| self.symbol_node(symbol))
    }

    fn static_global_require(&self, expression: &oxc_ast::ast::Expression<'a>) -> Option<String> {
        let oxc_ast::ast::Expression::CallExpression(call) = expression.get_inner_expression()
        else {
            return None;
        };
        let identifier = call.callee.get_identifier_reference()?;
        let reference = self
            .semantic
            .scoping()
            .get_reference(identifier.reference_id());
        if identifier.name != "require" || reference.symbol_id().is_some() {
            return None;
        }
        let oxc_ast::ast::Argument::StringLiteral(module) = call.arguments.first()? else {
            return None;
        };
        Some(module.value.to_string())
    }

    /// Returns a static CommonJS module and exact imported property for the
    /// two binding-safe forms `require("x")` and `require("x").name`.
    /// Computed members intentionally collapse to unknown rather than
    /// pretending that a dynamic property is a named module contract.
    fn static_commonjs_require_binding(
        &self,
        expression: &oxc_ast::ast::Expression<'a>,
    ) -> Option<(String, String)> {
        if let Some(module) = self.static_global_require(expression) {
            return Some((module, "*".to_string()));
        }
        let oxc_ast::ast::Expression::StaticMemberExpression(member) =
            expression.get_inner_expression()
        else {
            return None;
        };
        self.static_global_require(&member.object)
            .map(|module| (module, member.property.name.to_string()))
    }

    /// Keeps a literal dynamic import distinct from a static ESM import while
    /// still preserving the namespace binding that receives its promise. A
    /// direct or awaited literal import has the same namespace provenance.
    /// The boolean records whether the namespace promise has been awaited:
    /// only then can object destructuring name exact exports.
    fn static_dynamic_import(
        &self,
        expression: &oxc_ast::ast::Expression<'a>,
    ) -> Option<(String, bool)> {
        match expression.get_inner_expression() {
            oxc_ast::ast::Expression::ImportExpression(import) => {
                let oxc_ast::ast::Expression::StringLiteral(module) =
                    import.source.get_inner_expression()
                else {
                    return None;
                };
                Some((module.value.to_string(), false))
            }
            oxc_ast::ast::Expression::AwaitExpression(await_expression) => self
                .static_dynamic_import(&await_expression.argument)
                .map(|(module, _)| (module, true)),
            _ => None,
        }
    }

    /// Extracts only direct static object keys. Rest and nested patterns are
    /// excluded because they do not identify one module export.
    fn static_object_pattern_bindings(
        object: &oxc_ast::ast::ObjectPattern<'a>,
    ) -> Vec<(SymbolId, String)> {
        object
            .properties
            .iter()
            .filter(|property| !property.computed)
            .filter_map(|property| {
                let exported = match &property.key {
                    PropertyKey::StaticIdentifier(identifier) => identifier.name.to_string(),
                    PropertyKey::StringLiteral(literal) => literal.value.to_string(),
                    _ => return None,
                };
                let binding = property.value.get_binding_identifier()?;
                binding
                    .symbol_id
                    .get()
                    .map(|symbol_id| (symbol_id, exported))
            })
            .collect()
    }

    fn commonjs_require_bindings(
        &self,
        pattern: &oxc_ast::ast::BindingPattern<'a>,
    ) -> Vec<(SymbolId, String)> {
        let mut bindings = pattern
            .get_binding_identifiers()
            .into_iter()
            .filter_map(|binding| {
                binding
                    .symbol_id
                    .get()
                    .map(|symbol| (symbol, "*".to_string()))
            })
            .collect::<Vec<_>>();
        let oxc_ast::ast::BindingPattern::ObjectPattern(object) = pattern else {
            return bindings;
        };
        for (symbol_id, exported) in Self::static_object_pattern_bindings(object) {
            if let Some((_, imported)) =
                bindings.iter_mut().find(|(symbol, _)| *symbol == symbol_id)
            {
                *imported = exported;
            }
        }
        bindings
    }

    /// Returns an exact CommonJS export name only for the unshadowed global
    /// forms that Node exposes: `exports.name`, `module.exports`, and
    /// `module.exports.name`. Computed/property-alias forms deliberately stay
    /// unresolved: interpreting them would turn a candidate into false proof.
    fn static_commonjs_export(&self, expression: &AssignmentExpression<'a>) -> Option<String> {
        if expression.operator != oxc_syntax::operator::AssignmentOperator::Assign {
            return None;
        }
        let AssignmentTarget::StaticMemberExpression(member) = &expression.left else {
            return None;
        };
        let (_, exported) = member.static_property_info();
        let unresolved_global = |expression: &oxc_ast::ast::Expression<'a>, name: &str| {
            expression
                .get_identifier_reference()
                .is_some_and(|identifier| {
                    identifier.name == name
                        && self
                            .semantic
                            .scoping()
                            .get_reference(identifier.reference_id())
                            .symbol_id()
                            .is_none()
                })
        };

        if unresolved_global(&member.object, "exports") {
            return Some(exported.to_string());
        }
        if exported == "exports" && unresolved_global(&member.object, "module") {
            return Some("default".to_string());
        }
        let oxc_ast::ast::Expression::StaticMemberExpression(namespace) =
            member.object.get_inner_expression()
        else {
            return None;
        };
        (namespace.property.name == "exports" && unresolved_global(&namespace.object, "module"))
            .then(|| exported.to_string())
    }

    /// Extract only the unambiguous CommonJS forwarding forms:
    /// `module.exports = require("x")` and
    /// `exports.name = require("x").name`. A computed member or any wrapper
    /// remains unknown instead of fabricating a re-export contract.
    fn static_commonjs_reexport(
        &self,
        expression: &oxc_ast::ast::Expression<'a>,
    ) -> Option<(String, String)> {
        if let Some(module) = self.static_global_require(expression) {
            return Some((module, "*".to_string()));
        }
        let oxc_ast::ast::Expression::StaticMemberExpression(member) =
            expression.get_inner_expression()
        else {
            return None;
        };
        self.static_global_require(&member.object)
            .map(|module| (module, member.property.name.to_string()))
    }

    fn finish(mut self) -> SemanticGraph {
        let definitions = self
            .semantic
            .scoping()
            .symbol_ids()
            .filter_map(|symbol_id| {
                let declaration = self.semantic.scoping().symbol_declaration(symbol_id);
                let kind = self.semantic.nodes().kind(declaration);
                let span = kind.span();
                let graph_kind = match kind {
                    AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) => "Function",
                    AstKind::Class(_) => "Class",
                    _ if kind.is_statement() || kind.is_declaration() => "Statement",
                    _ => return None,
                };
                Some((symbol_id, graph_kind.to_string(), span))
            })
            .collect::<Vec<_>>();
        for (symbol_id, graph_kind, span) in definitions {
            let symbol = self.symbol_node(symbol_id);
            if let Some(target) = self
                .span_nodes
                .get(&(graph_kind, span.start, span.end))
                .cloned()
            {
                self.add_edge(symbol, target, "Defines", false, None);
            }
        }
        for (symbol_id, exported, is_type) in self.direct_export_symbols.clone() {
            let symbol = self.symbol_node(symbol_id);
            let module = self.external_node("module:<current>", false);
            self.add_edge(
                symbol,
                module,
                if is_type {
                    "TypeExportsBinding"
                } else {
                    "ExportsBinding"
                },
                false,
                Some(exported),
            );
        }
        for pending in &mut self.nodes {
            pending.node.tokens = pending.features.token_set();
            pending.node.linked_sha256 = sha256(format!(
                "{}\0{}\0{}",
                pending.node.kind,
                pending.node.label,
                pending.features.signature(false)
            ));
        }
        let mut nodes = self
            .nodes
            .into_iter()
            .map(|pending| pending.node)
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        SemanticGraph {
            nodes,
            edges: self.edges.into_iter().collect(),
        }
    }
}

impl<'a> Visit<'a> for GraphCollector<'a, '_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        // Parent/child relationships carry nested behavior. Recording an AST node into every
        // enclosing statement makes monolithic bundles quadratic in lexical depth and also
        // double-counts branches. The innermost executable owner is the correct graph owner.
        if let Some(index) = self.active_feature_nodes.last().copied() {
            record_ast_feature(&mut self.nodes[index].features, self.source, kind);
        }
    }

    fn enter_scope(
        &mut self,
        flags: oxc_syntax::scope::ScopeFlags,
        scope_id: &std::cell::Cell<Option<ScopeId>>,
    ) {
        let scope_id = scope_id.get().expect("semantic builder assigned scope ids");
        let container = self.current_container();
        let id = if let Some(id) = self.scope_nodes.get(&scope_id.index()) {
            id.clone()
        } else {
            let id = self.add_node(
                "Scope",
                &format!("depth-{}:{flags:?}", self.scope_depth(scope_id)),
                Span::new(0, 0),
                self.scope_stack.last().cloned(),
            );
            self.scope_nodes.insert(scope_id.index(), id.clone());
            id
        };
        self.add_edge(container, id.clone(), "Contains", false, None);
        self.scope_stack.push(id);
    }

    fn leave_scope(&mut self) {
        self.scope_stack.pop();
    }

    fn visit_statement(&mut self, statement: &Statement<'a>) {
        let span = statement.span();
        let label = format!("{:?}", std::mem::discriminant(statement));
        let container = self.current_container();
        let (id, index) = self.begin_owned_node("Statement", &label, span);
        if let Some(previous) = self
            .last_statement_by_container
            .insert(container, id.clone())
        {
            self.add_edge(previous, id, "NextStatement", false, None);
        }
        walk::walk_statement(self, statement);
        self.end_owned_node(index);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        let label = if function.is_declaration() {
            "declaration"
        } else {
            "expression"
        };
        let (_, index) = self.begin_owned_node("Function", label, function.span());
        walk::walk_function(self, function, flags);
        self.end_owned_node(index);
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let (_, index) = self.begin_owned_node("Function", "arrow", function.span());
        walk::walk_arrow_function_expression(self, function);
        self.end_owned_node(index);
    }

    fn visit_class(&mut self, class: &Class<'a>) {
        let label = if class.is_declaration() {
            "declaration"
        } else {
            "expression"
        };
        let (_, index) = self.begin_owned_node("Class", label, class.span());
        walk::walk_class(self, class);
        self.end_owned_node(index);
    }

    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        let is_write = self
            .write_reference_ids
            .contains(&identifier.reference_id().index());
        let occurrence = self.occurrence_node(
            if is_write {
                "WriteSite"
            } else {
                "ReferenceSite"
            },
            identifier.name.as_str(),
            identifier.span,
        );
        let (target, dynamic) = self.reference_target(identifier);
        self.add_edge(
            occurrence,
            target,
            if is_write { "Writes" } else { "References" },
            dynamic,
            Some(identifier.name.to_string()),
        );
        walk::walk_identifier_reference(self, identifier);
    }

    fn visit_static_member_expression(&mut self, expression: &StaticMemberExpression<'a>) {
        self.member_access_node(
            expression.span,
            &expression.object,
            expression.property.name.as_str(),
            expression.optional,
        );
        walk::walk_static_member_expression(self, expression);
    }

    fn visit_computed_member_expression(&mut self, expression: &ComputedMemberExpression<'a>) {
        let property = self
            .source
            .get(
                expression.expression.span().start as usize
                    ..expression.expression.span().end as usize,
            )
            .unwrap_or("<computed>")
            .to_string();
        self.member_access_node(
            expression.span,
            &expression.object,
            &property,
            expression.optional,
        );
        walk::walk_computed_member_expression(self, expression);
    }

    fn visit_call_expression(&mut self, expression: &CallExpression<'a>) {
        let occurrence = self.occurrence_node("CallSite", "call", expression.span);
        if let Some(identifier) = expression.callee.get_identifier_reference() {
            let reference = self
                .semantic
                .scoping()
                .get_reference(identifier.reference_id());
            if identifier.name == "require" && reference.symbol_id().is_none() {
                if let Some(oxc_ast::ast::Argument::StringLiteral(module)) =
                    expression.arguments.first()
                {
                    let target = self.external_node(&format!("module:{}", module.value), false);
                    self.add_edge(
                        occurrence.clone(),
                        target,
                        "Requires",
                        false,
                        Some(module.value.to_string()),
                    );
                }
            }
        }
        walk::walk_call_expression(self, expression);
        let (target, dynamic, label) = self.expression_target(&expression.callee);
        self.add_edge(occurrence, target, "Calls", dynamic, label);
    }

    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let Some(initializer) = &declarator.init {
            if let Some((module, requested)) = self.static_commonjs_require_binding(initializer) {
                let target = self.external_node(&format!("module:{module}"), false);
                let object_pattern = matches!(
                    declarator.id,
                    oxc_ast::ast::BindingPattern::ObjectPattern(_)
                );
                // Destructuring `require("x")` carries its own static names.
                // Destructuring a member result (`require("x").name`) would
                // need two runtime property operations, so keep it unresolved.
                if object_pattern && requested != "*" {
                    walk::walk_variable_declarator(self, declarator);
                    return;
                }
                for (symbol_id, imported) in self.commonjs_require_bindings(&declarator.id) {
                    let symbol = self.symbol_node(symbol_id);
                    self.add_edge(
                        symbol,
                        target.clone(),
                        "RequiresBinding",
                        false,
                        Some(if imported == "*" {
                            requested.clone()
                        } else {
                            imported
                        }),
                    );
                }
            }
            if let Some((module, awaited)) = self.static_dynamic_import(initializer) {
                let target = self.external_node(&format!("module:{module}"), true);
                let bindings = match &declarator.id {
                    oxc_ast::ast::BindingPattern::ObjectPattern(object) if awaited => {
                        Self::static_object_pattern_bindings(object)
                    }
                    oxc_ast::ast::BindingPattern::ObjectPattern(_) => Vec::new(),
                    _ => declarator
                        .id
                        .get_binding_identifiers()
                        .into_iter()
                        .filter_map(|binding| {
                            binding
                                .symbol_id
                                .get()
                                .map(|symbol_id| (symbol_id, "*".to_string()))
                        })
                        .collect(),
                };
                for (symbol_id, imported) in bindings {
                    let symbol = self.symbol_node(symbol_id);
                    self.add_edge(
                        symbol,
                        target.clone(),
                        "DynamicImportsBinding",
                        true,
                        Some(imported),
                    );
                }
            }
        }
        walk::walk_variable_declarator(self, declarator);
    }

    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        if let Some(exported) = self.static_commonjs_export(expression) {
            // CommonJS assignments own a public name through the assigned
            // local value when it is statically bound. Expressions remain a
            // module-level, explicitly non-symbol owner.
            let owner = expression
                .right
                .get_identifier_reference()
                .and_then(|identifier| {
                    self.semantic
                        .scoping()
                        .get_reference(identifier.reference_id())
                        .symbol_id()
                })
                .map(|symbol| self.symbol_node(symbol))
                .unwrap_or_else(|| self.current_container());
            let current_module = self.external_node("module:<current>", false);
            self.add_edge(
                owner,
                current_module.clone(),
                "ExportsBinding",
                false,
                Some(exported.clone()),
            );
            if let Some((module, imported)) = self.static_commonjs_reexport(&expression.right) {
                let source_module = self.external_node(&format!("module:{module}"), false);
                self.add_edge(
                    current_module,
                    source_module,
                    "ReExportsBinding",
                    false,
                    Some(format!("{exported} <- {imported}")),
                );
            }
        }
        let write_reference = match &expression.left {
            AssignmentTarget::AssignmentTargetIdentifier(identifier) => {
                Some(identifier.reference_id().index())
            }
            _ => None,
        };
        if let Some(reference) = write_reference {
            self.write_reference_ids.insert(reference);
        }
        walk::walk_assignment_expression(self, expression);
        if let Some(reference) = write_reference {
            self.write_reference_ids.remove(&reference);
        }
    }

    fn visit_import_expression(&mut self, expression: &ImportExpression<'a>) {
        match expression.source.get_inner_expression() {
            oxc_ast::ast::Expression::StringLiteral(module) => {
                self.add_dynamic_module_edge("DynamicImports", module.value.as_str());
            }
            _ => self.add_dynamic_module_edge("DynamicImports", "<dynamic>"),
        }
        walk::walk_import_expression(self, expression);
    }

    fn visit_new_expression(&mut self, expression: &NewExpression<'a>) {
        let occurrence = self.occurrence_node("NewSite", "new", expression.span);
        walk::walk_new_expression(self, expression);
        let (target, dynamic, label) = self.expression_target(&expression.callee);
        self.add_edge(occurrence, target, "Instantiates", dynamic, label);
    }

    fn visit_jsx_element(&mut self, element: &JSXElement<'a>) {
        let name_span = element.opening_element.name.span();
        let label = self
            .source
            .get(name_span.start as usize..name_span.end as usize)
            .unwrap_or("<jsx>")
            .to_string();
        let resolved = match &element.opening_element.name {
            JSXElementName::IdentifierReference(identifier) => {
                Some(self.reference_target(identifier))
            }
            _ => None,
        };
        walk::walk_jsx_element(self, element);
        let (target, dynamic) =
            resolved.unwrap_or_else(|| (self.external_node(&format!("jsx:{label}"), false), false));
        let occurrence = self.occurrence_node("RenderSite", &label, element.span());
        self.add_edge(occurrence, target, "Renders", dynamic, Some(label));
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        let declaration_is_type = declaration.import_kind.is_type();
        self.add_module_edge(
            if declaration_is_type {
                "TypeImports"
            } else {
                "Imports"
            },
            declaration.source.value.as_str(),
        );
        let module = declaration.source.value.as_str();
        let module_node = self.external_node(&format!("module:{module}"), false);
        if let Some(specifiers) = &declaration.specifiers {
            for specifier in specifiers {
                let (symbol_id, imported, specifier_is_type) = match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(specifier) => {
                        let imported = match &specifier.imported {
                            ModuleExportName::IdentifierName(name) => name.name.to_string(),
                            ModuleExportName::IdentifierReference(name) => name.name.to_string(),
                            ModuleExportName::StringLiteral(name) => name.value.to_string(),
                        };
                        (
                            specifier.local.symbol_id.get(),
                            imported,
                            specifier.import_kind.is_type(),
                        )
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => (
                        specifier.local.symbol_id.get(),
                        "default".to_string(),
                        false,
                    ),
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => {
                        (specifier.local.symbol_id.get(), "*".to_string(), false)
                    }
                };
                if let Some(symbol_id) = symbol_id {
                    let symbol = self.symbol_node(symbol_id);
                    self.add_edge(
                        symbol,
                        module_node.clone(),
                        if declaration_is_type || specifier_is_type {
                            "TypeImportsBinding"
                        } else {
                            "ImportsBinding"
                        },
                        false,
                        Some(imported),
                    );
                }
            }
        }
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_ts_import_equals_declaration(&mut self, declaration: &TSImportEqualsDeclaration<'a>) {
        // `import value = require("module")` is a real CommonJS module
        // boundary after TypeScript lowering. Preserve the identifier binding
        // just as for a destructuring `require`, while keeping `import type`
        // erased from runtime provenance. Identifier/qualified references are
        // intentionally left to ordinary resolved-reference edges: they do
        // not name a statically resolvable module path.
        if let TSModuleReference::ExternalModuleReference(reference) = &declaration.module_reference
        {
            let module = reference.expression.value.as_str();
            let is_type = declaration.import_kind.is_type();
            self.add_module_edge(if is_type { "TypeImports" } else { "Requires" }, module);
            if let Some(symbol_id) = declaration.id.symbol_id.get() {
                let symbol = self.symbol_node(symbol_id);
                let target = self.external_node(&format!("module:{module}"), false);
                self.add_edge(
                    symbol,
                    target,
                    if is_type {
                        "TypeImportsBinding"
                    } else {
                        "RequiresBinding"
                    },
                    false,
                    Some("*".to_string()),
                );
            }
        }
        walk::walk_ts_import_equals_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'a>) {
        let declaration_is_type = declaration.export_kind == ImportOrExportKind::Type
            || declaration
                .declaration
                .as_ref()
                .is_some_and(Declaration::is_type);
        if let Some(source) = &declaration.source {
            let owner = self.current_container();
            let current_module = self.external_node("module:<current>", false);
            let source_module = self.external_node(&format!("module:{}", source.value), false);
            let mut has_value = false;
            let mut has_type = false;
            for specifier in &declaration.specifiers {
                let local = Self::module_export_name(&specifier.local);
                let exported = Self::module_export_name(&specifier.exported);
                let specifier_is_type =
                    declaration_is_type || specifier.export_kind == ImportOrExportKind::Type;
                has_type |= specifier_is_type;
                has_value |= !specifier_is_type;
                // A barrel owns the name its consumers import, while the
                // ReExportsBinding preserves the exact upstream owner/name
                // chain. Keeping both edges prevents a barrel from looking
                // like an implementation and avoids guessing through `export
                // *`.
                self.add_edge(
                    owner.clone(),
                    current_module.clone(),
                    if specifier_is_type {
                        "TypeExportsBinding"
                    } else {
                        "ExportsBinding"
                    },
                    false,
                    Some(exported.clone()),
                );
                self.add_edge(
                    current_module.clone(),
                    source_module.clone(),
                    if specifier_is_type {
                        "TypeReExportsBinding"
                    } else {
                        "ReExportsBinding"
                    },
                    false,
                    Some(format!("{exported} <- {local}")),
                );
            }
            if has_value {
                self.add_module_edge("Exports", source.value.as_str());
            }
            if has_type {
                self.add_module_edge("TypeExports", source.value.as_str());
            }
        } else {
            let owner = self.current_container();
            let target = self.external_node("module:<current>", false);
            let mut has_value = declaration.declaration.is_some() && !declaration_is_type;
            let mut has_type = declaration.declaration.is_some() && declaration_is_type;
            if let Some(declared) = &declaration.declaration {
                self.direct_export_symbols.extend(
                    Self::declaration_symbols(declared)
                        .into_iter()
                        .map(|(symbol, name)| (symbol, name, declaration_is_type)),
                );
            }
            for specifier in &declaration.specifiers {
                let exported = Self::module_export_name(&specifier.exported);
                let specifier_is_type =
                    declaration_is_type || specifier.export_kind == ImportOrExportKind::Type;
                has_type |= specifier_is_type;
                has_value |= !specifier_is_type;
                // `export { local as public }` owns `public` through the
                // resolved local symbol. Falling back to the module owner is
                // deliberately explicit for malformed/unbound syntax only.
                let export_owner = self
                    .export_symbol_for_local(&specifier.local)
                    .unwrap_or_else(|| owner.clone());
                self.add_edge(
                    export_owner,
                    target.clone(),
                    if specifier_is_type {
                        "TypeExportsBinding"
                    } else {
                        "ExportsBinding"
                    },
                    false,
                    Some(exported),
                );
            }
            if has_value {
                self.add_edge(owner.clone(), target.clone(), "Exports", false, None);
            }
            if has_type {
                self.add_edge(owner, target, "TypeExports", false, None);
            }
        }
        walk::walk_export_named_declaration(self, declaration);
    }

    fn visit_export_default_declaration(&mut self, declaration: &ExportDefaultDeclaration<'a>) {
        let owner = match &declaration.declaration {
            oxc_ast::ast::ExportDefaultDeclarationKind::FunctionDeclaration(function) => function
                .id
                .as_ref()
                .and_then(|id| id.symbol_id.get())
                .map(|symbol| self.symbol_node(symbol)),
            oxc_ast::ast::ExportDefaultDeclarationKind::ClassDeclaration(class) => class
                .id
                .as_ref()
                .and_then(|id| id.symbol_id.get())
                .map(|symbol| self.symbol_node(symbol)),
            expression => expression
                .as_expression()
                .and_then(|expression| expression.get_identifier_reference())
                .and_then(|identifier| {
                    self.semantic
                        .scoping()
                        .get_reference(identifier.reference_id())
                        .symbol_id()
                })
                .map(|symbol| self.symbol_node(symbol)),
        }
        .unwrap_or_else(|| self.current_container());
        let target = self.external_node("module:<current>", false);
        self.add_edge(
            owner,
            target,
            "ExportsBinding",
            false,
            Some("default".to_string()),
        );
        walk::walk_export_default_declaration(self, declaration);
    }

    fn visit_ts_export_assignment(&mut self, declaration: &TSExportAssignment<'a>) {
        // TypeScript's `export = value` lowers to the CommonJS default module
        // contract. The expression is still walked so its resolved reference
        // or call relationship remains in the graph.
        let owner = declaration
            .expression
            .get_identifier_reference()
            .and_then(|identifier| {
                self.semantic
                    .scoping()
                    .get_reference(identifier.reference_id())
                    .symbol_id()
            })
            .map(|symbol| self.symbol_node(symbol))
            .unwrap_or_else(|| self.current_container());
        let target = self.external_node("module:<current>", false);
        self.add_edge(owner.clone(), target.clone(), "Exports", false, None);
        self.add_edge(
            owner,
            target,
            "ExportsBinding",
            false,
            Some("default".to_string()),
        );
        walk::walk_ts_export_assignment(self, declaration);
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'a>) {
        let is_type = declaration.export_kind == ImportOrExportKind::Type;
        self.add_module_edge(
            if is_type { "TypeExports" } else { "Exports" },
            declaration.source.value.as_str(),
        );
        let current_module = self.external_node("module:<current>", false);
        let source_module =
            self.external_node(&format!("module:{}", declaration.source.value), false);
        if let Some(exported) = &declaration.exported {
            let exported = Self::module_export_name(exported);
            self.add_edge(
                self.current_container(),
                current_module.clone(),
                if is_type {
                    "TypeExportsBinding"
                } else {
                    "ExportsBinding"
                },
                false,
                Some(exported.clone()),
            );
            self.add_edge(
                current_module,
                source_module,
                if is_type {
                    "TypeReExportsBinding"
                } else {
                    "ReExportsBinding"
                },
                false,
                Some(format!("{exported} <- *")),
            );
        } else {
            // `export *` has no statically enumerable public-name contract.
            // Retain its module lineage without inventing individual exports.
            self.add_edge(
                current_module,
                source_module,
                if is_type {
                    "TypeReExportsBinding"
                } else {
                    "ReExportsBinding"
                },
                false,
                Some("* <- *".to_string()),
            );
        }
        walk::walk_export_all_declaration(self, declaration);
    }
}

pub(crate) fn extract(
    program: &Program<'_>,
    semantic: &Semantic<'_>,
    source: &str,
    file: &str,
    side: &str,
) -> SemanticGraph {
    let mut collector = GraphCollector::new(source, file, side, semantic);
    collector.visit_program(program);
    collector.owner_stack.pop();
    collector.finish()
}
