# project-parity

`project-parity` is a standalone Rust/Oxc CLI for deep correspondence between
two JavaScript or TypeScript project trees. Give it an authoritative upstream
tree and a local implementation; it discovers files recursively, resolves
bindings and module edges, builds a lossless semantic graph, and emits a
bounded work queue for an LLM repair loop.

The right-hand input is the authoritative target. The tool never executes
either tree and never edits either input.

## Quick start

```bash
cargo run --release -- /path/to/local /path/to/upstream --out reports/run

# keep a report and its queue current while either tree changes
cargo run --release -- watch /path/to/local /path/to/upstream --out reports/run \
  --state .parity/state.sqlite

# CodeGraph-style foreground service entry point (agent/daemon wrappers can
# supervise this process; serve-status.json records its lifecycle state)
cargo run --release -- serve /path/to/local /path/to/upstream --out reports/run \
  --state .parity/state.sqlite

# stdio MCP server for an agent host
cargo run --release -- serve /path/to/local /path/to/upstream --out reports/run \
  --state .parity/state.sqlite --mcp

# select the next unresolved repair task
cargo run --release -- state-sync .parity/state.sqlite reports/run
cargo run --release -- state-next .parity/state.sqlite 10

# inspect complete source and graph evidence for one task
cargo run --release -- show-work reports/run WORK_ITEM_ID
cargo run --release -- inspect reports/run NODE_ID
cargo run --release -- graph-node reports/run NODE_ID 100 0
```

Use `--oracle FILE` when a fixture or reviewed corpus has expected stable
source locators. Use `codegraph-import` only to add supplementary navigation
evidence; the Oxc semantic graph remains the parity authority.

## Output contract

Each report contains `report.json`, a self-contained `report.html`, complete
lossless compressed graph/ledger artifacts, source-hash-checked inspectors,
`llm-manifest.json`, and `llm-work-items.jsonl`/`llm-batches.jsonl`. Work items
are prioritized P0/P1/P2 and retain missing, changed, ambiguous, candidate,
dependency, caller, scope, import, export, and package provenance evidence.

Byte-identical source files are promoted to proven coverage before fuzzy
matching, including their non-executable graph context. Auditing a project
against itself therefore produces an empty repair queue instead of false work
items from repeated or context-only nodes.

`state-sync` pins both input hashes in SQLite. After a local patch, rerun the
CLI against the same two roots and sync again. An item is resolved only when
its stable id disappears or its disposition is explicitly covered by fresh
evidence.

`watch` takes content-hash snapshots, debounces save bursts, skips no-op
cycles, writes `change-set.json`, reuses the per-file Oxc cache for unchanged
files, and runs `state-sync` after each settled change. The correspondence
phase remains global by design: `resync-plan.json` records the reverse
dependency impact closure, while reusing old matches without a persisted
component graph can silently lose cross-file relationships.

`serve` is the agent-friendly lifecycle wrapper around the same safe watcher.
It writes `serve-status.json` in the report directory and exits non-zero on a
failed initial scan or resync. With `--mcp`, it also exposes a newline-delimited
JSON-RPC MCP server over stdin/stdout (`parity_status`, `state_next`,
`show_work`, `inspect`, `graph_node`, and `resync`). The MCP layer is only a
transport facade over the same parity engine; it cannot edit either input.

## Discovery and trust boundaries

Discovery is recursive and build-system agnostic. Common generated and vendor
directories (`node_modules`, `target`, `coverage`, reports, and build output)
are skipped to avoid duplicate owners; pass a prepared projection directory as
an input when a build emits the authoritative executable surface. Upstream is
read-only by convention. AST/graph correspondence is source evidence, not a
claim of runtime, native, asset, or pixel equivalence.

## Bundled LLM skill

The [`skill/`](skill/) directory is a portable Codex/LLM skill. Copy it into a
skill registry or load `skill/SKILL.md` directly. It defines the evidence-first
loop, queue ordering, inspection commands, patch gates, and resynchronization
rules without assuming a particular product, version, bundler, or repository
layout.

### Agent installation

The bundled installer follows the useful part of CodeGraph's model: the CLI
and the skill are separate surfaces, installation is idempotent, and existing
agent instructions are preserved behind marker fences.

```bash
./install.sh --target=codex,claude,cursor --yes
# project-local instead of user-wide:
./install.sh --target=codex --location=local --yes
# remove only the installed skill/instructions and CLI:
./install.sh --uninstall
```

The installer currently installs the skill for Codex, Claude Code, and Cursor.
It does not silently rewrite MCP settings: the MCP command must be configured
with concrete local/upstream roots and a report directory for each project.
Use `serve ... --mcp` as the configured MCP command. `--skip-build` reuses an
existing `target/release/project-parity` binary. The upstream input remains
read-only; the skill tells the agent to patch only the local input and re-run
`state-sync`.

## Development

```bash
cargo +1.98.1 fmt --check
cargo +1.98.1 test
cargo +1.98.1 clippy --all-targets -- -D warnings
cargo +1.98.1 run --release -- fixtures/oracle-basic/left fixtures/oracle-basic/right \
  --out /tmp/project-parity-fixture --oracle fixtures/oracle-basic/oracle.json
```
