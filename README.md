# project-parity

`project-parity` is a standalone Rust/Oxc CLI for deep correspondence between
two JavaScript or TypeScript project trees. Give it an authoritative upstream
tree and a local implementation; it discovers files recursively, resolves
bindings and module edges, builds a lossless semantic graph, and emits a
bounded work queue for an LLM repair loop.

The right-hand input is the authoritative target. The tool never executes
either tree and never edits either input.

## Quick start

From a clean machine, install the CLI and skill in one command:

```bash
curl -fsSL https://raw.githubusercontent.com/beautyfree/project-parity/master/install.sh \
  | sh -s -- --target=codex --yes
```

Then, in the project where parity work will happen:

```bash
project-parity init /path/to/local /path/to/upstream
```

`init` creates `/path/to/local/.parity/`, runs the first authoritative
comparison, and stores the LLM queue in `.parity/state.sqlite`. Run it once per
project. It also saves the pair in `.parity/config.json`. When working from
the local project directory, the shorter forms are available:

```bash
project-parity init /path/to/upstream   # current directory is LOCAL
project-parity sync                    # uses .parity/config.json
```

After a local patch, use `project-parity sync`, or let the optional `serve`
watcher resync automatically.

The public installer downloads a versioned prebuilt binary and the bundled
skill; it does not require a Rust toolchain. Use
`PROJECT_PARITY_VERSION=vX.Y.Z` to pin a release. When run from a checkout,
the same `install.sh` switches to source-build mode for development.
Verify an installed binary with `project-parity --version`; the capability
list includes queue routing, batched evidence, upstream-owner routing for
ownerless work, `state-optimize-queue-v1`, and
`frontier-behavior-edges-v1`. `show-batch-compact-v1` enables lossless evidence
deduplication for large ambiguous batches without removing any owner context.

## Advanced operation

Keep the report and queue current while either tree changes:

```bash
project-parity serve /path/to/local /path/to/upstream \
  --out /path/to/local/.parity/report \
  --state /path/to/local/.parity/state.sqlite
```

For MCP-capable agent hosts, add `--mcp` to the same command. Manual queue and
evidence commands (`state-next`, `show-work`, `inspect`, `graph-node`) are
available when an agent needs direct inspection.

For bounded batches, mark a reviewed and locally patched item as waiting for
the next authoritative resync without running the expensive analysis yet:

```bash
project-parity state-done STATE_DB WORK_ITEM_ID "local patch complete; batch sync pending"
```

For larger reviewed batches, use the atomic form (the reason is one shell
argument, followed by one or more individually reviewed IDs):

```bash
project-parity state-done-batch STATE_DB "reviewed and patched; batch sync pending" WORK_ITEM_ID...
```

`state-next` defaults to compact routing output so a bare invocation cannot
dump 100 large evidence payloads into an agent context. Use `--full` only when
you explicitly need the legacy full-payload response; `--summary` adds compact
owner locators to routing output. Use `state-next STATE_DB 100 --routing` for
each review slice, but amortize the
expensive sync across up to 1,000 individually reviewed items. Mark each slice
with `state-done-batch`; run one serialized `sync` when `pendingSync` reaches
1,000 (or at the end if fewer remain). Never mark unseen work just to reach the
threshold. The command validates every ID before writing any decision and
preserves each payload snapshot, so a later sync reopens only changed evidence.

Queue reads default to 100 items. The normal routing form avoids sending full
evidence before the relevant shared batch is selected. Use `--summary` only when
its reasons and owner/file counts with sample paths will change which evidence
you inspect next; load complete evidence and all owner paths with `show-work` or
`show-batch`.

For the lowest-context routing pass, use
`project-parity state-next STATE_DB 100`. Each selected ID appears once in
`items`; `reviewGroups` maps semantic batches to item indexes, and
`ownerGroups` groups transitively overlapping LOCAL file sets for safe review
and worker partitioning; `upstreamGroups` groups items that reuse the same
read-only upstream file owners, including ownerless LOCAL locators. Use the
latter to avoid reopening the same upstream owner for each item. Both group
lists are routing aids only; inspect and record each work-item verdict
independently. Handle `ownerlessItemIndexes` via their upstream groups rather
than dropping them from the slice.
`unbatchedItemIndexes` identifies items without a semantic batch. Owner groups
are routing only, not shared verdicts: validate every ID independently. This
avoids repeating IDs and batch IDs in the
response. Add `--summary` only when compact reasons
and owner/file counts with sample paths will affect which evidence you inspect
next. Load complete evidence once per group with
`show-batch`, or use `show-work` for an individual item. Routing output is
never sufficient evidence to mark work done.

`inspect REPORT_DIRECTORY UNIT_ID [LIMIT] [OFFSET]` returns the exact source
plus a bounded page of linked relations (25 by default). Continue from
`nextOffset` until `remaining` is zero when the full relation set is needed;
pagination bounds response/context size but does not reduce the legacy report
scan cost.

When a selected slice repeats a `batchId`, use `show-batch REPORT_DIR BATCH_ID`
once to inspect that semantic owner’s full evidence together instead of making
one `show-work` call per ID. For high-ambiguity batches, add `--compact`:
identical fields move to `sharedFields`, and repeated inspection-node IDs are
interned in `inspectNodeIdTable`; each item retains indexes in original order.
This is lossless and reconstructs the same per-item evidence, while avoiding
large repeated upstream candidate lists. The default remains the full v2
response for compatibility. Still validate every work item separately, and
only mark IDs from the selected slice that were individually reviewed; a batch
page can also contain already-decided items or items beyond the slice.

For selected IDs that belong to different batches (especially singleton
batches), use `show-works REPORT_DIR WORK_ITEM_ID...`. It loads the indexed
work-item locator once and returns complete evidence in the requested order;
an unknown ID fails the command rather than returning a partial slice. This
avoids reparsing the report index once per `show-work` process without
weakening per-item review.

For an existing state database, `project-parity state-optimize-queue STATE_DB`
installs the derived priority/evidence-order index used by `state-next`. Within
each priority/confidence tier, items sharing a semantic evidence batch are kept
adjacent, reducing repeated `show-batch` loads across review slices. Proven
evidence still precedes candidates, and weak/unknown evidence follows; this
changes ordering only, never queue membership or decisions. It does not rescan
either project. On older databases it adds/backfills only the derived
`batch_id` locator and index; `sync` maintains that locator on new databases.

For an evidence-backed vendor/compiler segment, the equivalent durable batch
operation is:

```bash
project-parity state-skip-batch STATE_DB "installed vendor package" WORK_ITEM_ID...
```

`state-skip-batch` records durable skips, shown separately by `state-stats`.
For ordinary reviewed work, `state-done-batch` records `pendingSync`; the next
`sync` promotes unchanged reviewed payloads to durable `done`, while changed
payloads return to the queue for fresh review. Use skip only for
evidence-backed non-actionable/compiler/vendor cases.

`state-next` keeps `remove-or-justify-extra-local` and
`locate-unlinked-upstream-branch` in late phases so large low-priority cleanup
candidate sets do not crowd out upstream functionality gaps. Neither phase is
resolved or hidden: both remain in the queue, count toward `deferred`, and
surface automatically after earlier phases are exhausted. Unlinked upstream
roots have unknown ownership and package provenance, so they are P2 locators,
not confirmed P0 defects.

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

`state-sync` pins both input hashes in SQLite. After a local patch, run `sync`
against the same two roots. An item is resolved only when
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
are skipped to avoid duplicate owners. One deliberate exception is a root
`dist/` in a distribution-only input with no root `src/`, `source/`, or `lib/`:
that directory is treated as the authoritative executable surface, while
nested build directories remain excluded. This covers unpacked releases whose
renderer exists only as shipped chunks. Upstream is read-only by convention.
AST/graph correspondence is source evidence, not a claim of runtime, native,
asset, or pixel equivalence.

## Bundled LLM skill

The [`skill/`](skill/) directory is a portable Codex/LLM skill. Copy it into a
skill registry or load `skill/SKILL.md` directly. Its default path is only
`init once → next task → inspect → patch local → tests → sync`; detailed artifact
contracts live in `skill/references/` and do not clutter the normal workflow.

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
`sync`.

## Development

```bash
cargo +1.98.1 fmt --check
cargo +1.98.1 test
cargo +1.98.1 clippy --all-targets -- -D warnings
cargo +1.98.1 run --release -- fixtures/oracle-basic/left fixtures/oracle-basic/right \
  --out /tmp/project-parity-fixture --oracle fixtures/oracle-basic/oracle.json
```
