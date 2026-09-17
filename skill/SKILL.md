---
name: project-parity-loop
description: Use the project-parity CLI to compare an authoritative upstream JavaScript or TypeScript project with a local implementation and drive a hash-pinned LLM repair loop.
---

# Project parity loop

Use this skill when an upstream implementation is the behavioral/source target
and the local project must be brought into correspondence. The CLI is an
evidence generator and queue manager; it is not an automatic patcher.

## Invariants

- The report's `right` side is authoritative. Never edit it.
- The `left` side is the local implementation and is the only code you patch.
- A score is locator evidence, not proof. Read the complete owners, scopes,
  callers, dependency edges, imports/exports, and package provenance.
- `proven-structure` means alpha-equivalent AST/binding structure only. It does
  not prove runtime, native, asset, timing, or pixel parity.
- CodeGraph, when imported, is supplementary navigation evidence. It cannot
  promote a relation to proven parity.
- Never close a task because a name or file path looks similar.

## Start a run

```bash
project-parity LOCAL_DIR UPSTREAM_DIR --out REPORT_DIR
project-parity state-sync STATE_DB REPORT_DIR
project-parity state-next STATE_DB 10
```

For a long-running repair session, use the safe watcher:

```bash
project-parity watch LOCAL_DIR UPSTREAM_DIR --out REPORT_DIR \
  --state STATE_DB --interval 1000 --debounce 750
```

For an agent-supervised lifecycle, use the equivalent `serve` entry point:

```bash
project-parity serve LOCAL_DIR UPSTREAM_DIR --out REPORT_DIR \
  --state STATE_DB --interval 1000 --debounce 750
```

`serve` is a foreground service wrapper. It writes `serve-status.json` and
can be supervised by an agent or shell service manager. For agent hosts with
MCP support, add `--mcp`; this exposes only read/evidence tools plus an explicit
`resync` operation, while keeping upstream read-only.

It snapshots content hashes, coalesces editor save bursts, skips no-op cycles,
records `change-set.json`, reuses the per-file AST cache for unchanged files,
records `resync-plan.json` with the reverse dependency impact closure, reuses
the per-file AST cache for unchanged files, and syncs the SQLite queue after
each completed analysis. Correspondence remains global so a partial merge
cannot silently lose cross-file relations.

Read `REPORT_DIR/llm-manifest.json` first. It contains input hashes, artifact
names, lossless-ledger guarantees, and the current work-item contract. Treat a
changed input hash as a new audit boundary; do not reuse conclusions from an
older report.

## Process one work item

1. Take the highest-priority item from `state-next` (P0, then P1, then P2).
2. Load the full item with `show-work REPORT_DIR ITEM_ID`.
3. For every listed node, run `inspect REPORT_DIR NODE_ID`. Read the complete
   source spans returned for both sides, not only the snippet in the queue.
4. Use `graph-node REPORT_DIR NODE_ID` to page all incoming/outgoing edges.
   Trace callers, writes, renders, module edges, re-exports, scopes, and
   dependency/package bindings until the behavior boundary is understood.
5. Classify the evidence: exact structural coverage, candidate, ambiguous,
   changed, missing-local, extra-local, or dependency-only.
6. Patch the smallest coherent local owner set. Do not edit upstream or copy
   code blindly from a low-confidence candidate.

## Close the loop

Run focused unit/type tests and, where relevant, the real runtime/rendered
validation. Then regenerate the report against the same two roots and sync:

```bash
project-parity LOCAL_DIR UPSTREAM_DIR --out REPORT_DIR
project-parity state-sync STATE_DB REPORT_DIR
project-parity state-next STATE_DB 10
```

An item is resolved only when its stable id is absent from the fresh queue or
its disposition is explicitly justified as covered. If the source hashes
changed unexpectedly, stop and re-audit the affected chain. Do not claim full
parity while unresolved P0/P1 items, parse failures, or unreviewed ambiguous
groups remain.

## Required handoff

When reporting progress, include the report path, both input hashes, queue
counts by priority/status, tests and runtime gates actually run, and the exact
unresolved boundary. A passing CLI/build is structural evidence only.
