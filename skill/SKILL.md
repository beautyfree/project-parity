---
name: project-parity-loop
description: Bring a local JavaScript or TypeScript project into parity with an authoritative upstream project.
---

# Project parity loop

Use this skill when the user asks to reproduce or synchronize a local project
with an upstream implementation. The upstream tree is the reference; the
local tree is the only tree you may edit.

## Start automatically

If `LOCAL_DIR/.parity/` does not exist, initialize the analysis:

```bash
project-parity init LOCAL_DIR UPSTREAM_DIR
```

When the agent is started in the local project directory, prefer the shorter
form:

```bash
project-parity init UPSTREAM_DIR
```

The CLI treats the current directory as local and saves the pair in
`.parity/config.json`. Do not make the user learn report paths, SQLite
commands, or graph file names. Run `init` once per project.

For distribution-only upstreams, the scanner includes a root `dist/` when the
input has no root `src/`, `source/`, or `lib/`; nested generated directories
remain excluded. Check the report's corpus/file counts to ensure bundled
renderer or other shipped chunks were indexed instead of assuming a clean
parse count proves complete coverage.

## Repair loop

Before using persisted parity state, verify the installed CLI with
`project-parity --version`. Require `state-next-v2`,
`state-next-owner-groups-v1`, `state-next-upstream-groups-v1`,
`state-next-local-context-v1`, `state-done-batch-v1`,
`state-done-sync-progress-v1`, `state-skip-batch-v1`,
`show-works-v1`, `show-batch-compact-v1`, `state-optimize-queue-v1`, `frontier-triage-v2`, and
`frontier-behavior-edges-v1` in its capability list.
Older binaries may repeat IDs, emit oversized output, omit ownership routing,
lack efficient batch review or the derived queue-order index, or leave weak
graph-only frontiers misranked. If a capability is missing, first check whether
the current report and state database are compatible and whether any reviewed
items are waiting in `pendingSync`. Do not replace the CLI in the middle of an
accumulation window: finish the current safe batch/checkpoint with the
compatible binary, sync once, then update the CLI and sync again before taking
new queue decisions if the engine/report compatibility guard requires it. If
the CLI cannot safely read current state, stop and preserve the database; do
not initialize again or force decisions through the mismatch. Run
`state-optimize-queue STATE_DB` once for a large existing queue; it does not
rescan sources or alter decisions.

Repeat until the queue is empty:

1. Read a bounded batch from `LOCAL_DIR/.parity/state.sqlite` with
   `state-next STATE_DB 100` (the default limit is 100 and output defaults to
   compact routing). Never invoke bare `state-next` expecting full evidence;
   use `--full` only when a specific debugging need requires its large payload.
   This returns compact IDs once in `items`, with `reviewGroups` mapping
   `batchId` values to item indexes and `ownerGroups` joining work items whose
   LOCAL owner files or graph-context files overlap (including transitively).
   `localFiles` are candidate/local owner locators; `localContextFiles` are
   LOCAL files referenced by evidence paths, not proof that the upstream
   divergence already has a matching owner. Use `ownerGroups` to keep related
   owners/context in one review/worker partition. Truly context-free items
   remain in `ownerlessItemIndexes`. `upstreamGroups` joins items
   sharing read-only upstream files, including ownerless LOCAL candidates;
   use it to avoid repeating upstream owner inspection and to route those
   otherwise-unowned items. Both group lists are routing aids, not shared
   verdicts. Review and record every work-item ID independently. Do not drop
   `ownerlessItemIndexes` when partitioning.
   `unbatchedItemIndexes` identifies items without a semantic batch.
   Add `--summary` only when its extra owner/file locators will change which
   evidence you inspect next. Do not load
   full payloads for the whole batch. `state-next` keeps
   `remove-or-justify-extra-local` and `locate-unlinked-upstream-branch` in late
   phases so large low-priority cleanup candidate sets do not crowd out
   upstream functionality gaps. These items remain in the queue and in
   `state-stats.deferred`; they are surfaced automatically after earlier
   phases are exhausted. Unlinked upstream roots have unknown ownership and
   package provenance, so they are P2 locators, not confirmed P0 defects.
   Within each priority tier, proven evidence precedes
   candidates, then weak/unknown evidence; this is ordering only and does not
   resolve or hide uncertain work.
   A graph frontier supported only by global/neighbor shape matching without a
   behavioral edge chain is retained as a weak P2 candidate for later review.
   AST containment, next-statement, scope, and `Defines` binding edges locate
   syntax/ownership but do not corroborate behavior; `Calls`, `References`,
   `Instantiates`, and `Renders` edges do. Corroborated owner/behavior chains
   keep normal triage; a demotion never closes or resolves a work item.
   For a large state database created by an older CLI, run
   `state-optimize-queue STATE_DB` once before reviewing. It only installs a
   derived priority/evidence-order index and keeps equal-tier work from the
   same semantic batch adjacent; it does not rescan either project or alter
   queue decisions. On older databases it adds/backfills only the derived
   `batch_id` locator and index. New syncs maintain the locator automatically.
   If `state-next` reports that the manifest is newer than queue state, that
   the report was generated by a different engine version, or that selected
   IDs are absent from the current work-item index, stop that slice and run one
   `project-parity sync` before requesting more work. Engine changes can alter
   confidence and priority without changing source hashes, so do not review or
   mark a stale queue. Do not retry missing IDs, mark them done, or assume they
   resolved; the guard means the report and SQLite snapshot disagree.
2. Inspect complete evidence without repeating the same owner context:
   - If the selected 100-item slice contains multiple IDs with the same
     `batchId`, load that semantic owner once with
      `project-parity show-batch REPORT_DIR BATCH_ID [LIMIT] [OFFSET] [--compact]`. Use
      `--compact` for high-ambiguity batches: common fields are emitted once
      under `sharedFields`, and `inspectNodeIds` are losslessly interned in
      `inspectNodeIdTable` with per-item index arrays. Reconstruct each item by
      merging `sharedFields`, the item fields, and its indexed node IDs. Review
      every returned work item independently; the batch is a navigation unit,
      not a shared verdict. Only mark IDs from the current `state-next` slice
      after each one has been individually checked. A batch page may include
      items outside that slice or already decided items; do not mark those
      implicitly.
      A work item may contain `evidenceVariants` when several divergent edges
      share one stable owner-level ID. Review every variant as evidence for
      that single item; do not count or mark variants as separate work items.
   - For a one-item batch, or when the report is not current, use
     `project-parity show-work REPORT_DIR WORK_ITEM_ID`.
   - When several selected IDs belong to different batches, use one
     `project-parity show-works REPORT_DIR WORK_ITEM_ID...` invocation to load
     their full evidence together. It preserves input order and fails as a
     whole if any ID is missing; still make and record an independent verdict
     for every returned work item.
   Inspect listed units and graph edges when the evidence is ambiguous or
   crosses owner boundaries. `inspect REPORT_DIR UNIT_ID [LIMIT] [OFFSET]`
   returns source plus 25 relation records by default. Each invocation may scan
   large report artifacts again, so when the relation count is known, request a
   single page large enough to cover it (for example, `LIMIT=300` for 182 or 259
   relations) instead of issuing many small page requests. Still verify
   `remaining` is zero before making a decision that depends on the complete
   relation set; use smaller pages if one response would exceed the available
   context. Keep all owner chains and package provenance in view; batching
   reduces repeated reads, not the evidence required.
3. Compare the full upstream owner chain: imports, exports, scopes, callers,
   dependencies, and package provenance. A name or score is only a locator.
4. Patch only the local project. Never edit the upstream tree or copy a
   low-confidence candidate without understanding its contract.
   Keep review cadence separate from verification cadence: confirming an
   already-equivalent owner without editing code does not require rerunning
   tests. For code changes, accumulate related edits by non-overlapping LOCAL
   ownership, then run the focused tests once for that patch set. Run broader
   typecheck/runtime scenarios at the 1,000-item sync checkpoint and once at
   final validation; run them sooner when a change crosses a shared contract or
   a focused check exposes a wider risk. Never defer a check needed to safely
   decide or integrate a patch.
   When a multi-agent facility is available, parallelize only independent
   `ownerGroups` from the current slice, then give each worker the exact
   selected IDs and complete proof for its partition. Keep overlapping owners
   in one partition; cap worker
   count to the available concurrency and avoid one worker per item. Workers
   may inspect and patch only their assigned LOCAL files, run focused checks,
   and return per-ID evidence plus changed files. The parent owns the state
   database: workers must not run `sync`, `state-done*`, or `state-skip*`;
   independently review their findings and mark only verified IDs after
   integration. If owner/file overlap cannot be ruled out, keep that work
   serial. Parallelism reduces elapsed review time, not evidence requirements.
5. Run relevant tests/runtime checks. Review in compact slices of 100, and
   mark each slice's individually inspected items temporarily complete with
   one atomic command:
   `project-parity state-done-batch STATE_DB REASON WORK_ITEM_ID...`.
   Continue across slices without syncing; `state-done-batch` returns the
   cumulative `pendingSync` count after each batch. When it reaches 1,000, run
   one serialized `project-parity sync` and start the
   next accumulation window. If fewer than 1,000 items remain, sync once at
   the end. Never mark unseen items to hit the threshold. The next sync
   promotes unchanged reviewed payloads to durable `done`;
   changed payloads return to the queue for fresh evidence review, while
   disappeared items resolve. `state-stats` separates pending, done, and
   skipped counts and includes `queueBreakdown` grouped by priority,
   confidence, and action. Use that breakdown to identify queue composition;
   it is not an estimate of review effort or proof quality. Use `state-skip`
   only for evidence-backed non-actionable/compiler/vendor cases; for a
   reviewed segment use the atomic
   `state-skip-batch STATE_DB REASON WORK_ITEM_ID...` form. Never batch-mark an
   item that was not individually inspected and validated.
   The saved project config supplies both roots; the explicit
   `sync LOCAL_DIR UPSTREAM_DIR` form remains available.

6. Treat every concrete user-reported runtime defect as a direct audit item,
   even when `state-next` is empty or has no matching candidate. Trace the
   active local and upstream owners from the observed entry point through
   imports, exports, bindings, callers, dependencies, and package provenance;
   compare the complete upstream implementation, then reproduce the same
   scenario locally and validate the fix at runtime. Record this evidence
   separately from queue status: a static work item becoming `done` does not
   close a reported behavior defect, and an empty static queue does not prove
   runtime, native, media, timing, or pixel parity.

For a long session, an agent may run the optional service:

```bash
project-parity serve LOCAL_DIR UPSTREAM_DIR \
  --out LOCAL_DIR/.parity/report \
  --state LOCAL_DIR/.parity/state.sqlite
```

Use `--mcp` only when the host explicitly needs the stdio MCP transport.

## Trust rules

- `right`/upstream is authoritative and read-only; `left`/local is editable.
- `proven-structure` proves normalized AST/binding structure, not runtime,
  native, asset, timing, media, or pixel equivalence.
- Improve throughput by reducing repeated full syncs and redundant evidence
  reads, not by lowering match thresholds, suppressing candidate classes, or
  declaring ambiguous work complete. Any matcher/corpus change must add a
  regression fixture for the triggering false positive and a nearby true
  divergence that must remain visible.
- Ambiguous, candidate, missing, changed, and dependency-only evidence stays
  in the queue until reviewed; never mark it resolved by filename similarity.
- The generated queue is a candidate index, not an exhaustive behavioral
  oracle. User-observed failures and important runtime scenarios remain
  first-class audit inputs even when static matching does not surface them.
- If input hashes change unexpectedly, re-audit the affected chain.
- Finish only when no unresolved P0/P1 work remains, parse failures are handled,
  and the required runtime checks have passed.

See `references/evidence-boundaries.md` for the proof boundary and
`references/report-schema.md` when direct artifact inspection is necessary.
