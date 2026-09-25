# LLM loop reference

The durable loop is:

`init once → next routing slice (100 IDs) → load complete evidence per item/batch → inspect owner chain → patch local → tests/runtime gate → pendingSync batch`

`init` is the one-time project setup. `sync` is the short public resync command:
it regenerates the report and synchronizes the SQLite queue in one step.
When run from the local project directory, both roots are remembered in
`.parity/config.json`, so no absolute paths are needed after initialization.

Use batches for routing and the lossless semantic ledgers for completeness.
Use `state-next STATE_DB 100` to minimize prompt payload (routing is the CLI
default; `--full` opts into the potentially huge legacy response); it contains
only compact queue locators, grouped by shared batch and source files.
Each ID appears once in `items`; `reviewGroups` holds indexes into that array
instead of repeating IDs. `ownerGroups` joins items whose LOCAL owner-file sets
overlap, including transitively; use these as indivisible worker/review
partitions. `upstreamGroups` joins items whose read-only upstream owner files
overlap, allowing owner context to be reused and ownerless LOCAL locators to be
routed. `ownerlessItemIndexes` must not be silently dropped. These are routing
hints, never shared verdicts. Avoid `--summary` in
the normal loop: it adds owner/file locators that are normally available in the
complete batch evidence.
Add it only when those locators help choose the next evidence group. This
routing output is not evidence and cannot justify a done/skip decision. Load
each selected item's complete proof with `show-work` or shared context with
`show-batch`. For high-ambiguity batches, use `show-batch ... --compact` to
deduplicate repeated upstream owners without dropping evidence; reconstruct
each item from `sharedFields` and `inspectNodeIdTable` before making its
independent verdict.
Keep the upstream/right input immutable. Prefer a coherent owner-chain patch
over isolated line edits when an import, caller, scope, or dependency contract
crosses file boundaries. Accumulate up to 1,000 individually reviewed items
before one serialized sync; if fewer remain, sync once at the end. Never mark
unseen work merely to reach the batch threshold. This reduces repeated full
analysis while preserving the payload-hash check that reopens changed items.
The `state-done-batch` response includes the cumulative `pendingSync` count, so
the next sync checkpoint is visible without a separate `state-stats` call.

When multi-agent execution is available, parallelize disjoint LOCAL owner/file
partitions from the current slice (keep overlapping owners together; use a few
workers, not one per item). Give each worker its exact IDs and complete proofs.
Workers may patch only their assigned LOCAL files and report per-ID evidence;
the parent integrates/reviews and alone updates queue state or runs sync. If
file ownership overlaps or cannot be established, review serially. Parallel
work never relaxes proof or validation requirements.
