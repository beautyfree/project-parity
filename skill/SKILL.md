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

## Repair loop

Repeat until the queue is empty:

1. Read the next task from `LOCAL_DIR/.parity/state.sqlite`.
2. Load its complete evidence with `show-work`, then inspect the listed units
   and graph edges when the task is ambiguous or crosses file boundaries.
3. Compare the full upstream owner chain: imports, exports, scopes, callers,
   dependencies, and package provenance. A name or score is only a locator.
4. Patch only the local project. Never edit the upstream tree or copy a
   low-confidence candidate without understanding its contract.
5. Run the relevant tests/runtime checks, then run:
   `project-parity sync`. The saved project config supplies both roots; the
   explicit `sync LOCAL_DIR UPSTREAM_DIR` form remains available. The state
   queue is updated automatically and resolved items disappear.

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
- Ambiguous, candidate, missing, changed, and dependency-only evidence stays
  in the queue until reviewed; never mark it resolved by filename similarity.
- If input hashes change unexpectedly, re-audit the affected chain.
- Finish only when no unresolved P0/P1 work remains, parse failures are handled,
  and the required runtime checks have passed.

See `references/evidence-boundaries.md` for the proof boundary and
`references/report-schema.md` when direct artifact inspection is necessary.
