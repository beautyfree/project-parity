# LLM loop reference

The durable loop is:

`init → next task → show-work → inspect evidence → patch local → tests/runtime gate → init`

`init` is intentionally the single public resync command: it regenerates the
report and synchronizes the SQLite queue in one step.

Use batches for routing and the lossless semantic ledgers for completeness.
Keep the upstream/right input immutable. Prefer a coherent owner-chain patch
over isolated line edits when an import, caller, scope, or dependency contract
crosses file boundaries.
