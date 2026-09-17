# LLM loop reference

The durable loop is:

`analyze → state-sync → state-next → show-work → inspect/graph-node → patch → tests/runtime gate → analyze → state-sync`

Use batches for routing and the lossless semantic ledgers for completeness.
Keep the upstream/right input immutable. Prefer a coherent owner-chain patch
over isolated line edits when an import, caller, scope, or dependency contract
crosses file boundaries.
