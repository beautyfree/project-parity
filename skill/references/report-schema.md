# Report artifacts

- `report.json`: summary, source hashes, correspondences, failures, and graph summaries.
- `llm-manifest.json`: machine-readable entry point and trust/evidence contract.
- `llm-work-items.jsonl`: complete actionable queue with stable ids.
- `llm-batches.jsonl`: bounded priority routing index.
- `semantic-graph.jsonl.zst`: lossless nodes and typed edges for both inputs.
- `upstream-semantic-ledger.jsonl.zst` and `upstream-semantic-edge-ledger.jsonl.zst`: completeness ledgers for the authoritative side.
- `report.html`: interactive system, overlay, and source inspectors.

Use the CLI inspectors instead of parsing large compressed artifacts in an LLM
context window.
