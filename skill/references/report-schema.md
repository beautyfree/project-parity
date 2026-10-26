# Report artifacts

- `report.json`: summary, source hashes, correspondences, failures, and graph summaries.
- `llm-manifest.json`: machine-readable entry point and trust/evidence contract.
- `llm-work-items.jsonl`: complete actionable queue with stable ids.
- `llm-shared-evidence.jsonl`: SHA256-addressed large candidate arrays referenced
  by queue records. CLI inspectors expand `upstreamEvidenceRef` and exact
  `inspectNodeIdsFromOwners` sequences before presenting evidence. State
  synchronization compares expanded payloads to preserve review decisions.
- `llm-batches.jsonl`: bounded priority routing index.
- `semantic-graph.jsonl.zst`: lossless nodes and typed edges for both inputs.
- `upstream-semantic-ledger.jsonl.zst` and `upstream-semantic-edge-ledger.jsonl.zst`: completeness ledgers for the authoritative side.
- `report.html`: interactive system, overlay, and source inspectors.

Use the CLI inspectors instead of parsing large compressed artifacts in an LLM
context window.

Group candidate scores use feature occurrence counts, saturating explained
counts at the target count. Every member must add necessary material evidence
(properties, literals, or operators); targets without these channels require
necessary structural evidence. Rejecting a group leaves individual candidate
and ambiguity evidence available. A group remains a candidate, not behavioral
parity proof. Engine v50 requires a fresh sync before queue review.

Graph feature recording closes AST owners in release as well as debug builds.
Index cache v33 invalidates earlier records whose feature tokens could include
later sibling syntax. Group acceptance also requires a better combined score
than every individual member, before applying singleton acceptance thresholds.

Index cache v34 traverses erased TypeScript wrappers and parentheses through
their runtime expression before recording ordered graph features. Type-only
annotations and parameters do not create runtime reference occurrences;
explicit type import/export contracts remain available. Equal neighbor scores
do not establish a correspondence, even at 1.0. Unresolved identical runtime
shapes are ambiguity evidence rather than changed-branch evidence.

Owner multiplicity in the complete strict/linked index prevents mutual-best
fuzzy promotion. A bounded candidate shortlist cannot make an already
ambiguous owner unique; its ranked suggestions remain available for inspection.

Index cache v35 projects ordinary variable-declaration statements onto their
individual declarators, retaining source-order edges and exact symbol-definition
links. Grouped and separate declarations therefore expose the same initializer
owners. Changed initializer expressions remain divergence evidence; declarations
inside loop headers retain their enclosing statement representation.
Exported variable declarations also retain their export wrapper representation.
Declarator identity alone does not certify declaration-kind equivalence.

Index cache v36 records await, optional-call, and async/generator function
modifiers in the existing operator and ordered feature channels. These
observable protocols must not appear as an inactive operator channel when
ranking otherwise similar owners. Rejected fuzzy correspondences remain
reviewable candidates; downlevel transformations require separate evidence.
Optional member access and the near-exact operator relaxation retain their
existing boundaries; this projection is not a protocol-equivalence certificate.

Engine v52 settles exact/binding graph paths before deferred fuzzy neighbors.
`neighbor-binding-owner` records a unique reciprocal `Defines` declaration
from paired symbols; it establishes candidate owner identity, not initializer
equivalence. A conflicting fuzzy declaration route cannot claim either endpoint.
Unproven initializer structure remains `ambiguous-correspondence` evidence with
both declaration locators, including real initializer changes. This prevents
false missing declarations and false changed labels caused by bundled syntax
without certifying equivalence. Resync v51 reports before queue decisions.

Engine v53 also retains declared installed-package root entrypoint candidates
outside a heuristically selected dist/lib/build directory. It reuses package
main/exports resolution, including its conditional-candidate boundaries. A
native-only build directory cannot hide a JavaScript entrypoint.

Engine v58 keeps graph-only installed-dependency hints in
`dependencyCandidateEvidence` on executable and semantic ledger records. This
includes exact linked graph-node hashes, semantic-neighborhood hashes and
normalized graph scores, even a unique score of 1.0. The hint preserves its
package/source locator and candidate confidence; it cannot change the node's
disposition or remove its normal work-item route, and it is not counted as
dependency-covered evidence. Complete owner-unit and separately supplied legacy
certificates retain their existing routes; this change does not certify their
free bindings or solve all dependency ownership. Engine v57 also removed
Contains ancestor/descendant inheritance. Both require a compatible fresh report
before adoption; the source cache is v38 so cached ASTs are rebuilt with the
execution-feature events introduced in v63.

`dependencyCoveredNodes` counts retained per-node owner evidence only. An empty
owner-evidence map reports zero even if dependency files or graph hints exist;
`dependencyFiles` continues to report the separate package-source inventory.
