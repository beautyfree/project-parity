# Hook correspondence regression

This synthetic pair contains two nearby reference-hook declarations and one
action-runner declaration. The bundled form uses `(0, H.hook)` calls while the
local form uses direct calls. It exercises a graph route where structural
neighbors could incorrectly connect the local runner to a reference hook.

The regression requires declaration identity to retain the corresponding ref
owner, while the runner stays matched or reviewable through its own route. A
neighboring test changes the local ref initializer from `null` to `true` and
requires that divergence to remain visible. Source-derived locators keep the
fixture independent of byte offsets and application source trees.
