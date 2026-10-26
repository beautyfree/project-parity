# Constructor runtime roles regression fixture

`local.ts` contains a constructor whose empty source body still initializes two
parameter properties. `upstream.js` contains the explicit emitted equivalent,
its argument-renamed equivalent, and same-arity empty XML hooks, ordinary
methods and a constructor that discards both arguments. `changed-upstream.js`
contains swapped values, a missing assignment and reversed write order.
`DifferentFields` exposes why original TS parameter-property names cannot be
lost during canonical binding renaming: its consumer returns the same values,
but its own property names differ.

The standalone runtime proof transforms the TS fixture with
`module.stripTypeScriptTypes({ mode: "transform" })`, then executes all three
fixture modules without mocks or dependencies. It checks consuming methods,
property descriptors/order, argument reference identity, signed zero, method
constructability and finite negative witnesses. Class and parameter-renaming
positive controls retain behavior; type-only annotation erasure is also checked
against the explicit JS constructor.

These fixtures demonstrate source/runtime counterexamples. They do not run the
Rust matcher, reproduce its actual hashes, implement TS lowering in that matcher,
or establish application parity.
