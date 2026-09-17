# Evidence boundaries

`proven-structure` establishes normalized Oxc AST/binding equivalence. It does
not establish behavior outside the parsed JavaScript/TypeScript graph. Native
IPC, browser APIs, filesystem/network effects, timing, media, assets, runtime
bundler behavior, and pixels require their own validation. A CodeGraph import
can help locate callers but cannot override a missing or changed Oxc edge.
