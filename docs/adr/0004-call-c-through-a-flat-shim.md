# 0004. Call C libraries through a flat C shim and hand-written externs

- Status: Accepted
- Date: 2026-10-07

## Context

Zig 0.17 removed `@cImport`/`@cInclude`; C headers are now translated in
`build.zig` by the external `translate-c` package. That would be a new Zig
package dependency, and libetpan's `clist` iteration macros
(`clist_begin`, `clist_next`, `clist_content`) do not translate well, so C
helpers would be needed anyway.

Verified in a scratch project: a C file compiled with
`module.addCSourceFiles`, linked with `linkSystemLibrary("etpan")`, and called
from Zig via `extern fn` declarations builds and runs on Zig 0.17.

## Decision

Keep all walking of libetpan structures in C (`src/c/session.c`,
`src/c/mime.c`) behind a small flat API (`src/c/tpi.h`: about 15 functions
taking and returning plain C types and malloc'd buffers). Zig declares those
functions by hand in `src/imap/c.zig`. `src/imap/session.zig` copies every
result into arena memory and frees the C buffers immediately, so no C types
leak further into the Zig code. C sources compile with
`-std=c11 -Wall -Wextra -Werror`.

## Consequences

- No new Zig dependency; libetpan's macros and types are used natively in C.
- `src/c/tpi.h` and `src/imap/c.zig` must be kept in sync by hand; a mismatch
  is an ABI bug the compiler cannot catch.
- About 600 lines of C to maintain, tested through the Zig layer (fixtures and
  live integration checks).
- The same pattern applies to any later C dependency (see ADR 0015).
