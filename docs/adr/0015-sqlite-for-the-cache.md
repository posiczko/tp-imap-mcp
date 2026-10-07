# 0015. Use SQLite (system libsqlite3) for the cache

- Status: Accepted
- Date: 2026-10-07

## Context

The cache (ADR 0013) holds the mailbox list and per-message headers and sizes.
It must survive interrupted writes, support lookups by (mailbox, UIDVALIDITY,
UID), and be safe if two server processes share it. Options evaluated on
2026-10-07:

| Option | Zig 0.17 | Notes |
|---|---|---|
| SQLite via own C bindings | n/a | `libsqlite3` ships with macOS (SDK `libsqlite3.tbd`); Homebrew has 3.53.4 |
| `vrischmann/zig-sqlite` | Likely broken | 622 stars, but `minimum_zig_version = 0.14.0` and uses `@cImport`; downloads its own SQLite |
| `nDimensional/zig-sqlite` | Targets 0.17 | 52 stars, v0.5.0 this week; new Zig package dependency, downloads SQLite |
| `canvasxyz/zig-lmdb` | 0.17 support added 2026-10-02 | Fast key-value store; needs our own record format, no queries, harder to inspect |
| Plain JSON files | std only | Whole-file rewrites; slow for large mailboxes; not transactional |

## Decision

Use SQLite through hand-written `extern fn` declarations (ADR 0004 pattern),
linking the system library with `linkSystemLibrary("sqlite3", .{})` (resolves
to `-lsqlite3`, satisfied by the macOS SDK). Open each cache in WAL mode with a
5-second busy timeout. Schema versioned with `PRAGMA user_version`; a mismatched
version is dropped and rebuilt (it is only a cache).

## Consequences

- No Zig package dependency and nothing new to install.
- Transactional writes; inspectable with the `sqlite3` CLI; indexed lookups
  leave room for later features (e.g. `Message-ID` lookups for threading).
- The extern declarations for the SQLite calls used must be maintained by hand.
- Relies on the OS-provided SQLite version; acceptable for a cache.
