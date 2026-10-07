# 0014. Store local data in XDG base directories

- Status: Accepted
- Date: 2026-10-07

## Context

The cache (ADR 0013) needs a home on disk. The user prefers the XDG Base
Directory layout (`~/.config`, `~/.cache`, `~/.local`) over macOS's
`~/Library` conventions.

## Decision

- Cache: `$XDG_CACHE_HOME/tp-imap-mcp/` if `XDG_CACHE_HOME` is set and
  absolute, otherwise `$HOME/.cache/tp-imap-mcp/`. One file per account:
  `<account>.sqlite3` (account name lower-cased). Directory mode 0700, files
  0600.
- Config: `$XDG_CONFIG_HOME/tp-imap-mcp/` (default `~/.config/tp-imap-mcp/`)
  is reserved for future non-secret settings; nothing is read from it yet.
- State: `$XDG_STATE_HOME/tp-imap-mcp/` (default `~/.local/state/tp-imap-mcp/`)
  is reserved; nothing is written to it yet.
- If neither `XDG_CACHE_HOME` nor `HOME` is usable, caching is disabled with a
  stderr warning.

## Consequences

- Cache data is where XDG-aware tools and backups expect it, and is easy to
  find and delete.
- Same layout on macOS and Linux.
