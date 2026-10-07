# TODO

No open items. Everything deferred from the code reviews is done (below);
add new items here as they come up.

## Done (2026-10-07 cleanup)

- [x] `create_message` is not retried after a lost connection (no duplicate drafts).
- [x] `Registry.init` requires the active filters (filtering cannot be silently off).
- [x] Mailbox names cleaned by `list_mailboxes` resolve back to the real name (fresh cache).
- [x] Cached headers for expunged messages are pruned (`UID SEARCH UID …` before serving hits).
- [x] An empty RFC 2047 decode falls back to the raw value.
- [x] `x-tp-imap-mcp-*` headers from messages are dropped (no marker spoofing).
- [x] Withheld entries bypass the response budget.
- [x] Server text with invalid UTF-8 keeps its content in diagnostics (U+FFFD).
- [x] Regex/contains/glob patterns containing NUL are rejected in `filters.zon`.
- [x] `noembed`, `noframes`, `datalist`, closed `dialog` are dropped.
- [x] Embedded NUL after charset conversion no longer truncates a body (`charconv_buffer`).
- [x] Password-wipe promise reworded to what is achievable (spec §4, README).
- [x] Search criteria ending in an IMAP literal marker (`{N}`, `{N+}`) are rejected.
- [x] A cache found corrupt during use is deleted (with `-wal`/`-shm`) so the next start rebuilds it; startup rebuild also removes `-wal`/`-shm`.
- [x] The response budget counts JSON-escaped bytes.
- [x] `</` followed by a non-letter is treated as a bogus comment.
- [x] Link targets with whitespace/control characters or over 2048 bytes are dropped.
- [x] Self-closing raw-text elements (`<svg/>`) and implicit `</p>` handled.
- [x] Entity-encoded markup renders as inert literal text (asserted by a test).

