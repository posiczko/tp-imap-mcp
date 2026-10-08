# TODO

- [ ] **Confirm OAuth live:** Gmail via the runbook; Microsoft loopback
  registration (`http://127.0.0.1`, root path) per spec §9 — Entra may need it
  added via the app manifest (`replyUrlsWithType`).

### From the OAuth review (2026-10-07)

- [ ] **`auth` listener can hang past 5 minutes** if a local client connects
  and sends nothing (`flow.awaitCallback` reads without a timeout). *Fix:*
  receive timeout on the accepted socket.
- [ ] **`error=` aborts the flow without a `state` check**, and a transient
  `accept` error aborts it too. *Fix:* honor `error=` only with the matching
  `state`; ignore transient accept errors.
- [ ] **A rejected access token stays cached** after the final failed login,
  costing an extra login attempt per later call. *Fix:* forget it on the
  second failure.
- [ ] **Non-rejection failures on the first XOAUTH2 attempt** (e.g. connection
  lost) carry no account diagnostic. *Fix:* `setDiag` on every failure path.
- [ ] **Remaining secret copies are not zeroed** (arena-held parsed token,
  std.http and libetpan buffers). Cosmetic; note or zero what we own.
- [ ] **Token response bodies are unbounded.** *Fix:* cap at 64 KiB.
- [ ] **The browser shows "Authorization received" for failures too.** *Fix:*
  separate failure page.
- [ ] **The suggested `op item edit … field=<token>` puts the token in shell
  history and argv.** *Fix:* document a safer entry method.
- [ ] **PKCE/state use `io.random`**; `io.randomSecure` fails closed. Nit.
- [ ] **No offline test for the refresh-and-retry login path** (needs a fake
  IMAP server); covered only by the live OAuth check.

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

