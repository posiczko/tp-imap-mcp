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

## Mailbox organization (review, 2026-10-08)

- [ ] **COPYUID reversed ranges are expanded ascending**; RFC 4315 pairs them
  in copy order.
- [ ] **`forgetMoved` is not tested with a mismatched uidvalidity**;
  `mailboxesChanged`'s success path is covered only live.
- [ ] **create/rename/delete don't mark the mailbox list stale after
  `ConnectionLost`.**
- [ ] **`directory`/`name` are validated only after the fresh LIST.**
- [ ] **No fake-session seam:** handler paths (fallback move, rename child
  mapping, delete refusal) lack unit tests.
- [ ] **itest:** `.?` on `uid_map`/`PATH`; refusal checks don't assert the
  reason; the README PASS count doesn't mention `--organize`.
- [ ] **Gmail manual check pending** (labels, Trash, All Mail).

## Done (2026-10-08 mailbox quick fixes)

- [x] `mailboxName` test covers DEL (0x7f).
- [x] `targetReason` assumes Gmail's `/` when no delimiter is known, so `[Gmail]/X` is refused.
- [x] `isBelow` matches INBOX children in any case.
- [x] `organize` tests: `\NonExistent`, `specialUse` case, `batchCount(0)`, a COPYUID range ending at u32 max.
- [x] A dry run matching more than 5000 messages warns in its note that the real call will be refused.
- [x] A move dry run checks MOVE/UIDPLUS and is refused like the real call.
- [x] STORE uses `+FLAGS.SILENT` / `-FLAGS.SILENT` (callers re-fetch flags).
- [x] `create_missing` creates the destination only when something matches; the note says so otherwise.
- [x] `delete_mailbox` description notes that on Gmail it removes the label.
- [x] `mailboxes_status` takes an optional LIST `pattern`: STATUS for up to 200 matching folders in one call (auditing 184 folders had taken ~600 calls).
- [x] Audit log of every tool call in `~/.local/state/tp-imap-mcp/audit.log` (ADR 0023); 26 folders had vanished and the server could not show what it had done.
- [x] `list_mailboxes` leaves out `\HasChildren`/`\HasNoChildren`/`\Marked`/`\Unmarked` and empty `FLAGS` (596 folders: 54 KB → ~30 KB).
- [x] `organize_mailbox` snippets are 200 characters and the default `limit` is 30 (57 KB → ~35 KB at the old default).
- [x] Move/copy results list at most 100 `uid_map` pairs; `uid_map_omitted` counts the rest (a 4,746-message move returned 134 KB).

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

