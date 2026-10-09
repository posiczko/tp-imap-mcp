# TODO

- [ ] **Confirm OAuth live (Microsoft):** loopback
  registration (`http://127.0.0.1`, root path) per spec §9 — Entra may need it
  added via the app manifest (`replyUrlsWithType`).

### From the OAuth review (2026-10-07)

- [ ] **Remaining secret copies are not zeroed** (arena-held parsed token,
  std.http and libetpan buffers). Cosmetic; note or zero what we own.

## Mailbox organization (review, 2026-10-08)

- [ ] **Gmail manual check pending** (labels, Trash, All Mail).

## Done (2026-10-09 XOAUTH2 login path)

- [x] An access token the server rejects after the forced refresh is forgotten, not reused on the next call.
- [x] Every login failure (password or XOAUTH2, first or retried attempt) sets an account diag: rejection with the server's text, "connection lost during …", unparseable response, other errors by name.
- [x] Offline tests for refresh-and-retry, the second rejection, and a lost connection: the fake IMAP server now handles LOGIN and AUTHENTICATE XOAUTH2 (`accepted_token`).

## Done (2026-10-09 Gmail live check)

- [x] Gmail XOAUTH2 confirmed live (runbook steps 6–7; `itest` 0 failures).
- [x] `search` failed on Gmail with `BAD Could not parse command`: libetpan's `mailimap_custom_command` appends a space after the command text. `tpi_uid_search` now sends the command itself; offline tests check the exact bytes.

## Done (2026-10-08 OAuth hardening)

- [x] The `auth` listener reads each request line with a 10 s poll-based deadline: a client that connects and sends nothing (or stops mid-line) cannot stall the flow.
- [x] An `error=` redirect counts only with the matching `state`; transient `accept` errors (aborted connection) keep the flow waiting.
- [x] Token endpoint responses are read into a 64 KiB buffer (zeroed after use); a larger one fails the request.
- [x] A failed authorization shows "Authorization failed. Return to the terminal" (HTTP 400), not "Authorization received".
- [x] `auth` and the Gmail runbook no longer suggest `op item edit … field=<token>`; they say to pipe to `pbcopy` and paste into the 1Password app.
- [x] PKCE verifier and `state` use `io.randomSecure`; `auth` stops if no secure source is available.

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
- [x] COPYUID order: not a bug. RFC 4315 §3 says "12:10 is exactly equivalent to 10:12 and refers to the sequence 10,11,12"; copy order is the order of the ranges, which `uidMap` keeps. Pinned by a test and cited in `organize.expand`.
- [x] itest: no unguarded `.?` on result fields (`uid_map`, `PATH`, triage fields); refusal checks assert the reason (`already exists`, `is not empty`, `is protected`, `plan_hash does not match`); README gives the `--organize` PASS count.
- [x] Folder arguments (`name`, `directory`) are checked for NUL and UTF-8 before the fresh LIST, so a malformed call costs no server round trip.
- [x] `forgetMoved` test: a mismatched UIDVALIDITY or mailbox deletes nothing; the matching generation loses exactly the moved UIDs.
- [x] A dropped connection during a change that is not retried (create/rename/delete/move/copy) marks the cached folder list stale; `mailboxesChanged`'s success path has a unit test.
- [x] Fake-session seam: `src/imap/fake.zig` (in-memory IMAP server, test builds only) behind `Session`/`Registry.fake`; handler tests for the COPY+EXPUNGE fallback move, refused moves and dry runs, `create_missing`, rename with subfolders, delete refusal, bulk status.
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

