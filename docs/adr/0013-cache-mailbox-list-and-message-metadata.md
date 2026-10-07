# 0013. Cache the mailbox list and message headers and sizes

- Status: Accepted
- Date: 2026-10-07

## Context

`list_mailboxes` and drafts discovery issue `LIST` every time; the user's
account has 723 mailboxes. Header and size fetches repeat for the same
messages across a conversation. Three scopes were considered:

- A. Mailbox list only.
- B. Mailbox list plus message headers and sizes, keyed by (mailbox,
  UIDVALIDITY, UID).
- C. B plus message bodies.

Headers and sizes never change for a given (mailbox, UIDVALIDITY, UID), so
they can be cached without staleness. Flags change and must stay live. Bodies
are the most sensitive data and the largest.

## Decision

Scope B.

- **Mailbox list:** the cached full `LIST "" "*"` result answers
  `list_mailboxes` (matched locally against `directory` + `pattern` per RFC
  3501 wildcards) and drafts discovery. It is refreshed when older than
  `TP_IMAP_MCP_MAILBOX_TTL` seconds (default 3600), when `list_mailboxes` is
  called with `refresh: true`, or on the next call after the server rejects a
  command (e.g. a mailbox that no longer exists).
- **Messages:** `get_header`, `get_header_field`, and `get_size` serve cached
  rows. Misses are fetched together (`BODY.PEEK[HEADER] RFC822.SIZE`) and
  stored. A changed UIDVALIDITY (learned from `EXAMINE`) deletes that mailbox's
  rows.
- **Always live:** `search`, `mailboxes_status`, flags, bodies, write tools.
- **No size limit.** A `clear_cache(account)` tool deletes an account's rows;
  deleting the cache file is always safe. `TP_IMAP_MCP_CACHE=0` disables
  caching.
- **Failures never fail a tool call:** a cache error is logged to stderr and
  that account continues uncached; a corrupt file is rebuilt once.

## Consequences

- Fewer round trips for repeated listing and header reads.
- Subjects and addresses are stored on disk (permissions 0600 in the XDG cache
  directory, ADR 0014).
- Mailboxes created elsewhere may be invisible for up to the TTL unless the
  model refreshes.
- Bodies are not cached; adding them later would be a new decision (with a
  size cap).
