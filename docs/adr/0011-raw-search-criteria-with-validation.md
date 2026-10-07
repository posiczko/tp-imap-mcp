# 0011. Pass search criteria through raw, and validate all inputs

- Status: Accepted
- Date: 2026-10-07

## Context

The reference's `search` sends the model-written criteria string straight to
the server, which lets the model use the full IMAP SEARCH grammar (OR, NOT,
grouping, HEADER, X-GM-LABELS). libetpan's typed `mailimap_uid_search` wants a
structured key tree; `mailimap_custom_command` sends a raw command (verified
against Dovecot). Sending model input verbatim allows command smuggling: a
criteria string containing CRLF could end the SEARCH and start a `DELETE`,
also bypassing read-only accounts.

## Decision

Send `UID SEARCH CHARSET UTF-8 <criteria>` via `mailimap_custom_command`, and
validate before anything reaches the server:

- `criteria`: reject CR, LF, NUL.
- `uids`: non-empty; decimal strings 1..4294967295 only.
- `keywords`: system flags (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`,
  `\Draft`) or IMAP atoms.
- `field`: header-name characters only.
- Mailbox names: reject NUL; they go through libetpan's typed calls, which
  quote them.

## Consequences

- Full search expressiveness with no criteria parser to maintain.
- Server error text (e.g. "Unknown argument BOGUSKEY") is passed to the model so
  it can correct its query.
- Validation is security-critical code with dedicated tests.
