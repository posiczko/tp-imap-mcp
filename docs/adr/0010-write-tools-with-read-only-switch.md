# 0010. Keep the write tools, with a per-account read-only switch

- Status: Accepted
- Date: 2026-10-07

## Context

The reference has two state-changing tools: `change_keywords` (`UID STORE`)
and `create_message` (`APPEND` to a hard-coded `Drafts`). With several
accounts, some may need to be strictly hands-off, and the drafts folder name
differs between servers (`Drafts`, `INBOX.Drafts`, `[Gmail]/Drafts`).

## Decision

Keep both tools. `IMAP_<NAME>_READONLY=1` makes them return a tool error
without contacting the server. Read tools always open mailboxes with `EXAMINE`
and fetch with `BODY.PEEK`, so they never set `\Seen`; only `change_keywords`
uses `SELECT`. The drafts folder is `IMAP_<NAME>_DRAFTS` if set, otherwise the
mailbox flagged `\Drafts` (RFC 6154), otherwise `Drafts`.

## Consequences

- Full parity with the reference, plus a safety switch.
- The read-only guarantee depends on input validation (ADR 0011): a smuggled
  command in `criteria` would otherwise bypass it.
- `create_message` works across servers without per-server code.
