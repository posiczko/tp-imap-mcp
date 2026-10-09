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
- The folder and move/copy tools added later follow the same read-only
  switch; their own safeguards are in [ADR 0021](0021-mailbox-organization-tools.md).

## Amendment (2026-10-09): read-only by default

The switch is inverted: every account is read-only unless
`IMAP_<NAME>_READONLY` is set to `0`/`false`/`no`. An unset or empty value
means read-only; `1`/`true`/`yes` stays valid (read-only); anything else still
stops startup. Since the folder and move/copy tools (ADR 0021) and
`apply_organization` (ADR 0022) can rearrange a whole mailbox, write access is
now something the user opts into per account rather than out of.

- The refusal names the switch: `account "x" is read-only; set
  IMAP_X_READONLY=0 to allow changes`.
- The startup line lists the read/write accounts (`read/write: none` when
  there are none), so a forgotten switch is visible at launch.
- `itest --write` / `--organize` stop early on a read-only account.
- Breaking for existing configurations: an account that relied on the old
  default (writable) becomes read-only until `IMAP_<NAME>_READONLY=0` is
  added.
