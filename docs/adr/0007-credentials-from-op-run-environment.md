# 0007. Take credentials from the environment, injected by `op run`

- Status: Accepted
- Date: 2026-10-07

## Context

Credentials live in 1Password. The `op` CLI's `op run --env-file <file> -- <cmd>`
resolves `op://vault/item/field` references into environment variables for
the child process only, so secrets never sit on disk in plaintext.

## Decision

Configure accounts entirely through environment variables:

```
IMAP_ACCOUNTS=tetra,work
IMAP_<NAME>_HOST, IMAP_<NAME>_LOGIN, IMAP_<NAME>_PASSWORD   (required)
IMAP_<NAME>_PORT (default 993), IMAP_<NAME>_READONLY, IMAP_<NAME>_DRAFTS (optional)
```

`<NAME>` is the upper-cased account name (`[A-Za-z0-9_]+`). The MCP client
launches `op run --env-file imap.env -- tp_imap_mcp`. The real `imap.env`
(holding only `op://` references) is git-ignored; `imap.env.example` is
committed. Invalid configuration stops startup with a message naming the
variable, never its value. Passwords are zeroed on shutdown and never logged.

## Consequences

- No secrets in files, flags, or the repository.
- Every launch requires an unlocked 1Password session (or `op` service account).
- Values are still visible to the process environment for its lifetime; that is
  inherent to environment injection.
- Non-secret settings could later move to `$XDG_CONFIG_HOME` (see ADR 0014)
  without changing how secrets are supplied.

## Amendment (2026-10-09): `op run` optional

Configuration is still environment variables only, but they no longer have to
come from `op run`. The documented default loads a plain `imap.env` (mode
`0600`, values single-quoted where needed) with
`sh -c 'set -a; . imap.env; exec tp_imap_mcp'`; `op run --env-file imap.env`
with `op://` references is the documented alternative for keeping secrets off
disk. The same file works for both (`op run` strips the quotes and resolves
quoted references). With plain values, "no secrets in files" no longer holds:
the file is private to the user, not secret-free. The server itself is
unchanged: it never reads a file for credentials.
