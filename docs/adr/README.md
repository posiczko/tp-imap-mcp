# Architecture Decision Records

New ADRs: copy [template.md](template.md), take the next number, and add a line
here. Superseded ADRs stay, marked "Superseded by NNNN".

| # | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-use-libetpan-for-imap-and-mime.md) | Use libetpan for IMAP and MIME | Accepted |
| [0003](0003-link-libetpan-from-homebrew.md) | Link libetpan from Homebrew via pkg-config | Accepted |
| [0004](0004-call-c-through-a-flat-shim.md) | Call C libraries through a flat C shim and hand-written externs | Accepted |
| [0005](0005-hand-written-mcp-over-stdio.md) | Implement MCP by hand over stdio | Accepted |
| [0006](0006-one-process-many-accounts.md) | Serve multiple accounts from one process | Accepted |
| [0007](0007-credentials-from-op-run-environment.md) | Take credentials from the environment, injected by `op run` | Accepted |
| [0008](0008-password-login-over-implicit-tls.md) | Authenticate with password LOGIN over implicit TLS only | Accepted (password-only superseded by 0020) |
| [0009](0009-defer-pgp-decryption.md) | Defer PGP/MIME decryption | Accepted |
| [0010](0010-write-tools-with-read-only-switch.md) | Keep the write tools, with a per-account read-only switch | Accepted |
| [0011](0011-raw-search-criteria-with-validation.md) | Pass search criteria through raw, and validate all inputs | Accepted |
| [0012](0012-parity-and-deliberate-deviations.md) | Match the reference's behavior, with listed deviations | Accepted (raw headers superseded by 0019) |
| [0013](0013-cache-mailbox-list-and-message-metadata.md) | Cache the mailbox list and message headers and sizes | Accepted |
| [0014](0014-xdg-base-directories.md) | Store local data in XDG base directories | Accepted |
| [0015](0015-sqlite-for-the-cache.md) | Use SQLite (system libsqlite3) for the cache | Accepted |
| [0016](0016-verify-server-tls-certificates.md) | Verify server TLS certificates (chain, SNI, host name) | Accepted |
| [0017](0017-sensitive-content-filters.md) | Withhold sensitive messages with header-based filters | Accepted |
| [0018](0018-sanitize-model-bound-output.md) | Sanitize all model-bound output | Accepted |
| [0019](0019-decoded-sanitized-header-values.md) | Return header values decoded and sanitized | Accepted |
| [0020](0020-xoauth2-with-refresh-tokens-in-1password.md) | Support XOAUTH2 with refresh tokens kept in 1Password | Accepted |
| [0021](0021-mailbox-organization-tools.md) | Add folder and move/copy tools with safe moves, protected folders and dry runs | Accepted |
| [0022](0022-organize-mailbox-two-phase-plan.md) | Organize a mailbox as a model-classified, server-validated two-phase plan | Accepted |
