# 0017. Withhold sensitive messages with header-based filters

- Status: Accepted
- Date: 2026-10-07

## Context

Some emails should never reach the model, starting with password-reset
messages (they can carry reset links or codes). The user wants the system not
to download such emails, wants the mechanism composable so more categories can
be added, and asked whether matching should be a regex.

Constraints and findings:

- Deciding "is this a password reset?" without downloading the body leaves
  only the headers. Headers are already fetched and cached (ADR 0013).
- Subjects are often RFC 2047 encoded (`=?UTF-8?B?...?=`); matching raw values
  would miss them. libetpan provides `mailmime_encoded_phrase_parse`.
- Zig's standard library has no regex engine. macOS libc provides POSIX
  `regcomp`/`regexec` with `REG_EXTENDED | REG_ICASE | REG_NOSUB`, usable through
  the existing C-shim pattern (ADR 0004) with no new dependency.
- Most useful rules are plain keyword or address matches that are easier to
  write correctly as substring or glob than as regex.

Options considered for a matched message: (A) withhold content but show the
message exists; (B) hide it entirely, including from `search`; (C) per-filter
choice. Options for configuration: (A) built-ins plus an optional config file;
(B) config file only; (C) environment variables only. Options for matchers:
(A) `contains` + `glob` + `regex`; (B) defer regex; (C) regex only.

## Decision

- **Header-only classification.** Filters see decoded header values only;
  bodies are never fetched to decide, and never fetched for matched messages.
- **Withhold, don't hide (A).** `search` and metadata tools are unchanged;
  `get_text`/`get_html` return `[withheld by filter "<name>"]`; `get_header`
  keeps only `date` and `from` plus a marker header; `get_header_field`
  withholds every field except `date`/`from`. `Subject` is withheld because it
  can carry the secret.
- **Composable model.** Named filters → rules (any matches) → conditions (all
  hold) → one matcher kind with a list of patterns (any matches).
- **Matchers (A):** case-insensitive `contains`; case-insensitive `glob` with
  address extraction; POSIX `regex` from libc, compiled once at startup.
- **Configuration (A):** built-in `password_reset` (subject contains reset
  phrases), **active by default**; user filters in
  `$XDG_CONFIG_HOME/tp-imap-mcp/filters.zon` (ZON, parsed with `std.zon`); a
  file filter with a built-in's name replaces it. Activation via
  `TP_IMAP_MCP_FILTERS` (default `password_reset`, `none` to disable) and
  per-account `IMAP_<NAME>_FILTERS`.
- **Fail closed.** Unknown filter names, invalid files, or bad regexes stop
  startup; if headers cannot be retrieved, no body is fetched.

## Consequences

- Password-reset bodies never leave the server; the model can still say that
  such a message exists, from whom, and when.
- Messages whose headers look innocuous are not caught; header-only detection
  is a deliberate trade-off.
- `get_text`/`get_html` on accounts with active filters fetch headers before
  bodies (usually served from the cache).
- The default is protective: a fresh install filters password resets without
  any configuration; turning it off is explicit (`none`).
- New categories are added as built-ins (code) or by users (ZON) without
  changing tool signatures.
- First use of `$XDG_CONFIG_HOME` (ADR 0014).
- 2026-10-07: also applies to `list_attachments` (withheld marker; file names can be sensitive).
