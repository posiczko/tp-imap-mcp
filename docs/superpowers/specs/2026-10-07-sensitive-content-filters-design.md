# Sensitive-content filters — Design

Date: 2026-10-07
Status: Approved; plan `docs/superpowers/plans/2026-10-07-filters-and-sanitization.md`
Extends: `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`
Decision record: `docs/adr/0017-sensitive-content-filters.md`

## 1. Goal

Keep the content of sensitive emails (first: password resets) away from the
model, and never download their bodies, while still letting the model know the
message exists. The mechanism is composable: named filters made of rules, a
built-in set that can grow, and user-defined filters in a config file.

### Non-goals

- Detecting sensitive content from message bodies (that would require
  downloading them).
- Hiding messages entirely from `search` (rejected: option B, see ADR 0017).
- Per-filter choice of action (withhold vs hide).
- Built-in filters beyond `password_reset` (e.g. `one_time_codes`) — later.
- Filtering the write tools (`change_keywords`, `create_message`).

## 2. Model

- **Filter** — a name and a list of rules. A message matches the filter if
  **any** rule matches.
- **Rule** — a non-empty list of conditions. A rule matches if **all** its
  conditions hold.
- **Condition** — a header `field` (case-insensitive) and exactly one matcher
  with a non-empty list of patterns. It holds if **any** pattern matches **any**
  value of that header (repeated headers each count). A header the message
  lacks never holds.
- **Matcher kinds**
  - `contains` — case-insensitive (ASCII case folding) substring.
  - `glob` — case-insensitive, whole-value match; `*` = any run of characters,
    `?` = one byte. Intended for addresses (`*@accounts.google.com`). For
    `From`-like fields the pattern is matched against the whole decoded value
    *and* against each address inside angle brackets, so
    `"GitHub" <noreply@github.com>` matches `noreply@github.com`.
  - `regex` — POSIX extended regex via macOS libc,
    `regcomp(REG_EXTENDED | REG_ICASE | REG_NOSUB)`, compiled once at startup;
    unanchored search (`regexec`).
- **Classification** — `classify(headers, active_filters) ?filter_name`: the
  name of the first active filter (in configured order) that matches, or null.
- **Header decoding for matching** — values are unfolded, then RFC 2047
  encoded-words are decoded to UTF-8 (libetpan `mailmime_encoded_phrase_parse`,
  default charset `utf-8`). If decoding fails, the raw value is matched. Values
  returned to the model remain raw (spec §6.3 unchanged).

## 3. Built-in filters

`password_reset` — one rule, one condition:

```
field = subject, contains = [
  "password reset", "reset your password", "reset password",
  "password change", "change your password", "forgot your password",
  "password recovery", "recover your account", "account recovery",
]
```

Built-ins live in code (`src/filter/rules.zig`) and are documented in the
`list_accounts` description so the model knows what is withheld.

## 4. Configuration

### 4.1 Activation

| Variable | Meaning |
|---|---|
| `TP_IMAP_MCP_FILTERS` | Comma-separated active filters, or `none`. **Unset = `password_reset,one_time_codes`** (on by default). |
| `IMAP_<NAME>_FILTERS` | Same syntax; overrides the global value for one account. |

Order matters only for which filter name is reported when several match.
Whitespace around names is trimmed. An unknown name, an empty entry, or
`none` combined with other names is a startup error naming the variable and
the offending entry. An empty value is an error (use `none`).

### 4.2 User filters file

`$XDG_CONFIG_HOME/tp-imap-mcp/filters.zon` when `XDG_CONFIG_HOME` is set and
absolute, else `$HOME/.config/tp-imap-mcp/filters.zon` (ADR 0014). Optional:
a missing file means built-ins only. Parsed with `std.zon.parse.fromSlice`
into fixed types; unknown fields are rejected.

```zig
.{
    .filters = .{
        .{
            .name = "banking",
            .rules = .{
                .{ .{ .field = "from", .glob = .{ "*@chase.com", "*@schwab.com" } } },
                .{
                    .{ .field = "from", .glob = .{"*@paypal.com"} },
                    .{ .field = "subject", .regex = .{"(receipt|statement)"} },
                },
            },
        },
        // Same name as a built-in: replaces its rules entirely.
        .{ .name = "password_reset", .rules = .{
            .{ .{ .field = "subject", .contains = .{ "password reset", "passwort zurücksetzen" } } },
        } },
    },
}
```

Rules:

- Filter names: `[a-z0-9_]+`, unique within the file.
- A file filter with a built-in's name replaces that built-in.
- Defining a filter does not activate it (§4.1 decides).
- Each condition sets exactly one of `.contains`, `.glob`, `.regex`; the list
  is non-empty; patterns are non-empty strings. `field` is a valid header name
  (RFC 5322 ftext).
- Every rule has at least one condition; every filter at least one rule.
- Any violation, a ZON syntax error, or a regex that fails `regcomp` is a
  startup error reporting the file path, filter name, rule and condition index
  (and the `regerror` text or the ZON diagnostic). The server never starts
  with a partially loaded filter set.
- The file is read once at startup; edits need a restart.

## 5. Tool behavior

Withheld marker text: `[withheld by filter "<name>"]`.

| Tool | Behavior for a message matched by an active filter |
|---|---|
| `search`, `get_size`, `get_keywords`, `change_keywords`, `mailboxes_status`, `list_mailboxes` | Unchanged (no message content). |
| `get_text`, `get_html` | The marker string. The body is **never fetched**: headers are obtained first (from the cache when present, else `BODY.PEEK[HEADER] RFC822.SIZE`, which also fills the cache), messages are classified, and `BODY.PEEK[]` is requested only for unmatched UIDs. |
| `get_header` | Only the visible headers `date` and `from` (raw values, as usual), plus `"x-tp-imap-mcp-withheld": ["<name>"]`. |
| `get_header_field` | Normal values for `date`/`from`; for any other field, `["[withheld by filter \"<name>\"]"]`. |
| `list_accounts` | Each entry gains `"filters": ["password_reset", ...]` (the account's active filters). |
| `clear_cache` | Unchanged. |

Notes:

- `Subject` is withheld because reset and code emails often carry the secret
  in it.
- Filters apply to read-only and writable accounts alike.
- Tool descriptions for `get_text`, `get_html`, `get_header`,
  `get_header_field`, and `list_accounts` explain the marker so the model
  reports it rather than retrying.
- With no active filters for an account, behavior is exactly as before (no
  extra header fetch for bodies).

## 6. Architecture

| File | Responsibility |
|---|---|
| `src/filter/rules.zig` | Types `Filter`, `Rule`, `Condition`, `Matcher` (`contains`/`glob`/`regex`); built-in table; `classify`. Pure apart from regex calls. |
| `src/filter/glob.zig` | Case-insensitive `*`/`?` matcher, O(n·m) (no backtracking), plus angle-bracket address extraction. |
| `src/filter/regex.zig` + `src/c/regex.c` | Flat C wrapper over `regcomp`/`regexec`/`regerror`/`regfree` (ADR 0004 pattern); compiled patterns owned for the process lifetime. |
| `src/filter/load.zig` | Read and parse `filters.zon`, validate, merge with built-ins, resolve active sets per account from §4.1 variables. |
| `src/c/mime.c` (+ `tpi.h`, `imap/c.zig`, `imap/session.zig`) | `tpi_decode_header_value(raw, len, &out, &out_len)` via `mailmime_encoded_phrase_parse`; Zig `decodeHeaderValue`. |
| `src/config.zig` | `Settings.config_dir`; per-account raw `IMAP_<NAME>_FILTERS`. |
| `src/accounts.zig` | `Registry` holds each account's active filter list. |
| `src/tools.zig`, `src/descriptions.zig` | Classification in `get_text`/`get_html`/`get_header`/`get_header_field`; `list_accounts` filters field; description updates. |
| `src/main.zig` | Load filters at startup; exit 1 with the loader's message on error; log active filters per account to stderr. |

Data flow for `get_text`:

```
uids → CachedHeadersOp (cache or BODY.PEEK[HEADER]) → headers.parse → decode values
     → classify per active filters → withheld: marker
                                   → others: UID FETCH BODY.PEEK[] → body.render
```

Both IMAP steps run inside one `Registry.run` operation (one `EXAMINE`), so
the reconnect-and-retry semantics are unchanged.

## 7. Errors

- Configuration errors (§4) stop startup with exit 1; message on stderr.
- At runtime nothing in filtering can fail a tool call: decode failures fall
  back to raw values; regex matching cannot fail after successful compile.
- If header retrieval fails, the tool fails as it does today (no body is
  fetched without classification — fail closed).

## 8. Testing

Unit (offline):

- `glob.zig`: `*`, `?`, case-insensitivity, whole-value semantics, address
  extraction from `"Name" <a@b>`, pathological patterns finish quickly.
- `regex.zig`: match, no match, case-insensitive, compile error text,
  unanchored search.
- RFC 2047 decoding: B and Q encodings, ISO-8859-1 → UTF-8, adjacent
  encoded-words, malformed input falls back to raw.
- `rules.zig`: any-rule / all-conditions semantics; repeated headers; missing
  header; built-in `password_reset` positives ("Reset your password",
  "=?UTF-8?Q?Password_reset?=") and near-misses ("Passwords manager weekly
  digest", "Reset your router").
- `load.zig`: valid file; built-in replacement; each validation error with its
  message; missing file; activation resolution (default, `none`, per-account
  override, unknown name, empty entry, `none` mixed with names).
- `tools.zig` (offline, using a cache pre-seeded with fixture headers and an
  unreachable server): `get_header` / `get_header_field` redaction and
  `list_accounts` filters field. Body withholding needs the server and is
  covered by integration.

Integration (`zig build itest`, live, read-only):

- With an itest-local filter set whose single rule matches every message
  (`field = "date", regex = "."`): `get_text`/`get_html` return only markers,
  `get_header` returns only `date`/`from`/marker.
- With filters `none`: results identical to unfiltered behavior.
- The itest never prints message content (unchanged).

## 9. Build

- `src/c/regex.c` added to the C sources; libc only — no new dependency.
- No new Zig packages.

## 10. Implementation notes (from the verified prototype)

- Withholding needs a live `EXAMINE` for UIDVALIDITY, so the tool-level
  redaction is unit-tested through pure functions (`withheldBy`,
  `headerGroups`/`writeHeaderObject`, `headerFieldValues`); the end-to-end
  withholding path is covered by the live integration checks.
- Verified 2026-10-07: unit tests pass; live checks 26/26 against the user's
  Dovecot server (including the four filter checks).
- Review fix pass (2026-10-07): header values are matched as the model will
  see them — decoded, invisible characters removed, NBSP as a space — so
  `Reset\u200B your password` still matches. `get_text`/`get_html` fetch a
  body only for UIDs whose merged header data was received and matched no
  filter (fail closed: no headers, no body).
- 2026-10-07: built-in `one_time_codes` added (subject contains verification /
  sign-in / one-time code, 2FA, magic-link phrases; bare "otp" deliberately
  excluded) and made active by default alongside `password_reset`.
