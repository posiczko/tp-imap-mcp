# 0012. Match the reference's behavior, with listed deviations

- Status: Accepted
- Date: 2026-10-07

## Context

The goal is to mirror vivier/imap-mcp-server. Some of its behaviors come
from `imap-tools`/Python defaults, and some make results hard to use.

## Decision

Match the reference except where noted.

Kept as in the reference:
- Header values are raw: names lower-cased, values unfolded, RFC 2047
  encoded-words not decoded.
- `get_text`/`get_html` concatenate every non-attachment `text/plain` /
  `text/html` part in depth-first walk order, including inside
  `message/rfc822` parts.
- `create_message` appends with no flags (no `\Draft`), converting bare LF to
  CRLF as Python's `imaplib` does.
- The two prompts carry over word for word.

Deliberate deviations:
- **Input-ordered results:** per-UID tools return one entry per input UID, in
  input order, with `null` for UIDs that don't exist (the reference returns
  server order and drops missing UIDs). `get_header_field` returns `[]` for a
  message lacking the field.
- **Bodies** are valid UTF-8 (invalid sequences become U+FFFD) with LF line
  endings, so the result doesn't depend on transfer encoding.
- **Mailbox names** are decoded from modified UTF-7 to UTF-8 on output and
  encoded on input.
- **`change_keywords`** returns flags from a `UID FETCH (FLAGS)` after the
  store rather than from the server's unsolicited responses.
- **`create_message`** returns `{"status":"OK","data":[...]}` on success; a
  rejected append is a tool error carrying the server's text.

## Consequences

- Results are unambiguous to the model (no guessing which body belongs to
  which UID).
- Prompts written against the reference work, apart from the added `account`
  argument (ADR 0006).
