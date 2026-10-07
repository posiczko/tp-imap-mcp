# Output sanitization — Design

Date: 2026-10-07
Status: Approved; plan `docs/superpowers/plans/2026-10-07-filters-and-sanitization.md`
Extends: `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`
Builds on: `docs/superpowers/specs/2026-10-07-sensitive-content-filters-design.md`
Decision records: `docs/adr/0018-sanitize-model-bound-output.md`, `docs/adr/0019-decoded-sanitized-header-values.md`

## 1. Goal

Defend against prompt injection and oversized output: everything returned to
the model is plain text with hidden content removed, invisible Unicode
stripped, and sizes capped — before it leaves the server.

### Non-goals

- Detecting text hidden by CSS colour (e.g. white on white), off-screen
  positioning, or small-but-nonzero fonts (would require a CSS engine).
- Returning HTML markup in any form.
- An off switch for sanitization (only the caps are configurable).
- Sanitizing input to write tools (`create_message` content is the model's own).

## 2. Pipeline

Order for `get_text` / `get_html`, per message:

1. **Filters** (sensitive-content design): withheld messages are never
   downloaded; their marker is returned as-is.
2. **Part selection** (MIME, unchanged walk rules from spec §6.4):
   - `get_text`: concatenated `text/plain` parts; if there are none, the
     concatenated `text/html` parts converted to text (§3).
   - `get_html`: concatenated `text/html` parts converted to text (§3); `""`
     if none.
   - Encrypted messages: the existing marker (spec §6.6).
3. **Unicode cleaning** (§4).
4. **Line endings** LF; whitespace normalization (§3.6) applies to HTML-derived
   text only.
5. **Body cap** (§5.1).
6. **Response budget** across the returned list (§5.2).

## 3. HTML → text

A tolerant tokenizer written in Zig (`src/sanitize/html.zig`). Input is UTF-8
(the MIME layer has already converted the charset and replaced invalid
sequences). It never fails: unparseable constructs are treated as text.

### 3.1 Tokens

Text, start tag (name lower-cased, attributes with optional quoted/unquoted
values, self-closing flag), end tag, comment (`<!-- ... -->`, plus the
degenerate `<!-->` and `<!--->`), doctype/processing instructions (`<!...>`,
`<?...>`, dropped). Tag names and attribute names are ASCII case-insensitive.
A `<` not followed by a letter, `/`, `!` or `?` is text.

### 3.2 Dropped subtrees (element and all content)

- Raw-text elements, whose content is not tokenized as HTML: `script`,
  `style`, `template`, `noscript`, `iframe`, `object`, `svg`, `textarea`,
  `title`. Content runs until the matching `</name` (case-insensitive) or end
  of input.
- `head`.
- Elements with the `hidden` attribute.
- Elements whose `style` attribute, after removing whitespace and lower-casing,
  contains any of: `display:none`, `visibility:hidden`, `opacity:0`
  (also `opacity:0.0`, `opacity:0%`), `font-size:0` (followed by end, `;`,
  `px`, `pt`, `em`, `rem`, `%`), `mso-hide:all`.
- `img`, `picture`, `video`, `audio`, `canvas` (including `alt`).

### 3.3 Element stack

An open-element stack tracks, per element, whether it starts a dropped
subtree. Text is emitted only when no open element is dropped. An end tag pops
up to the most recent matching open element; an end tag with no match is
ignored. Void elements (`br`, `hr`, `img`, `input`, `meta`, `link`, `wbr`,
`area`, `base`, `col`, `embed`, `source`, `track`) never push. Stack depth is
capped at 256; deeper nesting stops pushing (content stays visible unless an
already-open ancestor is hidden).

### 3.4 Structure

- Line break before and after: `p`, `div`, `section`, `article`, `header`,
  `footer`, `main`, `nav`, `aside`, `blockquote`, `pre`, `table`, `tr`, `ul`,
  `ol`, `dl`, `dt`, `dd`, `h1`–`h6`, `form`, `fieldset`, `address`, `center`.
- `br` → line break; `hr` → line break, `---`, line break.
- `li` → line break then `- `.
- `td`, `th` → a single space separator.

### 3.5 Links

`<a href="U">T</a>` renders `T (U)` when `U` is an `http:`, `https:` or
`mailto:` URL (case-insensitive scheme) and `U` is not already equal to the
trimmed `T` (or `T` with `mailto:` removed). Other schemes (`javascript:`,
`data:`, `vbscript:`, relative URLs) render `T` only. Entities in `href` are
decoded first. A link inside a dropped subtree renders nothing.

### 3.6 Entities and whitespace

- Entities are decoded in text and attribute values: numeric (`&#NNN;`,
  `&#xHH;`; invalid or surrogate code points become U+FFFD) and a table of
  common named entities (at least `amp lt gt quot apos nbsp copy reg trade
  hellip mdash ndash lsquo rsquo ldquo rdquo sbquo bdquo laquo raquo bull
  middot euro pound yen cent sect para deg plusmn times divide frac12 frac14
  frac34 iexcl iquest shy zwnj zwj zwsp lrm rlm ensp emsp thinsp`). Unknown or
  unterminated entities are kept literally.
- Non-breaking space becomes a space. Runs of spaces and tabs collapse to one
  space; spaces around line breaks are removed; more than two consecutive line
  breaks collapse to two; leading/trailing whitespace is trimmed. Inside `pre`,
  whitespace is preserved.

## 4. Unicode cleaning

Applied to bodies (after §3 for HTML), decoded header values, mailbox names,
and server error text in diagnostics (`src/sanitize/unicode.zig`). Removed:

| Range | What |
|---|---|
| U+0000–U+0008, U+000B–U+001F, U+007F, U+0080–U+009F | C0/C1 controls (except `\t`, `\n`; `\r` is removed after LF normalization) |
| U+00AD | soft hyphen |
| U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069 | bidi marks and overrides |
| U+200B–U+200D, U+2060–U+2064, U+FEFF | zero-width and invisible operators |
| U+E0000–U+E007F | tag characters |
| U+E0100–U+E01EF | supplementary variation selectors |

Kept: U+FE00–U+FE0F (emoji/text presentation), all visible text.
U+2028 and U+2029 become `\n`. Input is valid UTF-8 (already sanitized);
output is valid UTF-8.

## 5. Size limits

### 5.1 Per value

- Body: `TP_IMAP_MCP_MAX_BODY_BYTES` (default 32768). Longer text is cut at a
  UTF-8 boundary to at most the limit and suffixed with
  `\n[truncated: N bytes omitted]` (N = bytes removed).
- Header value: 2048 bytes (constant), same marker format.
- Markers are not counted against the limit.

### 5.2 Per response

`TP_IMAP_MCP_MAX_RESPONSE_BYTES` (default 131072) is a running budget over
the item payloads of `get_text`, `get_html`, `get_header`, `get_header_field`
(body text; sum of header names and values). Items are processed in input
order; once adding an item would exceed the budget, that item and every later
non-null item is replaced by:

- `get_text`/`get_html`/`get_header_field`: the string (or one-element list)
  `[omitted: response size limit reached; request fewer UIDs]`;
- `get_header`: `{"x-tp-imap-mcp-omitted": ["response size limit reached; request fewer UIDs"]}`.

The first item is always returned (truncated per §5.1), so a single large
message is never fully omitted. `null` entries (nonexistent UIDs) and withheld
markers stay as they are.

### 5.3 Configuration

| Variable | Default | Rule |
|---|---|---|
| `TP_IMAP_MCP_MAX_BODY_BYTES` | 32768 | integer ≥ 1024 |
| `TP_IMAP_MCP_MAX_RESPONSE_BYTES` | 131072 | integer ≥ 1024 |

Invalid values stop startup with a message naming the variable.

## 6. Headers (supersedes ADR 0012's "raw headers")

`get_header` and `get_header_field` return values that are unfolded,
RFC 2047-decoded (`imap.decodeHeaderValue`, falling back to the raw value),
Unicode-cleaned (§4), and capped (§5.1). Names stay lower-cased. Withheld
messages keep their visible `date`/`from` (now decoded and cleaned too).

## 7. Other outputs

- `list_mailboxes` `PATH`: Unicode-cleaned after modified-UTF-7 decoding.
- Server text in tool errors (`Registry.setDiag`): Unicode-cleaned.
- Unchanged: `search` (UIDs), `get_size`, `get_keywords`/`change_keywords`
  (IMAP atoms), `mailboxes_status`, `list_accounts`, `create_message`.

## 8. Architecture

| File | Responsibility |
|---|---|
| `src/sanitize/html.zig` | Tokenizer + converter (§3). |
| `src/sanitize/entities.zig` | Entity decoding (§3.6). |
| `src/sanitize/unicode.zig` | Invisible/control character removal (§4). |
| `src/sanitize/limit.zig` | `truncate(arena, text, max)`; `Budget` (§5). |
| `src/c/mime.c`, `src/c/tpi.h`, `src/imap/c.zig`, `src/imap/session.zig` | Extraction can report whether any part of the requested subtype was found, so `get_text` can fall back to HTML. |
| `src/body.zig` | `render(arena, message, kind, max_body)` implements §2 steps 2–5. |
| `src/tools.zig` | Header decoding/cleaning/capping; budgets; mailbox-name cleaning. |
| `src/accounts.zig` | Diagnostics cleaned. |
| `src/config.zig` | `Settings.max_body_bytes`, `Settings.max_response_bytes`. |
| `src/descriptions.zig` | Plain-text output, link format, markers. |

## 9. Errors

Nothing in sanitization can fail a tool call or reject input. Allocation
failure behaves as elsewhere.

## 10. Testing

Unit (offline):

- `html.zig`: each §3.2 rule alone and nested; comments including `<!-->`;
  unterminated `<script`; raw-text content containing `</scriptx>`;
  unquoted/missing attribute values; stray and unmatched end tags; void
  elements; depth cap; `pre`; structure (§3.4); links (§3.5) including
  `javascript:` and `href` equal to text; a realistic marketing email fixture;
  an injection fixture whose `display:none` paragraph must not appear.
- `html.zig` fuzz test (`std.testing.fuzz`): never crashes; output is valid
  UTF-8; output never contains `<script`.
- `entities.zig`: named, decimal, hex, invalid code points, unknown and
  unterminated entities.
- `unicode.zig`: every range removed; emoji with U+FE0F, accented text, CJK
  kept; U+2028/2029 → `\n`.
- `limit.zig`: boundary-safe truncation, exact marker text, budget
  replacement order, first item always kept.
- `body.zig`: `get_text` falls back to HTML when no plain part; `get_html` of a
  plain-only message is `""`; caps applied after cleaning.
- `tools.zig`: encoded subject hiding U+200B returns decoded and clean;
  oversized header value capped; mailbox name cleaned.
- `config.zig`: defaults, valid overrides, values below 1024 and non-numeric
  rejected.

Integration (`zig build itest`): for the newest messages, every `get_text`
and `get_html` result contains no `<` immediately followed by a letter and no
character from §4's removed ranges.

## 11. Build

No new dependencies; no new C files (the MIME change extends `mime.c`).

## 12. Implementation notes (from the verified prototype)

- Fuzzing: `zig build test --fuzz` cannot link the C shim, and Zig 0.17's
  fuzzer fails on this machine even for pure-Zig code (coverage-file errors).
  The `std.testing.fuzz` harness is kept (it runs once in normal test runs);
  a seeded 20,000-input randomized stress test over HTML-ish fragments
  substitutes for continuous fuzzing.
- The live markup check looks for common HTML tag names (`<div`, `<p `,
  `<span`, `<table`, `<script`, ...) rather than any `<` followed by a letter,
  which legitimately occurs in plain text (`John <john@example.org>`).
- libetpan drops a body's final CRLF for 8-bit parts; truncation counts
  reflect that.
- Verified 2026-10-07: unit tests pass; live checks 26/26 (including the two
  sanitization checks over the ten newest INBOX messages).
- Review fix pass (2026-10-07) tightened §3: style normalization strips CSS
  comments and backslashes with no length cutoff, adds
  `visibility:collapse`; repeated attributes use the first occurrence;
  numeric character references are decoded without a trailing `;`;
  `&colon;`, `&semi;`, `&lpar;`, `&rpar;` added; raw-text elements end only at
  `</name` followed by whitespace, `/` or `>`; a hidden element renders
  nothing (no link target, no line break); past depth 256 a hiding element
  hides everything after it (supersedes "content stays visible" in §3.3).
- One `get_header` item is capped at `TP_IMAP_MCP_MAX_BODY_BYTES` of names and
  values; dropped lines are reported as
  `"x-tp-imap-mcp-truncated": ["N header lines omitted"]`.
- The encrypted-message marker's `protocol` parameter is cleaned and limited
  to 64 bytes.
- Live checks re-run after the fix pass: 26/26.
- Live markup check (itest) applies to `get_html` only: a `text/plain`
  alternative may contain raw HTML written by the sender, returned verbatim as
  inert text (observed on the user's server, 2026-10-07). Invisible-character
  checks apply to both tools.
- Cleanup (2026-10-07): `noembed`/`noframes` are raw-text dropped elements;
  `datalist` and `dialog` without `open` are dropped; withheld entries bypass
  the response budget; `x-tp-imap-mcp-*` message headers are not shown.
