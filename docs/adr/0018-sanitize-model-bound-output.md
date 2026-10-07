# 0018. Sanitize all model-bound output

- Status: Accepted
- Date: 2026-10-07

## Context

Email is attacker-controlled input that ends up in the model's context.
Prompt injection hides instructions in places a human reader never sees: HTML
comments, `display:none` elements, zero-width or tag Unicode characters, bidi
overrides, or RFC 2047 encoded headers. Very large messages also waste context
and can crowd out the user's actual request. Until now `get_html` returned raw
HTML and bodies were returned uncapped.

Options considered for `get_html`: (A) both body tools return sanitized plain
text; (B) A plus a per-account raw-HTML escape hatch; (C) keep HTML with
hidden elements removed. For HTML parsing: (A) a small tokenizer in Zig;
(B) libxml2's HTML parser (ships with macOS; long CVE history on hostile
input); (C) lexbor (new Homebrew dependency). For limits: configurable
defaults, fixed constants, or per-account values.

## Decision

- **Plain text only.** `get_text` returns `text/plain` parts, falling back to
  HTML converted to text; `get_html` returns HTML converted to text. No markup
  reaches the model. This deviates from reference parity.
- **Hidden content removed** during conversion: comments, `script`/`style`/
  `head`/`template`/`noscript`/`iframe`/`object`/`svg`/`textarea`/`title`,
  images (including `alt`), elements with `hidden`, and `style` declaring
  `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, or
  `mso-hide:all`. Links render as `text (url)` for `http`/`https`/`mailto`
  only.
- **Invisible Unicode removed** from all text output: controls, soft hyphen,
  zero-width characters, bidi controls, tag characters, supplementary
  variation selectors.
- **Size caps:** `TP_IMAP_MCP_MAX_BODY_BYTES` (default 32 KiB per body),
  `TP_IMAP_MCP_MAX_RESPONSE_BYTES` (default 128 KiB running budget per
  response), 2 KiB per header value; explicit truncation/omission markers.
- **Implementation:** a tolerant HTML tokenizer written in Zig — no new
  dependency, bounds-checked, fuzz-tested, never rejects input.
- **Always on;** only the caps are configurable.

## Consequences

- Injected instructions hidden by the listed techniques never reach the model.
- CSS-colour or off-screen hiding is not detected (would need a CSS engine);
  documented as a known gap.
- `get_html` no longer returns HTML; prompts relying on markup break.
- Long messages are truncated with a visible marker; the model can request
  fewer UIDs when the response budget is reached.
- More CPU per body (tokenizing), negligible next to network I/O.
- 2026-10-07: attachment file names from `list_attachments` are decoded, cleaned, path-stripped, and capped at 255 bytes.
