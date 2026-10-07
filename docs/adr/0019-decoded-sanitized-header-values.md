# 0019. Return header values decoded and sanitized

- Status: Accepted
- Date: 2026-10-07
- Supersedes: the "header values are raw" point of [ADR 0012](0012-parity-and-deliberate-deviations.md)

## Context

ADR 0012 kept header values raw (RFC 2047 encoded-words not decoded) for
parity with the reference server. With output sanitization (ADR 0018), raw
encoded-words are a gap: zero-width characters, bidi overrides, or injected
text inside `=?UTF-8?B?...?=` would pass the sanitizer unseen and be decoded
by the model itself. Options: (A) decode then sanitize; (B) stay raw and strip
only control characters; (C) return both raw and decoded values.

## Decision

`get_header` and `get_header_field` return values that are unfolded,
RFC 2047-decoded to UTF-8 (libetpan `mailmime_encoded_phrase_parse`, falling
back to the raw value on failure), cleaned of invisible and control
characters, and capped at 2 KiB each. Header names remain lower-cased; the
result shapes are unchanged.

## Consequences

- Hidden content inside encoded-words is removed before reaching the model.
- The model gets readable subjects and names without decoding them.
- Callers can no longer see the exact raw bytes of a header; nothing in the
  server needs them.
- The same decoder serves sensitive-content filtering (ADR 0017).
