# 0009. Defer PGP/MIME decryption

- Status: Accepted
- Date: 2026-10-07

## Context

The reference decrypts `multipart/encrypted` messages in `get_text`/`get_html`
by running `gpg --batch --decrypt` with the local keyring. That requires gpg
installed and able to decrypt non-interactively, and it sends decrypted
content to the model, which is a privacy decision as much as a technical one.
The user does not currently need it.

## Decision

Do not decrypt. For a top-level `multipart/encrypted` message, `get_text` and
`get_html` return
`[encrypted message (multipart/encrypted; protocol=<protocol>) — not decrypted]`.

## Consequences

- No gpg dependency; decrypted content never reaches the model.
- Adding decryption later (as the reference does, or via GPGME) changes no tool
  signature.
