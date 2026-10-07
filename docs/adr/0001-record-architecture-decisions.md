# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-10-07

## Context

tp-imap-mcp makes several hard-to-reverse choices up front (IMAP library,
C interop strategy, credential handling, on-disk cache format). The reasoning
behind them was worked out in conversation and in the design spec
(`docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`), but a spec
describes the current design, not why alternatives were rejected.

## Decision

Record significant decisions as Architecture Decision Records in `docs/adr/`,
one file per decision, numbered sequentially, using `docs/adr/template.md`
(Status / Context / Decision / Consequences). Routine or trivial changes do not
get an ADR. A decision that is replaced is marked "Superseded by NNNN", never
deleted.

## Consequences

- New contributors (and agents) can see why the project looks the way it does.
- Revisiting a decision means writing a new ADR that supersedes the old one.
- `docs/adr/README.md` must be kept in sync as an index.
