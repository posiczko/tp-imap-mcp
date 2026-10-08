# 0022. Organize a mailbox as a model-classified, server-validated two-phase plan

- Status: Accepted
- Date: 2026-10-08

## Context

The user wants one action that triages a folder: for each recent message,
move it to a folder, delete it, flag it as needing attention, or keep it,
following their own organizing instructions or a built-in default, shown as a
dry run and carried out only when they confirm.

- **Who classifies.** An MCP server cannot run the model itself. MCP
  "sampling" (the server asking the client's model) is not supported by
  Claude Code, the target client. Options: classify in the conversation's
  model with server-side gathering and validation; a prompt-only workflow on
  the existing tools; sampling.
- **Safety.** A plan can touch hundreds of messages. The model may err, and
  message content can carry prompt injection. Sensitive mail (password
  resets, codes) is withheld from the model (ADR 0017), so it cannot be
  classified reliably.
- **Re-runs.** Working through a backlog means running repeatedly on the
  newest messages; messages kept last time would come back every run.

## Decision

- Two tools and one MCP prompt. `organize_mailbox` (read-only) returns the
  organizing instructions (`<config_dir>/organize.<account>.md`, else
  `organize.md`, else built-in), the folders, the Trash folder, and the
  newest candidate messages with sanitized headers and a short snippet.
  `apply_organization` validates the model's actions and returns a grouped
  dry run with a `plan_hash`; with `execute=true` and that hash it carries
  the plan out. The prompt `organize_my_mailbox` tells the model the
  workflow: gather, classify, dry run, confirm, execute.
- "Delete" moves to the `\Trash` folder; nothing is expunged by the user's
  plan. "Needs attention" sets `\Flagged`.
- Withheld messages accept only "keep", enforced by the server.
- Execution requires the dry run's `plan_hash` (SHA-256 over account, folder,
  UIDVALIDITY and the sorted actions), so what runs is exactly what was
  shown; the UIDVALIDITY must still match.
- Kept and flagged messages get the keyword `$TpOrganized`; the next
  `organize_mailbox` skips them unless `include_reviewed=true`.
- Moves reuse ADR 0021's machinery (MOVE, else COPY + UID EXPUNGE, else
  refuse; protected folders; no retry after a lost connection).

## Consequences

- Works with today's MCP clients; the model's judgment is bounded by server
  validation and a hash-checked confirmation step.
- Classification costs model tokens per message (headers plus a 500-character
  snippet; at most 200 messages per call).
- `$TpOrganized` is visible in clients that show keywords; servers that refuse
  custom keywords re-offer kept messages (the result says so).
- The plan cannot create folders; the model suggests them and the user creates
  them with `create_mailbox`.
