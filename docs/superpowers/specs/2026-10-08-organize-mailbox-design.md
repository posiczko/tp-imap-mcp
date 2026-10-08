# Organize a mailbox — Design

Date: 2026-10-08
Status: Approved (design); spec under review
Extends: `docs/superpowers/specs/2026-10-08-mailbox-organization-design.md`
Decision record: `docs/adr/0022-organize-mailbox-two-phase-plan.md` (new)

## 1. Goal

One user-facing action, "organize my mailbox" (default `INBOX`): the model
classifies each recent message as *move to folder X*, *delete* (move to Trash),
*needs attention* (flag), or *keep*, following the user's organizing prompt or
a built-in default. The result is shown as a dry run; nothing changes until the
user confirms and the plan is executed.

An MCP server cannot run the model itself (MCP sampling is not supported by the
target client, Claude Code), so classification happens in the conversation's
model; the server gathers input, validates the model's plan, and executes it.

### Non-goals

- Permanent deletion (no `EXPUNGE` of the user's mail; "delete" is a move to
  Trash).
- Creating folders as part of a plan (the model suggests them; the user creates
  them with `create_mailbox`).
- Gmail's Important label (not settable through standard IMAP).
- Server-side rules (Sieve) or scheduled/unattended runs.

## 2. Tools

### 2.1 `organize_mailbox` (read-only)

| Parameter | Default | Meaning |
|---|---|---|
| `account` | — | required |
| `directory` | `"INBOX"` | folder to organize |
| `limit` | `50` | 1–200 newest messages |
| `criteria` | none | optional IMAP SEARCH criteria narrowing the candidates (validated like `search()`) |
| `include_reviewed` | `false` | include messages already carrying `$TpOrganized` |

Allowed on read-only accounts. Returns:

```json
{"account": "work", "directory": "INBOX", "uidvalidity": 1700000000,
 "instructions": "<organizing prompt text>",
 "instructions_source": "~/.config/tp-imap-mcp/organize.work.md",
 "folders": ["Archive", "Receipts/2026", "Newsletters"],
 "trash": "Trash",
 "messages": [
   {"uid": "4711", "date": "...", "from": "...", "to": "...", "subject": "...",
    "size": 18234, "flags": ["\\Seen"], "snippet": "first ~500 characters of text"},
   {"uid": "4712", "date": "...", "from": "...", "withheld": "password_reset"}
 ],
 "omitted": 0,
 "next": "Classify each message, then call apply_organization with dry run."}
```

- **Candidates:** `UID SEARCH` of `NOT KEYWORD $TpOrganized` (unless
  `include_reviewed`), AND `criteria` if given; the newest `limit` by UID.
- **`instructions`:** the first existing file of
  `<config_dir>/organize.<account>.md`, `<config_dir>/organize.md`
  (`config_dir` = the XDG config dir already used for `filters.zon`), else the
  built-in default (§5). Read on every call; at most 16 KiB (longer: an error
  naming the file). `instructions_source` names the file or `"built-in"`.
- **`folders`:** selectable folders usable as move destinations: excludes the
  source folder, `\Noselect` folders, `\All`, and `\Trash`/`\Junk` (Trash is
  reported separately as `trash`; Junk is never a target).
- **`trash`:** the folder with the `\Trash` attribute, or `null` (then "delete"
  actions are refused).
- **Message fields:** UID; `date`, `from`, `to`, `subject` decoded and
  sanitized like `get_header` (ADR 0019); size; flags; `snippet`: sanitized
  plain text (ADR 0018) of the first 16 KiB of the message, cut to 500
  characters. Messages withheld by a sensitive-content filter (ADR 0017) show
  only `uid`, `date`, `from` and `withheld` (no snippet, no subject).
- **Budget:** the response respects `max_response_bytes`; messages that do not
  fit are counted in `omitted` (the model can call again with a smaller
  `limit`).

### 2.2 `apply_organization`

| Parameter | Default | Meaning |
|---|---|---|
| `account`, `directory` | — | as returned by `organize_mailbox` |
| `uidvalidity` | — | as returned by `organize_mailbox` |
| `actions` | — | array of `{uid, action, destination?}` |
| `execute` | `false` | `true` performs the plan |
| `plan_hash` | — | required when `execute=true` |

Actions: `{"uid":"4711","action":"move","destination":"Receipts/2026"}`,
`{"uid":"…","action":"delete"}`, `{"uid":"…","action":"flag"}`,
`{"uid":"…","action":"keep"}`.

Validation (every call, before any change):
- UIDVALIDITY of `directory` must equal `uidvalidity`; otherwise refuse
  ("the folder changed since organize_mailbox; run it again").
- 1–500 actions; each UID at most once; UIDs are decimal (`validate.uids`).
- `move`: `destination` exists, is selectable, is not the source, not `\All`,
  not `\Trash`/`\Junk` (use `delete` for Trash), and the source is not `\All`
  (existing `organize` rules).
- `delete`: the account has a `\Trash` folder, and the source is not it.
- UIDs that no longer exist are not an error: listed under `missing` and skipped.
- Withheld messages (active sensitive-content filters) accept only `keep` (§5.1).

Dry run (`execute=false`, also on read-only accounts) returns the plan grouped
by outcome, with subjects shown as in `organize_mailbox`:

```json
{"dry_run": true, "plan_hash": "3f9a0c2e5b7d1a44",
 "groups": [
   {"action": "move", "destination": "Receipts/2026", "count": 2,
    "messages": [{"uid": "4711", "from": "...", "subject": "..."}]},
   {"action": "delete", "destination": "Trash", "count": 1, "messages": [...]},
   {"action": "flag", "count": 1, "messages": [...]},
   {"action": "keep", "count": 3}],
 "missing": []}
```

- `plan_hash`: lowercase hex of the first 8 bytes of SHA-256 over a canonical
  serialization of account, directory, uidvalidity, and the actions sorted by
  UID (so it does not depend on the order of `actions`).

Execute (`execute=true`):
- Refused on read-only accounts.
- `plan_hash` must equal the hash of this call's actions; otherwise refuse
  ("the plan differs from the dry run; run a dry run and show it again").
- Order: flag (`UID STORE +FLAGS (\Flagged)`), then moves per destination and
  the delete move to Trash (the existing batched move path: MOVE, else
  COPY + `\Deleted` + `UID EXPUNGE`, else refused — ADR 0021), then
  `$TpOrganized` on the kept and flagged messages.
- Not retried after a lost connection (like every organization operation).
- Result: per-group counts done; on failure, the error states which groups
  completed, which partially (with the existing partial-move wording), and
  which were not attempted.
- Cache: moved UIDs are forgotten (`Registry.forgetMoved`).
- If the server refuses the `$TpOrganized` keyword (no `\*` in
  PERMANENTFLAGS), the plan still succeeds and the result carries a note that
  reviewed messages will appear again.

### 2.3 MCP prompt `organize_my_mailbox`

Arguments (optional): `account`, `directory`. Renders a user message telling
the model to: call `organize_mailbox`; classify every returned message using
the returned `instructions`; call `apply_organization` as a dry run; present the
grouped plan to the user (counts and subjects per group); call it again with
`execute=true` and the `plan_hash` only after the user confirms; repeat while
messages remain if the user wants. In Claude Code:
`/mcp__tp-imap-mcp__organize_my_mailbox`.

## 3. Safety

- Two phases: execution requires the hash of the plan the dry run produced;
  any change to the actions requires a new dry run.
- No permanent deletion; Trash and Junk are never move destinations; `\All`
  is never a source; protected folders are unaffected (no folder is renamed,
  created or deleted).
- Read-only accounts can gather and dry-run, never execute.
- Withheld messages contribute no content to the model and are never moved,
  deleted or flagged: the server accepts only `keep` for them (§5.1).
- The instructions file is user-controlled configuration (like `filters.zon`);
  message content reaches the model only sanitized.

## 4. Code layout

- `src/triage.zig` (new, pure): instruction resolution (given a lookup
  function), action parsing and validation, grouping, `planHash`, snippet
  truncation.
- `src/organize_prompt.md` (new): built-in default instructions, embedded with
  `@embedFile`.
- `src/c/*`, `src/imap/*`: partial fetch of the first 16 KiB
  (`BODY.PEEK[]<0.16384>`) for snippets.
- `src/tools.zig`: `organize_mailbox`, `apply_organization` handlers and ops;
  reuse `TransferOp`, `StoreOp`-style stores, `CachedHeadersOp`, filters,
  `body.render`, `limit.Budget`.
- `src/prompts.zig`: `organize_my_mailbox` with optional arguments.
- `src/descriptions.zig`, README, ADR 0022, `docs/TODO.md`.

## 5. Built-in instructions (exact text of `src/organize_prompt.md`)

```markdown
# How to organize this mailbox

You are proposing a plan; the user reviews it before anything changes. Be
conservative: a message left in place costs nothing, a message filed or deleted
by mistake can be missed. When unsure, choose **keep**.

## Never touch (always **keep**)

- Messages shown as `withheld`. They were hidden by a sensitive-content filter
  (password resets, one-time codes, sign-in links). Do not guess what they are.
- Anything about credentials or account access, even if it was not withheld:
  password or PIN changes, verification or confirmation codes, magic or sign-in
  links, two-factor setup, recovery codes, API keys or tokens, new-device or
  new-login alerts, "confirm it's you" requests.
- Drafts, and messages the user sent themselves.
- Anything that looks like it is in the middle of a conversation the user is
  part of, unless it clearly belongs in a folder for that topic.

## Flag (needs attention)

Flag a message, and keep it where it is, when it:
- asks the user, personally, to do or answer something;
- mentions a deadline, appointment or expiry in the next two weeks;
- is an invoice, bill, payment request, failed payment, or money owed;
- comes from a person (not a mailing list or a no-reply address) and is not
  plainly social chatter;
- is a security or fraud notice about one of the user's accounts that is not
  about credentials (those are **keep**, see above).

## Move to a folder

Move a message only to a folder from the `folders` list, and only when the
sender or subject clearly matches that folder's purpose (for example receipts
and order confirmations to a receipts folder, newsletters to a newsletters
folder, notifications from a service to that service's folder). Never invent a
folder name. If several messages would fit a folder that does not exist, keep
them and tell the user which new folder you would suggest.

Do not move a message you also flag.

## Delete (move to Trash)

Delete only when it is plainly worthless:
- obvious spam or bulk mail the user never signed up for;
- promotions and sales whose offer has expired;
- automated notifications that are superseded (e.g. a shipping update after a
  later "delivered" message for the same order).
Never delete messages from people, receipts, invoices, anything legal, medical,
financial or tax related, or anything you are not sure about.

## Output

Give exactly one action per message: `keep`, `flag`, `move` (with
`destination`), or `delete`. When presenting the dry run, summarize per group
and mention anything you deliberately left alone and why.
```

### 5.1 Server-enforced rule for withheld messages

`apply_organization` re-classifies the plan's messages with the account's
active sensitive-content filters (from their headers, as `organize_mailbox`
did) and refuses any action other than `keep` for a withheld message:
`message 4712 is withheld by filter "password_reset"; only "keep" is allowed`.
The rule holds even if a custom `organize.md` says otherwise.

## 6. Testing

Unit (no server):
- instruction resolution order and the 16 KiB cap (temporary config dir);
- every validation rule; missing UIDs reported, not fatal;
- a withheld message with `move`/`delete`/`flag` is refused, `keep` accepted;
- `planHash` is independent of action order and changes with any action;
- grouping output; execute without / with a wrong `plan_hash` refused;
  read-only: dry run allowed, execute refused;
- snippet truncation at a UTF-8 boundary.

Live (`zig build itest -- <account> --organize`, in its throwaway folders):
append three messages to A; `organize_mailbox` on A lists them; dry run of
{move one to B, flag one, keep one} changes nothing; execute with the hash
moves/flags/keeps; a second `organize_mailbox` returns none of the remaining
two (`$TpOrganized`). The delete-to-Trash path is unit-tested only (the live
check never touches the user's real Trash).

Manual: run the prompt in Claude Code against a real inbox, read the dry run,
execute.
