<div align="center">

# 📬 tp-imap-mcp

![Zig](https://img.shields.io/badge/Zig-0.17-F7A41D?style=for-the-badge&logo=zig&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000?style=for-the-badge&logo=apple&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio-6E56CF?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-working-2EA043?style=for-the-badge)

**An MCP server that lets an AI assistant read and search several IMAP mailboxes — with credentials from 1Password, verified TLS, a local cache, and filters that keep sensitive mail out of the model.**

[Quick Start](#-quick-start) · [Running](#-running-the-server) · [Configuration](#-configuration) · [Tools](#-tools) · [Troubleshooting](#-troubleshooting) · [Roadmap](#-roadmap)

</div>

---

## 💡 Concept

> Mirror [vivier/imap-mcp-server](https://github.com/vivier/imap-mcp-server) in Zig, without implementing IMAP yourself, and make it safe to point at more than one real mailbox.

tp-imap-mcp exposes IMAP mailboxes to MCP clients (Claude Code, Claude Desktop, …) over stdio. IMAP and MIME come from [libetpan](https://github.com/dinhvh/libetpan); everything else is a small Zig 0.17 codebase. Secrets never touch disk: `op run` injects them as environment variables at launch.

## ✨ Features

| Feature | Description |
|---|---|
| 📮 Multiple accounts | One server process, an `account` argument on every tool. |
| 🔐 1Password credentials | Config is environment variables; values can be `op://` references resolved by `op run`. |
| 🛡️ Verified TLS | Certificate chain checked against a CA bundle, SNI set, host name verified **before** the password is sent. |
| 👀 Read-only accounts | `IMAP_<NAME>_READONLY=1` refuses the two write tools; reads never mark mail as seen. |
| ⚡ Local cache | Mailbox list and message headers/sizes cached in SQLite under `~/.cache/tp-imap-mcp/`. |
| 🔎 Full IMAP search | The model's IMAP `SEARCH` criteria are passed through, with input validation against command injection. |
| 🙈 Sensitive-content filters | *Planned* — see [Roadmap](#-roadmap). |

## 🚀 Quick Start

```bash
brew install zig libetpan ca-certificates 1password-cli
zig build -Doptimize=safe
cp imap.env.example imap.env        # edit: account names + op:// references
op run --env-file imap.env -- zig build itest -- <account>     # optional live check
claude mcp add --scope user imap -- op run --env-file "$PWD/imap.env" -- "$PWD/zig-out/bin/tp_imap_mcp"
```

The full walkthrough follows.

## 🏃 Running the server

### 1. Prerequisites

| Requirement | Install | Check |
|---|---|---|
| macOS on Apple Silicon | — | `uname -m` → `arm64` |
| Zig **0.17.0** | `brew install zig` | `zig version` → `0.17.0` |
| libetpan (IMAP/MIME) | `brew install libetpan` | `pkg-config --modversion libetpan` → `1.10.x` |
| CA certificates (TLS) | `brew install ca-certificates` | `ls /opt/homebrew/etc/ca-certificates/cert.pem` |
| 1Password CLI | `brew install 1password-cli` | `op --version` |
| SQLite | ships with macOS | — |

### 2. Build

```bash
git clone <this repo> tp-imap-mcp && cd tp-imap-mcp
zig build -Doptimize=safe          # optimized, keeps runtime safety checks
zig build test                     # optional: unit tests (offline)
```

The binary is `zig-out/bin/tp_imap_mcp`. MCP clients launch it by absolute path, so after rebuilding you only need to restart the client.

### 3. Store credentials in 1Password

Create one item per IMAP account (any item type works; a *Login* or *Server* item is typical) with fields for the user name and password. Find the exact field labels — they become part of the `op://` reference:

```bash
op item get "Work IMAP" --vault Private --format json | jq -r '.fields[] | "\(.label)\t\(.type)"'
```

A reference is `op://<vault>/<item>/<field>`, e.g. `op://Private/Work IMAP/password`. Check that one resolves (prints the value, so mind your screen):

```bash
op read "op://Private/Work IMAP/username"
```

> [!TIP]
> The host is not secret; you can write it in plain text instead of storing it in 1Password.

### 4. Write `imap.env`

```bash
cp imap.env.example imap.env
```

```bash
IMAP_ACCOUNTS=work,personal

IMAP_WORK_HOST=imap.example.org
IMAP_WORK_LOGIN=op://Private/Work IMAP/username
IMAP_WORK_PASSWORD=op://Private/Work IMAP/password

IMAP_PERSONAL_HOST=imap.fastmail.com
IMAP_PERSONAL_LOGIN=op://Private/Fastmail/username
IMAP_PERSONAL_PASSWORD=op://Private/Fastmail/app password
IMAP_PERSONAL_READONLY=1
```

- One `IMAP_<NAME>_*` block per name in `IMAP_ACCOUNTS`; `<NAME>` is upper-cased.
- Spaces inside `op://` references are fine in an env file — don't quote them.
- Gmail / Outlook need an **app password** (OAuth is not supported).
- See [Configuration](#-configuration) for every variable.

### 5. Check the configuration

Start the server once with no input; it validates everything, prints one line to stderr, and exits:

```bash
op run --env-file imap.env -- ./zig-out/bin/tp_imap_mcp </dev/null
# tp-imap-mcp: serving 2 account(s) on stdio; cache: /Users/you/.cache/tp-imap-mcp
```

Then run the live read-only checks against each account (they print only PASS/FAIL, never message content, and use a throwaway cache):

```bash
op run --env-file imap.env -- zig build itest -- work
# … 20 PASS lines …
# 0 failure(s)
```

### 6. Register with your MCP client

<details open>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add --scope user imap -- \
  op run --env-file /absolute/path/to/tp-imap-mcp/imap.env -- \
  /absolute/path/to/tp-imap-mcp/zig-out/bin/tp_imap_mcp

claude mcp list          # should show "imap" as connected
```

`--scope user` makes it available in every project; use `--scope project` to share it via the repo's `.mcp.json`, or `--scope local` for this directory only.

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "imap": {
      "command": "/opt/homebrew/bin/op",
      "args": ["run", "--env-file", "/absolute/path/to/tp-imap-mcp/imap.env", "--",
               "/absolute/path/to/tp-imap-mcp/zig-out/bin/tp_imap_mcp"]
    }
  }
}
```

Use absolute paths everywhere — GUI apps don't inherit your shell's `PATH`. Restart Claude Desktop.

</details>

<details>
<summary><b>Any other MCP client</b></summary>

The server speaks MCP over **stdio** (newline-delimited JSON-RPC 2.0). Configure the client to run:

```
command: op
args:    run --env-file /absolute/path/to/imap.env -- /absolute/path/to/zig-out/bin/tp_imap_mcp
```

</details>

### 7. Let 1Password unlock non-interactively

The MCP client starts the server in the background, so `op run` must be able to read secrets without a terminal prompt:

- **Desktop app integration (recommended for a personal Mac):** 1Password app → *Settings → Developer → Integrate with 1Password CLI*. `op` then asks the app, which can unlock with Touch ID when the client starts the server.
- **Service account (headless/automation):** create a service account with read access to the vault and expose `OP_SERVICE_ACCOUNT_TOKEN` to the client's environment.

If neither is set up, the client will report the server as failed to start; see [Troubleshooting](#-troubleshooting).

### 8. Try it

Ask your assistant things like:

- "List my mail accounts."
- "How many unread messages are in my work INBOX?"
- "Find emails from alice@example.org since 1 October and summarize them."
- "Flag the newest message from Bob." *(not on read-only accounts)*
- "Draft a reply to that message." *(creates a draft; it never sends mail)*

<details>
<summary>Talking to the server by hand (no MCP client)</summary>

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_accounts"}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mailboxes_status","arguments":{"account":"work","directory":"INBOX"}}}' \
| op run --env-file imap.env -- ./zig-out/bin/tp_imap_mcp
```

Or use the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (needs Node.js):

```bash
npx @modelcontextprotocol/inspector op run --env-file "$PWD/imap.env" -- "$PWD/zig-out/bin/tp_imap_mcp"
```

</details>

### 9. Day-to-day operation

| Task | How |
|---|---|
| Update after code changes | `zig build -Doptimize=safe`, then restart / reconnect the client (`/mcp` in Claude Code) |
| Add an account | Add its name to `IMAP_ACCOUNTS` and an `IMAP_<NAME>_*` block; restart the client |
| Make an account read-only | `IMAP_<NAME>_READONLY=1`; restart |
| See new folders immediately | Ask the assistant to list mailboxes with refresh, or wait for the TTL (1 h) |
| Clear cached data | Ask the assistant to clear the cache, or `rm ~/.cache/tp-imap-mcp/<account>.sqlite3*` |
| Disable the cache | `TP_IMAP_MCP_CACHE=0` |
| Logs | The server logs to **stderr**; MCP clients usually keep it in their MCP log (Claude Code: `claude --debug`) |

## ⚙️ Configuration

All configuration is environment variables (usually via `op run --env-file imap.env`).

| Variable | Required | Meaning |
|---|---|---|
| `IMAP_ACCOUNTS` | yes | Comma-separated account names, e.g. `work,personal` (`[A-Za-z0-9_]+`) |
| `IMAP_<NAME>_HOST` | yes | IMAP server host name |
| `IMAP_<NAME>_LOGIN` | yes | Login (may be `op://…`) |
| `IMAP_<NAME>_PASSWORD` | yes | Password (should be `op://…`) |
| `IMAP_<NAME>_PORT` | no | Default `993` (implicit TLS) |
| `IMAP_<NAME>_READONLY` | no | `1`/`true`/`yes` makes the account read-only |
| `IMAP_<NAME>_DRAFTS` | no | Drafts folder; default is the server's `\Drafts` folder, else `Drafts` |
| `TP_IMAP_MCP_CACHE` | no | `0` disables the on-disk cache |
| `TP_IMAP_MCP_MAILBOX_TTL` | no | Seconds the cached mailbox list stays fresh (default `3600`) |
| `TP_IMAP_MCP_CA_FILE` | no | PEM bundle for TLS verification (default `/opt/homebrew/etc/ca-certificates/cert.pem`) |
| `XDG_CACHE_HOME` | no | Cache location base (default `~/.cache`) |

`<NAME>` is the upper-cased account name. Invalid configuration stops startup with a message naming the variable — never its value.

<details>
<summary>Example <code>imap.env</code></summary>

```bash
IMAP_ACCOUNTS=work
IMAP_WORK_HOST=imap.example.org
IMAP_WORK_LOGIN=op://Private/Work IMAP/username
IMAP_WORK_PASSWORD=op://Private/Work IMAP/password
# IMAP_WORK_READONLY=1
```

</details>

## 🧰 Tools

Every tool except `list_accounts` takes an `account` argument.

| Tool | What it does |
|---|---|
| `list_accounts` | Configured accounts, logins, read-only status |
| `whoami` | The account's login |
| `list_mailboxes` | Folders matching a LIST pattern (`*`, `%`); `refresh: true` bypasses the cache |
| `mailboxes_status` | `MESSAGES`, `RECENT`, `UNSEEN` counts |
| `search` | UIDs matching IMAP SEARCH criteria (default `ALL` in `INBOX`) |
| `get_header` / `get_header_field` | Raw headers, or one field, per UID |
| `get_text` / `get_html` | Plain-text / HTML body per UID (UTF-8, LF line endings) |
| `get_size` | Message size in bytes |
| `get_keywords` / `change_keywords` | Read / add / remove IMAP flags and keywords |
| `create_message` | Append a raw RFC 822 message to the Drafts folder |
| `clear_cache` | Delete the account's local cache |

Per-UID results are aligned with the requested UIDs (`null` for UIDs that don't exist). Reading never sets `\Seen`. PGP/MIME messages are not decrypted; a marker is returned instead.

## 🔒 Security model

- **TLS:** the server certificate must chain to the CA bundle and match the configured host; otherwise the connection is refused and no credentials are sent.
- **Secrets:** only in memory, from the environment; never logged or returned by tools.
- **Command injection:** search criteria cannot contain CR/LF/NUL; UIDs, keywords, and header names are validated.
- **Read-only accounts:** write tools refuse before contacting the server.
- **Cache:** `~/.cache/tp-imap-mcp/<account>.sqlite3`, mode `0600`. It contains message headers (subjects, addresses); delete it any time or set `TP_IMAP_MCP_CACHE=0`.

## 🩺 Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `[ERROR] … item '…' does not have a field '…'` | Wrong field label in an `op://` reference — list labels with the `op item get … \| jq` command in step 3. |
| `could not find item … in vault …` | Wrong vault name, or you're signed in to a different 1Password account: `op account list`, add `--account <shorthand>` after `op run`. |
| `invalid character in secret reference` | Two variables ran together on one line (missing space/newline) — keep one `KEY=value` per line in `imap.env`. |
| Server fails to start only inside the MCP client | `op` can't unlock non-interactively — see step 7. Use absolute paths for `op` and the binary. |
| `IMAP_X is missing or empty` / `must be …` | Configuration error; the message names the variable. |
| `CA bundle … is not readable` | `brew install ca-certificates`, or point `TP_IMAP_MCP_CA_FILE` at a PEM bundle. |
| `TLS handshake … failed; the certificate is not trusted` | The server's certificate doesn't chain to your CA bundle (self-signed or private CA): add that CA to a bundle and set `TP_IMAP_MCP_CA_FILE`. |
| `the TLS certificate … is not valid for host …` | `IMAP_<NAME>_HOST` doesn't match a name in the certificate — use the host name the certificate is issued for. |
| `login failed: …` | Wrong credentials, or the provider requires an app password. |
| `cannot connect to host:port` | Host/port wrong, or port 993 blocked. Only implicit TLS (993-style) is supported, not STARTTLS. |
| A negated search (`NOT FROM "x"`) returns nothing | Some servers (seen on Dovecot) mishandle `NOT` on header keys; search the positive form instead. |
| A folder created elsewhere doesn't show up | The mailbox list is cached for an hour; ask for a refresh. |

## 🛠 Tech Stack

| Component | Technology |
|---|---|
| Language | Zig 0.17 (+ a small C shim) |
| IMAP & MIME | libetpan 1.10 (Homebrew) |
| TLS | OpenSSL (via libetpan) + Zig `std.crypto.Certificate` for host-name checks |
| Cache | SQLite (macOS system `libsqlite3`) |
| Protocol | MCP over stdio (JSON-RPC 2.0, hand-written) |

<details>
<summary>Project layout</summary>

```
src/
├── main.zig            entry point, config loading
├── mcp.zig             JSON-RPC / MCP stdio loop
├── tools.zig           tool handlers (descriptions.zig: model-facing texts)
├── accounts.zig        per-account sessions, reconnect, cache, drafts discovery
├── config.zig          environment → accounts and settings
├── validate.zig        argument validation (injection defense)
├── listmatch.zig       local LIST pattern matching
├── headers.zig, body.zig, text.zig   header/body rendering, UTF-8 handling
├── cache/              sqlite.zig (bindings), store.zig (schema, operations)
├── imap/               session.zig (Zig wrapper), c.zig (externs), mutf7.zig
├── c/                  tpi.h, session.c, mime.c — flat C API over libetpan
├── itest.zig           live integration checks
└── testdata/           MIME fixtures
docs/
├── adr/                architecture decision records (0001–0017)
└── superpowers/        design specs and implementation plans
```

</details>

<details>
<summary>Development</summary>

```bash
zig build test                                        # unit tests (offline)
op run --env-file imap.env -- zig build itest -- work # live read-only checks against an account
```

The live checks print only PASS/FAIL lines and use a throwaway cache in `.zig-cache/`.

</details>

## 🗺 Roadmap

- [x] All tools of the reference server, multi-account
- [x] 1Password-injected credentials
- [x] Verified TLS (chain, SNI, host name)
- [x] Read-only accounts
- [x] SQLite cache for mailbox list and headers/sizes (XDG)
- [ ] **Sensitive-content filters** (designed, not yet implemented)
  - Header-based filters keep sensitive messages' bodies from ever being downloaded; the model sees `[withheld by filter "password_reset"]` instead, plus only `From` and `Date`.
  - Built-in `password_reset` filter, **on by default**; enable/disable with `TP_IMAP_MCP_FILTERS` (or `none`) and per account with `IMAP_<NAME>_FILTERS`.
  - Your own filters in `~/.config/tp-imap-mcp/filters.zon`, composable from `contains`, `glob`, and `regex` conditions.
  - Design: [spec](docs/superpowers/specs/2026-10-07-sensitive-content-filters-design.md) · [ADR 0017](docs/adr/0017-sensitive-content-filters.md)
- [ ] Deferred minor issues — see [docs/TODO.md](docs/TODO.md)

## 🤝 Contributing

Decisions are recorded as ADRs in [`docs/adr/`](docs/adr/README.md); significant changes should add one. Work test-first: `zig build test` must stay green.

## 📄 License

> [!WARNING]
> No license has been chosen yet; until a `LICENSE` file is added, all rights are reserved by the author.
