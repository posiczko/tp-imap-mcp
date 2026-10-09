# tp-imap-mcp

An MCP server that lets an AI assistant read, search, and organize several IMAP
mailboxes. TLS is verified, headers are cached locally, sensitive mail is kept
from the model by filters, and credentials can come from 1Password.

Zig 0.17 · macOS (Apple Silicon) and Linux (Ubuntu) · MCP over stdio · MIT license

> [!CAUTION]
> # USE AT YOUR OWN RISK
>
> ## This is a hobby project. It is not a product, not audited, and comes with no support or warranty.
> 
> I started this project to learn Zig, but my itch of unorganized email was too real, my middle name name is 
> Impatience, so I used Claude to build it up. 
> This MCP did help me organize my voluminous email archives. It worked for me, but you should not trust me.
>
> ## Prompt injection is real.
>
> Every email the assistant reads is text written by **someone else**, and the model cannot reliably tell their instructions from yours. A crafted message can try to make your assistant leak what it has read, or — on a read/write account — flag, file or move your mail, including into Trash. This server's [sanitizing and filters](#security-model) reduce the risk; **they do not and cannot eliminate it.** Keep accounts read-only (the default) unless you need changes, and review what the assistant does (the [audit log](#7-day-to-day-operation) records every tool call).
>
> Read before pointing this at a real mailbox:
> - Simon Willison, [Prompt injection (series)](https://simonwillison.net/series/prompt-injection/)
> - Liu et al., [Prompt Injection attack against LLM-integrated Applications](https://arxiv.org/html/2306.05499v3) (arXiv 2306.05499)
>
> ## Turn it off when you are done.
>
> Once registered, the server starts with every session of your MCP client and stays running, with its tools available to the assistant — and open to prompt injection from any email it reads — until you turn it off. When you have finished with your mail, turn it off: in Claude Code, `/mcp`, pick `imap`, **Disable**. See [Day-to-day operation](#7-day-to-day-operation).

---

## Contents

- [Overview](#overview)
- [Features](#features)
- [Tech stack](#tech-stack)
- [Quick start](#quick-start)
- [Running the server](#running-the-server)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Build](#2-build)
  - [3. Write `imap.env`](#3-write-imapenv)
  - [4. Check the configuration](#4-check-the-configuration)
  - [5. Register with your MCP client](#5-register-with-your-mcp-client)
  - [6. Try it](#6-try-it)
  - [7. Day-to-day operation](#7-day-to-day-operation)
- [Configuration](#configuration)
  - [Gmail app passwords](#gmail-app-passwords)
  - [OAuth accounts](#oauth-accounts)
- [Keeping secrets in 1Password (optional)](#keeping-secrets-in-1password-optional)
- [Tools](#tools)
  - [Organizing mail](#organizing-mail)
  - [Organize my mailbox](#organize-my-mailbox)
- [Security model](#security-model)
- [TLS and certificates](#tls-and-certificates)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Colophon](#colophon)
- [License](#license)

## Overview

The tool set follows [vivier/imap-mcp-server](https://github.com/vivier/imap-mcp-server), reimplemented in Zig on top of libetpan rather than a hand-written IMAP client, with additions for running against several real mailboxes.

tp-imap-mcp exposes IMAP mailboxes to MCP clients (Claude Code, Claude Desktop, …) over stdio. IMAP and MIME come from [libetpan](https://github.com/dinhvh/libetpan); everything else is a small Zig 0.17 codebase. Configuration is environment variables, loaded from a private env file at launch; optionally, `op run` resolves `op://` references from 1Password so secrets never touch disk.

## Features

| Feature                   | Description                                                                                                                                      |
|---------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Multiple accounts         | One server process, an `account` argument on every tool.                                                                                         |
| Credentials               | Environment variables from a private (`0600`) env file — or `op://` references resolved by `op run`, keeping secrets in 1Password.               |
| Verified TLS              | Certificate chain checked against a CA bundle, SNI set, host name verified **before** the password is sent.                                      |
| Mail organization         | Create, rename/move and delete folders; move or copy messages by UID or by search criteria, with dry runs and protected system folders.          |
| Read-only by default      | Every account refuses the tools that change the mailbox until you set `IMAP_<NAME>_READONLY=0`; reads never mark mail as seen.                   |
| Local cache               | Mailbox list and message headers/sizes cached in SQLite under `~/.cache/tp-imap-mcp/`.                                                           |
| Full IMAP search          | The model's IMAP `SEARCH` criteria are passed through, with input validation against command injection.                                          |
| Sensitive-content filters | Password-reset and one-time-code emails (and anything you define) are withheld: the model learns they exist, never their content. On by default. |
| Output sanitization       | Plain text only; hidden HTML, comments, scripts and invisible Unicode removed; headers decoded; size caps — a defense against prompt injection.  |

## Tech stack

| Component   | Technology                                                                 |
|-------------|----------------------------------------------------------------------------|
| Language    | Zig 0.17 (+ a small C shim)                                                |
| IMAP & MIME | libetpan 1.10 (Homebrew)                                                   |
| TLS         | OpenSSL (via libetpan) + Zig `std.crypto.Certificate` for host-name checks |
| Cache       | SQLite (macOS system `libsqlite3`)                                         |
| Protocol    | MCP over stdio (JSON-RPC 2.0, hand-written)                                |

## Quick start

```bash
brew install zig libetpan ca-certificates                    # Ubuntu: sudo apt install libetpan-dev libsqlite3-dev ca-certificates pkg-config, plus Zig 0.17
zig build -Doptimize=safe --prefix ~/.local                  # installs ~/.local/bin/tp_imap_mcp
mkdir -p ~/.config/tp-imap-mcp
cp imap.env.example ~/.config/tp-imap-mcp/imap.env    # edit: account names, hosts, logins, passwords
chmod 600 ~/.config/tp-imap-mcp/imap.env
ln -s ~/.config/tp-imap-mcp/imap.env imap.env         # so repo commands can say ./imap.env
sh -c 'set -a; . ./imap.env; exec zig build itest -- <account>'     # optional live check
zig build install-claude-code -Doptimize=safe          # register with Claude Code (also: install-claude-desktop, install-chatgpt)
```

The server reads its configuration from environment variables; `sh -c 'set -a; . <file>; exec …'` loads them from `imap.env` and starts the command. It works the same from bash, zsh or fish. To keep passwords out of that file, store them in 1Password instead: see [Keeping secrets in 1Password](#keeping-secrets-in-1password-optional).

When you have finished, turn the server off (`/mcp` in Claude Code, pick `imap`, **Disable**); otherwise it keeps running in every session.

The full walkthrough follows.

## Running the server

### 1. Prerequisites

| Requirement                | macOS (Apple Silicon)          | Ubuntu / Debian                                                                       | Check                                                                                     |
|----------------------------|--------------------------------|---------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| Zig **0.17.0**             | `brew install zig`             | [ziglang.org/download](https://ziglang.org/download/) or `snap install zig --classic` | `zig version` → `0.17.0`                                                                  |
| libetpan (IMAP/MIME)       | `brew install libetpan`        | `apt install libetpan-dev`                                                            | `pkg-config --modversion libetpan` → `1.10.x` (macOS), `1.9.x` (Ubuntu)                   |
| CA certificates (TLS)      | `brew install ca-certificates` | `apt install ca-certificates`                                                         | `ls /opt/homebrew/etc/ca-certificates/cert.pem` / `ls /etc/ssl/certs/ca-certificates.crt` |
| SQLite, pkg-config         | ships with macOS / Homebrew    | `apt install libsqlite3-dev pkg-config`                                               | —                                                                                         |
| 1Password CLI *(optional)* | `brew install 1password-cli`   | [1Password CLI for Linux](https://developer.1password.com/docs/cli/get-started/)      | `op --version` — only for [secrets in 1Password](#keeping-secrets-in-1password-optional)  |

> [!NOTE]
> On Linux, libetpan is built with GnuTLS, which cannot check the server's certificate chain against a CA file. The server then checks the chain itself (Zig `std.crypto`) before sending any credential; this covers chain, validity and CA flags, but not revocation. See [TLS and certificates](#tls-and-certificates).

### 2. Build

```bash
git clone <this repo> tp-imap-mcp && cd tp-imap-mcp
zig build -Doptimize=safe --prefix ~/.local   # optimized, keeps runtime safety checks; installs the server
zig build test                                # optional: unit tests (offline)
```

`--prefix ~/.local` installs the server as `~/.local/bin/tp_imap_mcp`, outside the repository, so `zig build clean`, `git clean` or a fresh clone never removes the binary your MCP client runs. Without `--prefix` the binary stays in `zig-out/bin/tp_imap_mcp`, which also works if you register that path instead. MCP clients launch it by absolute path, so after reinstalling you only need to restart or reconnect the client.

### 3. Write `imap.env`

Keep it in the per-user config directory, next to `filters.zon` and `organize.md`:

```bash
mkdir -p ~/.config/tp-imap-mcp
cp imap.env.example ~/.config/tp-imap-mcp/imap.env
chmod 600 ~/.config/tp-imap-mcp/imap.env
ln -s ~/.config/tp-imap-mcp/imap.env imap.env    # optional: lets the repo commands below use ./imap.env
```

> [!NOTE]
> Why not in the repository? The MCP client starts the server from this file on every launch. In `~/.config` it survives `git clean -fdx`, a fresh clone, or deleting the checkout. A plain `imap.env` in the repository root also works (it is git-ignored); then use that path when registering the server.

> [!WARNING]
> This file holds your passwords in plain text. Keep it mode `600`, out of backups you share, and out of the repository. If that is not acceptable, put `op://` references in it instead and keep the secrets in 1Password: [Keeping secrets in 1Password](#keeping-secrets-in-1password-optional).

The example defines three accounts: a plain IMAP server, Gmail with an app
password and a Google account with XOAUTH2. Keep only the blocks you use, and
list exactly those names in `IMAP_ACCOUNTS`. A minimal file looks like this:

```bash
IMAP_ACCOUNTS=work,personal

IMAP_WORK_HOST=imap.example.org
IMAP_WORK_LOGIN=me@example.org
IMAP_WORK_PASSWORD='correct horse battery staple'
IMAP_WORK_READONLY=0          # allow changes (flags, drafts, folders, moves)

IMAP_PERSONAL_HOST=imap.fastmail.com
IMAP_PERSONAL_LOGIN=me@fastmail.com
IMAP_PERSONAL_PASSWORD='app-password-here'
# read-only: no IMAP_PERSONAL_READONLY line needed
```

- One `IMAP_<NAME>_*` block per name in `IMAP_ACCOUNTS`; `<NAME>` is upper-cased.
- Accounts are **read-only by default**: the assistant can read and search, but cannot flag, draft, create folders or move mail until you set `IMAP_<NAME>_READONLY=0` for that account.
- One `KEY=value` per line, no spaces around `=`. Put a value in **single quotes** if it contains spaces or shell characters such as `$`, `"`, `\`, `#`, `&`, `;`, `|` or a backtick. (`op run` reads the same file and strips the quotes too.)
- Gmail / Outlook: use an **app password** ([Gmail app passwords](#gmail-app-passwords)), or OAuth 2.0 (XOAUTH2) where app passwords are disabled — see [OAuth accounts](#oauth-accounts) and the [Gmail XOAUTH2 runbook](docs/runbooks/gmail-xoauth2.md).
- See [Configuration](#configuration) for every variable.

### 4. Check the configuration

Start the server once with no input; it validates everything, prints one line to stderr, and exits:

```bash
sh -c 'set -a; . ./imap.env; exec ./zig-out/bin/tp_imap_mcp' </dev/null
# tp-imap-mcp: serving 2 account(s) on stdio; cache: /Users/you/.cache/tp-imap-mcp; …; read/write: work
```

Then run the live read-only checks against each account (they print only PASS/FAIL, never message content, and use a throwaway cache):

```bash
sh -c 'set -a; . ./imap.env; exec zig build itest -- work'
# … about 30 PASS lines (more with --write and --organize) …
# 0 failure(s)
```

`--organize` adds 20 PASS lines; like `--write`, it needs the account to be read/write (`IMAP_<NAME>_READONLY=0`). It also checks the folder and move/copy tools. It creates two folders named `tp-imap-mcp-itest-<random>`, appends one test message, moves, copies and renames, and removes everything again (it never touches other folders):

```bash
sh -c 'set -a; . ./imap.env; exec zig build itest -- work --organize'
```

### 5. Register with your MCP client

One build step per client installs the server as `~/.local/bin/tp_imap_mcp` and registers it as `imap` (ADR 0024):

```bash
zig build install-claude-code    -Doptimize=safe   # Claude Code, user scope (claude mcp add-json)
zig build install-claude-desktop -Doptimize=safe   # Claude Desktop; restart it afterwards
zig build install-chatgpt        -Doptimize=safe   # ChatGPT desktop app and Codex CLI ($CODEX_HOME/config.toml)

claude mcp list                                    # Claude Code: should show "imap" as connected
```

The entry runs a small wrapper that loads `imap.env` before the server starts. The step picks it for you, writing absolute paths everywhere (GUI apps don't inherit your shell's `PATH`):

| `imap.env` contains        | The client runs                                                       |
|----------------------------|-----------------------------------------------------------------------|
| no `op://` references      | `/bin/sh -c 'set -a; . "$0"; exec "$1"' <imap.env> <tp_imap_mcp>`     |
| `op://` references         | `<op> run --env-file <imap.env> -- <tp_imap_mcp>` (1Password CLI)     |

Options: `-Dsecrets=op|envfile` overrides the choice, `-Denv-file=<path>` uses another file (default `~/.config/tp-imap-mcp/imap.env`), `-Dop=<path>` sets the 1Password CLI (default: found on `PATH`). Re-running a step replaces only the `imap` entry; other servers and settings are kept, and the previous file is saved as `<file>.bak`. `zig build uninstall-<client>` removes the entry, `zig build uninstall-local` the binary.

| Client          | Step                     | What it changes                                               | Secrets in 1Password mode                                                      |
|-----------------|--------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------|
| Claude Code     | `install-claude-code`    | `claude mcp add-json --scope user imap …`                     | `op` asks the 1Password app (Touch ID) when a session starts the server        |
| Claude Desktop  | `install-claude-desktop` | `~/Library/Application Support/Claude/claude_desktop_config.json` | needs the 1Password desktop-app integration (no terminal for a prompt)     |
| ChatGPT / Codex | `install-chatgpt`        | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`)    | as Claude Desktop                                                              |

After changing `imap.env` or re-running `tp_imap_mcp auth`, restart or reconnect the client: the server reads its configuration only when it starts.

> [!NOTE]
> Not yet verified on a real machine: that the ChatGPT desktop app reads `~/.codex/config.toml`, and that `op run` can reach the 1Password app from Claude Desktop and from inside Codex's sandbox. If a client cannot start the server, register it by hand as below.

<details>
<summary><b>Registering by hand: Claude Code</b></summary>

```bash
claude mcp add --scope user imap -- \
  sh -c 'set -a; . "$HOME/.config/tp-imap-mcp/imap.env"; exec "$HOME/.local/bin/tp_imap_mcp"'
```

`--scope user` makes it available in every project; use `--scope project` to share it via the repo's `.mcp.json`, or `--scope local` for this directory only.

</details>

<details>
<summary><b>Registering by hand: Claude Desktop</b></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "imap": {
      "command": "/bin/sh",
      "args": ["-c", "set -a; . /Users/you/.config/tp-imap-mcp/imap.env; exec /Users/you/.local/bin/tp_imap_mcp"]
    }
  }
}
```

Use absolute paths everywhere — GUI apps don't inherit your shell's `PATH` or `$HOME` expansions. Restart Claude Desktop.

</details>

<details>
<summary><b>Any other MCP client</b></summary>

The server speaks MCP over **stdio** (newline-delimited JSON-RPC 2.0). Configure the client to run:

```
command: /bin/sh
args:    -c "set -a; . /Users/you/.config/tp-imap-mcp/imap.env; exec /Users/you/.local/bin/tp_imap_mcp"
```

If the client lets you set environment variables for a server directly, you can put the `IMAP_*` variables there instead and run `/Users/you/.local/bin/tp_imap_mcp` with no wrapper.

</details>

### 6. Try it

Ask your assistant things like:

- "List my mail accounts."
- "How many unread messages are in my work INBOX?"
- "Find emails from alice@example.org since 1 October and summarize them."
- "Flag the newest message from Bob." *(read/write accounts only)*
- "Draft a reply to that message." *(creates a draft; it never sends mail)*
- "File every receipt from this year into Receipts/2026." *(read/write accounts only)*

<details>
<summary>Talking to the server by hand (no MCP client)</summary>

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_accounts"}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mailboxes_status","arguments":{"account":"work","directory":"INBOX"}}}' \
| sh -c 'set -a; . ./imap.env; exec ./zig-out/bin/tp_imap_mcp'
```

Or use the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) (needs Node.js):

```bash
npx @modelcontextprotocol/inspector sh -c 'set -a; . ./imap.env; exec ./zig-out/bin/tp_imap_mcp'
```

</details>

### 7. Day-to-day operation

Once registered, the server starts with every session of your MCP client and stays running, with its tools available to the assistant, until you turn it off. When you have finished with your mail, turn it off (see "Turn the server off" below) and turn it back on next time you need it.

| Task                        | How                                                                                                                                                            |
|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Update after code changes   | `zig build -Doptimize=safe --prefix ~/.local`, then restart / reconnect the client (`/mcp` in Claude Code)                                                     |
| Add an account              | Add its name to `IMAP_ACCOUNTS` and an `IMAP_<NAME>_*` block; restart the client                                                                               |
| Change a password           | Edit `imap.env` (or the 1Password item); restart the client                                                                                                    |
| Allow changes on an account | `IMAP_<NAME>_READONLY=0` (read-only is the default); restart                                                                                                   |
| Turn the server off         | Claude Code: `/mcp`, pick `imap`, **Disable** (**Enable** to turn it back on). Claude Desktop: remove the `imap` entry; restart                                |
| Remove the server           | `claude mcp remove imap --scope user` (the scope it was added with); re-add with the command in step 5                                                         |
| See new folders immediately | Ask the assistant to list mailboxes with refresh, or wait for the TTL (1 h)                                                                                    |
| Clear cached data           | Ask the assistant to clear the cache, or `rm ~/.cache/tp-imap-mcp/<account>.sqlite3*`                                                                          |
| Disable the cache           | `TP_IMAP_MCP_CACHE=0`                                                                                                                                          |
| Logs                        | The server logs to **stderr**; MCP clients usually keep it in their MCP log (Claude Code: `claude --debug`)                                                    |
| See what the MCP did        | Every tool call is in `~/.local/state/tp-imap-mcp/audit.log` (JSON Lines), e.g. `grep '"rename_mailbox\|"delete_mailbox' ~/.local/state/tp-imap-mcp/audit.log` |

## Configuration

All configuration is environment variables, usually loaded from `~/.config/tp-imap-mcp/imap.env` (see [Write `imap.env`](#3-write-imapenv)). Any value may instead be an `op://` reference when you launch through `op run` ([1Password](#keeping-secrets-in-1password-optional)).

| Variable                                             | Required      | Meaning                                                                                                                                        |
|------------------------------------------------------|---------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| `IMAP_ACCOUNTS`                                      | yes           | Comma-separated account names, e.g. `work,personal` (`[A-Za-z0-9_]+`)                                                                          |
| `IMAP_<NAME>_HOST`                                   | yes           | IMAP server host name                                                                                                                          |
| `IMAP_<NAME>_LOGIN`                                  | yes           | Login                                                                                                                                          |
| `IMAP_<NAME>_PASSWORD`                               | password auth | Password; must not be set with `AUTH=oauth2`                                                                                                   |
| `IMAP_<NAME>_AUTH`                                   | no            | `password` (default) or `oauth2` — see [OAuth accounts](#oauth-accounts)                                                                       |
| `IMAP_<NAME>_OAUTH_PROVIDER`                         | oauth2        | `google`, `microsoft`, or `custom`                                                                                                             |
| `IMAP_<NAME>_OAUTH_CLIENT_ID`                        | oauth2        | OAuth client ID                                                                                                                                |
| `IMAP_<NAME>_OAUTH_CLIENT_SECRET`                    | google        | OAuth client secret (optional for Microsoft)                                                                                                   |
| `IMAP_<NAME>_OAUTH_REFRESH_TOKEN`                    | oauth2        | From `tp_imap_mcp auth <account>`                                                                                                              |
| `IMAP_<NAME>_OAUTH_TENANT`                           | no            | Microsoft tenant (default `common`)                                                                                                            |
| `IMAP_<NAME>_OAUTH_AUTH_URL`, `_TOKEN_URL`, `_SCOPE` | custom        | Endpoints (https) and scopes for a custom provider                                                                                             |
| `IMAP_<NAME>_PORT`                                   | no            | Default `993` (implicit TLS)                                                                                                                   |
| `IMAP_<NAME>_READONLY`                               | no            | Default read-only; `0`/`false`/`no` allows changes (`1`/`true`/`yes` is read-only)                                                             |
| `IMAP_<NAME>_DRAFTS`                                 | no            | Drafts folder; default is the server's `\Drafts` folder, else `Drafts`                                                                         |
| `TP_IMAP_MCP_CACHE`                                  | no            | `0` disables the on-disk cache                                                                                                                 |
| `TP_IMAP_MCP_MAILBOX_TTL`                            | no            | Seconds the cached mailbox list stays fresh (default `3600`)                                                                                   |
| `TP_IMAP_MCP_CA_FILE`                                | no            | PEM bundle for TLS verification (default `/opt/homebrew/etc/ca-certificates/cert.pem` on macOS, `/etc/ssl/certs/ca-certificates.crt` on Linux) |
| `XDG_CACHE_HOME`                                     | no            | Cache location base (default `~/.cache`)                                                                                                       |
| `TP_IMAP_MCP_FILTERS`                                | no            | Active sensitive-content filters, comma-separated, or `none` (default `password_reset,one_time_codes`)                                         |
| `IMAP_<NAME>_FILTERS`                                | no            | Per-account override of `TP_IMAP_MCP_FILTERS`                                                                                                  |
| `XDG_CONFIG_HOME`                                    | no            | Config location base for `filters.zon` (default `~/.config`)                                                                                   |
| `TP_IMAP_MCP_MAX_BODY_BYTES`                         | no            | Max bytes per message body after sanitizing (default `32768`, min `1024`)                                                                      |
| `TP_IMAP_MCP_MAX_RESPONSE_BYTES`                     | no            | Size budget per per-UID tool response (default `131072`, min `1024`)                                                                           |
| `TP_IMAP_MCP_AUDIT`                                  | no            | `0` disables the audit log of tool calls                                                                                                       |
| `TP_IMAP_MCP_AUDIT_FILE`                             | no            | Audit log path, absolute (default `$XDG_STATE_HOME/tp-imap-mcp/audit.log`, i.e. `~/.local/state/…`)                                            |

`<NAME>` is the upper-cased account name. Invalid configuration stops startup with a message naming the variable — never its value.

<details>
<summary>Example <code>imap.env</code></summary>

```bash
IMAP_ACCOUNTS=work
IMAP_WORK_HOST=imap.example.org
IMAP_WORK_LOGIN=me@example.org
IMAP_WORK_PASSWORD='correct horse battery staple'
# IMAP_WORK_READONLY=0       # uncomment to allow changes
```

</details>

<details>
<summary>Custom filters: <code>~/.config/tp-imap-mcp/filters.zon</code></summary>

```zig
.{
    .filters = .{
        .{
            .name = "banking",
            .rules = .{
                // a rule matches when ALL its conditions hold; a filter when ANY rule matches
                .{ .{ .field = "from", .glob = .{ "*@chase.com", "*@schwab.com" } } },
                .{
                    .{ .field = "from", .glob = .{"*@paypal.com"} },
                    .{ .field = "subject", .regex = .{"(receipt|statement)"} },
                },
            },
        },
        // same name as a built-in replaces it
        .{ .name = "password_reset", .rules = .{ .{ .{ .field = "subject", .contains = .{ "password reset", "passwort" } } } } },
    },
}
```

- Each condition sets exactly one of `.contains` (case-insensitive substring), `.glob` (`*`/`?`, also matches the address inside `Name <addr>`), or `.regex` (POSIX extended, case-insensitive).
- Headers are RFC 2047-decoded before matching; bodies are never inspected (or downloaded) to decide.
- Defining a filter doesn't enable it — list it in `TP_IMAP_MCP_FILTERS` / `IMAP_<NAME>_FILTERS`.
- Any error in the file (syntax, unknown key, bad regex) stops startup with the file, filter, rule and condition named. Restart after editing.

</details>

### Gmail app passwords

Gmail no longer accepts your normal Google password over IMAP. Without OAuth, the alternative is an **app password**: a 16-character password that only works for this one client. The server logs in with it like any other password (`AUTH=password`, the default).

1. Turn on [2-Step Verification](https://myaccount.google.com/signinoptions/two-step-verification) for the Google account.
2. Make sure IMAP is enabled in Gmail: **Settings → See all settings → Forwarding and POP/IMAP**.
3. Create the password at [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords). Give it a name like `tp-imap-mcp`. Google shows it only once.
4. Put it in `imap.env` as `IMAP_<NAME>_PASSWORD`. Quote it, since Google displays it with spaces. Better still, store it in 1Password and reference it with `op://`.

```bash
IMAP_GMAIL_HOST=imap.gmail.com
IMAP_GMAIL_LOGIN=you@gmail.com
IMAP_GMAIL_PASSWORD='abcd efgh ijkl mnop'
IMAP_GMAIL_DRAFTS=[Gmail]/Drafts
```

> [!IMPORTANT]
> Changing your main Google password revokes all app passwords. If that happens, create a new one; until then, logins fail with `login failed`. An app password gives full access to the mailbox and can't be limited, so treat it like your main password. Revoke it on the same page when you no longer need it.

App passwords aren't always available. They're blocked under the Advanced Protection Program, may not be offered on accounts that use only security keys for 2-Step Verification, and Google Workspace admins can turn them off. In those cases, use [OAuth](#oauth-accounts).

### OAuth accounts

Microsoft 365 / Outlook.com (where IMAP passwords are usually disabled) and Gmail can use OAuth 2.0 (XOAUTH2) instead of a password:

1. Register an OAuth app with the provider — step by step for Gmail: [docs/runbooks/gmail-xoauth2.md](docs/runbooks/gmail-xoauth2.md). Microsoft: an Entra ID app ("Mobile and desktop applications", redirect `http://127.0.0.1`, permissions `IMAP.AccessAsUser.All` + `offline_access`).
2. Put `IMAP_<NAME>_AUTH=oauth2`, the provider, and the client ID and secret in `imap.env`.
3. Run `tp_imap_mcp auth <account>` (below): your browser opens, you consent, and the refresh token is printed once on stdout. Add it to `imap.env` as `IMAP_<NAME>_OAUTH_REFRESH_TOKEN`.

```bash
sh -c 'set -a; . ./imap.env; exec ~/.local/bin/tp_imap_mcp auth work' | pbcopy   # token → clipboard
# then paste it into imap.env:  IMAP_WORK_OAUTH_REFRESH_TOKEN=<paste>
```

Only the token goes to stdout (instructions go to the terminal), so `| pbcopy` copies it without showing it. Run `auth` again whenever the token expires.

> [!NOTE]
> Each OAuth account needs its own refresh token, and so its own `auth` run. In the browser, choose the account that matches `IMAP_<NAME>_LOGIN`. Several accounts may share one OAuth client. The server refuses to start while an OAuth account has no refresh token (`auth` itself does not need one). Never set `IMAP_<NAME>_PASSWORD` on an OAuth account.

A Google Workspace account next to a personal Gmail account that uses an app password:

```bash
IMAP_ACCOUNTS=work,gmail

IMAP_WORK_HOST=imap.gmail.com
IMAP_WORK_LOGIN=you@work.example
IMAP_WORK_AUTH=oauth2
IMAP_WORK_OAUTH_PROVIDER=google
IMAP_WORK_OAUTH_CLIENT_ID=1234-abc.apps.googleusercontent.com
IMAP_WORK_OAUTH_CLIENT_SECRET=GOCSPX-…
IMAP_WORK_OAUTH_REFRESH_TOKEN=1//0g…
IMAP_WORK_DRAFTS=[Gmail]/Drafts

IMAP_GMAIL_HOST=imap.gmail.com
IMAP_GMAIL_LOGIN=you@gmail.com
IMAP_GMAIL_PASSWORD='abcd efgh ijkl mnop'
IMAP_GMAIL_DRAFTS=[Gmail]/Drafts
```

For Microsoft 365, set `IMAP_<NAME>_HOST=outlook.office365.com`, `IMAP_<NAME>_OAUTH_PROVIDER=microsoft` and, optionally, `IMAP_<NAME>_OAUTH_TENANT` (default `common`). The client secret is optional for Microsoft.

Access tokens are refreshed automatically and kept only in memory. When a refresh token expires (Microsoft ~90 days; Google apps in *Testing* 7 days), tools report it and tell you to run `auth` again.

## Keeping secrets in 1Password (optional)

Instead of writing passwords and tokens into `imap.env`, write [1Password secret references](https://developer.1password.com/docs/cli/secret-references/) (`op://<vault>/<item>/<field>`) and start every command through `op run`, which resolves them into the environment just before the process starts. The file then holds no secrets, and nothing secret is written to disk.

**1. Install the CLI and let it unlock without a terminal.** The MCP client starts the server in the background, so `op` must read secrets without a prompt:

```bash
brew install 1password-cli
```

- **Desktop app integration (recommended for a personal Mac):** 1Password app → *Settings → Developer → Integrate with 1Password CLI*. `op` then asks the app, which can unlock with Touch ID when the client starts the server.
- **Service account (headless/automation):** create a service account with read access to the vault and expose `OP_SERVICE_ACCOUNT_TOKEN` to the client's environment.

**2. Store the credentials.** Create one item per IMAP account (a *Login* or *Server* item is typical) with fields for the user name and password. Find the exact field labels — they become part of the reference:

```bash
op item get "Work IMAP" --vault Private --format json | jq -r '.fields[] | "\(.label)\t\(.type)"'
op read "op://Private/Work IMAP/username"     # check one resolves (prints the value — mind your screen)
```

**3. Put references in `imap.env`.** Plain values and references can be mixed; the host, for example, is not secret. Quote references that contain spaces, as with any value:

```bash
IMAP_ACCOUNTS=work
IMAP_WORK_HOST=imap.example.org
IMAP_WORK_LOGIN='op://Private/Work IMAP/username'
IMAP_WORK_PASSWORD='op://Private/Work IMAP/password'
```

**4. Run commands through `op run`.** Wherever this README runs `sh -c 'set -a; . FILE; exec COMMAND'`, run `op run --env-file FILE -- COMMAND` instead:

| Task                           | With 1Password                                                                                                                                             |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Check the configuration        | `op run --env-file imap.env -- ./zig-out/bin/tp_imap_mcp </dev/null`                                                                                       |
| Live checks                    | `op run --env-file imap.env -- zig build itest -- work`                                                                                                    |
| Register with a client         | `zig build install-claude-code` (or `-claude-desktop`, `-chatgpt`): it sees the `op://` references and registers `op run` with absolute paths             |
| Register with Claude Code      | `claude mcp add --scope user imap -- op run --env-file "$HOME/.config/tp-imap-mcp/imap.env" -- "$HOME/.local/bin/tp_imap_mcp"`                             |
| Claude Desktop / other clients | `"command": "/opt/homebrew/bin/op"`, `"args": ["run", "--env-file", "/Users/you/.config/tp-imap-mcp/imap.env", "--", "/Users/you/.local/bin/tp_imap_mcp"]` |
| OAuth `auth`                   | `op run --env-file imap.env -- ~/.local/bin/tp_imap_mcp auth work \| pbcopy`                                                                               |

**5. OAuth refresh tokens.** Paste the token from `auth` into a password field of the item in the **1Password app**, and reference it as `IMAP_<NAME>_OAUTH_REFRESH_TOKEN='op://…/refresh token'`. Don't pass it to `op item edit` on the command line: it would stay in your shell history and be visible to other processes. `op run` fails on a reference to a field that does not exist yet, so keep that line commented out until the field exists.

| Symptom                                                              | Cause / fix                                                                                                                            |
|----------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `[ERROR] … item '…' does not have a field '…'`                       | Wrong field label in an `op://` reference — list labels with the `op item get … \| jq` command above.                                  |
| `could not find item … in vault …` / `isn't a vault in this account` | Wrong vault name, or you're signed in to a different 1Password account: `op account list`, add `--account <shorthand>` after `op run`. |
| `invalid character in secret reference`                              | Two variables ran together on one line (missing newline) — keep one `KEY=value` per line.                                              |
| `error initializing client: authorization timeout`                   | Approve the 1Password prompt (Touch ID) in time, or unlock 1Password first.                                                            |
| Server fails to start only inside the MCP client                     | `op` can't unlock non-interactively — see step 1. Use absolute paths for `op` and the binary in GUI clients.                           |

## Tools

Every tool except `list_accounts` takes an `account` argument.

| Tool                               | What it does                                                                                      |
|------------------------------------|---------------------------------------------------------------------------------------------------|
| `list_accounts`                    | Configured accounts, logins, read-only status                                                     |
| `whoami`                           | The account's login                                                                               |
| `list_mailboxes`                   | Folders matching a LIST pattern (`*`, `%`); `refresh: true` bypasses the cache                    |
| `mailboxes_status`                 | `MESSAGES`, `RECENT`, `UNSEEN` counts                                                             |
| `search`                           | UIDs matching IMAP SEARCH criteria (default `ALL` in `INBOX`)                                     |
| `get_header` / `get_header_field`  | Raw headers, or one field, per UID                                                                |
| `get_text` / `get_html`            | Message body per UID as sanitized plain text (`get_text` prefers the plain-text part)             |
| `list_attachments`                 | Attachments per UID: file name, type, approximate size, inline flag — content is never downloaded |
| `get_size`                         | Message size in bytes                                                                             |
| `get_keywords` / `change_keywords` | Read / add / remove IMAP flags and keywords                                                       |
| `create_message`                   | Append a raw RFC 822 message to the Drafts folder                                                 |
| `create_mailbox`                   | Create a folder (and subscribe to it)                                                             |
| `rename_mailbox`                   | Rename a folder or move it under another parent                                                   |
| `delete_mailbox`                   | Delete an empty folder                                                                            |
| `move_messages` / `copy_messages`  | Move or copy messages by `uids` or by search `criteria`; criteria default to a dry run            |
| `organize_mailbox`                 | Gather the organizing instructions, folders and newest messages for the model to classify         |
| `apply_organization`               | Preview (dry run) or carry out the model's per-message plan: move, delete (to Trash), flag, keep  |
| `clear_cache`                      | Delete the account's local cache                                                                  |

Per-UID results are aligned with the requested UIDs (`null` for UIDs that don't exist). Reading never sets `\Seen`. PGP/MIME messages are not decrypted; a marker is returned instead.

What the model sees, after filtering and sanitizing:

| Situation                         | Output                                                                                                                      |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| Message matched by a filter       | `get_text`/`get_html`: `[withheld by filter "password_reset"]`; `get_header`: only `date`, `from`, `x-tp-imap-mcp-withheld` |
| HTML email                        | Plain text; links as `text (https://…)`; hidden elements, comments, scripts, images dropped                                 |
| Long body                         | Cut at 32 KiB with `[truncated: N bytes omitted]`                                                                           |
| Too many UIDs at once             | Later items become `[omitted: response size limit reached; request fewer UIDs]`                                             |
| Encoded headers (`=?UTF-8?B?…?=`) | Decoded, invisible characters removed, 2 KiB max per value                                                                  |

### Organizing mail

The folder and move/copy tools ([ADR 0021](docs/adr/0021-mailbox-organization-tools.md)) follow a few rules:

- **Bulk moves are previewed.** With `criteria`, `move_messages` and `copy_messages` only report the match count and the first 100 UIDs, unless `dry_run=false` is passed. With `uids` they act immediately. At most 5000 messages per call.
- **Safe moves.** `MOVE` is used when the server supports it, otherwise `COPY` + `\Deleted` + `UID EXPUNGE` of exactly those messages. A server with neither MOVE nor UIDPLUS cannot move messages (copy still works).
- **Protected folders.** INBOX, folders the server marks as special-use (Sent, Drafts, Trash, Junk/Spam, Archive, All Mail, …), the configured drafts folder used by `create_message`, and folders containing them are never renamed or deleted. Nothing is created inside Gmail's `[Gmail]/` tree. Messages *can* be moved to Trash or Spam; the result notes that those folders are purged automatically.
- **Only empty folders are deleted.** Move the messages and subfolders out first.
- **Missing destinations** are an error unless `create_missing=true`.
- **Gmail:** folders are labels. Moving out of INBOX archives the message and applies the label; copying adds a label; every message stays in `[Gmail]/All Mail`. Moving out of All Mail is refused (use `copy_messages` to add a label).

A typical exchange: *"Move all newsletters from news@example.com in INBOX to Newsletters"* → the assistant runs a dry run (`matched: 42`), shows you the count, then repeats the call with `dry_run=false`.

### Organize my mailbox

Ask *"organize my inbox"*, or in Claude Code run `/mcp__tp-imap-mcp__organize_my_mailbox` ([ADR 0022](docs/adr/0022-organize-mailbox-two-phase-plan.md)):

1. `organize_mailbox` returns your organizing instructions, your folders and the newest 30 messages (sanitized headers plus a short snippet; messages hidden by a filter show only date and sender).
2. The assistant classifies each message: **move** to a folder, **delete** (moved to Trash, never erased), **flag** (needs your attention), or **keep**.
3. `apply_organization` shows the plan grouped by action, as a dry run. Nothing changes.
4. Only after you confirm does it run again with `execute=true` and the dry run's `plan_hash`. A changed plan needs a new dry run.

Kept and flagged messages get the keyword `$TpOrganized`, so the next run continues with messages it has not seen. Withheld messages (password resets, codes) are always kept; the server refuses anything else for them.

Write your own instructions in `~/.config/tp-imap-mcp/organize.md`, or `organize.<account>.md` for one account (Markdown, at most 16 KiB, read on every run). Without one, the built-in [default](src/organize_prompt.md) is used. A short example:

```markdown
# How to organize my mail
- Receipts and order confirmations go to "Receipts/2026".
- Newsletters I read: move to "Newsletters". Other marketing: delete.
- Anything from my accountant or my bank: flag.
- Never touch password, login or verification emails: keep.
- When unsure: keep.
```

## Security model

- **TLS:** the server certificate must chain to the CA bundle and match the configured host; otherwise the connection is refused and no credentials are sent. See [TLS and certificates](#tls-and-certificates).
- **Secrets:** the server reads them from its environment and never logs or returns them. In `imap.env` they are plain text on disk (mode `0600`); with [1Password references](#keeping-secrets-in-1password-optional) the file holds none and `op run` passes them only to the process. In memory, the server wipes token buffers and its own copies when done; the environment copy lives as long as the process.
- **Command injection:** search criteria cannot contain CR/LF/NUL; UIDs, keywords, and header names are validated.
- **Read-only accounts:** accounts are read-only unless `IMAP_<NAME>_READONLY=0`; write tools refuse before contacting the server (dry runs of `move_messages` / `copy_messages` / `apply_organization` are allowed).
- **Organizing:** see [Organizing mail](#organizing-mail): previews for bulk moves, no plain `EXPUNGE`, protected system folders, and no automatic retry of a folder or move/copy command after a dropped connection.
- **Cache:** `~/.cache/tp-imap-mcp/<account>.sqlite3`, mode `0600`. It contains message headers (subjects, addresses); delete it any time or set `TP_IMAP_MCP_CACHE=0`.
- **Audit log:** `~/.local/state/tp-imap-mcp/audit.log`, mode `0600`: one JSON line per tool call with its arguments (search criteria and folder names included), outcome and duration. Changes are logged with their result; reads only with the result's size, so no message content is written. Rotates at 10 MB (two old files kept); `TP_IMAP_MCP_AUDIT=0` disables it. See ADR 0023.
- **Sensitive mail:** filtered messages' bodies are never downloaded; their subjects are never shown.
- **Prompt injection:** output is plain text with hidden HTML content and invisible Unicode removed. Text hidden only by CSS colour (white on white) or off-screen positioning is *not* detected.

## TLS and certificates

The server only speaks IMAP over implicit TLS (port 993 by default); STARTTLS on port 143 is not supported. Before it sends a password or OAuth token, it checks that it is talking to the server you configured:

1. **Chain of trust.** The server's certificate must be signed, possibly through intermediate certificates, by a certificate authority (CA) in a trusted bundle. Every certificate in the chain must be within its validity dates, and every certificate that signs another must be a CA.
2. **Host name.** The server's own certificate must be issued for `IMAP_<NAME>_HOST` (its DNS or IP subject alternative names, else its common name).
3. **SNI.** The host name is sent in the TLS handshake, so servers that host several domains present the right certificate.

If any check fails, the connection is closed and nothing is sent. The tool error says which check failed: `the certificate is not trusted by <bundle>` or `the TLS certificate … is not valid for host …`.

**The CA bundle** is a PEM file of trusted root certificates, the same kind your operating system and browser use:

| Platform | Default bundle                               | Provided by                                          |
|----------|----------------------------------------------|------------------------------------------------------|
| macOS    | `/opt/homebrew/etc/ca-certificates/cert.pem` | `brew install ca-certificates` (Mozilla's root list) |
| Linux    | `/etc/ssl/certs/ca-certificates.crt`         | `apt install ca-certificates`                        |

`TP_IMAP_MCP_CA_FILE` points at a different bundle. The same bundle is used for OAuth token requests (HTTPS).

**Who checks what.** On macOS, libetpan's OpenSSL backend checks the chain during the handshake. On Linux, distributions build libetpan with GnuTLS, which cannot take a CA file; the handshake then completes unchecked, and the server checks the chain itself with Zig's `std.crypto` before going further. The host-name check is always done by the server. Neither path checks revocation (CRL/OCSP), so a revoked but unexpired certificate is still accepted; on Linux, name and policy constraints are not checked either. Details: ADR 0016.

**Self-signed or private-CA servers** (a home server, a company CA) are refused with the default bundle. Add their CA to a bundle of your own instead of turning checks off (there is no switch for that):

```bash
cat /opt/homebrew/etc/ca-certificates/cert.pem my-ca.pem > ~/.config/tp-imap-mcp/ca.pem   # Linux: /etc/ssl/certs/ca-certificates.crt
# in imap.env:
TP_IMAP_MCP_CA_FILE=/Users/you/.config/tp-imap-mcp/ca.pem
```

`my-ca.pem` is the CA that signed the server's certificate, not the server's certificate itself. To see what a server presents:

```bash
openssl s_client -connect imap.example.org:993 -servername imap.example.org -showcerts </dev/null
```

Connect by the name on the certificate: `IMAP_<NAME>_HOST=mail.example.org` works for a certificate issued to `mail.example.org`, but an IP address or another alias of the same machine does not, unless the certificate lists it too.

## Troubleshooting

| Symptom                                                              | Cause / fix                                                                                                                                                                                                            |
|----------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `imap.env: line N: …: command not found`                             | A value on line N contains a space or shell character and is not quoted — put it in single quotes.                                                                                                                     |
| `imap.env: No such file or directory`                                | Wrong path in the `sh -c` command; GUI clients need absolute paths (no `~` or `$HOME`).                                                                                                                                |
| Server fails to start only inside the MCP client                     | Use absolute paths for the env file and the binary; with 1Password, see [its troubleshooting](#keeping-secrets-in-1password-optional).                                                                                 |
| `IMAP_X is missing or empty` / `must be …`                           | Configuration error; the message names the variable.                                                                                                                                                                   |
| `CA bundle … is not readable`                                        | `brew install ca-certificates` (macOS) or `apt install ca-certificates` (Linux), or point `TP_IMAP_MCP_CA_FILE` at a PEM bundle.                                                                                       |
| `TLS handshake … failed; the certificate is not trusted`             | The server's certificate doesn't chain to your CA bundle (self-signed or private CA): add that CA to a bundle and set `TP_IMAP_MCP_CA_FILE`.                                                                           |
| `the TLS certificate … is not valid for host …`                      | `IMAP_<NAME>_HOST` doesn't match a name in the certificate — use the host name the certificate is issued for.                                                                                                          |
| `account "x" is read-only; set IMAP_X_READONLY=0 to allow changes`   | Accounts are read-only by default; add `IMAP_X_READONLY=0` to `imap.env` and restart the client.                                                                                                                       |
| `login failed: …`                                                    | Wrong credentials, or the provider requires an app password (or OAuth).                                                                                                                                                |
| `the OAuth refresh token was rejected (expired or revoked)`          | Run `auth` again ([OAuth accounts](#oauth-accounts)) and replace the stored token.                                                                                                                                     |
| `cannot connect to host:port`                                        | Host/port wrong, or port 993 blocked. Only implicit TLS (993-style) is supported, not STARTTLS.                                                                                                                        |
| A negated search (`NOT FROM "x"`) returns nothing                    | Some servers (seen on Dovecot) mishandle `NOT` on header keys; search the positive form instead.                                                                                                                       |
| A folder created elsewhere doesn't show up                           | The mailbox list is cached for an hour; ask for a refresh.                                                                                                                                                             |
| `TP_IMAP_MCP_FILTERS: unknown filter "x"`                            | The name isn't built in or defined in `filters.zon`; fix the name or use `none`.                                                                                                                                       |
| `…/filters.zon: filter "x" rule N condition M: …`                    | Fix the named rule (exactly one of `.contains`/`.glob`/`.regex`, non-empty patterns, valid regex) and restart.                                                                                                         |
| `… is a special-use folder (\Sent) and cannot be renamed or deleted` | Working as intended (ADR 0021); reorganize system folders in your mail client.                                                                                                                                         |
| `the server supports neither MOVE nor UIDPLUS…`                      | The server cannot move messages safely; use `copy_messages` and delete the originals in your mail client.                                                                                                              |
| `connection lost while moving or copying messages…`                  | The outcome is unknown; search both folders before retrying.                                                                                                                                                           |
| An email shows `[withheld by filter "…"]`                            | Working as intended. Disable for an account with `IMAP_<NAME>_FILTERS=none` (or keep just one, e.g. `IMAP_<NAME>_FILTERS=password_reset` to let the assistant read login codes), or narrow the rules in `filters.zon`. |
| `… must be a number of bytes >= 1024`                                | Fix `TP_IMAP_MCP_MAX_BODY_BYTES` / `TP_IMAP_MCP_MAX_RESPONSE_BYTES`.                                                                                                                                                   |


<details>
<summary>Project layout</summary>

```
src/
├── main.zig            entry point, config loading
├── mcp.zig             JSON-RPC / MCP stdio loop
├── tools.zig           tool handlers (descriptions.zig: model-facing texts)
├── organize.zig        folder protection, move strategy, batching (ADR 0021)
├── triage.zig          organize_mailbox / apply_organization rules (ADR 0022)
├── organize_prompt.md  built-in organizing instructions
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
├── adr/                architecture decision records (0001–0020)
├── runbooks/           step-by-step operational guides (e.g. Gmail XOAUTH2)
└── superpowers/        design specs and implementation plans
```

</details>

<details>
<summary>Development</summary>

```bash
zig build test                                                # unit tests (offline)
sh -c 'set -a; . ./imap.env; exec zig build itest -- work'   # live read-only checks against an account
zig build clean                                               # remove zig-out and .zig-cache (the ~/.local install is untouched)
```

The live checks print only PASS/FAIL lines and use a throwaway cache in `.zig-cache/`.

CI (`.github/workflows/ci.yml`) runs the unit tests, an optimized build, and a startup smoke test on Apple Silicon macOS and on Ubuntu for every push and pull request, with Zig pinned to 0.17.0 (checksum-verified). The live checks are not run in CI because they need your mail credentials.

</details>

## Roadmap

- [x] All tools of the reference server, multi-account
- [x] Credentials from environment variables, optionally from 1Password
- [x] Verified TLS (chain, SNI, host name)
- [x] Read-only accounts (the default)
- [x] SQLite cache for mailbox list and headers/sizes (XDG)
- [x] Sensitive-content filters — [spec](docs/superpowers/specs/2026-10-07-sensitive-content-filters-design.md) · [ADR 0017](docs/adr/0017-sensitive-content-filters.md)
- [x] Output sanitization — [spec](docs/superpowers/specs/2026-10-07-output-sanitization-design.md) · [ADR 0018](docs/adr/0018-sanitize-model-bound-output.md) · [ADR 0019](docs/adr/0019-decoded-sanitized-header-values.md)
- [x] Attachment listing (`list_attachments`, metadata only)
- [x] **OAuth (XOAUTH2)** for Microsoft 365 / Outlook.com and Gmail — [spec](docs/superpowers/specs/2026-10-07-oauth2-design.md) · [ADR 0020](docs/adr/0020-xoauth2-with-refresh-tokens-in-1password.md) · [Gmail runbook](docs/runbooks/gmail-xoauth2.md)
- [x] Built-in `one_time_codes` filter (2FA codes, sign-in links, verification emails), on by default
- [x] Mail organization: folders and move/copy — [spec](docs/superpowers/specs/2026-10-08-mailbox-organization-design.md) · [ADR 0021](docs/adr/0021-mailbox-organization-tools.md)
- [x] Organize my mailbox: model-classified plan with dry run and confirmation — [spec](docs/superpowers/specs/2026-10-08-organize-mailbox-design.md) · [ADR 0022](docs/adr/0022-organize-mailbox-two-phase-plan.md)
- [ ] Deferred minor issues — see [docs/TODO.md](docs/TODO.md)

## Contributing

Decisions are recorded as ADRs in [`docs/adr/`](docs/adr/README.md); significant changes should add one. Work test-first: `zig build test` must stay green.

Git hooks guard against leaking credentials. Install them once per clone:

```sh
brew install prek gitleaks actionlint zizmor
prek install          # pre-commit and pre-push, per .pre-commit-config.yaml
prek run --all-files  # optional: check the whole tree now
```

On commit, [gitleaks](https://github.com/gitleaks/gitleaks) scans the staged diff, private keys and env files such as `imap.env` are refused, and files over 512 KB are flagged. On push, gitleaks scans the whole history, and actionlint and zizmor check the GitHub Actions workflows for mistakes and security problems.

## Colophon

* Zig, because I'm learning it right now and I wanted to see what Claude would come up with.
* Used Claude Code with [Superpowers plugin](https://github.com/obra/superpowers). I wanted to evaluate a small 
  project against BMAD and Spec Kit.
* I always use ADRs to keep track of decisions.

## License

[MIT](LICENSE)
