# Runbook: Gmail with XOAUTH2

Set up a Gmail account in tp-imap-mcp using OAuth 2.0 (SASL XOAUTH2) instead
of an app password. Design: [spec](../superpowers/specs/2026-10-07-oauth2-design.md),
[ADR 0020](../adr/0020-xoauth2-with-refresh-tokens-in-1password.md).

> [!WARNING]
> While your Google OAuth app is in **Testing** status, Google expires its
> refresh tokens after **7 days**. You will repeat step 6 weekly unless you
> publish the app (see [Keeping access beyond 7 days](#keeping-access-beyond-7-days)).
> If that is not acceptable, an [app password](https://myaccount.google.com/apppasswords)
> with `IMAP_<NAME>_AUTH=password` is the simpler choice.

**Time:** about 15 minutes. **You need:** a Google account (Gmail or Google
Workspace), access to [Google Cloud Console](https://console.cloud.google.com/),
and a tp-imap-mcp build (the 1Password CLI `op` only if you keep secrets in
1Password).

Throughout, the account is called `gmail` (env prefix `IMAP_GMAIL_`), and
`imap.env` is the file from the README (`~/.config/tp-imap-mcp/imap.env`,
symlinked into the repository). Substitute your own names. Secrets go into
`imap.env` by default; to keep them in 1Password instead, follow
[With 1Password](#with-1password) alongside steps 5–7.

---

## 1. Create a Google Cloud project

1. Open <https://console.cloud.google.com/> and sign in with the Google account
   whose mail you want to read (or any account you administer).
2. Project picker → **New project** → name it e.g. `tp-imap-mcp` → **Create**.
3. Make sure the new project is selected in the picker.
4. **APIs & Services → Library** → search **Gmail API** → **Enable**. tp-imap-mcp
   only uses IMAP (it never calls the Gmail REST API), but the scope picker in
   step 2.4 lists `https://mail.google.com/` only for enabled APIs.

## 2. Configure the OAuth consent screen

Google Cloud Console → **Google Auth Platform** (older UI: *APIs & Services →
OAuth consent screen*).

1. **Branding:** app name `tp-imap-mcp`, user support email = your address,
   developer contact = your address. Save.
2. **Audience:** user type **External** (or **Internal** for a Workspace
   account used only inside your organization — internal apps have no 7-day
   limit). Leave the publishing status as **Testing** for now.
3. **Audience → Test users:** **Add users** → your Gmail address. Only listed
   test users can authorize a Testing app.
4. **Data access:** **Add or remove scopes** → add
   `https://mail.google.com/` (listed as a *restricted* scope: "Read, compose,
   send, and permanently delete all your email from Gmail"). If it is not in
   the list, the Gmail API is not enabled (step 1.4) — or paste the scope into
   **Manually add scopes** at the bottom of the dialog. Save.

## 3. Create the OAuth client

Google Auth Platform → **Clients** → **Create client**:

- **Application type:** **Desktop app** (required: Desktop clients accept the
  `http://127.0.0.1:<port>/` loopback redirect tp-imap-mcp uses, with no
  redirect URI to register).
  Newer consoles may first ask whether the client is for an **AI agent / MCP
  client**; answering yes creates a Desktop client directly, without asking
  for a redirect URI. Either way, the downloaded JSON must have a top-level
  `"installed"` key (a `"web"` key means the wrong type).
- **Name:** `tp-imap-mcp`.
- **Create**, then copy the **Client ID** and **Client secret** (or download
  the JSON and take `installed.client_id` and `installed.client_secret`; then
  delete the file once the values are in `imap.env` or 1Password).

> For a Desktop app the client secret is not truly secret (Google says so), but
> keep it private anyway.

## 4. Check that IMAP is available

Gmail → ⚙ **See all settings** → **Forwarding and POP/IMAP**: IMAP access
should be enabled (Google enables it for all personal accounts). Workspace
admins can restrict IMAP or third-party OAuth apps in the Admin console; if
step 6 or 7 fails with an access error, check there.

## 5. Add the account to `imap.env`

Keep any existing accounts; add `gmail` to `IMAP_ACCOUNTS`:

```bash
IMAP_ACCOUNTS=tetra,gmail

IMAP_GMAIL_HOST=imap.gmail.com
IMAP_GMAIL_LOGIN=you@gmail.com
IMAP_GMAIL_AUTH=oauth2
IMAP_GMAIL_OAUTH_PROVIDER=google
IMAP_GMAIL_OAUTH_CLIENT_ID=1234-abc.apps.googleusercontent.com
IMAP_GMAIL_OAUTH_CLIENT_SECRET=GOCSPX-your-client-secret
# Added in step 6:
# IMAP_GMAIL_OAUTH_REFRESH_TOKEN=
```

`IMAP_GMAIL_PASSWORD` must **not** be set for an OAuth account. The file now
holds the client secret (and, after step 6, the refresh token) in plain text:
keep it mode `600`.

## 6. Authorize and obtain the refresh token

```bash
sh -c 'set -a; . ./imap.env; exec ~/.local/bin/tp_imap_mcp auth gmail' | pbcopy
```

Only the refresh token goes to stdout (instructions go to the terminal), so
`| pbcopy` copies it without showing it.

1. Your browser opens Google's consent page (the URL is also printed, in case
   it does not open). Choose the Gmail account you added as a test user.
2. Google warns **"Google hasn't verified this app"**. This is expected for
   your own Testing app: **Advanced → Go to tp-imap-mcp (unsafe)**.
3. Grant access to Gmail. The browser shows "Authorization received. You can
   close this tab." (If it shows "Authorization failed", read the terminal.)
4. The **refresh token** is now on the clipboard (without `| pbcopy` the
   terminal prints it once).

Paste it into `imap.env` in an editor, replacing the commented line from
step 5:

```bash
IMAP_GMAIL_OAUTH_REFRESH_TOKEN=1//0g…
```

Then clear the clipboard. Don't append it with `echo … >> imap.env`: the
token would stay in your shell history.

> Clear your terminal scrollback afterwards if others can see your screen.

## 7. Verify

```bash
sh -c 'set -a; . ./imap.env; exec ~/.local/bin/tp_imap_mcp' </dev/null
# tp-imap-mcp: serving 2 account(s) on stdio; cache: …; filters: … gmail=password_reset,one_time_codes; read/write: …

sh -c 'set -a; . ./imap.env; exec zig build itest -- gmail'
# … PASS lines …
# 0 failure(s)
```

The live checks log in with XOAUTH2, refreshing an access token first. If the
MCP client is already registered, reconnect it (`/mcp` in Claude Code) so it
picks up the new account.

## With 1Password

To keep the client secret and refresh token out of `imap.env`, store them in
1Password and put references in the file; then run every command above
through `op run --env-file imap.env --` instead of
`sh -c 'set -a; . ./imap.env; exec …'` (README: *Keeping secrets in
1Password*).

**Step 5:** create the item and reference its fields:

```bash
op item create --vault Private --category "API Credential" --title "Gmail OAuth" \
  "client id[text]=<CLIENT_ID>" \
  "client secret[password]=<CLIENT_SECRET>"
```

```bash
IMAP_GMAIL_OAUTH_CLIENT_ID='op://Private/Gmail OAuth/client id'
IMAP_GMAIL_OAUTH_CLIENT_SECRET='op://Private/Gmail OAuth/client secret'
# Enable after step 6 (the field does not exist yet, and `op run` fails on
# references to missing fields):
# IMAP_GMAIL_OAUTH_REFRESH_TOKEN='op://Private/Gmail OAuth/refresh token'
```

**Step 6:**

```bash
op run --env-file imap.env -- ~/.local/bin/tp_imap_mcp auth gmail | pbcopy
```

In the 1Password app, open the item, paste into a password field named
`refresh token`, and save. Don't put the token on a command line (e.g.
`op item edit … field=<token>`): it would stay in your shell history and be
visible to other processes. Then enable the reference line in `imap.env`.

**Step 7:**

```bash
op run --env-file imap.env -- ~/.local/bin/tp_imap_mcp </dev/null
op run --env-file imap.env -- zig build itest -- gmail
```

---

## Day-to-day

- Access tokens are refreshed automatically (in memory, 5 minutes before they
  expire); nothing to do.
- When the refresh token stops working you will see a tool error:
  `account "gmail": the OAuth refresh token was rejected (expired or revoked);
  run … tp_imap_mcp auth gmail and store the new token`. Repeat step 6 and
  replace the old token (in `imap.env`, or in the 1Password field; comment out
  the reference line first only if that field was deleted).

## Keeping access beyond 7 days

Refresh tokens of **External** apps in **Testing** expire after 7 days. Options:

- **Accept weekly re-authorization** (step 6).
- **Workspace accounts:** set the audience to **Internal** (no 7-day limit,
  no verification for internal use).
- **Publish the app:** Google Auth Platform → Audience → **Publish app**.
  Apps requesting the restricted `https://mail.google.com/` scope may require
  Google's verification (and possibly a security assessment) before broad use;
  check Google's current policy for personal-use apps before relying on this.
- **Use an app password** instead (requires 2-Step Verification):
  `IMAP_GMAIL_AUTH=password` (or unset) and `IMAP_GMAIL_PASSWORD='…'` (or an
  `op://` reference).

## Revoking access

<https://myaccount.google.com/permissions> → **tp-imap-mcp** → **Remove
access**. The stored refresh token stops working immediately; delete it from
`imap.env` (or 1Password) too.

## Troubleshooting

| Symptom                                                                            | Fix                                                                                                                                     |
|------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `Error 400: redirect_uri_mismatch`                                                 | The OAuth client is not of type **Desktop app**. Create a Desktop client (step 3) and update the client ID/secret.                      |
| `Error 403: access_denied` / "has not completed the Google verification process"   | Your address is not a **test user** (step 2.3), or a Workspace admin blocks the app.                                                    |
| `IMAP_GMAIL_OAUTH_CLIENT_SECRET is missing or empty`                               | Google requires the client secret; check its line in `imap.env` (or the 1Password reference).                                           |
| `imap.env: line N: …: command not found`                                           | A value on line N has a space or shell character: put it in single quotes.                                                              |
| `op run` fails: `item 'Private/Gmail OAuth' does not have a field 'refresh token'` | (1Password) You enabled the reference before step 6; comment it out, run `auth`, store the token, re-enable.                            |
| `The provider returned no refresh token`                                           | Google issues one only on fresh consent: remove access at myaccount.google.com/permissions and run `auth` again.                        |
| `IMAP_GMAIL_OAUTH_REFRESH_TOKEN is missing or empty`                               | Step 6 not done yet, or the token line is still commented out.                                                                          |
| `the OAuth refresh token was rejected (expired or revoked)`                        | 7-day Testing expiry, password change, or revoked access: repeat step 6.                                                                |
| `OAuth login failed: … Invalid credentials`                                        | The token lacks the `https://mail.google.com/` scope (step 2.4), IMAP is disabled, or `IMAP_GMAIL_LOGIN` is not the authorized address. |
| `Timed out waiting for the authorization redirect`                                 | Complete the consent within 5 minutes; if the browser shows "connection refused", make sure nothing blocks `127.0.0.1`.                 |
| `error initializing client: authorization timeout` (from `op`, 1Password)         | Approve the 1Password prompt (Touch ID) in time, or unlock 1Password first.                                                             |
