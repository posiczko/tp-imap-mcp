//! Tool descriptions, adapted from vivier/imap-mcp-server docstrings with an
//! `account` argument added. These are what the model reads; edit with care.

pub const account_param = "Account name, as returned by list_accounts().";

pub const list_accounts =
    \\Lists the configured IMAP accounts. Every other tool takes one of these
    \\names as its `account` argument.
    \\
    \\Return:
    \\    [ {"name": "tetra", "login": "me@example.org", "readonly": false,
    \\       "filters": ["password_reset"]}, ... ]
    \\    readonly accounts refuse change_keywords, create_message and the
    \\    folder and move/copy tools (dry runs are allowed).
    \\    filters are the account's active sensitive-content filters. Messages
    \\    they match are withheld: get_text/get_html return
    \\    [withheld by filter "<name>"] and get_header shows only date and from.
    \\    Built-in filters: password_reset (password resets, account recovery)
    \\    and one_time_codes (verification and sign-in codes, 2FA, magic links).
;

pub const whoami =
    \\Returns the configured email address (login) for the given account.
    \\Use it to confirm which mailbox the other commands will operate on.
;

pub const list_mailboxes =
    \\Enumerates mailboxes under a given folder.
    \\
    \\Args:
    \\    directory: base folder to search (e.g. "INBOX" for standard inbox,
    \\               INBOX/Trash for standard trash folder, ...)
    \\               if empty - get from root, includes "Sent", "Trash", "Drafts", "Junk", ...
    \\    pattern:   glob-like match for names directory (e.g., "*" for all children,
    \\               and for instance "Archives*" to match all archives folders
    \\               * is a wildcard, and matches zero or more characters at this position
    \\               % is similar to * but it does not match a hierarchy delimiter
    \\
    \\Examples:
    \\    - All folders: list_mailboxes(account, "", "*")
    \\    - Only Archives tree: list_mailboxes(account, "Archives", "*")
    \\    - Root-level folders starting with "Q": list_mailboxes(account, "", "Q%")
    \\
    \\Return:
    \\    a list of mailboxes: PATH for the full path, DELIMITER for the path
    \\    delimiter and FLAGS for the list of the flags of the mailbox.
    \\
    \\    Flags (RFC 6154):
    \\        \HasNoChildren     mailbox has no child mailbox
    \\        \Sent              mailbox is the Sent mailbox
    \\        \Junk              mailbox is the Junk mailbox
    \\        \Drafts            mailbox is the Drafts mailbox
    \\        \Flagged           mailbox presents all messages marked in some way as "important"
    \\        \Archive           mailbox is used to archive messages
    \\        \All               mailbox presents all messages in the user's message store
    \\        \Trash             mailbox is the Trash mailbox
    \\Notes:
    \\    - Paths in results are absolute from the root (so use INBOX/...).
    \\    - The delimiter varies by server ("/" or ".").
    \\    - Results come from a cached mailbox list (refreshed hourly by
    \\      default). Pass refresh=true if a folder was just created, renamed,
    \\      or deleted in another mail client.
;

pub const mailboxes_status =
    \\Get the status of a mailbox: the number of messages, recent messages and
    \\unseen messages.
    \\
    \\Args:
    \\    directory: mailbox to get the status of
    \\
    \\Return a status like:
    \\    { "MESSAGES": 41, "RECENT": 0, "UNSEEN": 5 }
;

pub const search =
    \\Search for messages in a given mailbox with given criteria.
    \\Return a list of message UIDs (strings), ascending.
    \\
    \\Args:
    \\    directory: mailbox to search; search doesn't include child folders.
    \\               Like "INBOX", "Sent", "Drafts", "Trash"; get the list with
    \\               list_mailboxes(account, "", "*")
    \\    criteria: IMAP SEARCH criteria (RFC 3501), sent to the server as-is
    \\
    \\    Possible criteria:
    \\        ALL                     all emails
    \\        ANSWERED/UNANSWERED     with/without the Answered flag
    \\        SEEN/UNSEEN             with/without the Seen flag
    \\        FLAGGED/UNFLAGGED       with/without the Flagged flag
    \\        DRAFT/UNDRAFT           with/without the Draft flag
    \\        DELETED/UNDELETED       with/without the Deleted flag
    \\        NEW/OLD                 with/without the recent flag
    \\        FROM "email"            with email address in the FROM field
    \\        TO "email"              with email address in the TO field
    \\        SUBJECT "subject"       with subject in the SUBJECT field
    \\        BODY "string"           with string in the BODY of the message
    \\        TEXT "string"           with string in the HEADER or the BODY
    \\        KEYWORD keyword         message has the given keyword/label (atom, no quotes: KEYWORD AI)
    \\        BCC "email"             with email in the BCC field
    \\        CC "email"              with email in the CC field
    \\        ON DD-Mon-YYYY          internal date is within that day (e.g. 15-Mar-2000)
    \\        SINCE DD-Mon-YYYY       internal date is within or later than that day
    \\        BEFORE DD-Mon-YYYY      internal date is earlier than that day
    \\        SENTON DD-Mon-YYYY      Date: header is within that day
    \\        SENTSINCE DD-Mon-YYYY   Date: header is within or later than that day
    \\        SENTBEFORE DD-Mon-YYYY  Date: header is earlier than that day
    \\        LARGER SIZE             size is larger than SIZE bytes
    \\        SMALLER SIZE            size is smaller than SIZE bytes
    \\        HEADER "tag" "string"   header tag contains string
    \\        X-GM-LABELS "string"    has this Gmail label (Gmail only)
    \\        UID uid_list            has a UID in uid_list (like 1,2,23)
    \\
    \\    Criteria use prefix notation. Criteria at the same level are AND-ed:
    \\        SEEN UNANSWERED FLAGGED
    \\    NOT negates one key, which may be a parenthesized group:
    \\        NOT (SEEN UNANSWERED FLAGGED)
    \\    OR takes exactly two keys; nest it for more:
    \\        OR FROM "a@example" OR FROM "b@example" FROM "c@example"
    \\    Keys after an OR are AND-ed with it:
    \\        OR FROM "a@example" FROM "b@example" ON 01-Jan-2025
    \\
    \\Notes:
    \\    UIDs are only valid relative to the given directory.
    \\    Sent, Drafts, Trash are usually at root level, not under INBOX/.
    \\    Never show UIDs to the user; they are not useful to them.
    \\    Pass keywords as atoms: search(account, "INBOX", "KEYWORD AI"), not KEYWORD "AI".
    \\    Some servers return nothing for NOT on header keys (NOT FROM "x");
    \\    if a negated header search is unexpectedly empty, search the positive
    \\    form and subtract.
;

const uids_note =
    \\    uids: an array of UID strings from search()
    \\
    \\Results are aligned with `uids`: one entry per input UID, in the same
    \\order, null for a UID that does not exist in the mailbox.
;

const sanitized_note =
    \\
    \\Output is sanitized: plain text only, hidden HTML content and invisible
    \\Unicode removed, links shown as "text (url)". Long bodies end with
    \\"[truncated: N bytes omitted]". If the response grows too large, later
    \\items are replaced by "[omitted: response size limit reached; request
    \\fewer UIDs]" -- ask again for those UIDs in a smaller batch.
;

const withheld_note =
    \\
    \\A message matched by one of the account's sensitive-content filters (see
    \\list_accounts) is withheld: its content is never downloaded and you get
    \\[withheld by filter "<name>"] instead. Tell the user the message exists
    \\but is withheld; do not retry or try to work around it.
;

pub const get_header =
    \\Read message headers for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of {lowercased header name: [values]}. Values are decoded
    \\    (RFC 2047) and sanitized. For a withheld message only date and from
    \\    are returned, plus "x-tp-imap-mcp-withheld": ["<filter>"].
++ sanitized_note ++ withheld_note;

pub const get_header_field =
    \\Read one header field for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
    \\    field: header field name (case-insensitive), e.g. "Message-ID"
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of [values] (decoded, sanitized); [] when the message lacks the
    \\    field. For a withheld message, fields other than date and from return
    \\    the marker.
++ sanitized_note ++ withheld_note;

pub const get_text =
    \\Read the plain text body for the given UIDs in directory. Concatenates
    \\every text/plain part that is not an attachment; if there is none, the
    \\HTML part converted to plain text. Charset is UTF-8.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++ sanitized_note ++ withheld_note;

pub const get_html =
    \\Read the HTML body for the given UIDs in directory, converted to plain
    \\text (no markup is returned). Concatenates every text/html part that
    \\is not an attachment; "" if the message has no HTML part.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++ sanitized_note ++ withheld_note;

pub const list_attachments =
    \\List the attachments of the given UIDs: file name, content type, approximate
    \\size in bytes, and whether the part is inline (e.g. an image embedded in
    \\the HTML). Attachment content is never downloaded or returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return, e.g. for list_attachments(account, "INBOX", ["12", "13", "999"]):
    \\    [ [{"filename": "invoice.pdf", "content_type": "application/pdf",
    \\        "size": 48213, "inline": false}],
    \\      [],
    \\      null ]
    \\
    \\File names are sanitized (decoded, invisible characters and paths removed).
    \\An attached e-mail without a name is listed as forwarded-message.eml.
++ withheld_note;

pub const get_size =
    \\Read the message size in bytes (RFC822.SIZE) for the given UIDs.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note;

pub const get_keywords =
    \\Read the keywords (IMAP flags) for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return, e.g. for get_keywords(account, "INBOX", ["250855", "999"]):
    \\    [ {"250855": ["\\Flagged", "\\Seen", "NonJunk"]}, {"999": null} ]
    \\
    \\Notes:
    \\    keyword | general meaning
    \\    --------+-----------------
    \\    $label1 | Important
    \\    $label2 | Work
    \\    $label3 | Personal
    \\    $label4 | To Do
    \\    $label5 | Later
    \\
    \\    To search messages with a keyword use search() with criteria
    \\    KEYWORD, for instance search(account, "INBOX", "KEYWORD $label2")
;

pub const change_keywords =
    \\Add or remove keywords (IMAP flags) on the given UIDs. Refused for
    \\read-only accounts.
    \\
    \\Args:
    \\    directory: directory containing the messages
    \\    uids: an array of UID strings
    \\    keywords: keywords to add or remove, e.g. ["\\Flagged", "$label2"]
    \\    set: true to add the keywords, false to remove them
    \\
    \\Return:
    \\    the resulting keywords for each UID (same format as get_keywords())
;

pub const create_message =
    \\Create a message in the account's Drafts folder. Refused for read-only
    \\accounts.
    \\
    \\Args:
    \\    content: raw RFC 822 content of the mail (headers, blank line, body)
    \\
    \\Return:
    \\    {"status": "OK", "data": [server response text]}
    \\
    \\Notes:
    \\    In the header, use the current date and time.
    \\    Check the date in the header before calling create_message.
    \\    If the message is a reply to another one, its "In-Reply-To" header
    \\    must contain the "Message-ID" of the original message.
;

pub const create_mailbox =
    \\Create a folder (mailbox) and subscribe to it. Missing parent folders
    \\are created by the server. Refused for read-only accounts.
    \\
    \\Args:
    \\    name: folder path using the account's hierarchy delimiter (see
    \\          list_mailboxes DELIMITER), e.g. "Receipts/2026"
    \\
    \\Return:
    \\    {"created": "Receipts/2026", "subscribed": true}
    \\
    \\Notes:
    \\    Folders cannot be created inside Gmail's [Gmail]/ system folders.
    \\    On Gmail a folder is a label.
;

pub const rename_mailbox =
    \\Rename a folder, or move it under another parent by giving a new path.
    \\Subfolders move with it and subscriptions follow. Refused for read-only
    \\accounts.
    \\
    \\Args:
    \\    name: the folder to rename, e.g. "Projects/X"
    \\    new_name: its new path, e.g. "Archive/2025/X"
    \\
    \\Return:
    \\    {"renamed": "Projects/X", "to": "Archive/2025/X", "note": null}
    \\
    \\Notes:
    \\    INBOX, special-use folders (Sent, Drafts, Trash, Junk/Spam,
    \\    Archive, All Mail, ...), the drafts folder create_message uses, and
    \\    folders containing them, cannot be renamed. On Gmail this renames
    \\    the label.
;

pub const delete_mailbox =
    \\Delete an empty folder. Refused if it still holds messages or
    \\subfolders (move or delete those first), and for read-only accounts.
    \\
    \\Args:
    \\    name: the folder to delete
    \\
    \\Return:
    \\    {"deleted": "Old/Empty", "note": null}
    \\
    \\Notes:
    \\    INBOX, special-use folders and the drafts folder create_message
    \\    uses cannot be deleted.
;

pub const move_messages =
    \\Move messages from one folder to another. Select them with uids (from
    \\search) or with criteria (IMAP SEARCH syntax, as in search()).
    \\
    \\Args:
    \\    directory: the source folder, e.g. "INBOX"
    \\    destination: the target folder, e.g. "Receipts/2026"
    \\    uids: an array of UID strings, or
    \\    criteria: e.g. "FROM \"billing@example.com\" SINCE 1-Jan-2026"
    \\    create_missing: true to create the destination if it does not exist
    \\    dry_run: with criteria the default is true: nothing is moved and the
    \\        result shows how many messages match (and the first 100 UIDs).
    \\        Show this to the user, then call again with dry_run=false.
    \\        With uids the default is false.
    \\
    \\Return:
    \\    {"moved": 3, "source": "INBOX", "destination": "Receipts/2026",
    \\     "uid_map": [{"from": "101", "to": "7"}, ...], "note": null}
    \\    uid_map gives the messages' new UIDs in the destination (null if the
    \\    server does not report them). A dry run returns
    \\    {"dry_run": true, "matched": 42, "uids": [...], ...}.
    \\
    \\Notes:
    \\    At most 5000 messages per call. Refused for read-only accounts
    \\    (dry runs are allowed). Moving to Trash or Spam/Junk works like a
    \\    deletion: servers may purge those folders (Gmail after 30 days).
    \\    Gmail: moving out of INBOX archives the message and applies the
    \\    destination label; every message also stays in [Gmail]/All Mail.
    \\    Moving out of All Mail (\All) is refused; use copy_messages to add
    \\    a label.
;

pub const copy_messages =
    \\Copy messages to another folder, keeping the originals. Arguments and
    \\selection rules are those of move_messages (uids or criteria; criteria
    \\default to a dry run; at most 5000 messages per call).
    \\
    \\Return:
    \\    {"copied": 3, "source": "INBOX", "destination": "Receipts/2026",
    \\     "uid_map": [{"from": "101", "to": "7"}, ...], "note": null}
    \\
    \\Notes:
    \\    On Gmail, copying adds the destination label; the message stays
    \\    where it was. Refused for read-only accounts (dry runs are allowed).
;

pub const clear_cache =
    \\Deletes this account's local cache (mailbox list, message headers and
    \\sizes). Use when the user asks to clear cached data or results look
    \\stale. Nothing on the IMAP server is changed.
    \\
    \\Return:
    \\    {"status": "OK"} (with a "note" when caching is disabled)
;
