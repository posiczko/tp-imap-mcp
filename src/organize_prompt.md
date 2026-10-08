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
