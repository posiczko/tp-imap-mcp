//! Argument validation. `criteria` is sent to the server verbatim, so these
//! checks are the only barrier against smuggling a second IMAP command (which
//! would also bypass read-only accounts).

const std = @import("std");
const Allocator = std.mem.Allocator;
const unicode = @import("sanitize/unicode.zig");

pub const Error = error{
    CriteriaHasControlChars,
    CriteriaEndsWithLiteral,
    EmptyUids,
    InvalidUid,
    EmptyKeywords,
    InvalidKeyword,
    InvalidField,
    MailboxHasNul,
    MailboxNameEmpty,
    MailboxNameTooLong,
    MailboxNameInvalid,
    MailboxNameWildcard,
    MailboxNameDelimiter,
    MailboxNameInvisible,
} || Allocator.Error;

pub fn message(err: Error) []const u8 {
    return switch (err) {
        error.CriteriaHasControlChars => "criteria must not contain CR, LF, or NUL",
        error.CriteriaEndsWithLiteral => "criteria must not end with an IMAP literal marker like {5}",
        error.EmptyUids => "uids must be a non-empty array",
        error.InvalidUid => "each uid must be a decimal string between 1 and 4294967295",
        error.EmptyKeywords => "keywords must be a non-empty array",
        error.InvalidKeyword => "each keyword must be a system flag (\\Seen, \\Answered, \\Flagged, \\Deleted, \\Draft) or an IMAP atom",
        error.InvalidField => "field must be a header name (printable ASCII, no ':' or space)",
        error.MailboxHasNul => "mailbox name must not contain NUL",
        error.MailboxNameEmpty => "mailbox name must not be empty",
        error.MailboxNameTooLong => "mailbox name must be at most 512 bytes",
        error.MailboxNameInvalid => "mailbox name must be valid UTF-8 without control characters",
        error.MailboxNameWildcard => "mailbox name must not contain * or %",
        error.MailboxNameDelimiter => "mailbox name must not start or end with the hierarchy delimiter or contain it twice in a row",
        error.MailboxNameInvisible => "mailbox name must not contain invisible or control characters",
        error.OutOfMemory => "out of memory",
    };
}

pub fn criteria(s: []const u8) Error!void {
    if (std.mem.findAny(u8, s, "\r\n\x00") != null) return error.CriteriaHasControlChars;
    // `{N}` / `{N+}` at the very end would announce an IMAP literal; today
    // libetpan's trailing space defuses it, but do not rely on that.
    const t = std.mem.trimEnd(u8, s, " \t");
    if (t.len > 0 and t[t.len - 1] == '}') {
        if (std.mem.findScalarLast(u8, t, '{')) |open| {
            var inner = t[open + 1 .. t.len - 1];
            if (inner.len > 0 and inner[inner.len - 1] == '+') inner = inner[0 .. inner.len - 1];
            if (inner.len > 0) {
                for (inner) |ch| {
                    if (!std.ascii.isDigit(ch)) break;
                } else return error.CriteriaEndsWithLiteral;
            }
        }
    }
}

/// Parses decimal UID strings. The result is owned by `gpa`.
pub fn uids(gpa: Allocator, strings: []const []const u8) Error![]u32 {
    if (strings.len == 0) return error.EmptyUids;
    const out = try gpa.alloc(u32, strings.len);
    errdefer gpa.free(out);
    for (strings, out) |s, *u| {
        if (s.len == 0) return error.InvalidUid;
        for (s) |c| if (!std.ascii.isDigit(c)) return error.InvalidUid;
        u.* = std.fmt.parseInt(u32, s, 10) catch return error.InvalidUid;
        if (u.* == 0) return error.InvalidUid;
    }
    return out;
}

const system_flags = [_][]const u8{ "\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft" };

fn isAtomChar(c: u8) bool {
    if (c <= 0x20 or c >= 0x7f) return false; // SP, CTL, non-ASCII
    return std.mem.findScalar(u8, "(){%*\"\\]", c) == null;
}

pub fn keywords(list: []const []const u8) Error!void {
    if (list.len == 0) return error.EmptyKeywords;
    for (list) |k| {
        if (k.len == 0) return error.InvalidKeyword;
        if (k[0] == '\\') {
            for (system_flags) |f| {
                if (std.ascii.eqlIgnoreCase(f, k)) break;
            } else return error.InvalidKeyword;
            continue;
        }
        for (k) |c| if (!isAtomChar(c)) return error.InvalidKeyword;
    }
}

pub fn field(s: []const u8) Error!void {
    if (s.len == 0) return error.InvalidField;
    for (s) |c| if (c <= 0x20 or c >= 0x7f or c == ':') return error.InvalidField;
}

pub fn mailbox(s: []const u8) Error!void {
    if (std.mem.findScalar(u8, s, 0) != null) return error.MailboxHasNul;
}

pub const mailbox_name_max = 512;

/// A folder name to create or rename to (ADR 0021), in UTF-8 before
/// modified UTF-7 encoding. `delimiter` is the account's hierarchy delimiter
/// (null when the server has none).
pub fn mailboxName(s: []const u8, delimiter: ?u8) Error!void {
    if (s.len == 0) return error.MailboxNameEmpty;
    if (s.len > mailbox_name_max) return error.MailboxNameTooLong;
    if (!std.unicode.utf8ValidateSlice(s)) return error.MailboxNameInvalid;
    for (s) |c| if (c < 0x20 or c == 0x7f) return error.MailboxNameInvalid;
    if (!unicode.isClean(s)) return error.MailboxNameInvisible; // look-alikes ("INBOX\u{200B}")
    if (std.mem.findAny(u8, s, "*%") != null) return error.MailboxNameWildcard;
    const d = delimiter orelse return;
    if (s[0] == d or s[s.len - 1] == d) return error.MailboxNameDelimiter;
    if (std.mem.find(u8, s, &.{ d, d }) != null) return error.MailboxNameDelimiter;
}

const testing = std.testing;

test "criteria rejects CR, LF, NUL" {
    try criteria("OR FROM \"a@b\" SINCE 01-Jan-2025");
    try criteria("SUBJECT \"r\xc3\xa9sum\xc3\xa9\"");
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\r\nA1 DELETE INBOX"));
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\nX"));
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\x00"));
}

test "uids parse decimal and reject the rest" {
    const ok = try uids(testing.allocator, &.{ "1", "250735", "4294967295" });
    defer testing.allocator.free(ok);
    try testing.expectEqualSlices(u32, &.{ 1, 250735, 4294967295 }, ok);

    try testing.expectError(error.EmptyUids, uids(testing.allocator, &.{}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"0"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"4294967296"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"1:*"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"+5"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{""}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{ "5", "1 FLAGS" }));
}

test "keywords accept system flags and atoms" {
    try keywords(&.{ "\\Seen", "\\flagged", "$label1", "NonJunk", "AI" });
    try testing.expectError(error.EmptyKeywords, keywords(&.{}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"\\Recent"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"two words"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"a)b"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"x\r\n"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{""}));
}

test "field accepts header names only" {
    try field("Message-ID");
    try field("x-gm-labels");
    try testing.expectError(error.InvalidField, field(""));
    try testing.expectError(error.InvalidField, field("Subject:"));
    try testing.expectError(error.InvalidField, field("a b"));
}

test "mailbox rejects NUL" {
    try mailbox("INBOX/Archives");
    try testing.expectError(error.MailboxHasNul, mailbox("IN\x00BOX"));
}

test "mailboxName accepts folder paths and rejects unsafe names" {
    try mailboxName("Receipts/2026", '/');
    try mailboxName("Projets/R\u{e9}sum\u{e9}s", '/');
    try mailboxName("Archive.2025", '.');
    try mailboxName("/odd", null); // no delimiter: no delimiter rules
    try testing.expectError(error.MailboxNameEmpty, mailboxName("", '/'));
    const long: [513]u8 = @splat('a');
    try testing.expectError(error.MailboxNameTooLong, mailboxName(&long, '/'));
    try mailboxName(long[0..512], '/');
    try testing.expectError(error.MailboxNameInvalid, mailboxName("bad\xff", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("two\r\nlines", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("tab\there", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("nul\x00", '/'));
    try testing.expectError(error.MailboxNameWildcard, mailboxName("All*", '/'));
    try testing.expectError(error.MailboxNameWildcard, mailboxName("50%", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("/Receipts", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("Receipts/", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("A//B", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("A..B", '.'));
}

test "review: mailboxName rejects invisible, bidi and C1 characters" {
    try testing.expectError(error.MailboxNameInvisible, mailboxName("INBOX\u{200B}", '/'));
    try testing.expectError(error.MailboxNameInvisible, mailboxName("Bills\u{202E}fdp", '/'));
    try testing.expectError(error.MailboxNameInvisible, mailboxName("C1\u{85}", '/'));
    try testing.expectError(error.MailboxNameInvisible, mailboxName("soft\u{AD}hyphen", '/'));
    try mailboxName("R\u{e9}sum\u{e9}s", '/');
}

test "todo: criteria cannot end in an IMAP literal marker" {
    try testing.expectError(error.CriteriaEndsWithLiteral, criteria("SUBJECT {5}"));
    try testing.expectError(error.CriteriaEndsWithLiteral, criteria("SUBJECT {12+}  "));
    try criteria("SUBJECT \"{5}\" FROM x"); // braces elsewhere are fine
    try criteria("SUBJECT {x}");
}
