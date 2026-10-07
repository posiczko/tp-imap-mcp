//! Local evaluation of IMAP LIST arguments against a cached mailbox list
//! (RFC 3501 §6.3.8): the reference and pattern are concatenated; `*` matches
//! anything, `%` matches anything except the hierarchy delimiter; the name
//! INBOX is case-insensitive.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// `name`, `reference`, and `pattern` are all UTF-8. Runs in
/// O(name.len * pattern.len) time; the pattern is model-supplied, so no
/// backtracking.
pub fn matches(arena: Allocator, name: []const u8, reference: []const u8, pattern: []const u8, delimiter: ?u8) Allocator.Error!bool {
    const n = try canonicalInbox(arena, name, delimiter);
    const p = try canonicalInbox(arena, try std.mem.concat(arena, u8, &.{ reference, pattern }), delimiter);

    // NFA simulation: active[i] means "pattern prefix p[0..i] matches the
    // name prefix consumed so far".
    var active = try arena.alloc(bool, p.len + 1);
    var next = try arena.alloc(bool, p.len + 1);
    @memset(active, false);
    active[0] = true;
    closeOverWildcards(p, active);
    for (n) |ch| {
        @memset(next, false);
        for (p, 0..) |pc, i| {
            if (!active[i]) continue;
            switch (pc) {
                '*' => next[i] = true,
                '%' => if (delimiter == null or ch != delimiter.?) {
                    next[i] = true;
                },
                else => if (pc == ch) {
                    next[i + 1] = true;
                },
            }
        }
        closeOverWildcards(p, next);
        std.mem.swap([]bool, &active, &next);
    }
    return active[p.len];
}

/// A wildcard may match the empty string, so reaching it also reaches the
/// state after it.
fn closeOverWildcards(p: []const u8, states: []bool) void {
    for (p, 0..) |pc, i| {
        if (states[i] and (pc == '*' or pc == '%')) states[i + 1] = true;
    }
}

/// Rewrites a leading "inbox" (any case, followed by end or delimiter) as
/// "INBOX".
fn canonicalInbox(arena: Allocator, s: []const u8, delimiter: ?u8) Allocator.Error![]const u8 {
    if (s.len >= 5 and std.ascii.eqlIgnoreCase(s[0..5], "INBOX") and
        (s.len == 5 or (delimiter != null and s[5] == delimiter.?)))
    {
        return std.mem.concat(arena, u8, &.{ "INBOX", s[5..] });
    }
    return s;
}

const testing = std.testing;

fn m(name: []const u8, reference: []const u8, pattern: []const u8, delimiter: ?u8) bool {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    return matches(arena_state.allocator(), name, reference, pattern, delimiter) catch unreachable;
}

test "star matches across levels, percent stops at the delimiter" {
    try testing.expect(m("Archives/2024/Q1", "", "*", '/'));
    try testing.expect(m("Archives/2024/Q1", "Archives/", "*", '/'));
    try testing.expect(!m("Archives/2024/Q1", "Archives/", "%", '/'));
    try testing.expect(m("Archives/2024", "Archives/", "%", '/'));
    try testing.expect(m("Archives", "", "Archives*", '/'));
    try testing.expect(m("Archives2", "", "Archives*", '/'));
    try testing.expect(!m("Sent", "", "Archives*", '/'));
    try testing.expect(m("Queue", "", "Q%", '/'));
    try testing.expect(!m("Queue/Sub", "", "Q%", '/'));
}

test "reference and pattern concatenate without an inserted delimiter" {
    try testing.expect(m("INBOX.Foo", "INBOX.", "*", '.'));
    try testing.expect(m("INBOXed", "INBOX", "*", '.'));
    try testing.expect(m("Archives", "Arch", "ives", '/'));
}

test "INBOX is case-insensitive, other names are not" {
    try testing.expect(m("INBOX", "", "inbox", '/'));
    try testing.expect(m("INBOX/Sub", "", "Inbox/%", '/'));
    try testing.expect(m("INBOX/Sub", "inbox/", "%", '/'));
    try testing.expect(!m("Sent", "", "sent", '/'));
}

test "empty pattern matches nothing; nil delimiter means flat" {
    try testing.expect(!m("INBOX", "", "", '/'));
    try testing.expect(m("a/b", "", "%", null));
}

test "pathological wildcard runs stay fast (no exponential backtracking)" {
    const name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try testing.expect(!m(name, "", "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%b", '/'));
    try testing.expect(!m(name, "", "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", '/'));
    try testing.expect(m(name, "", "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*", '/'));
}
