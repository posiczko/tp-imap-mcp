//! Case-insensitive whole-value glob (`*`, `?`) for filter conditions, plus
//! address extraction so `noreply@x` matches `"X" <noreply@x>` (ADR 0017).

const std = @import("std");

/// Whole-value match. Greedy single-backtrack algorithm: O(text * pattern),
/// no recursion.
pub fn matches(pattern: []const u8, text: []const u8) bool {
    var p: usize = 0;
    var t: usize = 0;
    var star: ?usize = null; // position after the last '*' in pattern
    var star_t: usize = 0; // text position that '*' is currently absorbing up to
    while (t < text.len) {
        if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(text[t]))) {
            p += 1;
            t += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p + 1;
            star_t = t;
            p += 1;
        } else if (star) |s| {
            p = s;
            star_t += 1;
            t = star_t;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// True if the pattern matches the whole value or any `<address>` in it.
pub fn matchesValueOrAddress(pattern: []const u8, value: []const u8) bool {
    if (matches(pattern, std.mem.trim(u8, value, " \t"))) return true;
    var rest = value;
    while (std.mem.findScalar(u8, rest, '<')) |open| {
        const close = std.mem.findScalarPos(u8, rest, open + 1, '>') orelse break;
        if (matches(pattern, rest[open + 1 .. close])) return true;
        rest = rest[close + 1 ..];
    }
    return false;
}

const testing = std.testing;

test "star, question mark, case-insensitive, whole value" {
    try testing.expect(matches("*@accounts.google.com", "no-reply@Accounts.Google.com"));
    try testing.expect(matches("no-reply@*", "no-reply@github.com"));
    try testing.expect(matches("a?c", "abc"));
    try testing.expect(!matches("a?c", "abbc"));
    try testing.expect(!matches("*@github.com", "noreply@github.com.evil.example"));
    try testing.expect(matches("*", ""));
    try testing.expect(!matches("x", ""));
}

test "addresses inside angle brackets are matched too" {
    try testing.expect(matchesValueOrAddress("noreply@github.com", "\"GitHub\" <noreply@github.com>"));
    try testing.expect(matchesValueOrAddress("*@chase.com", "Chase <alerts@chase.com>, Other <x@y.z>"));
    try testing.expect(!matchesValueOrAddress("*@chase.com", "Phisher <alerts@chase.com.evil.example>"));
}

test "pathological patterns finish quickly" {
    const text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try testing.expect(!matches("*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b", text));
}
