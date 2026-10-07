//! Sensitive-content filters (ADR 0017): a filter matches if any rule
//! matches; a rule matches if all its conditions hold; a condition holds if
//! any pattern matches any value of its header.

const std = @import("std");
const Allocator = std.mem.Allocator;
const headers = @import("../headers.zig");
const imap = @import("../imap/session.zig");
const glob = @import("glob.zig");
const Regex = @import("regex.zig").Regex;
const unicode = @import("../sanitize/unicode.zig");
const text = @import("../text.zig");

pub const Matcher = union(enum) {
    contains: []const []const u8,
    glob: []const []const u8,
    regex: []const Regex,
};

pub const Condition = struct {
    field: []const u8, // header name, matched case-insensitively
    matcher: Matcher,
};

pub const Rule = struct {
    conditions: []const Condition,
};

pub const Filter = struct {
    name: []const u8,
    rules: []const Rule,
};

/// Marker text shown instead of withheld content.
pub fn marker(arena: Allocator, filter_name: []const u8) Allocator.Error![]const u8 {
    return arena.print("[withheld by filter \"{s}\"]", .{filter_name});
}

/// Headers a withheld message still exposes (lower-case names).
pub const visible_headers = [_][]const u8{ "date", "from" };

pub fn isVisibleHeader(name: []const u8) bool {
    for (visible_headers) |v| if (std.ascii.eqlIgnoreCase(v, name)) return true;
    return false;
}

pub const password_reset: Filter = .{
    .name = "password_reset",
    .rules = &.{.{ .conditions = &.{.{
        .field = "subject",
        .matcher = .{ .contains = &.{
            "password reset",      "reset your password",  "reset password",
            "password change",     "change your password", "forgot your password",
            "password recovery",   "recover your account", "account recovery",
        } },
    }} }},
};

pub const builtins = [_]Filter{password_reset};

/// Parses a raw header block and prepares every value for matching the way
/// the model will see it: RFC 2047-decoded, invisible characters removed,
/// NBSP as a plain space (so `Reset\u{200B} your password` still matches).
pub fn decodeHeaders(arena: Allocator, raw: []const u8) Allocator.Error![]headers.Header {
    const hs = try headers.parse(arena, raw);
    for (hs) |*h| {
        const decoded = try text.sanitizeUtf8(arena, try imap.decodeHeaderValue(arena, h.value));
        const cleaned = try unicode.clean(arena, decoded);
        h.value = try std.mem.replaceOwned(u8, arena, cleaned, "\u{A0}", " ");
    }
    return hs;
}

fn conditionHolds(arena: Allocator, cond: Condition, hs: []const headers.Header) Allocator.Error!bool {
    for (hs) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, cond.field)) continue;
        switch (cond.matcher) {
            .contains => |pats| for (pats) |p| {
                if (std.ascii.findIgnoreCase(h.value, p) != null) return true;
            },
            .glob => |pats| for (pats) |p| {
                if (glob.matchesValueOrAddress(p, h.value)) return true;
            },
            .regex => |res| for (res) |re| {
                if (try re.matches(arena, h.value)) return true;
            },
        }
    }
    return false;
}

pub fn filterMatches(arena: Allocator, f: Filter, hs: []const headers.Header) Allocator.Error!bool {
    rules: for (f.rules) |rule| {
        for (rule.conditions) |cond| if (!try conditionHolds(arena, cond, hs)) continue :rules;
        return true;
    }
    return false;
}

/// Name of the first active filter matching the (decoded) headers, or null.
pub fn classify(arena: Allocator, active: []const *const Filter, hs: []const headers.Header) Allocator.Error!?[]const u8 {
    for (active) |f| if (try filterMatches(arena, f.*, hs)) return f.name;
    return null;
}

const testing = std.testing;

fn subject(arena: Allocator, raw_subject: []const u8) ![]headers.Header {
    return decodeHeaders(arena, try arena.print("From: x@y.z\r\nSubject: {s}\r\n\r\n", .{raw_subject}));
}

test "built-in password_reset: positives, encoded subjects, near-misses" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const active = [_]*const Filter{&password_reset};
    for ([_][]const u8{
        "Reset your password",
        "[GitHub] Please reset your password",
        "Your PASSWORD RESET request",
        "=?UTF-8?Q?Password_reset?=",
        "=?UTF-8?B?Rm9yZ290IHlvdXIgcGFzc3dvcmQ/?=",
        "Account recovery for alice",
    }) |s| {
        const got = try classify(a, &active, try subject(a, s));
        try testing.expectEqualStrings("password_reset", got orelse return error.TestExpectedMatch);
    }
    for ([_][]const u8{
        "Passwords manager weekly digest",
        "Reset your router",
        "Your order has shipped",
    }) |s| try testing.expect((try classify(a, &active, try subject(a, s))) == null);
}

test "any rule / all conditions; repeated and missing headers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const banking: Filter = .{ .name = "banking", .rules = &.{
        .{ .conditions = &.{.{ .field = "from", .matcher = .{ .glob = &.{"*@chase.com"} } }} },
        .{ .conditions = &.{
            .{ .field = "from", .matcher = .{ .glob = &.{"*@paypal.com"} } },
            .{ .field = "subject", .matcher = .{ .contains = &.{"receipt"} } },
        } },
    } };
    const active = [_]*const Filter{&banking};
    const hs = struct {
        fn of(arena: Allocator, block: []const u8) ![]headers.Header {
            return decodeHeaders(arena, block);
        }
    };
    // Rule 1 alone.
    try testing.expect((try classify(a, &active, try hs.of(a, "From: Chase <alerts@chase.com>\r\n\r\n"))) != null);
    // Rule 2 needs both conditions.
    try testing.expect((try classify(a, &active, try hs.of(a, "From: service@paypal.com\r\nSubject: Your receipt\r\n\r\n"))) != null);
    try testing.expect((try classify(a, &active, try hs.of(a, "From: service@paypal.com\r\nSubject: Hello\r\n\r\n"))) == null);
    // Missing header never holds.
    try testing.expect((try classify(a, &active, try hs.of(a, "Subject: receipt\r\n\r\n"))) == null);
    // Any value of a repeated header counts.
    try testing.expect((try classify(a, &active, try hs.of(a, "From: a@b.c\r\nFrom: alerts@chase.com\r\n\r\n"))) != null);
}

test "first matching active filter wins; no active filters means no match" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const everything: Filter = .{ .name = "everything", .rules = &.{.{ .conditions = &.{.{ .field = "from", .matcher = .{ .glob = &.{"*"} } }} }} };
    const hs = try subject(a, "Reset your password");
    try testing.expectEqualStrings("everything", (try classify(a, &.{ &everything, &password_reset }, hs)).?);
    try testing.expectEqualStrings("password_reset", (try classify(a, &.{ &password_reset, &everything }, hs)).?);
    try testing.expect((try classify(a, &.{}, hs)) == null);
}

test "marker and visible headers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("[withheld by filter \"password_reset\"]", try marker(arena_state.allocator(), "password_reset"));
    try testing.expect(isVisibleHeader("Date") and isVisibleHeader("from"));
    try testing.expect(!isVisibleHeader("subject"));
}

test "review: invisible characters and NBSP do not defeat filters" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const active = [_]*const Filter{&password_reset};
    try testing.expectEqualStrings("password_reset", (try classify(a, &active, try subject(a, "Reset\u{200B} your password"))).?);
    try testing.expectEqualStrings("password_reset", (try classify(a, &active, try subject(a, "Reset\u{A0}your password"))).?);
    try testing.expectEqualStrings("password_reset", (try classify(a, &active, try subject(a, "=?UTF-8?B?UmVzZXTigIsgeW91ciBwYXNzd29yZA==?="))).?);
}
