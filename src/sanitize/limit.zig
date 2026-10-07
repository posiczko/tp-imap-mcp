//! Size limits for model-bound output (sanitization spec §5).

const std = @import("std");
const Allocator = std.mem.Allocator;
const text_util = @import("../text.zig");

pub const header_value_max = 2048;

pub const omitted_text = "[omitted: response size limit reached; request fewer UIDs]";
pub const omitted_reason = "response size limit reached; request fewer UIDs";

/// `text` cut at a UTF-8 boundary to at most `max` bytes, with a marker
/// stating how many bytes were removed. Unchanged when it fits.
pub fn truncate(arena: Allocator, text: []const u8, max: usize) Allocator.Error![]const u8 {
    if (text.len <= max) return text;
    const kept = text_util.truncateUtf8(text, max);
    return arena.print("{s}\n[truncated: {d} bytes omitted]", .{ kept, text.len - kept.len });
}

/// Bytes `s` occupies inside a JSON string (std.json escaping): `"` and `\`
/// take 2, control characters 2 (`\n`-style) or 6 (`\u00XX`), UTF-8 as is.
pub fn jsonLen(s: []const u8) usize {
    var n: usize = 0;
    for (s) |ch| n += switch (ch) {
        '"', '\\', '\n', '\r', '\t', 0x08, 0x0C => 2,
        0x00...0x07, 0x0B, 0x0E...0x1F => 6,
        else => 1,
    };
    return n;
}

/// Running per-response budget. The first item is always admitted; after
/// that, an item that would exceed the budget is refused, and so is every
/// later item.
pub const Budget = struct {
    remaining: usize,
    admitted_any: bool = false,
    exhausted: bool = false,

    pub fn init(max: usize) Budget {
        return .{ .remaining = max };
    }

    pub fn admit(self: *Budget, size: usize) bool {
        if (self.exhausted) return false;
        if (self.admitted_any and size > self.remaining) {
            self.exhausted = true;
            return false;
        }
        self.admitted_any = true;
        self.remaining -|= size;
        return true;
    }
};

const testing = std.testing;

test "truncate keeps short text and cuts long text on a code-point boundary" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("short", try truncate(a, "short", 10));
    try testing.expectEqualStrings("ab\n[truncated: 3 bytes omitted]", try truncate(a, "ab\u{e9}x", 3));
}

test "budget admits the first item, then refuses everything after the first overflow" {
    var b: Budget = .init(10);
    try testing.expect(b.admit(25)); // first item always admitted
    try testing.expect(!b.admit(1)); // budget already spent
    try testing.expect(!b.admit(0));

    var c: Budget = .init(10);
    try testing.expect(c.admit(4));
    try testing.expect(c.admit(6));
    try testing.expect(!c.admit(1));
    try testing.expect(!c.admit(0)); // stays exhausted
}

test "todo: jsonLen counts JSON-escaped bytes" {
    try testing.expectEqual(3, jsonLen("abc"));
    try testing.expectEqual(4, jsonLen("\"\\"));
    try testing.expectEqual(2, jsonLen("\n"));
    try testing.expectEqual(6, jsonLen("\x01"));
    try testing.expectEqual(2, jsonLen("\u{e9}")); // UTF-8 passes through unescaped
}
