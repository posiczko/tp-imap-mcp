//! UTF-8 helpers for data coming off the wire.

const std = @import("std");
const Allocator = std.mem.Allocator;

const replacement = "\u{FFFD}";

/// Returns `in` unchanged if it is valid UTF-8, otherwise a copy (in `arena`)
/// with each invalid sequence replaced by U+FFFD.
pub fn sanitizeUtf8(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    if (std.unicode.utf8ValidateSlice(in)) return in;
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, in.len + 16);
    var i: usize = 0;
    while (i < in.len) {
        const len = std.unicode.utf8ByteSequenceLength(in[i]) catch {
            try out.appendSlice(arena, replacement);
            i += 1;
            continue;
        };
        if (i + len <= in.len and std.unicode.utf8ValidateSlice(in[i .. i + len])) {
            try out.appendSlice(arena, in[i .. i + len]);
            i += len;
        } else {
            // One U+FFFD per broken sequence: skip the lead byte plus any
            // continuation bytes that belonged to it.
            try out.appendSlice(arena, replacement);
            i += 1;
            var k: usize = 1;
            while (k < len and i < in.len and in[i] & 0xC0 == 0x80) : (k += 1) i += 1;
        }
    }
    return out.toOwnedSlice(arena);
}

/// Longest prefix of `s` that is at most `max` bytes and does not end inside
/// a UTF-8 sequence.
pub fn truncateUtf8(s: []const u8, max: usize) []const u8 {
    if (s.len <= max) return s;
    var end = max;
    // Back up over continuation bytes, then drop the lead byte if its
    // sequence would not fit.
    while (end > 0 and s[end] & 0xC0 == 0x80) end -= 1;
    return s[0..end];
}

/// Converts CRLF to LF. Allocated in `arena`.
pub fn toLf(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    const out = try arena.alloc(u8, std.mem.replacementSize(u8, in, "\r\n", "\n"));
    _ = std.mem.replace(u8, in, "\r\n", "\n", out);
    return out;
}

/// Converts bare LF to CRLF, leaving existing CRLF alone. Allocated in `arena`.
pub fn toCrlf(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, in.len + in.len / 32 + 2);
    for (in, 0..) |c, i| {
        if (c == '\n' and (i == 0 or in[i - 1] != '\r')) try out.append(arena, '\r');
        try out.append(arena, c);
    }
    return out.toOwnedSlice(arena);
}

const testing = std.testing;

test "valid utf-8 is returned as-is" {
    const s = "résumé ✓";
    try testing.expectEqual(s.ptr, (try sanitizeUtf8(testing.allocator, s)).ptr);
}

test "invalid bytes become U+FFFD" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("r\u{FFFD}sum\u{FFFD}", try sanitizeUtf8(a, "r\xe9sum\xe9"));
    try testing.expectEqualStrings("ok\u{FFFD}", try sanitizeUtf8(a, "ok\xe2\x82"));
}

test "toLf collapses CRLF" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("a\nb\nc\r", try toLf(arena_state.allocator(), "a\r\nb\nc\r"));
}

test "toCrlf normalizes bare LF only" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("a\r\nb\r\nc", try toCrlf(a, "a\nb\r\nc"));
    try testing.expectEqualStrings("\r\n", try toCrlf(a, "\n"));
}

test "sanitized bytes always serialize to valid JSON" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const clean = try sanitizeUtf8(a, "Subject: caf\xe9 \xff\xfe \xf0\x9f");
    const json = try std.json.Stringify.valueAlloc(a, clean, .{});
    const back = try std.json.parseFromSliceLeaky([]const u8, a, json, .{});
    try testing.expectEqualStrings(clean, back);
}

test "truncateUtf8 never splits a code point" {
    try testing.expectEqualStrings("ab", truncateUtf8("ab", 5));
    try testing.expectEqualStrings("a", truncateUtf8("a\u{e9}", 2)); // é is 2 bytes
    try testing.expectEqualStrings("a\u{e9}", truncateUtf8("a\u{e9}x", 3));
    try testing.expectEqualStrings("", truncateUtf8("\u{1F4C1}", 3));
}
