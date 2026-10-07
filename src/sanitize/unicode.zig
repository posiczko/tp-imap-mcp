//! Removes invisible and control characters from model-bound text
//! (ADR 0018, sanitization spec §4). Input must be valid UTF-8.

const std = @import("std");
const Allocator = std.mem.Allocator;

fn removed(cp: u21) bool {
    return switch (cp) {
        0x00...0x08, 0x0B...0x1F, 0x7F, 0x80...0x9F => true, // controls (keeps \t, \n)
        0xAD => true, // soft hyphen
        0x061C, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069 => true, // bidi
        0x200B...0x200D, 0x2060...0x2064, 0xFEFF => true, // zero-width / invisible operators
        0xE0000...0xE007F => true, // tag characters
        0xE0100...0xE01EF => true, // supplementary variation selectors
        else => false,
    };
}

/// Cleaned copy of `text` (or `text` itself when nothing changes).
/// U+2028/U+2029 become '\n'.
pub fn clean(arena: Allocator, text: []const u8) Allocator.Error![]const u8 {
    var view = std.unicode.Utf8View.init(text) catch return text; // caller guarantees UTF-8
    var it = view.iterator();
    var needs_copy = false;
    while (it.nextCodepoint()) |cp| {
        if (removed(cp) or cp == 0x2028 or cp == 0x2029) {
            needs_copy = true;
            break;
        }
    }
    if (!needs_copy) return text;

    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, text.len);
    it = view.iterator();
    while (it.nextCodepointSlice()) |slice| {
        const cp = std.unicode.utf8Decode(slice) catch unreachable;
        if (cp == 0x2028 or cp == 0x2029) {
            try out.append(arena, '\n');
        } else if (!removed(cp)) {
            try out.appendSlice(arena, slice);
        }
    }
    return out.items;
}

/// Allocation-free variant for fixed buffers: writes the cleaned text into
/// `buf` (truncating at a code-point boundary) and returns the written slice.
/// Invalid UTF-8 (e.g. raw server text) becomes U+FFFD instead of being lost.
pub fn cleanInto(buf: []u8, text: []const u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const len = std.unicode.utf8ByteSequenceLength(text[i]) catch 0;
        const valid = len > 0 and i + len <= text.len and std.unicode.utf8ValidateSlice(text[i .. i + len]);
        const slice: []const u8 = if (valid) text[i .. i + len] else "\u{FFFD}";
        i += if (valid) len else 1;
        const cp = std.unicode.utf8Decode(slice) catch unreachable;
        const piece: []const u8 = if (cp == 0x2028 or cp == 0x2029) "\n" else if (removed(cp)) "" else slice;
        if (n + piece.len > buf.len) break;
        @memcpy(buf[n..][0..piece.len], piece);
        n += piece.len;
    }
    return buf[0..n];
}

const testing = std.testing;

test "removes every listed range" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dirty = "a\x00b\x1bc\x7fd\u{85}e\u{AD}f\u{61C}g\u{200E}h\u{202E}i\u{2067}j\u{200B}k\u{200D}l\u{2060}m\u{FEFF}n\u{E0041}o\u{E007F}p\u{E0100}q";
    try testing.expectEqualStrings("abcdefghijklmnopq", try clean(a, dirty));
}

test "keeps tabs, newlines, emoji presentation selectors, accents, CJK" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const keep = "caf\u{e9}\tna\u{ef}ve\n\u{2764}\u{FE0F} \u{65E5}\u{672C}";
    try testing.expectEqual(keep.ptr, (try clean(arena_state.allocator(), keep)).ptr);
}

test "line and paragraph separators become newlines" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("a\nb\nc", try clean(arena_state.allocator(), "a\u{2028}b\u{2029}c"));
}

test "cleanInto respects the buffer and code-point boundaries" {
    var buf: [5]u8 = undefined;
    try testing.expectEqualStrings("ab", cleanInto(&buf, "a\u{200B}b"));
    try testing.expectEqualStrings("abc\u{e9}", cleanInto(&buf, "abc\u{e9}\u{e9}")); // second é would not fit whole
}

test "todo: cleanInto keeps text around invalid UTF-8" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("a\u{FFFD}b", cleanInto(&buf, "a\xffb"));
}
