//! Raw RFC 5322 header block -> ordered (lowercased name, unfolded value)
//! pairs, matching what imap-tools exposes as `message.headers`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Header = struct {
    name: []const u8, // lowercased
    value: []const u8, // unfolded, leading whitespace trimmed, otherwise raw
};

/// All slices are allocated in `arena`.
pub fn parse(arena: Allocator, raw: []const u8) Allocator.Error![]Header {
    var out: std.ArrayList(Header) = .empty;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    var name: ?[]u8 = null;
    var value: std.ArrayList(u8) = .empty;

    while (lines.next()) |line_crlf| {
        const line = std.mem.trimEnd(u8, line_crlf, "\r");
        if (line.len == 0) break; // end of header block
        if (line[0] == ' ' or line[0] == '\t') {
            // Continuation: RFC 5322 unfolding removes only the CRLF.
            if (name != null) try value.appendSlice(arena, line);
            continue;
        }
        if (name) |n| try out.append(arena, .{ .name = n, .value = try value.toOwnedSlice(arena) });
        name = null;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue; // malformed line: skip
        // Obsolete syntax allows whitespace before the colon; the name itself
        // must be 1*ftext (RFC 5322 §3.6.8), or the line is not a header.
        const raw_name = std.mem.trimEnd(u8, line[0..colon], " \t");
        if (!isFieldName(raw_name)) continue;
        name = try std.ascii.allocLowerString(arena, raw_name);
        value = .empty;
        try value.appendSlice(arena, std.mem.trimStart(u8, line[colon + 1 ..], " \t"));
    }
    if (name) |n| try out.append(arena, .{ .name = n, .value = try value.toOwnedSlice(arena) });
    return out.toOwnedSlice(arena);
}

/// 1*ftext: printable US-ASCII except ':' (0x21-0x39, 0x3B-0x7E).
fn isFieldName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < 0x21 or c > 0x7E or c == ':') return false;
    return true;
}

const testing = std.testing;

test "parses, lowercases, unfolds, keeps repeats in order" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const raw =
        "Received: from a\r\n" ++
        "\tby b\r\n" ++
        "Subject: =?UTF-8?B?w6k=?=\r\n" ++
        "Received: from c\r\n" ++
        "X-Empty:\r\n" ++
        "\r\n" ++
        "Body-Looking: not a header\r\n";
    const hs = try parse(arena_state.allocator(), raw);
    try testing.expectEqual(4, hs.len);
    try testing.expectEqualStrings("received", hs[0].name);
    try testing.expectEqualStrings("from a\tby b", hs[0].value);
    try testing.expectEqualStrings("subject", hs[1].name);
    try testing.expectEqualStrings("=?UTF-8?B?w6k=?=", hs[1].value);
    try testing.expectEqualStrings("received", hs[2].name);
    try testing.expectEqualStrings("from c", hs[2].value);
    try testing.expectEqualStrings("x-empty", hs[3].name);
    try testing.expectEqualStrings("", hs[3].value);
}

test "bare LF and missing terminator" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const hs = try parse(arena_state.allocator(), "From: a@b\nTo: c@d");
    try testing.expectEqual(2, hs.len);
    try testing.expectEqualStrings("c@d", hs[1].value);
}

test "leading continuation and colon-less lines are skipped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const hs = try parse(arena_state.allocator(), " orphan continuation\r\nnot a header\r\nFrom: a@b\r\n\r\n");
    try testing.expectEqual(1, hs.len);
    try testing.expectEqualStrings("from", hs[0].name);
    try testing.expectEqualStrings("a@b", hs[0].value);
}

test "lines whose name is not RFC 5322 ftext are not headers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const hs = try parse(arena_state.allocator(), "X-Sp\xe4m: 1\r\nnot a header: x\r\n: empty\r\n\tcontinues nothing\r\nSubject: ok\r\n\r\n");
    try testing.expectEqual(1, hs.len);
    try testing.expectEqualStrings("subject", hs[0].name);
    try testing.expectEqualStrings("ok", hs[0].value);
}
