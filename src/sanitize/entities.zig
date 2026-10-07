//! HTML character references (sanitization spec §3.6). Unknown or
//! unterminated references are kept literally.

const std = @import("std");
const Allocator = std.mem.Allocator;

const named = std.StaticStringMap(u21).initComptime(.{
    .{ "amp", '&' },       .{ "lt", '<' },         .{ "gt", '>' },         .{ "quot", '"' },
    .{ "apos", '\'' },     .{ "nbsp", 0xA0 },      .{ "copy", 0xA9 },      .{ "reg", 0xAE },
    .{ "trade", 0x2122 },  .{ "hellip", 0x2026 },  .{ "mdash", 0x2014 },   .{ "ndash", 0x2013 },
    .{ "lsquo", 0x2018 },  .{ "rsquo", 0x2019 },   .{ "ldquo", 0x201C },   .{ "rdquo", 0x201D },
    .{ "sbquo", 0x201A },  .{ "bdquo", 0x201E },   .{ "laquo", 0xAB },     .{ "raquo", 0xBB },
    .{ "bull", 0x2022 },   .{ "middot", 0xB7 },    .{ "euro", 0x20AC },    .{ "pound", 0xA3 },
    .{ "yen", 0xA5 },      .{ "cent", 0xA2 },      .{ "sect", 0xA7 },      .{ "para", 0xB6 },
    .{ "deg", 0xB0 },      .{ "plusmn", 0xB1 },    .{ "times", 0xD7 },     .{ "divide", 0xF7 },
    .{ "frac12", 0xBD },   .{ "frac14", 0xBC },    .{ "frac34", 0xBE },    .{ "iexcl", 0xA1 },
    .{ "iquest", 0xBF },   .{ "shy", 0xAD },       .{ "zwnj", 0x200C },    .{ "zwj", 0x200D },
    .{ "zwsp", 0x200B },   .{ "lrm", 0x200E },     .{ "rlm", 0x200F },     .{ "ensp", 0x2002 },
    .{ "emsp", 0x2003 },   .{ "thinsp", 0x2009 },  .{ "eacute", 0xE9 },    .{ "egrave", 0xE8 },
    .{ "colon", ':' },     .{ "semi", ';' },       .{ "lpar", '(' },       .{ "rpar", ')' },
    .{ "aacute", 0xE1 },   .{ "agrave", 0xE0 },    .{ "uuml", 0xFC },      .{ "ouml", 0xF6 },
    .{ "auml", 0xE4 },     .{ "szlig", 0xDF },     .{ "ccedil", 0xE7 },    .{ "ntilde", 0xF1 },
});

/// Decodes the reference starting at s[0] == '&'. Returns the code point and
/// the number of bytes consumed, or null if it is not a valid reference.
/// Numeric references may omit the ';' (browsers decode `&#58none` too).
pub fn decodeAt(s: []const u8) ?struct { cp: u21, len: usize } {
    if (s.len < 3 or s[0] != '&') return null;
    if (s[1] == '#') {
        const hex = s.len > 3 and (s[2] == 'x' or s[2] == 'X');
        const start: usize = if (hex) 3 else 2;
        var end = start;
        while (end < s.len and end - start < 8 and (if (hex) std.ascii.isHex(s[end]) else std.ascii.isDigit(s[end]))) end += 1;
        if (end == start) return null;
        const value = std.fmt.parseInt(u32, s[start..end], if (hex) 16 else 10) catch return null;
        const valid = value != 0 and value <= 0x10FFFF and !(value >= 0xD800 and value <= 0xDFFF);
        const consumed = if (end < s.len and s[end] == ';') end + 1 else end;
        return .{ .cp = if (valid) @intCast(value) else 0xFFFD, .len = consumed };
    }
    const semi = std.mem.findScalar(u8, s[0..@min(s.len, 34)], ';') orelse return null;
    const body = s[1..semi];
    if (body.len == 0) return null;
    const cp = named.get(body) orelse return null;
    return .{ .cp = cp, .len = semi + 1 };
}

/// Decodes all references in `s` (attribute values, text runs).
pub fn decodeAll(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    if (std.mem.findScalar(u8, s, '&') == null) return s;
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, s.len);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '&') if (decodeAt(s[i..])) |e| {
            var buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(e.cp, &buf) catch unreachable;
            try out.appendSlice(arena, buf[0..n]);
            i += e.len;
            continue;
        };
        try out.append(arena, s[i]);
        i += 1;
    }
    return out.items;
}

const testing = std.testing;

test "named, decimal, hex" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("a & b < c \u{2014} \u{e9}", try decodeAll(a, "a &amp; b &lt; c &mdash; &eacute;"));
    try testing.expectEqualStrings("A\u{20AC}", try decodeAll(a, "&#65;&#x20ac;"));
}

test "invalid code points become U+FFFD; unknown and unterminated are literal" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("\u{FFFD}\u{FFFD}\u{FFFD}", try decodeAll(a, "&#0;&#xD800;&#x110000;"));
    try testing.expectEqualStrings("&bogus; &amp &", try decodeAll(a, "&bogus; &amp &"));
    try testing.expectEqualStrings("AT&T", try decodeAll(a, "AT&T"));
}
