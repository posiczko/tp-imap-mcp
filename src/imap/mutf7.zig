//! IMAP modified UTF-7 mailbox names (RFC 3501 §5.1.3) <-> UTF-8.

const std = @import("std");
const Allocator = std.mem.Allocator;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn isDirect(c: u8) bool {
    return c >= 0x20 and c <= 0x7e and c != '&';
}

fn sextet(c: u8) ?u6 {
    const i = std.mem.findScalar(u8, alphabet, c) orelse return null;
    return @intCast(i);
}

pub const DecodeError = error{InvalidMutf7} || Allocator.Error;

/// Decode a wire mailbox name. Malformed input is an error so callers can
/// fall back to showing the raw name.
pub fn decode(gpa: Allocator, in: []const u8) DecodeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < in.len) {
        const c = in[i];
        if (c != '&') {
            if (c < 0x20 or c > 0x7e) return error.InvalidMutf7;
            try out.append(gpa, c);
            i += 1;
            continue;
        }
        const end = std.mem.findScalarPos(u8, in, i + 1, '-') orelse return error.InvalidMutf7;
        if (end == i + 1) {
            try out.append(gpa, '&');
            i = end + 1;
            continue;
        }
        // Base64 run -> UTF-16BE code units -> UTF-8.
        var bits: u32 = 0;
        var nbits: u5 = 0;
        var high: ?u16 = null;
        for (in[i + 1 .. end]) |b| {
            const v = sextet(b) orelse return error.InvalidMutf7;
            bits = (bits << 6) | v;
            nbits += 6;
            if (nbits >= 16) {
                nbits -= 16;
                const unit: u16 = @truncate(bits >> nbits);
                bits &= (@as(u32, 1) << nbits) - 1;
                if (high) |h| {
                    if (unit < 0xDC00 or unit > 0xDFFF) return error.InvalidMutf7;
                    const cp: u21 = 0x10000 + ((@as(u21, h) - 0xD800) << 10) + (unit - 0xDC00);
                    try appendCodepoint(gpa, &out, cp);
                    high = null;
                } else if (unit >= 0xD800 and unit <= 0xDBFF) {
                    high = unit;
                } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
                    return error.InvalidMutf7;
                } else {
                    try appendCodepoint(gpa, &out, unit);
                }
            }
        }
        if (high != null or bits != 0) return error.InvalidMutf7;
        i = end + 1;
    }
    return out.toOwnedSlice(gpa);
}

fn appendCodepoint(gpa: Allocator, out: *std.ArrayList(u8), cp: u21) Allocator.Error!void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch unreachable;
    try out.appendSlice(gpa, buf[0..n]);
}

pub const EncodeError = error{InvalidUtf8} || Allocator.Error;

/// Encode a UTF-8 mailbox name for the wire.
pub fn encode(gpa: Allocator, in: []const u8) EncodeError![]u8 {
    if (!std.unicode.utf8ValidateSlice(in)) return error.InvalidUtf8;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < in.len) {
        const c = in[i];
        if (c == '&') {
            try out.appendSlice(gpa, "&-");
            i += 1;
            continue;
        }
        if (isDirect(c)) {
            try out.append(gpa, c);
            i += 1;
            continue;
        }
        // Collect a run of non-direct characters and base64 their UTF-16BE.
        try out.append(gpa, '&');
        var bits: u32 = 0;
        var nbits: u5 = 0;
        while (i < in.len and !isDirect(in[i]) and in[i] != '&') {
            const len = std.unicode.utf8ByteSequenceLength(in[i]) catch unreachable;
            const cp = std.unicode.utf8Decode(in[i .. i + len]) catch unreachable;
            i += len;
            var units: [2]u16 = undefined;
            var nunits: usize = 1;
            if (cp >= 0x10000) {
                const v = cp - 0x10000;
                units = .{ @intCast(0xD800 + (v >> 10)), @intCast(0xDC00 + (v & 0x3FF)) };
                nunits = 2;
            } else {
                units[0] = @intCast(cp);
            }
            for (units[0..nunits]) |u| {
                bits = (bits << 16) | u;
                nbits += 16;
                while (nbits >= 6) {
                    nbits -= 6;
                    try out.append(gpa, alphabet[@as(u6, @truncate(bits >> nbits))]);
                }
                bits &= (@as(u32, 1) << nbits) - 1;
            }
        }
        if (nbits > 0) {
            try out.append(gpa, alphabet[@as(u6, @truncate(bits << (6 - nbits)))]);
        }
        try out.append(gpa, '-');
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;

fn expectRoundTrip(utf8: []const u8, wire: []const u8) !void {
    const enc = try encode(testing.allocator, utf8);
    defer testing.allocator.free(enc);
    try testing.expectEqualStrings(wire, enc);
    const dec = try decode(testing.allocator, wire);
    defer testing.allocator.free(dec);
    try testing.expectEqualStrings(utf8, dec);
}

test "ascii passes through" {
    try expectRoundTrip("INBOX/Archives 2024", "INBOX/Archives 2024");
}

test "ampersand escapes to &-" {
    try expectRoundTrip("Tom & Jerry", "Tom &- Jerry");
}

test "RFC 3501 example" {
    try expectRoundTrip("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
}

test "latin accents" {
    try expectRoundTrip("Entwürfe", "Entw&APw-rfe");
    try expectRoundTrip("Éléments envoyés", "&AMk-l&AOk-ments envoy&AOk-s");
}

test "non-BMP uses surrogate pairs" {
    try expectRoundTrip("📁", "&2D3cwQ-");
}

test "decode rejects malformed input" {
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "&U,BTFw"));
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "&!!-"));
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "caf\xc3\xa9"));
}

test "encode rejects invalid utf-8" {
    try testing.expectError(error.InvalidUtf8, encode(testing.allocator, "\xff"));
}

test "quoting-sensitive characters pass through unchanged" {
    // libetpan quotes or literal-encodes these on the wire; we must not alter them.
    try expectRoundTrip("Projects \"2024\"\\Q%*", "Projects \"2024\"\\Q%*");
    try expectRoundTrip("", "");
}
