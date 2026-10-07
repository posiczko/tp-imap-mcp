//! Attachment listing (list_attachments): which BODYSTRUCTURE leaf parts are
//! attachments, and their sanitized file names, types and sizes. Pure logic;
//! the C walker in src/c/attach.c supplies the raw parts.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap/session.zig");
const text = @import("text.zig");
const unicode = @import("sanitize/unicode.zig");

pub const max_filename = 255;
pub const max_content_type = 100;

/// One leaf part as reported by the server (raw, untrusted).
pub const Part = struct {
    content_type: []const u8, // "type/subtype"
    disposition: []const u8, // "" when absent
    params: []const u8, // content-type params: name \x1f value, joined by \x1e
    disp_params: []const u8, // disposition params, same format
    size: u32, // encoded size in bytes
    base64: bool,
};

pub const Attachment = struct {
    filename: []const u8,
    content_type: []const u8,
    size: u64,
    inline_: bool,
};

const Param = struct { name: []const u8, value: []const u8 };

fn parseParams(arena: Allocator, flat: []const u8) Allocator.Error![]Param {
    var out: std.ArrayList(Param) = .empty;
    var it = std.mem.splitScalar(u8, flat, 0x1e);
    while (it.next()) |kv| {
        const sep = std.mem.findScalar(u8, kv, 0x1f) orelse continue;
        try out.append(arena, .{ .name = kv[0..sep], .value = kv[sep + 1 ..] });
    }
    return out.items;
}

fn get(ps: []const Param, name: []const u8) ?[]const u8 {
    for (ps) |q| if (std.ascii.eqlIgnoreCase(q.name, name)) return q.value;
    return null;
}

fn percentDecode(arena: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                try out.append(arena, b);
                i += 2;
                continue;
            } else |_| {}
        }
        try out.append(arena, s[i]);
    }
    return out.items;
}

/// Bytes in `charset` → UTF-8 (UTF-8/ASCII as is, ISO-8859-1 mapped,
/// anything else kept and left to UTF-8 sanitizing).
fn toUtf8(arena: Allocator, charset: []const u8, bytes: []const u8) Allocator.Error![]const u8 {
    if (std.ascii.eqlIgnoreCase(charset, "iso-8859-1") or std.ascii.eqlIgnoreCase(charset, "latin1")) {
        var out: std.ArrayList(u8) = .empty;
        for (bytes) |b| {
            var buf: [2]u8 = undefined;
            const n = std.unicode.utf8Encode(b, &buf) catch unreachable;
            try out.appendSlice(arena, buf[0..n]);
        }
        return out.items;
    }
    return bytes;
}

/// RFC 2231 value for `name` (`name*` or continued `name*0*`, `name*1`, ...),
/// or null when absent.
fn rfc2231(arena: Allocator, ps: []const Param, name: []const u8) Allocator.Error!?[]const u8 {
    var charset: []const u8 = "utf-8";
    var bytes: std.ArrayList(u8) = .empty;
    var found = false;
    var idx: usize = 0;
    while (idx < 64) : (idx += 1) {
        const enc_name = try arena.print("{s}*{d}*", .{ name, idx });
        const raw_name = try arena.print("{s}*{d}", .{ name, idx });
        if (get(ps, enc_name)) |v| {
            var value = v;
            if (idx == 0) value = try splitCharset(v, &charset);
            try bytes.appendSlice(arena, try percentDecode(arena, value));
        } else if (get(ps, raw_name)) |v| {
            try bytes.appendSlice(arena, v);
        } else break;
        found = true;
    }
    if (!found) {
        const single = try arena.print("{s}*", .{name});
        const v = get(ps, single) orelse return null;
        const value = try splitCharset(v, &charset);
        try bytes.appendSlice(arena, try percentDecode(arena, value));
    }
    return try toUtf8(arena, charset, bytes.items);
}

/// `charset'lang'value` → value, setting `charset` (unchanged if malformed).
fn splitCharset(v: []const u8, charset: *[]const u8) Allocator.Error![]const u8 {
    const q1 = std.mem.findScalar(u8, v, '\'') orelse return v;
    const q2 = std.mem.findScalarPos(u8, v, q1 + 1, '\'') orelse return v;
    if (q1 > 0) charset.* = v[0..q1];
    return v[q2 + 1 ..];
}

fn decode2047(arena: Allocator, v: []const u8) Allocator.Error![]const u8 {
    return if (std.mem.find(u8, v, "=?") != null) imap.decodeHeaderValue(arena, v) else v;
}

/// Display file name: disposition `filename*`/`filename`, else content-type
/// `name*`/`name`; decoded, cleaned, path-stripped, capped. Null if none.
pub fn fileName(arena: Allocator, params_flat: []const u8, disp_flat: []const u8) Allocator.Error!?[]const u8 {
    const ps = try parseParams(arena, params_flat);
    const ds = try parseParams(arena, disp_flat);
    // RFC 2231 values are already decoded; plain values may carry RFC 2047
    // encoded-words (common, though not standard).
    const decoded: []const u8 = (try rfc2231(arena, ds, "filename")) orelse
        if (get(ds, "filename")) |v| try decode2047(arena, v) else (try rfc2231(arena, ps, "name")) orelse
        if (get(ps, "name")) |v| try decode2047(arena, v) else return null;
    const clean = try unicode.clean(arena, try text.sanitizeUtf8(arena, decoded));
    // Strip any path: the sender controls this string.
    const base_start = if (std.mem.findLastAny(u8, clean, "/\\")) |i| i + 1 else 0;
    const base = std.mem.trim(u8, clean[base_start..], " \t");
    if (base.len == 0) return null;
    return text.truncateUtf8(base, max_filename);
}

/// Attachments among the leaf parts, in order.
pub fn select(arena: Allocator, parts: []const Part) Allocator.Error![]Attachment {
    var out: std.ArrayList(Attachment) = .empty;
    for (parts) |p| {
        const name = try fileName(arena, p.params, p.disp_params);
        const is_attachment = std.ascii.eqlIgnoreCase(p.disposition, "attachment");
        const is_message = std.ascii.eqlIgnoreCase(p.content_type, "message/rfc822");
        if (name == null and !is_attachment and !is_message) continue;
        const ct = try std.ascii.allocLowerString(arena, text.truncateUtf8(try unicode.clean(arena, try text.sanitizeUtf8(arena, p.content_type)), max_content_type));
        try out.append(arena, .{
            .filename = name orelse if (is_message) "forwarded-message.eml" else "unnamed-attachment",
            .content_type = ct,
            .size = if (p.base64) @as(u64, p.size) * 3 / 4 else p.size,
            .inline_ = std.ascii.eqlIgnoreCase(p.disposition, "inline"),
        });
    }
    return out.items;
}

const testing = std.testing;

fn part(ct: []const u8, disp: []const u8, params: []const u8, disp_params: []const u8, size: u32, base64: bool) Part {
    return .{ .content_type = ct, .disposition = disp, .params = params, .disp_params = disp_params, .size = size, .base64 = base64 };
}

fn only(a: Allocator, p: Part) !?Attachment {
    const got = try select(a, &.{p});
    return if (got.len == 0) null else got[0];
}

test "selection: file name or attachment disposition; body text never listed" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // body text parts
    try testing.expect((try only(a, part("text/plain", "", "charset\x1futf-8", "", 10, false))) == null);
    try testing.expect((try only(a, part("text/html", "inline", "", "", 10, false))) == null);
    // a real attachment
    const pdf = (try only(a, part("application/pdf", "attachment", "name\x1fx.pdf", "filename\x1finvoice.pdf", 400, true))).?;
    try testing.expectEqualStrings("invoice.pdf", pdf.filename);
    try testing.expectEqualStrings("application/pdf", pdf.content_type);
    try testing.expectEqual(300, pdf.size);
    try testing.expect(!pdf.inline_);
    // inline image with only a content-type name
    const logo = (try only(a, part("image/png", "inline", "name\x1flogo.png", "", 80, true))).?;
    try testing.expectEqualStrings("logo.png", logo.filename);
    try testing.expect(logo.inline_);
    // text attachment with a file name is listed
    try testing.expectEqualStrings("notes.txt", (try only(a, part("text/plain", "attachment", "", "filename\x1fnotes.txt", 5, false))).?.filename);
    // attachment disposition without a name
    try testing.expectEqualStrings("unnamed-attachment", (try only(a, part("application/octet-stream", "attachment", "", "", 7, false))).?.filename);
    // forwarded message without a name
    const fwd = (try only(a, part("message/rfc822", "", "", "", 1000, false))).?;
    try testing.expectEqualStrings("forwarded-message.eml", fwd.filename);
    try testing.expectEqual(1000, fwd.size);
}

test "RFC 2231: single, continued, percent-encoded, Latin-1, unknown charset" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("résumé.pdf", (try fileName(a, "", "filename*\x1fUTF-8''r%C3%A9sum%C3%A9.pdf")).?);
    try testing.expectEqualStrings("very long name.pdf", (try fileName(a, "", "filename*0*\x1fUTF-8''very%20long\x1efilename*1\x1f name.pdf")).?);
    try testing.expectEqualStrings("café.txt", (try fileName(a, "", "filename*\x1fiso-8859-1'fr'caf%E9.txt")).?);
    try testing.expectEqualStrings("x\u{FFFD}.bin", (try fileName(a, "", "filename*\x1fshift_jis''x%FF.bin")).?);
    // RFC 2231 wins over a plain filename; disposition wins over content-type name
    try testing.expectEqualStrings("b.pdf", (try fileName(a, "name\x1fc.pdf", "filename\x1fa.pdf\x1efilename*\x1fUTF-8''b.pdf")).?);
    try testing.expectEqualStrings("c.pdf", (try fileName(a, "name\x1fc.pdf", "")).?);
    try testing.expect((try fileName(a, "charset\x1futf-8", "")) == null);
}

test "RFC 2047 encoded names are decoded" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("Rechnung.pdf", (try fileName(arena_state.allocator(), "", "filename\x1f=?UTF-8?Q?Rechnung.pdf?=")).?);
}

test "file names are cleaned: paths stripped, invisible characters removed, capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("evil.sh", (try fileName(a, "", "filename\x1f../../evil.sh")).?);
    try testing.expectEqualStrings("evil.exe", (try fileName(a, "", "filename\x1fC:\\temp\\evil.exe")).?);
    try testing.expectEqualStrings("invoice.pdf", (try fileName(a, "", "filename\x1finvoice\u{200B}.pdf")).?);
    try testing.expectEqualStrings("fdp.exe", (try fileName(a, "", "filename\x1f\u{202E}fdp.exe")).?);
    var long: std.ArrayList(u8) = .empty;
    try long.appendSlice(a, "filename\x1f");
    try long.appendNTimes(a, 'n', 400);
    try testing.expectEqual(255, (try fileName(a, "", long.items)).?.len);
    try testing.expect((try fileName(a, "", "filename\x1f../")) == null);
}

test "content type is lower-cased and capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const att = (try only(a, part("Application/PDF", "attachment", "", "filename\x1fa.pdf", 4, false))).?;
    try testing.expectEqualStrings("application/pdf", att.content_type);
}
