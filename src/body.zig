//! get_text / get_html body rendering: part selection, HTML → text, Unicode
//! cleaning, size cap (spec §6.4, §6.6; sanitization spec §2).

const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("imap/session.zig");
const text = @import("text.zig");
const html = @import("sanitize/html.zig");
const unicode = @import("sanitize/unicode.zig");
const limit = @import("sanitize/limit.zig");

pub const Kind = enum { plain, html };

/// Sanitized plain text for the message (both kinds return plain text), or
/// the not-decrypted marker for multipart/encrypted messages. At most
/// `max_bytes` of text plus a truncation marker.
pub fn render(arena: Allocator, message: []const u8, kind: Kind, max_bytes: usize) session.Error![]const u8 {
    const raw = switch (kind) {
        .plain => blk: {
            const plain = try extract(arena, message, "plain");
            switch (plain) {
                .encrypted => |m| return m,
                .text => |t| if (t.parts > 0) break :blk t.bytes,
            }
            // No text/plain part: fall back to the HTML part as text.
            break :blk switch (try extract(arena, message, "html")) {
                .encrypted => |m| return m,
                .text => |t| try html.toText(arena, t.bytes),
            };
        },
        .html => switch (try extract(arena, message, "html")) {
            .encrypted => |m| return m,
            .text => |t| try html.toText(arena, t.bytes),
        },
    };
    return limit.truncate(arena, try unicode.clean(arena, raw), max_bytes);
}

const Part = union(enum) {
    text: struct { bytes: []const u8, parts: usize }, // valid UTF-8, LF
    encrypted: []const u8, // the finished marker
};

/// A sender-controlled MIME parameter shown to the model: cleaned and short.
fn shortParam(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    const cleaned = try unicode.clean(arena, try text.sanitizeUtf8(arena, raw));
    const max = 64;
    if (cleaned.len <= max) return cleaned;
    return arena.print("{s}…", .{text.truncateUtf8(cleaned, max)});
}

fn extract(arena: Allocator, message: []const u8, subtype: [:0]const u8) session.Error!Part {
    return switch (try session.extractText(arena, message, subtype)) {
        .text => |t| .{ .text = .{
            .bytes = try text.toLf(arena, try text.sanitizeUtf8(arena, t.bytes)),
            .parts = t.parts,
        } },
        .encrypted => |protocol| .{ .encrypted = try arena.print(
            "[encrypted message (multipart/encrypted; protocol={s}) — not decrypted]",
            .{try shortParam(arena, protocol)},
        ) },
    };
}
