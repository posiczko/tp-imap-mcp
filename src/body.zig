//! get_text / get_html body rendering (spec §6.4, §6.6).

const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("imap/session.zig");
const text = @import("text.zig");

pub const Kind = enum {
    plain,
    html,

    fn subtype(k: Kind) [:0]const u8 {
        return switch (k) {
            .plain => "plain",
            .html => "html",
        };
    }
};

/// Concatenated text/<kind> parts as valid UTF-8 with LF line endings, or the
/// not-decrypted marker for multipart/encrypted messages.
pub fn render(arena: Allocator, message: []const u8, kind: Kind) session.Error![]const u8 {
    return switch (try session.extractText(arena, message, kind.subtype())) {
        .text => |t| text.toLf(arena, try text.sanitizeUtf8(arena, t)),
        .encrypted => |protocol| arena.print(
            "[encrypted message (multipart/encrypted; protocol={s}) — not decrypted]",
            .{try text.sanitizeUtf8(arena, protocol)},
        ),
    };
}
