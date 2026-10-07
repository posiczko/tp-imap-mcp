//! POSIX extended regex via libc (ADR 0017): case-insensitive, match/no-match.
//! Patterns come only from the user's filters.zon, never from the model.

const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("../imap/c.zig");

pub const Regex = struct {
    handle: *c.Regex,

    /// On failure, writes regerror's message to `err_out` and returns
    /// error.InvalidRegex.
    pub fn compile(arena: Allocator, pattern: []const u8, err_out: *[]const u8) (Allocator.Error || error{InvalidRegex})!Regex {
        const z = try arena.dupeSentinel(u8, pattern, 0);
        var buf: [256]u8 = undefined;
        buf[0] = 0;
        const h = c.tpi_regex_compile(z, &buf, buf.len) orelse {
            err_out.* = try arena.dupe(u8, std.mem.sliceTo(&buf, 0));
            return error.InvalidRegex;
        };
        return .{ .handle = h };
    }

    pub fn deinit(self: Regex) void {
        c.tpi_regex_free(self.handle);
    }

    /// Unanchored search; `text` is copied to add the NUL terminator.
    pub fn matches(self: Regex, arena: Allocator, text: []const u8) Allocator.Error!bool {
        const z = try arena.dupeSentinel(u8, text, 0);
        return c.tpi_regex_match(self.handle, z) == 1;
    }
};

const testing = std.testing;

test "compiles, matches case-insensitively and unanchored" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var err: []const u8 = "";
    const re = try Regex.compile(a, "(receipt|statement)", &err);
    defer re.deinit();
    try testing.expect(try re.matches(a, "Your monthly STATEMENT is ready"));
    try testing.expect(!try re.matches(a, "Your order shipped"));
}

test "invalid pattern reports regerror text" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var err: []const u8 = "";
    try testing.expectError(error.InvalidRegex, Regex.compile(arena_state.allocator(), "(unclosed", &err));
    try testing.expect(err.len > 0);
}
