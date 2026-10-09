//! An allocator that wipes memory before handing it back to its parent, for
//! arenas and clients that hold OAuth tokens and secrets (ADR 0020): the
//! token response body, its parsed JSON, the request form, and std.http's
//! TLS and read buffers. Relocating remaps are refused (the caller then
//! allocates, copies and frees, so the old block is wiped too).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const Wiping = struct {
    parent: Allocator,

    pub fn allocator(self: *Wiping) Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn alloc(ctx: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Wiping = @ptrCast(@alignCast(ctx));
        return self.parent.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Wiping = @ptrCast(@alignCast(ctx));
        // A shrink gives up the tail whether or not it happens in place.
        if (new_len < memory.len) std.crypto.secureZero(u8, memory[new_len..]);
        return self.parent.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        return if (resize(ctx, memory, alignment, new_len, ret_addr)) memory.ptr else null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
        const self: *Wiping = @ptrCast(@alignCast(ctx));
        std.crypto.secureZero(u8, memory);
        self.parent.rawFree(memory, alignment, ret_addr);
    }
};

const testing = std.testing;

test "an arena over Wiping leaves no secret in its parent's memory after deinit" {
    // A fixed buffer as the parent: freed bytes stay readable, so a missing
    // wipe shows up.
    var backing: [4096]u8 = @splat(0);
    var fba: std.heap.FixedBufferAllocator = .init(&backing);
    var wiping: Wiping = .{ .parent = fba.allocator() };
    var arena_state: std.heap.ArenaAllocator = .init(wiping.allocator());
    const a = arena_state.allocator();
    _ = try a.dupe(u8, "refresh_token=SECRET-RT");
    var list: std.ArrayList(u8) = .empty;
    for (0..40) |_| try list.appendSlice(a, "ACCESS-TOKEN "); // grows: resize/remap
    arena_state.deinit();

    try testing.expect(std.mem.find(u8, &backing, "SECRET") == null);
    try testing.expect(std.mem.find(u8, &backing, "ACCESS-TOKEN") == null);
}

test "Wiping: a shrink wipes the released tail" {
    var backing: [256]u8 = @splat(0);
    var fba: std.heap.FixedBufferAllocator = .init(&backing);
    var wiping: Wiping = .{ .parent = fba.allocator() };
    const w = wiping.allocator();
    const buf = try w.alloc(u8, 32);
    @memcpy(buf, "public-part-----SECRET-TAIL-----");
    try testing.expect(w.resize(buf, 16));
    try testing.expect(std.mem.find(u8, &backing, "SECRET") == null);
    w.free(buf[0..16]);
    try testing.expect(std.mem.find(u8, &backing, "public") == null);
}
