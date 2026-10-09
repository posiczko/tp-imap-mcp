//! In-memory IMAP server for unit tests: the test seam behind `Session`
//! (test builds only). Holds folders with UIDs and flags, records the
//! commands it receives, and can fail one chosen command, so tool handlers
//! run end to end without a network.

const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("session.zig");
const Error = session.Error;

pub const Fake = struct {
    arena_state: std.heap.ArenaAllocator,
    boxes: std.ArrayList(Box) = .empty,
    caps: session.Caps = .{ .move = true, .uidplus = true },
    delimiter: u8 = '/',
    selected: ?usize = null,
    /// Every command received, e.g. "UID MOVE 1,2 Archive", in order.
    commands: std.ArrayList([]const u8) = .empty,
    /// Fail the next command whose name starts with `command` (once).
    fail: ?Fail = null,
    response: []const u8 = "OK",
    /// Gmail: UNSUBSCRIBE of a folder that no longer exists is refused.
    unsubscribe_needs_box: bool = false,
    /// XOAUTH2 accepts only this access token (any, when null).
    accepted_token: ?[]const u8 = null,

    pub const Box = struct {
        name: []const u8,
        flags: []const []const u8 = &.{},
        uidvalidity: u32 = 7,
        next_uid: u32 = 1,
        messages: std.ArrayList(Message) = .empty,
    };

    pub const Message = struct {
        uid: u32,
        flags: std.ArrayList([]const u8) = .empty,
    };

    pub const Fail = struct {
        /// Command name prefix, e.g. "UID EXPUNGE", "RENAME", "STATUS".
        command: []const u8,
        err: Error,
        response: []const u8 = "NO [fake] refused",
    };

    pub fn init(gpa: Allocator) Fake {
        return .{ .arena_state = .init(gpa) };
    }

    pub fn deinit(self: *Fake) void {
        self.arena_state.deinit();
    }

    fn arena(self: *Fake) Allocator {
        return self.arena_state.allocator();
    }

    // ---- setup and inspection (tests) -------------------------------------

    pub fn addBox(self: *Fake, name: []const u8, flags: []const []const u8) Allocator.Error!void {
        try self.boxes.append(self.arena(), .{ .name = try self.arena().dupe(u8, name), .flags = flags });
    }

    /// Adds `n` messages (UIDs continue from the box's next UID).
    pub fn addMessages(self: *Fake, name: []const u8, n: usize) Allocator.Error!void {
        const b = self.box(name).?;
        for (0..n) |_| {
            try b.messages.append(self.arena(), .{ .uid = b.next_uid });
            b.next_uid += 1;
        }
    }

    pub fn box(self: *Fake, name: []const u8) ?*Box {
        for (self.boxes.items) |*b| if (std.mem.eql(u8, b.name, name)) return b;
        return null;
    }

    pub fn uidsOf(self: *Fake, name: []const u8) Allocator.Error![]u32 {
        const b = self.box(name) orelse return &.{};
        const out = try self.arena().alloc(u32, b.messages.items.len);
        for (b.messages.items, out) |m, *u| u.* = m.uid;
        return out;
    }

    /// True if some received command starts with `prefix`.
    pub fn sawCommand(self: *Fake, prefix: []const u8) bool {
        for (self.commands.items) |c| if (std.mem.startsWith(u8, c, prefix)) return true;
        return false;
    }

    // ---- Session methods ---------------------------------------------------

    /// Records `name` + `args`; fails if a `Fail` matches.
    fn command(self: *Fake, comptime fmt: []const u8, args: anytype) Error!void {
        const line = try self.arena().print(fmt, args);
        try self.commands.append(self.arena(), line);
        self.response = "OK";
        if (self.fail) |f| if (std.mem.startsWith(u8, line, f.command)) {
            self.fail = null;
            self.response = f.response;
            return f.err;
        };
    }

    fn reject(self: *Fake, response: []const u8) Error {
        self.response = response;
        return error.ServerRejected;
    }

    fn index(self: *Fake, name: []const u8) ?usize {
        for (self.boxes.items, 0..) |b, i| if (std.mem.eql(u8, b.name, name)) return i;
        return null;
    }

    fn current(self: *Fake) Error!*Box {
        const i = self.selected orelse return self.reject("BAD no mailbox selected");
        return &self.boxes.items[i];
    }

    fn find(b: *Box, uid: u32) ?usize {
        for (b.messages.items, 0..) |m, i| if (m.uid == uid) return i;
        return null;
    }

    fn uidList(self: *Fake, uids: []const u32) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        for (uids, 0..) |u, i| try out.print(self.arena(), "{s}{d}", .{ if (i > 0) "," else "", u });
        return out.items;
    }

    pub fn lastResponse(self: *Fake) []const u8 {
        return self.response;
    }

    pub fn login(self: *Fake, user: []const u8) Error!void {
        try self.command("LOGIN {s}", .{user});
    }

    /// Records the token (tests only) so a test can see which one was sent.
    pub fn oauth2Login(self: *Fake, user: []const u8, access_token: []const u8) Error!void {
        try self.command("AUTHENTICATE XOAUTH2 {s} {s}", .{ user, access_token });
        if (self.accepted_token) |want| if (!std.mem.eql(u8, want, access_token))
            return self.reject("NO [AUTHENTICATIONFAILED] Invalid credentials (Failure)");
    }

    pub fn noop(self: *Fake) Error!void {
        try self.command("NOOP", .{});
    }

    pub fn examine(self: *Fake, mailbox: []const u8) Error!u32 {
        try self.command("EXAMINE {s}", .{mailbox});
        return self.open(mailbox);
    }

    pub fn select(self: *Fake, mailbox: []const u8) Error!u32 {
        try self.command("SELECT {s}", .{mailbox});
        return self.open(mailbox);
    }

    fn open(self: *Fake, mailbox: []const u8) Error!u32 {
        const i = self.index(mailbox) orelse return self.reject("NO Mailbox doesn't exist");
        self.selected = i;
        return self.boxes.items[i].uidvalidity;
    }

    /// Understands "ALL" and "UID <n>[,<n>…]" (after an optional CHARSET).
    pub fn uidSearch(self: *Fake, arena_out: Allocator, criteria: []const u8) Error![]u32 {
        try self.command("UID SEARCH {s}", .{criteria});
        const b = try self.current();
        const c = if (std.mem.startsWith(u8, criteria, "CHARSET UTF-8 ")) criteria["CHARSET UTF-8 ".len..] else criteria;
        var out: std.ArrayList(u32) = .empty;
        if (std.mem.eql(u8, c, "ALL")) {
            for (b.messages.items) |m| try out.append(arena_out, m.uid);
        } else if (std.mem.startsWith(u8, c, "UID ")) {
            var it = std.mem.splitScalar(u8, c["UID ".len..], ',');
            while (it.next()) |s| {
                const u = std.fmt.parseInt(u32, s, 10) catch return error.ProtocolError;
                if (find(b, u) != null) try out.append(arena_out, u);
            }
        } else return self.reject("BAD [fake] unsupported search criteria");
        return out.items;
    }

    pub fn list(self: *Fake, arena_out: Allocator, reference: []const u8, pattern: []const u8) Error![]session.Mailbox {
        try self.command("LIST \"{s}\" \"{s}\"", .{ reference, pattern });
        const out = try arena_out.alloc(session.Mailbox, self.boxes.items.len);
        for (self.boxes.items, out) |b, *m| m.* = .{ .name = b.name, .delimiter = self.delimiter, .flags = b.flags };
        return out;
    }

    pub fn status(self: *Fake, mailbox: []const u8) Error!session.Status {
        try self.command("STATUS {s}", .{mailbox});
        const i = self.index(mailbox) orelse return self.reject("NO Mailbox doesn't exist");
        const b = self.boxes.items[i];
        var unseen: u32 = 0;
        for (b.messages.items) |m| {
            if (!hasFlag(m, "\\Seen")) unseen += 1;
        }
        return .{ .messages = @intCast(b.messages.items.len), .recent = 0, .unseen = unseen };
    }

    pub fn uidFetch(self: *Fake, arena_out: Allocator, uids: []const u32, what: session.What) Error![]session.Fetched {
        _ = what;
        try self.command("UID FETCH {s}", .{try self.uidList(uids)});
        const b = try self.current();
        var out: std.ArrayList(session.Fetched) = .empty;
        for (uids) |u| {
            const i = find(b, u) orelse continue;
            const flags = try arena_out.dupe([]const u8, b.messages.items[i].flags.items);
            try out.append(arena_out, .{ .uid = u, .size = 100, .data = null, .flags = flags });
        }
        return out.items;
    }

    pub fn uidStoreFlags(self: *Fake, arena_out: Allocator, uids: []const u32, add: bool, flags: []const []const u8) Error!void {
        _ = arena_out;
        try self.command("UID STORE {s} {s}FLAGS.SILENT", .{ try self.uidList(uids), if (add) "+" else "-" });
        const b = try self.current();
        for (uids) |u| {
            const i = find(b, u) orelse continue;
            const m = &b.messages.items[i];
            for (flags) |f| {
                if (add and !hasFlag(m.*, f)) try m.flags.append(self.arena(), try self.arena().dupe(u8, f));
                if (!add) removeFlag(m, f);
            }
        }
    }

    pub fn uidBodyParts(self: *Fake, arena_out: Allocator, uids: []const u32) Error![]session.BodyPart {
        _ = arena_out;
        try self.command("UID FETCH {s} BODYSTRUCTURE", .{try self.uidList(uids)});
        return &.{};
    }

    pub fn append(self: *Fake, mailbox: []const u8, data: []const u8) Error!void {
        try self.command("APPEND {s} {d}", .{ mailbox, data.len });
        const b = self.box(mailbox) orelse return self.reject("NO [TRYCREATE] Mailbox doesn't exist");
        try b.messages.append(self.arena(), .{ .uid = b.next_uid });
        b.next_uid += 1;
    }

    pub fn create(self: *Fake, mailbox: []const u8) Error!void {
        try self.command("CREATE {s}", .{mailbox});
        if (self.index(mailbox) != null) return self.reject("NO Mailbox already exists");
        try self.addBox(mailbox, &.{});
    }

    /// Renames `from` and every folder below it, like Dovecot.
    pub fn rename(self: *Fake, from: []const u8, to: []const u8) Error!void {
        try self.command("RENAME {s} {s}", .{ from, to });
        if (self.index(from) == null) return self.reject("NO Mailbox doesn't exist");
        if (self.index(to) != null) return self.reject("NO Mailbox already exists");
        for (self.boxes.items) |*b| {
            if (std.mem.eql(u8, b.name, from)) {
                b.name = try self.arena().dupe(u8, to);
            } else if (b.name.len > from.len and std.mem.startsWith(u8, b.name, from) and b.name[from.len] == self.delimiter) {
                b.name = try std.mem.concat(self.arena(), u8, &.{ to, b.name[from.len..] });
            }
        }
    }

    pub fn delete(self: *Fake, mailbox: []const u8) Error!void {
        try self.command("DELETE {s}", .{mailbox});
        const i = self.index(mailbox) orelse return self.reject("NO Mailbox doesn't exist");
        for (self.boxes.items) |b| {
            if (b.name.len > mailbox.len and std.mem.startsWith(u8, b.name, mailbox) and b.name[mailbox.len] == self.delimiter)
                return self.reject("NO Mailbox has children");
        }
        if (self.selected) |s| {
            if (s == i) self.selected = null else if (s > i) self.selected = s - 1;
        }
        _ = self.boxes.orderedRemove(i);
    }

    pub fn subscribe(self: *Fake, mailbox: []const u8) Error!void {
        try self.command("SUBSCRIBE {s}", .{mailbox});
    }

    pub fn unsubscribe(self: *Fake, mailbox: []const u8) Error!void {
        try self.command("UNSUBSCRIBE {s}", .{mailbox});
        if (self.unsubscribe_needs_box and self.index(mailbox) == null) return self.reject("NO [NONEXISTENT] Unknown Mailbox");
    }

    pub fn capabilities(self: *Fake) Error!session.Caps {
        try self.command("CAPABILITY", .{});
        return self.caps;
    }

    /// UID MOVE or UID COPY from the selected folder; COPYUID only with
    /// UIDPLUS, one single-UID range per message.
    pub fn uidTransfer(self: *Fake, arena_out: Allocator, uids: []const u32, mailbox: []const u8, move: bool) Error!?session.CopyUid {
        try self.command("UID {s} {s} {s}", .{ if (move) "MOVE" else "COPY", try self.uidList(uids), mailbox });
        const src = try self.current();
        const di = self.index(mailbox) orelse return self.reject("NO [TRYCREATE] Mailbox doesn't exist");
        var src_ranges: std.ArrayList([2]u32) = .empty;
        var dst_ranges: std.ArrayList([2]u32) = .empty;
        for (uids) |u| {
            const i = find(src, u) orelse continue;
            const dst = &self.boxes.items[di];
            var copy: Message = .{ .uid = dst.next_uid };
            for (src.messages.items[i].flags.items) |f| try copy.flags.append(self.arena(), f);
            try dst.messages.append(self.arena(), copy);
            dst.next_uid += 1;
            try src_ranges.append(arena_out, .{ u, u });
            try dst_ranges.append(arena_out, .{ copy.uid, copy.uid });
            if (move) _ = src.messages.orderedRemove(i);
        }
        if (!self.caps.uidplus or src_ranges.items.len == 0) return null;
        return .{ .uidvalidity = self.boxes.items[di].uidvalidity, .src = src_ranges.items, .dst = dst_ranges.items };
    }

    /// Removes the given UIDs that carry \Deleted.
    pub fn uidExpunge(self: *Fake, uids: []const u32) Error!void {
        try self.command("UID EXPUNGE {s}", .{try self.uidList(uids)});
        const b = try self.current();
        for (uids) |u| {
            const i = find(b, u) orelse continue;
            if (hasFlag(b.messages.items[i], "\\Deleted")) _ = b.messages.orderedRemove(i);
        }
    }
};

fn hasFlag(m: Fake.Message, flag: []const u8) bool {
    for (m.flags.items) |f| if (std.ascii.eqlIgnoreCase(f, flag)) return true;
    return false;
}

fn removeFlag(m: *Fake.Message, flag: []const u8) void {
    var i: usize = 0;
    while (i < m.flags.items.len) {
        if (std.ascii.eqlIgnoreCase(m.flags.items[i], flag)) _ = m.flags.orderedRemove(i) else i += 1;
    }
}
