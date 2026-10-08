//! Mailbox organization rules (ADR 0021, spec §2-4): folder protection, move
//! strategy, batching, selection limits and COPYUID pairing. No I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap/session.zig");
const mutf7 = @import("imap/mutf7.zig");
const unicode = @import("sanitize/unicode.zig");

/// Most messages one move_messages/copy_messages call acts on.
pub const max_messages = 5000;
/// UIDs per MOVE/COPY/STORE/EXPUNGE command, keeping command lines short.
pub const batch_size = 500;
/// UIDs listed in a dry-run result.
pub const dry_run_preview = 100;

/// RFC 6154 special-use attributes, plus Gmail's \Important.
pub const special_use = [_][]const u8{ "\\All", "\\Archive", "\\Drafts", "\\Flagged", "\\Junk", "\\Sent", "\\Trash", "\\Important" };

const gmail_roots = [_][]const u8{ "[Gmail]", "[Google Mail]" };

pub const trash_note = "destination is the Trash folder; servers may purge it automatically (Gmail: after 30 days)";
pub const junk_note = "destination is the spam/junk folder; servers may purge it automatically (Gmail: after 30 days)";

/// The special-use attribute among `flags`, if any.
pub fn specialUse(flags: []const []const u8) ?[]const u8 {
    for (flags) |f| for (special_use) |su| if (std.ascii.eqlIgnoreCase(f, su)) return su;
    return null;
}

fn isInbox(wire: []const u8) bool {
    return std.ascii.eqlIgnoreCase(wire, "INBOX");
}

/// The mailbox with wire name `wire` (INBOX matched case-insensitively).
pub fn find(boxes: []const imap.Mailbox, wire: []const u8) ?imap.Mailbox {
    for (boxes) |b| {
        if (std.mem.eql(u8, b.name, wire)) return b;
        if (isInbox(wire) and isInbox(b.name)) return b;
    }
    return null;
}

/// False for \Noselect / \NonExistent mailboxes, which hold no messages.
pub fn selectable(box: imap.Mailbox) bool {
    for (box.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Noselect") or std.ascii.eqlIgnoreCase(f, "\\NonExistent")) return false;
    }
    return true;
}

/// Hierarchy delimiter for `wire`: its own, else the account's first.
pub fn delimiterOf(boxes: []const imap.Mailbox, wire: []const u8) ?u8 {
    if (find(boxes, wire)) |b| if (b.delimiter) |d| return d;
    for (boxes) |b| if (b.delimiter) |d| return d;
    return null;
}

/// True if `name` lies strictly below `parent` in the hierarchy.
pub fn isBelow(name: []const u8, parent: []const u8, delimiter: ?u8) bool {
    const d = delimiter orelse return false;
    return name.len > parent.len + 1 and std.mem.startsWith(u8, name, parent) and name[parent.len] == d;
}

/// A server folder name for messages: decoded, invisible characters removed.
fn display(arena: Allocator, wire: []const u8) Allocator.Error![]const u8 {
    const decoded = mutf7.decode(arena, wire) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => wire,
    };
    return unicode.clean(arena, decoded);
}

/// Why the folder `wire` must not be renamed or deleted, or null (spec §3.2).
/// `drafts` is the wire name of the folder create_message appends to.
pub fn protectedReason(arena: Allocator, boxes: []const imap.Mailbox, wire: []const u8, drafts: ?[]const u8) Allocator.Error!?[]const u8 {
    const name = try display(arena, wire);
    if (isInbox(wire)) return try arena.print("\"{s}\" is protected and cannot be renamed or deleted", .{name});
    if (find(boxes, wire)) |b| if (specialUse(b.flags)) |su|
        return try arena.print("\"{s}\" is a special-use folder ({s}) and cannot be renamed or deleted", .{ name, su });
    const d = delimiterOf(boxes, wire);
    if (drafts) |dr| {
        if (std.mem.eql(u8, dr, wire))
            return try arena.print("\"{s}\" is the drafts folder used by create_message and cannot be renamed or deleted", .{name});
        if (isBelow(dr, wire, d))
            return try arena.print("\"{s}\" contains the drafts folder \"{s}\" used by create_message and cannot be renamed or deleted", .{ name, try display(arena, dr) });
    }
    for (boxes) |b| {
        if (!isBelow(b.name, wire, d)) continue;
        const su = specialUse(b.flags) orelse continue;
        return try arena.print("\"{s}\" contains the special-use folder \"{s}\" ({s}) and cannot be renamed or deleted", .{ name, try display(arena, b.name), su });
    }
    return null;
}

/// Why `target` (UTF-8; `target_wire` encoded) cannot be created or be a
/// rename target, or null. `source_wire` is the folder being renamed.
pub fn targetReason(arena: Allocator, target: []const u8, target_wire: []const u8, source_wire: ?[]const u8, delimiter: ?u8) Allocator.Error!?[]const u8 {
    for (gmail_roots) |root| {
        if (!std.ascii.startsWithIgnoreCase(target, root)) continue;
        const rest = target[root.len..];
        if (rest.len == 0 or (delimiter != null and rest[0] == delimiter.?))
            return try arena.print("\"{s}\" is inside Gmail's system folders; choose a name outside {s}", .{ target, root });
    }
    if (isInbox(target_wire)) return try arena.print("\"{s}\" is reserved for the inbox", .{target});
    if (source_wire) |src| {
        if (std.mem.eql(u8, src, target_wire)) return try arena.dupe(u8, "new_name is the same as name");
        if (isBelow(target_wire, src, delimiter))
            return try arena.print("cannot move \"{s}\" inside itself", .{try display(arena, src)});
    }
    return null;
}

/// True if wire names `a` and `b` denote the same mailbox (INBOX in any case).
pub fn sameMailbox(boxes: []const imap.Mailbox, a: []const u8, b: []const u8) bool {
    if (std.mem.eql(u8, a, b) or (isInbox(a) and isInbox(b))) return true;
    const x = find(boxes, a) orelse return false;
    const y = find(boxes, b) orelse return false;
    return std.mem.eql(u8, x.name, y.name);
}

/// Why messages cannot be moved out of `box`, or null. Moving out of a
/// folder of all mail (Gmail's All Mail) is unverified and may trash them.
pub fn moveSourceReason(arena: Allocator, box: imap.Mailbox) Allocator.Error!?[]const u8 {
    for (box.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\All"))
            return try arena.print("moving out of \"{s}\" (\\All) is not supported; use copy_messages to add a label", .{try display(arena, box.name)});
    }
    return null;
}

/// Note for a move/copy into Trash or Junk (spec §2.2).
pub fn destinationNote(box: ?imap.Mailbox) ?[]const u8 {
    const b = box orelse return null;
    for (b.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Trash")) return trash_note;
        if (std.ascii.eqlIgnoreCase(f, "\\Junk")) return junk_note;
    }
    return null;
}

pub const MoveStrategy = enum {
    /// UID MOVE.
    move,
    /// UID COPY, STORE +FLAGS (\Deleted), UID EXPUNGE of those UIDs.
    copy_expunge,
    /// Neither MOVE nor UIDPLUS: a plain EXPUNGE could purge unrelated
    /// messages, so refuse.
    unsupported,
};

pub fn moveStrategy(caps: imap.Caps) MoveStrategy {
    if (caps.move) return .move;
    if (caps.uidplus) return .copy_expunge;
    return .unsupported;
}

pub fn batchCount(n: usize) usize {
    return (n + batch_size - 1) / batch_size;
}

/// The `i`-th batch of at most `batch_size` UIDs.
pub fn batch(uids: []const u32, i: usize) []const u32 {
    const start = i * batch_size;
    return uids[start..@min(uids.len, start + batch_size)];
}

/// Problem with the uids/criteria combination, or null.
pub fn selectionProblem(has_uids: bool, has_criteria: bool) ?[]const u8 {
    if (has_uids and has_criteria) return "pass either uids or criteria, not both";
    if (!has_uids and !has_criteria) return "pass uids (from search) or criteria";
    return null;
}

pub const UidPair = struct { from: u32, to: u32 };

/// Expanded UIDs, ascending within each range; null for a "*" end or more
/// than `max` UIDs (a server cannot make us allocate without bound).
fn expand(arena: Allocator, ranges: []const [2]u32, max: usize) Allocator.Error!?[]u32 {
    var total: usize = 0;
    for (ranges) |r| {
        if (r[0] == 0 or r[1] == 0) return null;
        total += @as(usize, @max(r[0], r[1]) - @min(r[0], r[1])) + 1;
        if (total > max) return null;
    }
    const out = try arena.alloc(u32, total);
    var n: usize = 0;
    for (ranges) |r| {
        var u = @min(r[0], r[1]);
        while (true) : (u += 1) {
            out[n] = u;
            n += 1;
            if (u == @max(r[0], r[1])) break;
        }
    }
    return out;
}

/// Source → destination UID pairs from COPYUID, or null when the server
/// sent none or the sets do not line up.
pub fn uidMap(arena: Allocator, cu: ?imap.CopyUid) Allocator.Error!?[]UidPair {
    const c = cu orelse return null;
    const src = (try expand(arena, c.src, max_messages)) orelse return null;
    const dst = (try expand(arena, c.dst, max_messages)) orelse return null;
    if (src.len != dst.len or src.len == 0) return null;
    const out = try arena.alloc(UidPair, src.len);
    for (out, src, dst) |*o, s, d| o.* = .{ .from = s, .to = d };
    return out;
}

const testing = std.testing;

fn mbox(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

const gmail_boxes = [_]imap.Mailbox{
    mbox("INBOX", &.{"\\HasNoChildren"}),
    mbox("Receipts", &.{"\\HasChildren"}),
    mbox("Receipts/2026", &.{"\\HasNoChildren"}),
    mbox("[Gmail]", &.{ "\\HasChildren", "\\Noselect" }),
    mbox("[Gmail]/All Mail", &.{ "\\All", "\\HasNoChildren" }),
    mbox("[Gmail]/Sent Mail", &.{ "\\HasNoChildren", "\\Sent" }),
    mbox("[Gmail]/Trash", &.{ "\\HasNoChildren", "\\Trash" }),
    mbox("[Gmail]/Spam", &.{ "\\HasNoChildren", "\\Junk" }),
    mbox("Old", &.{"\\HasChildren"}),
    mbox("Old/Drafts", &.{ "\\Drafts", "\\HasNoChildren" }),
    mbox("R&AOk-sum&AOk-s", &.{"\\HasNoChildren"}),
};

test "protectedReason: INBOX, special-use folders and their ancestors" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("\"inbox\" is protected and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "inbox", null)).?);
    try testing.expectEqualStrings("\"[Gmail]/Sent Mail\" is a special-use folder (\\Sent) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "[Gmail]/Sent Mail", null)).?);
    for (special_use) |su| {
        const boxes = [_]imap.Mailbox{mbox("X", &.{su})};
        try testing.expect((try protectedReason(a, &boxes, "X", null)) != null);
    }
    try testing.expectEqualStrings("\"[Gmail]\" contains the special-use folder \"[Gmail]/All Mail\" (\\All) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "[Gmail]", null)).?);
    try testing.expectEqualStrings("\"Old\" contains the special-use folder \"Old/Drafts\" (\\Drafts) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "Old", null)).?);
    try testing.expect((try protectedReason(a, &gmail_boxes, "Receipts", null)) == null);
    try testing.expect((try protectedReason(a, &gmail_boxes, "Receipts/2026", null)) == null);
    try testing.expect((try protectedReason(a, &gmail_boxes, "R&AOk-sum&AOk-s", null)) == null);
    // "Ol" is a name prefix of "Old/Drafts" but not its ancestor.
    try testing.expect((try protectedReason(a, &gmail_boxes, "Ol", null)) == null);
}

test "targetReason: Gmail system trees, INBOX, renaming into itself" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("\"[Gmail]/Mine\" is inside Gmail's system folders; choose a name outside [Gmail]", (try targetReason(a, "[Gmail]/Mine", "[Gmail]/Mine", null, '/')).?);
    try testing.expect((try targetReason(a, "[gmail]", "[gmail]", null, '/')) != null);
    try testing.expect((try targetReason(a, "[Google Mail]/X", "[Google Mail]/X", null, '/')) != null);
    try testing.expect((try targetReason(a, "[Gmail]Notes", "[Gmail]Notes", null, '/')) == null);
    try testing.expectEqualStrings("\"Inbox\" is reserved for the inbox", (try targetReason(a, "Inbox", "Inbox", null, '/')).?);
    try testing.expectEqualStrings("new_name is the same as name", (try targetReason(a, "A", "A", "A", '/')).?);
    try testing.expectEqualStrings("cannot move \"A\" inside itself", (try targetReason(a, "A/B", "A/B", "A", '/')).?);
    try testing.expect((try targetReason(a, "AB", "AB", "A", '/')) == null);
    try testing.expect((try targetReason(a, "Archive/2025/X", "Archive/2025/X", "Projects/X", '/')) == null);
}

test "find, selectable, delimiterOf, destinationNote" {
    try testing.expectEqualStrings("INBOX", find(&gmail_boxes, "Inbox").?.name);
    try testing.expect(find(&gmail_boxes, "receipts") == null); // only INBOX is case-insensitive
    try testing.expect(!selectable(find(&gmail_boxes, "[Gmail]").?));
    try testing.expect(selectable(find(&gmail_boxes, "Receipts").?));
    try testing.expectEqual('/', delimiterOf(&gmail_boxes, "New/Folder").?);
    try testing.expect(delimiterOf(&.{}, "X") == null);
    try testing.expectEqualStrings(trash_note, destinationNote(find(&gmail_boxes, "[Gmail]/Trash")).?);
    try testing.expectEqualStrings(junk_note, destinationNote(find(&gmail_boxes, "[Gmail]/Spam")).?);
    try testing.expect(destinationNote(find(&gmail_boxes, "Receipts")) == null);
    try testing.expect(destinationNote(null) == null);
}

test "moveStrategy from capabilities" {
    try testing.expectEqual(.move, moveStrategy(.{ .move = true, .uidplus = true }));
    try testing.expectEqual(.move, moveStrategy(.{ .move = true }));
    try testing.expectEqual(.copy_expunge, moveStrategy(.{ .uidplus = true }));
    try testing.expectEqual(.unsupported, moveStrategy(.{}));
}

test "batches of at most 500 UIDs" {
    var uids: [5000]u32 = undefined;
    for (&uids, 1..) |*u, i| u.* = @intCast(i);
    try testing.expectEqual(1, batchCount(1));
    try testing.expectEqual(1, batchCount(500));
    try testing.expectEqual(2, batchCount(501));
    try testing.expectEqual(10, batchCount(5000));
    try testing.expectEqual(500, batch(&uids, 0).len);
    try testing.expectEqual(1, batch(uids[0..501], 1).len);
    try testing.expectEqual(501, batch(uids[0..501], 1)[0]);
    try testing.expectEqual(5000, batch(&uids, 9)[499]);
}

test "selectionProblem: exactly one of uids and criteria" {
    try testing.expect(selectionProblem(true, false) == null);
    try testing.expect(selectionProblem(false, true) == null);
    try testing.expectEqualStrings("pass either uids or criteria, not both", selectionProblem(true, true).?);
    try testing.expectEqualStrings("pass uids (from search) or criteria", selectionProblem(false, false).?);
}

test "uidMap pairs COPYUID ranges and rejects malformed data" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const m = (try uidMap(a, .{ .uidvalidity = 7, .src = &.{ .{ 101, 102 }, .{ 105, 105 } }, .dst = &.{.{ 7, 9 }} })).?;
    try testing.expectEqual(3, m.len);
    try testing.expectEqual(UidPair{ .from = 105, .to = 9 }, m[2]);
    const rev = (try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 3, 1 }}, .dst = &.{.{ 10, 12 }} })).?;
    try testing.expectEqual(UidPair{ .from = 1, .to = 10 }, rev[0]);
    try testing.expect((try uidMap(a, null)) == null);
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 2 }}, .dst = &.{.{ 5, 5 }} })) == null); // lengths differ
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 0 }}, .dst = &.{.{ 5, 0 }} })) == null); // "*"
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 4294967295 }}, .dst = &.{.{ 1, 4294967295 }} })) == null); // unbounded
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{}, .dst = &.{} })) == null);
}

test "review: sameMailbox treats INBOX case-insensitively and other names exactly" {
    try testing.expect(sameMailbox(&gmail_boxes, "INBOX", "inbox"));
    try testing.expect(sameMailbox(&gmail_boxes, "Inbox", "INBOX"));
    try testing.expect(sameMailbox(&.{}, "inbox", "INBOX"));
    try testing.expect(sameMailbox(&gmail_boxes, "Receipts", "Receipts"));
    try testing.expect(!sameMailbox(&gmail_boxes, "Receipts", "receipts"));
    try testing.expect(!sameMailbox(&gmail_boxes, "INBOX", "Receipts"));
}

test "review: moving out of the \\All folder is refused, other sources are not" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings(
        "moving out of \"[Gmail]/All Mail\" (\\All) is not supported; use copy_messages to add a label",
        (try moveSourceReason(a, find(&gmail_boxes, "[Gmail]/All Mail").?)).?,
    );
    try testing.expect((try moveSourceReason(a, find(&gmail_boxes, "INBOX").?)) == null);
    try testing.expect((try moveSourceReason(a, find(&gmail_boxes, "[Gmail]/Trash").?)) == null);
}

test "review: the configured drafts folder and its ancestors are protected" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        mbox("Entw&APw-rfe", &.{"\\HasNoChildren"}),
        mbox("Mail", &.{"\\HasChildren"}),
        mbox("Mail/Drafts", &.{"\\HasNoChildren"}),
    };
    try testing.expectEqualStrings(
        "\"Entw\u{fc}rfe\" is the drafts folder used by create_message and cannot be renamed or deleted",
        (try protectedReason(a, &boxes, "Entw&APw-rfe", "Entw&APw-rfe")).?,
    );
    try testing.expectEqualStrings(
        "\"Mail\" contains the drafts folder \"Mail/Drafts\" used by create_message and cannot be renamed or deleted",
        (try protectedReason(a, &boxes, "Mail", "Mail/Drafts")).?,
    );
    try testing.expect((try protectedReason(a, &boxes, "Mail", "Entw&APw-rfe")) == null);
    try testing.expect((try protectedReason(a, &boxes, "Mail/Drafts", null)) == null);
}

test "review: protection messages show server names without invisible characters" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        mbox("Sent&IAs-", &.{"\\Sent"}), // "Sent\u{200B}"
        mbox("Old", &.{"\\HasChildren"}),
        mbox("Old/Arch&IA4-ive", &.{"\\Archive"}), // "Old/Arch\u{200E}ive"
    };
    try testing.expectEqualStrings(
        "\"Sent\" is a special-use folder (\\Sent) and cannot be renamed or deleted",
        (try protectedReason(a, &boxes, "Sent&IAs-", null)).?,
    );
    try testing.expectEqualStrings(
        "\"Old\" contains the special-use folder \"Old/Archive\" (\\Archive) and cannot be renamed or deleted",
        (try protectedReason(a, &boxes, "Old", null)).?,
    );
}
