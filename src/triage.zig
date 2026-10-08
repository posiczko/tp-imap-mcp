//! organize_mailbox / apply_organization rules (ADR 0022, spec §2-§5):
//! organizing instructions, action parsing and validation, grouping, plan
//! hash, snippets. No IMAP I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap/session.zig");
const organize = @import("organize.zig");
const text = @import("text.zig");

/// Most actions one apply_organization call accepts.
pub const max_actions = 500;
/// Most messages one organize_mailbox call returns.
pub const max_limit = 200;
pub const default_limit = 50;
/// Bytes of each message fetched for its snippet (BODY.PEEK[]<0.N>).
pub const partial_bytes = imap.What.partial_bytes;
/// Characters of sanitized text in a snippet.
pub const snippet_bytes = 500;
/// Largest organize.md accepted.
pub const instructions_max = 16 * 1024;
/// Keyword marking messages a plan kept or flagged (spec §2.2).
pub const reviewed_keyword = "$TpOrganized";
/// Built-in organizing instructions (spec §5).
pub const default_instructions = @embedFile("organize_prompt.md");

pub const Instructions = struct {
    text: []const u8,
    /// The file it came from, or "built-in".
    source: []const u8,
};

pub const LoadResult = union(enum) {
    ok: Instructions,
    /// Human-readable reason (the file is too large or unreadable).
    problem: []const u8,
};

/// `<config_dir>/organize.<account>.md`, else `<config_dir>/organize.md`,
/// else the built-in default. The account name is lowercased.
pub fn loadInstructions(arena: Allocator, io: std.Io, config_dir: ?[]const u8, account: []const u8) Allocator.Error!LoadResult {
    const dir = config_dir orelse return .{ .ok = .{ .text = default_instructions, .source = "built-in" } };
    const per_account = try arena.print("organize.{s}.md", .{try std.ascii.allocLowerString(arena, account)});
    for ([_][]const u8{ per_account, "organize.md" }) |name| {
        const path = try std.fs.path.join(arena, &.{ dir, name });
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(instructions_max + 1)) catch |err| switch (err) {
            error.FileNotFound => continue,
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return .{ .problem = try arena.print("{s} is larger than {d} bytes", .{ path, instructions_max }) },
            else => return .{ .problem = try arena.print("{s}: cannot read ({t})", .{ path, err }) },
        };
        if (bytes.len > instructions_max) return .{ .problem = try arena.print("{s} is larger than {d} bytes", .{ path, instructions_max }) };
        return .{ .ok = .{ .text = try text.sanitizeUtf8(arena, bytes), .source = path } };
    }
    return .{ .ok = .{ .text = default_instructions, .source = "built-in" } };
}

pub const Kind = enum { move, delete, flag, keep };

pub const Action = struct {
    uid: u32,
    kind: Kind,
    /// UTF-8 folder name; set for `move` only.
    destination: ?[]const u8 = null,
};

pub const ParseResult = union(enum) {
    ok: []Action,
    problem: []const u8,
};

/// Parses the `actions` argument (spec §2.2): 1..max_actions objects
/// `{uid, action, destination?}`, each UID at most once.
pub fn parseActions(arena: Allocator, value: ?std.json.Value) Allocator.Error!ParseResult {
    const v = value orelse return .{ .problem = "missing required argument \"actions\"" };
    if (v != .array) return .{ .problem = "argument \"actions\" must be an array" };
    const items = v.array.items;
    if (items.len == 0) return .{ .problem = "actions must not be empty" };
    if (items.len > max_actions) return .{ .problem = try arena.print("at most {d} actions per call; got {d}", .{ max_actions, items.len }) };
    const out = try arena.alloc(Action, items.len);
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for (items, out, 0..) |item, *o, i| {
        if (item != .object) return .{ .problem = try arena.print("actions[{d}] must be an object", .{i}) };
        const obj = item.object;
        const uid_v = obj.get("uid") orelse return .{ .problem = try arena.print("actions[{d}] has no \"uid\"", .{i}) };
        if (uid_v != .string) return .{ .problem = try arena.print("actions[{d}].uid must be a string", .{i}) };
        const uid = parseUid(uid_v.string) orelse return .{ .problem = try arena.print("actions[{d}].uid must be a decimal string between 1 and 4294967295", .{i}) };
        if ((try seen.getOrPut(arena, uid)).found_existing) return .{ .problem = try arena.print("uid {d} appears more than once", .{uid}) };
        const kind_v = obj.get("action") orelse return .{ .problem = try arena.print("actions[{d}] has no \"action\"", .{i}) };
        const kind = if (kind_v == .string) std.meta.stringToEnum(Kind, kind_v.string) else null;
        const k = kind orelse return .{ .problem = try arena.print("actions[{d}].action must be \"move\", \"delete\", \"flag\" or \"keep\"", .{i}) };
        const dest_v = obj.get("destination");
        if (k == .move) {
            const d = dest_v orelse return .{ .problem = try arena.print("actions[{d}]: \"move\" needs a \"destination\"", .{i}) };
            if (d != .string or d.string.len == 0) return .{ .problem = try arena.print("actions[{d}].destination must be a non-empty string", .{i}) };
            o.* = .{ .uid = uid, .kind = k, .destination = d.string };
        } else {
            if (dest_v != null and dest_v.? != .null) return .{ .problem = try arena.print("actions[{d}]: only \"move\" takes a \"destination\"", .{i}) };
            o.* = .{ .uid = uid, .kind = k };
        }
    }
    return .{ .ok = out };
}

fn parseUid(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    const u = std.fmt.parseInt(u32, s, 10) catch return null;
    return if (u == 0) null else u;
}

/// 16 lowercase hex characters: SHA-256 over account, directory,
/// UIDVALIDITY, the actions sorted by UID (independent of input order), and
/// the plan's UIDs that do not exist in the folder. Binding the missing UIDs
/// means a message that arrives after the dry run under a planned UID
/// changes the hash, so the plan cannot act on mail the user never saw.
pub fn planHash(arena: Allocator, account: []const u8, directory: []const u8, uidvalidity: u32, actions: []const Action, missing: []const u32) Allocator.Error![16]u8 {
    const sorted = try arena.dupe(Action, actions);
    std.mem.sort(Action, sorted, {}, struct {
        fn lt(_: void, a: Action, b: Action) bool {
            return a.uid < b.uid;
        }
    }.lt);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var num: [16]u8 = undefined;
    h.update(account);
    h.update(&.{0});
    h.update(directory);
    h.update(&.{0});
    h.update(std.mem.print(&num, "{d}", .{uidvalidity}) catch unreachable);
    for (sorted) |a| {
        h.update(&.{0});
        h.update(std.mem.print(&num, "{d}", .{a.uid}) catch unreachable);
        h.update(&.{0});
        h.update(@tagName(a.kind));
        h.update(&.{0});
        h.update(a.destination orelse "");
    }
    const gone = try arena.dupe(u32, missing);
    std.mem.sort(u32, gone, {}, std.sort.asc(u32));
    h.update(&.{1});
    for (gone) |u| {
        h.update(&.{0});
        h.update(std.mem.print(&num, "{d}", .{u}) catch unreachable);
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest[0..8].*, .lower);
}

pub const Group = struct {
    kind: Kind,
    /// Move destination as given (UTF-8); null for other kinds.
    destination: ?[]const u8 = null,
    uids: []const u32,
};

/// Actions grouped for display and execution: moves (by destination, in
/// first-appearance order), then delete, flag, keep. Empty groups omitted.
pub fn group(arena: Allocator, actions: []const Action) Allocator.Error![]Group {
    var out: std.ArrayList(Group) = .empty;
    var dests: std.ArrayList([]const u8) = .empty;
    for (actions) |a| {
        if (a.kind != .move) continue;
        for (dests.items) |d| {
            if (std.mem.eql(u8, d, a.destination.?)) break;
        } else try dests.append(arena, a.destination.?);
    }
    for (dests.items) |d| {
        var uids: std.ArrayList(u32) = .empty;
        for (actions) |a| if (a.kind == .move and std.mem.eql(u8, a.destination.?, d)) try uids.append(arena, a.uid);
        try out.append(arena, .{ .kind = .move, .destination = d, .uids = uids.items });
    }
    for ([_]Kind{ .delete, .flag, .keep }) |k| {
        var uids: std.ArrayList(u32) = .empty;
        for (actions) |a| if (a.kind == k) try uids.append(arena, a.uid);
        if (uids.items.len > 0) try out.append(arena, .{ .kind = k, .uids = uids.items });
    }
    return out.items;
}

/// The account's Trash folder (`\Trash` attribute), if any.
pub fn trashFolder(boxes: []const imap.Mailbox) ?imap.Mailbox {
    for (boxes) |b| for (b.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Trash")) return b;
    };
    return null;
}

fn hasFlag(box: imap.Mailbox, flag: []const u8) bool {
    for (box.flags) |f| if (std.ascii.eqlIgnoreCase(f, flag)) return true;
    return false;
}

/// Folders offered as move destinations from `source` (spec §2.1): selectable,
/// not the source, not \All, \Trash or \Junk.
pub fn folderChoices(arena: Allocator, boxes: []const imap.Mailbox, source: []const u8) Allocator.Error![]imap.Mailbox {
    var out: std.ArrayList(imap.Mailbox) = .empty;
    for (boxes) |b| {
        if (!organize.selectable(b)) continue;
        if (organize.sameMailbox(boxes, b.name, source)) continue;
        if (hasFlag(b, "\\All") or hasFlag(b, "\\Trash") or hasFlag(b, "\\Junk")) continue;
        try out.append(arena, b);
    }
    return out.items;
}

/// Why `dest` (wire name; `shown` for messages) cannot receive a `move` from
/// `source`, or null (spec §2.2).
pub fn destinationProblem(arena: Allocator, boxes: []const imap.Mailbox, source: []const u8, dest: []const u8, shown: []const u8) Allocator.Error!?[]const u8 {
    const box = organize.find(boxes, dest) orelse return try arena.print("destination \"{s}\" does not exist", .{shown});
    if (!organize.selectable(box)) return try arena.print("\"{s}\" cannot hold messages (\\Noselect)", .{shown});
    if (organize.sameMailbox(boxes, source, dest)) return try arena.print("destination \"{s}\" is the folder being organized", .{shown});
    if (hasFlag(box, "\\Trash")) return try arena.print("\"{s}\" is the Trash folder; use action \"delete\"", .{shown});
    if (hasFlag(box, "\\Junk")) return try arena.print("\"{s}\" is the spam/junk folder and is not a move destination", .{shown});
    if (hasFlag(box, "\\All")) return try arena.print("\"{s}\" holds all mail (\\All) and is not a move destination", .{shown});
    return null;
}

/// Sanitized message text cut for a snippet: whitespace runs collapsed, at
/// most `snippet_bytes`, cut at a UTF-8 boundary.
pub fn snippet(arena: Allocator, body_text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var space = false;
    for (body_text) |c| {
        if (std.ascii.isWhitespace(c)) {
            space = out.items.len > 0;
            continue;
        }
        if (space) try out.append(arena, ' ');
        space = false;
        try out.append(arena, c);
        if (out.items.len > snippet_bytes + 4) break;
    }
    return text.truncateUtf8(out.items, snippet_bytes);
}

const testing = std.testing;

fn parseJson(arena: Allocator, s: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, s, .{});
}

test "loadInstructions: per-account file, then organize.md, then the built-in default" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dir = try a.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});

    const none = try loadInstructions(a, testing.io, null, "work");
    try testing.expectEqualStrings("built-in", none.ok.source);
    try testing.expect(std.mem.startsWith(u8, none.ok.text, "# How to organize this mailbox"));
    try testing.expectEqualStrings("built-in", (try loadInstructions(a, testing.io, dir, "work")).ok.source);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = "shared rules" });
    try testing.expectEqualStrings("shared rules", (try loadInstructions(a, testing.io, dir, "work")).ok.text);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.work.md", .data = "work rules" });
    const per = try loadInstructions(a, testing.io, dir, "Work");
    try testing.expectEqualStrings("work rules", per.ok.text);
    try testing.expect(std.mem.endsWith(u8, per.ok.source, "organize.work.md"));
    try testing.expectEqualStrings("shared rules", (try loadInstructions(a, testing.io, dir, "home")).ok.text);
}

test "loadInstructions rejects a file over 16 KiB, naming it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dir = try a.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    const big: [instructions_max + 1]u8 = @splat('x');
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = &big });
    const r = try loadInstructions(a, testing.io, dir, "work");
    try testing.expect(std.mem.endsWith(u8, r.problem, "organize.md is larger than 16384 bytes"));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = big[0..instructions_max] });
    try testing.expectEqual(instructions_max, (try loadInstructions(a, testing.io, dir, "work")).ok.text.len);
}

test "the built-in instructions keep credential mail and withheld messages" {
    try testing.expect(std.mem.find(u8, default_instructions, "withheld") != null);
    try testing.expect(std.mem.find(u8, default_instructions, "password") != null);
    try testing.expect(default_instructions.len <= instructions_max);
}

test "parseActions accepts the four actions and rejects malformed input" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ok = (try parseActions(a, try parseJson(a,
        \\[{"uid":"7","action":"move","destination":"Receipts"},{"uid":"8","action":"delete"},
        \\ {"uid":"9","action":"flag"},{"uid":"10","action":"keep","destination":null}]
    ))).ok;
    try testing.expectEqual(4, ok.len);
    try testing.expectEqualStrings("Receipts", ok[0].destination.?);
    try testing.expectEqual(Kind.keep, ok[3].kind);

    const cases = [_]struct { json: []const u8, problem: []const u8 }{
        .{ .json = "{}", .problem = "argument \"actions\" must be an array" },
        .{ .json = "[]", .problem = "actions must not be empty" },
        .{ .json = "[1]", .problem = "actions[0] must be an object" },
        .{ .json = "[{\"action\":\"keep\"}]", .problem = "actions[0] has no \"uid\"" },
        .{ .json = "[{\"uid\":7,\"action\":\"keep\"}]", .problem = "actions[0].uid must be a string" },
        .{ .json = "[{\"uid\":\"0\",\"action\":\"keep\"}]", .problem = "actions[0].uid must be a decimal string between 1 and 4294967295" },
        .{ .json = "[{\"uid\":\"1:*\",\"action\":\"keep\"}]", .problem = "actions[0].uid must be a decimal string between 1 and 4294967295" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"keep\"},{\"uid\":\"7\",\"action\":\"flag\"}]", .problem = "uid 7 appears more than once" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"archive\"}]", .problem = "actions[0].action must be \"move\", \"delete\", \"flag\" or \"keep\"" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"move\"}]", .problem = "actions[0]: \"move\" needs a \"destination\"" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"move\",\"destination\":\"\"}]", .problem = "actions[0].destination must be a non-empty string" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"delete\",\"destination\":\"Trash\"}]", .problem = "actions[0]: only \"move\" takes a \"destination\"" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.problem, (try parseActions(a, try parseJson(a, c.json))).problem);
    try testing.expectEqualStrings("missing required argument \"actions\"", (try parseActions(a, null)).problem);

    var many: std.ArrayList(u8) = .empty;
    try many.append(a, '[');
    for (1..max_actions + 2) |i| try many.print(a, "{s}{{\"uid\":\"{d}\",\"action\":\"keep\"}}", .{ if (i > 1) "," else "", i });
    try many.append(a, ']');
    try testing.expectEqualStrings("at most 500 actions per call; got 501", (try parseActions(a, try parseJson(a, many.items))).problem);
}

test "planHash ignores action order and changes with any action" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const one = [_]Action{ .{ .uid = 7, .kind = .move, .destination = "Receipts" }, .{ .uid = 8, .kind = .delete } };
    const swapped = [_]Action{ one[1], one[0] };
    const h = try planHash(a, "work", "INBOX", 42, &one, &.{});
    try testing.expectEqual(16, h.len);
    for (h) |c| try testing.expect(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'));
    try testing.expectEqualStrings(&h, &(try planHash(a, "work", "INBOX", 42, &swapped, &.{})));
    const other_dest = [_]Action{ .{ .uid = 7, .kind = .move, .destination = "Receipt" }, one[1] };
    const other_kind = [_]Action{ one[0], .{ .uid = 8, .kind = .keep } };
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 42, &other_dest, &.{}))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 42, &other_kind, &.{}))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 43, &one, &.{}))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "home", "INBOX", 42, &one, &.{}))));
}

test "review: planHash changes when a missing UID appears (new mail after the dry run)" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const plan = [_]Action{ .{ .uid = 7, .kind = .keep }, .{ .uid = 900, .kind = .delete } };
    // Dry run: 900 did not exist yet. Execute: a new message received UID 900.
    const at_dry_run = try planHash(a, "work", "INBOX", 42, &plan, &.{900});
    const at_execute = try planHash(a, "work", "INBOX", 42, &plan, &.{});
    try testing.expect(!std.mem.eql(u8, &at_dry_run, &at_execute));
    try testing.expectEqualStrings(&at_dry_run, &(try planHash(a, "work", "INBOX", 42, &plan, &.{900})));
}

test "group orders moves by destination, then delete, flag, keep" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const acts = [_]Action{
        .{ .uid = 1, .kind = .keep },
        .{ .uid = 2, .kind = .move, .destination = "B" },
        .{ .uid = 3, .kind = .flag },
        .{ .uid = 4, .kind = .move, .destination = "A" },
        .{ .uid = 5, .kind = .move, .destination = "B" },
    };
    const g = try group(a, &acts);
    try testing.expectEqual(4, g.len);
    try testing.expectEqualStrings("B", g[0].destination.?);
    try testing.expectEqualSlices(u32, &.{ 2, 5 }, g[0].uids);
    try testing.expectEqualStrings("A", g[1].destination.?);
    try testing.expectEqual(Kind.flag, g[2].kind);
    try testing.expectEqual(Kind.keep, g[3].kind);
}

fn mbox(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

const test_boxes = [_]imap.Mailbox{
    mbox("INBOX", &.{}),
    mbox("Receipts", &.{}),
    mbox("[Gmail]", &.{"\\Noselect"}),
    mbox("[Gmail]/All Mail", &.{"\\All"}),
    mbox("[Gmail]/Trash", &.{"\\Trash"}),
    mbox("[Gmail]/Spam", &.{"\\Junk"}),
    mbox("[Gmail]/Sent Mail", &.{"\\Sent"}),
};

test "folderChoices and trashFolder" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const choices = try folderChoices(arena_state.allocator(), &test_boxes, "inbox");
    try testing.expectEqual(2, choices.len);
    try testing.expectEqualStrings("Receipts", choices[0].name);
    try testing.expectEqualStrings("[Gmail]/Sent Mail", choices[1].name);
    try testing.expectEqualStrings("[Gmail]/Trash", trashFolder(&test_boxes).?.name);
    try testing.expect(trashFolder(test_boxes[0..2]) == null);
}

test "destinationProblem enforces spec §2.2" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "Receipts", "Receipts")) == null);
    try testing.expectEqualStrings("destination \"Nope\" does not exist", (try destinationProblem(a, &test_boxes, "INBOX", "Nope", "Nope")).?);
    try testing.expectEqualStrings("\"[Gmail]\" cannot hold messages (\\Noselect)", (try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]", "[Gmail]")).?);
    try testing.expectEqualStrings("destination \"Inbox\" is the folder being organized", (try destinationProblem(a, &test_boxes, "INBOX", "Inbox", "Inbox")).?);
    try testing.expectEqualStrings("\"[Gmail]/Trash\" is the Trash folder; use action \"delete\"", (try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/Trash", "[Gmail]/Trash")).?);
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/Spam", "[Gmail]/Spam")) != null);
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/All Mail", "[Gmail]/All Mail")) != null);
}

test "snippet collapses whitespace and cuts at a UTF-8 boundary" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("Hello there, see you", try snippet(a, "  Hello\n\nthere,\t see   you\n"));
    var long: std.ArrayList(u8) = .empty;
    for (0..400) |_| try long.appendSlice(a, "é");
    const s = try snippet(a, long.items);
    try testing.expect(s.len <= snippet_bytes);
    try testing.expect(std.unicode.utf8ValidateSlice(s));
}
