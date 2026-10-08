//! MCP prompts: two carried over verbatim from vivier/imap-mcp-server (spec
//! §6.1), plus organize_my_mailbox (organize-mailbox spec §2.3).

const std = @import("std");
const Stringify = std.json.Stringify;

const Argument = struct {
    name: []const u8,
    description: []const u8 = "",
    required: bool = true,
};

const Prompt = struct {
    name: []const u8,
    description: []const u8,
    arguments: []const Argument = &.{},
};

pub const prompts = [_]Prompt{
    .{
        .name = "list_patches_of_a_series",
        .description = "Generates a user message to list all patches in a series given a cover letter.\nFor a cover letter [PATCH 0/X], this will find patches [PATCH 1/X] to [PATCH X/X]",
        .arguments = &.{.{ .name = "cover_letter" }},
    },
    .{
        .name = "review_a_patch_series",
        .description = "Generates a user message with instructions on how to properly review a patch series",
    },
    .{
        .name = "organize_my_mailbox",
        .description = "Organize a mailbox: classify the newest messages (move, delete to Trash, flag, keep), show the plan as a dry run, and carry it out only after confirmation.",
        .arguments = &.{
            .{ .name = "account", .description = "Account name (default: ask, or the only account)", .required = false },
            .{ .name = "directory", .description = "Folder to organize (default INBOX)", .required = false },
        },
    },
};

pub fn writeList(jw: *Stringify) Stringify.Error!void {
    try jw.beginArray();
    for (prompts) |p| {
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(p.name);
        try jw.objectField("description");
        try jw.write(p.description);
        try jw.objectField("arguments");
        try jw.beginArray();
        for (p.arguments) |a| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(a.name);
            if (a.description.len > 0) {
                try jw.objectField("description");
                try jw.write(a.description);
            }
            try jw.objectField("required");
            try jw.write(a.required);
            try jw.endObject();
        }
        try jw.endArray();
        try jw.endObject();
    }
    try jw.endArray();
}

pub const GetError = error{ UnknownPrompt, MissingArgument } || std.mem.Allocator.Error;

/// Returns the user-message text for `prompts/get`.
pub fn render(arena: std.mem.Allocator, name: []const u8, args: ?std.json.ObjectMap) GetError![]const u8 {
    if (std.mem.eql(u8, name, "list_patches_of_a_series")) {
        const v = (if (args) |a| a.get("cover_letter") else null) orelse return error.MissingArgument;
        if (v != .string) return error.MissingArgument;
        return arena.print("Search emails with In-Reply-To equal to Message-ID of {s}", .{v.string});
    }
    if (std.mem.eql(u8, name, "organize_my_mailbox")) {
        const account = optionalString(args, "account");
        const directory = optionalString(args, "directory") orelse "INBOX";
        const who = if (account) |a|
            try arena.print("account \"{s}\"", .{a})
        else
            "the account I name (call list_accounts and ask me if it is not obvious)";
        return arena.print(organize_text, .{ directory, who });
    }
    if (std.mem.eql(u8, name, "review_a_patch_series")) {
        return "When replying to reviews or patch series: reply to each message individually, include the full original message inline, and place your comment directly beneath the specific line you are annotating. Format your answer on 80 columns";
    }
    return error.UnknownPrompt;
}

fn optionalString(args: ?std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = (args orelse return null).get(key) orelse return null;
    if (v != .string or v.string.len == 0) return null;
    return v.string;
}

const organize_text =
    \\Organize the folder "{s}" of {s}.
    \\
    \\1. Call organize_mailbox for it. Read the returned "instructions" and follow them.
    \\2. Classify every returned message: move (to a folder from "folders"), delete (moves to Trash), flag (needs my attention), or keep. Messages marked "withheld" must be keep.
    \\3. Call apply_organization with execute=false and show me the plan: for each group, the count and the senders and subjects; mention anything you left alone on purpose and any new folders you would suggest.
    \\4. Only after I confirm, call apply_organization again with the same actions, execute=true and the plan_hash from step 3. If I change the plan, run step 3 again first.
    \\5. If more messages remain, offer to continue with the next batch.
;

const testing = std.testing;

test "render" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var args: std.json.ObjectMap = .empty;
    try args.put(a, "cover_letter", .{ .string = "<cover@x>" });
    try testing.expectEqualStrings(
        "Search emails with In-Reply-To equal to Message-ID of <cover@x>",
        try render(a, "list_patches_of_a_series", args),
    );
    try testing.expectError(error.MissingArgument, render(a, "list_patches_of_a_series", null));
    try testing.expectError(error.UnknownPrompt, render(a, "nope", null));
}

test "organize_my_mailbox: optional account and directory" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const plain = try render(a, "organize_my_mailbox", null);
    try testing.expect(std.mem.startsWith(u8, plain, "Organize the folder \"INBOX\" of the account I name"));
    try testing.expect(std.mem.find(u8, plain, "execute=false") != null);
    try testing.expect(std.mem.find(u8, plain, "plan_hash") != null);
    var args: std.json.ObjectMap = .empty;
    try args.put(a, "account", .{ .string = "work" });
    try args.put(a, "directory", .{ .string = "Archive" });
    try testing.expect(std.mem.startsWith(u8, try render(a, "organize_my_mailbox", args), "Organize the folder \"Archive\" of account \"work\"."));
}

test "prompts/list marks organize_my_mailbox arguments optional" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    try testing.expect(std.mem.find(u8, aw.written(), "{\"name\":\"cover_letter\",\"required\":true}") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"name\":\"account\",\"description\":\"Account name (default: ask, or the only account)\",\"required\":false") != null);
}
