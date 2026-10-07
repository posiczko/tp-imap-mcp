//! MCP prompts, carried over verbatim from vivier/imap-mcp-server (spec §6.1).

const std = @import("std");
const Stringify = std.json.Stringify;

const Prompt = struct {
    name: []const u8,
    description: []const u8,
    argument: ?[]const u8,
};

pub const prompts = [_]Prompt{
    .{
        .name = "list_patches_of_a_series",
        .description = "Generates a user message to list all patches in a series given a cover letter.\nFor a cover letter [PATCH 0/X], this will find patches [PATCH 1/X] to [PATCH X/X]",
        .argument = "cover_letter",
    },
    .{
        .name = "review_a_patch_series",
        .description = "Generates a user message with instructions on how to properly review a patch series",
        .argument = null,
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
        if (p.argument) |a| try jw.write(.{ .name = a, .required = true });
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
    if (std.mem.eql(u8, name, "review_a_patch_series")) {
        return "When replying to reviews or patch series: reply to each message individually, include the full original message inline, and place your comment directly beneath the specific line you are annotating. Format your answer on 80 columns";
    }
    return error.UnknownPrompt;
}

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
