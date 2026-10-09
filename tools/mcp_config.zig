//! Build-time helper that adds the server entry to an MCP client's
//! configuration file, or removes it again. Run by the install-*/uninstall-*
//! steps in build.zig (ADR 0024). Adapted from tp-things3-mcp.
//!
//! The server must load imap.env before it starts, so the entry runs a
//! wrapper. Two templates in <config-dir> describe it:
//!
//!   mcp.envfile.json   /bin/sh -c 'set -a; . <env-file>; exec <binary>'
//!   mcp.op.json        <op> run --env-file <env-file> -- <binary>
//!
//! Their placeholders @BINARY@, @ENV_FILE@ and @OP@ are replaced by absolute
//! paths given as `key=value` settings:
//!
//!   binary=<path>  env-file=<path>  op=<path>  secrets=auto|op|envfile
//!
//! `secrets=auto` (the default) picks op mode when the env file contains an
//! `op://` reference outside comments, env-file mode otherwise.
//!
//!   mcp_config name <config-dir>
//!   mcp_config entry <config-dir> <setting>...              prints the entry as JSON
//!   mcp_config install-json <config-dir> <file> <setting>...   mcpServers JSON (Claude Desktop)
//!   mcp_config uninstall-json <config-dir> <file>
//!   mcp_config install-toml <config-dir> <file> <setting>...   [mcp_servers.*] TOML (ChatGPT, Codex)
//!   mcp_config uninstall-toml <config-dir> <file>
//!
//! Other servers and settings in the file are kept. Before changing an
//! existing file, its previous contents are saved next to it as `<file>.bak`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = Io.Dir;
const json = std.json;

const max_file = 16 * 1024 * 1024;

const Entry = struct {
    name: []const u8,
    /// The server object, e.g. {"command": "...", "args": [...]}.
    value: json.Value,
};

const Secrets = enum { auto, op, envfile };

/// The `key=value` settings of an install command.
const Settings = struct {
    binary: ?[]const u8 = null,
    env_file: ?[]const u8 = null,
    op: ?[]const u8 = null,
    secrets: Secrets = .auto,

    fn parse(args: []const [:0]const u8) !Settings {
        var s: Settings = .{};
        for (args) |arg| {
            const eq = std.mem.findScalar(u8, arg, '=') orelse return error.Usage;
            const key = arg[0..eq];
            const value = arg[eq + 1 ..];
            if (eql(key, "binary")) {
                s.binary = value;
            } else if (eql(key, "env-file")) {
                s.env_file = value;
            } else if (eql(key, "op")) {
                s.op = if (value.len == 0) null else value;
            } else if (eql(key, "secrets")) {
                s.secrets = std.meta.stringToEnum(Secrets, value) orelse return error.UnknownSecretsMode;
            } else return error.Usage;
        }
        return s;
    }
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(arena);
    var stderr_buf: [1024]u8 = undefined;
    var stderr = Io.File.stderr().writer(io, &stderr_buf);
    const err_out = &stderr.interface;

    run(arena, io, argv, init.environ_map.get("PATH") orelse "") catch |err| {
        switch (err) {
            error.Usage => try err_out.writeAll(usage),
            error.EnvFileNotFound => try err_out.writeAll("mcp_config: the env file does not exist; create it (see imap.env.example) or pass -Denv-file=<path>\n"),
            error.OpNotFound => try err_out.writeAll("mcp_config: 1Password mode needs the op CLI; install it (brew install 1password-cli) or pass -Dop=<path>, or use -Dsecrets=envfile\n"),
            error.PathNotAbsolute => try err_out.writeAll("mcp_config: binary, env-file and op must be absolute paths\n"),
            else => try err_out.print("mcp_config: {t}\n", .{err}),
        }
        try err_out.flush();
        return 1;
    };
    return 0;
}

const usage =
    \\usage: mcp_config name <config-dir>
    \\       mcp_config entry <config-dir> <setting>...
    \\       mcp_config (install-json|install-toml) <config-dir> <file> <setting>...
    \\       mcp_config (uninstall-json|uninstall-toml) <config-dir> <file>
    \\settings: binary=<path> env-file=<path> [op=<path>] [secrets=auto|op|envfile]
    \\
;

fn run(arena: Allocator, io: Io, argv: []const [:0]const u8, path_env: []const u8) !void {
    if (argv.len < 3) return error.Usage;
    const cmd = argv[1];
    const config_dir = argv[2];
    const args = argv[3..];

    var stdout_buf: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buf);
    const out = &stdout.interface;

    if (eql(cmd, "name") and args.len == 0) {
        const entry = try loadTemplate(arena, io, config_dir, .envfile, null);
        try out.print("{s}\n", .{entry.name});
    } else if (eql(cmd, "entry")) {
        const entry = try resolveEntry(arena, io, path_env, config_dir, try Settings.parse(args));
        try json.Stringify.value(entry.value, .{}, out);
        try out.writeByte('\n');
    } else if (eql(cmd, "install-json") and args.len >= 1) {
        const entry = try resolveEntry(arena, io, path_env, config_dir, try Settings.parse(args[1..]));
        const old = try readOptional(arena, io, args[0]);
        try update(arena, io, args[0], old, try jsonInstall(arena, old, entry), out);
    } else if (eql(cmd, "uninstall-json") and args.len == 1) {
        const entry = try loadTemplate(arena, io, config_dir, .envfile, null);
        const old = try readOptional(arena, io, args[0]) orelse return notFound(out, args[0]);
        try update(arena, io, args[0], old, try jsonUninstall(arena, old, entry.name), out);
    } else if (eql(cmd, "install-toml") and args.len >= 1) {
        const entry = try resolveEntry(arena, io, path_env, config_dir, try Settings.parse(args[1..]));
        const old = try readOptional(arena, io, args[0]);
        try update(arena, io, args[0], old, try tomlInstall(arena, old orelse "", entry), out);
    } else if (eql(cmd, "uninstall-toml") and args.len == 1) {
        const entry = try loadTemplate(arena, io, config_dir, .envfile, null);
        const old = try readOptional(arena, io, args[0]) orelse return notFound(out, args[0]);
        try update(arena, io, args[0], old, try tomlRemove(arena, old, entry.name), out);
    } else return error.Usage;
    try out.flush();
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn notFound(out: *Io.Writer, path: []const u8) !void {
    try out.print("{s} does not exist; nothing to remove\n", .{path});
    try out.flush();
}

/// Checks the settings, picks the template for the secrets mode and fills in
/// the paths.
fn resolveEntry(arena: Allocator, io: Io, path_env: []const u8, config_dir: []const u8, s: Settings) !Entry {
    const binary = s.binary orelse return error.Usage;
    const env_file = s.env_file orelse return error.Usage;
    if (!std.fs.path.isAbsolute(binary) or !std.fs.path.isAbsolute(env_file)) return error.PathNotAbsolute;
    const env_text = Dir.cwd().readFileAlloc(io, env_file, arena, .limited(max_file)) catch |err| switch (err) {
        error.FileNotFound => return error.EnvFileNotFound,
        else => return err,
    };
    const mode: Secrets = switch (s.secrets) {
        .auto => if (hasOpReference(env_text)) .op else .envfile,
        else => s.secrets,
    };
    var op: []const u8 = "";
    if (mode == .op) {
        op = s.op orelse try findOp(arena, io, path_env);
        if (!std.fs.path.isAbsolute(op)) return error.PathNotAbsolute;
    }
    return loadTemplate(arena, io, config_dir, mode, .{ .binary = binary, .env_file = env_file, .op = op });
}

/// The first executable `op` on PATH or in the usual Homebrew locations.
fn findOp(arena: Allocator, io: Io, path_env: []const u8) ![]const u8 {
    var dirs = std.mem.tokenizeScalar(u8, path_env, ':');
    var candidates: std.ArrayList([]const u8) = .empty;
    while (dirs.next()) |dir| if (std.fs.path.isAbsolute(dir)) try candidates.append(arena, dir);
    try candidates.appendSlice(arena, &.{ "/opt/homebrew/bin", "/usr/local/bin" });
    for (candidates.items) |dir| {
        const path = try std.fs.path.join(arena, &.{ dir, "op" });
        Dir.cwd().access(io, path, .{ .execute = true }) catch continue;
        return path;
    }
    return error.OpNotFound;
}

/// True when a non-comment line of an env file contains an `op://` reference.
fn hasOpReference(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (t.len == 0 or t[0] == '#') continue;
        if (std.mem.find(u8, t, "op://") != null) return true;
    }
    return false;
}

const Paths = struct { binary: []const u8, env_file: []const u8, op: []const u8 };

/// The single server in the mode's template `mcpServers`, with the
/// placeholders replaced when `paths` is given.
fn loadTemplate(arena: Allocator, io: Io, config_dir: []const u8, mode: Secrets, paths: ?Paths) !Entry {
    const file = switch (mode) {
        .op => "mcp.op.json",
        .envfile, .auto => "mcp.envfile.json",
    };
    const text = try Dir.cwd().readFileAlloc(io, try std.fs.path.join(arena, &.{ config_dir, file }), arena, .limited(max_file));
    return parseTemplate(arena, text, paths);
}

fn parseTemplate(arena: Allocator, template: []const u8, paths: ?Paths) !Entry {
    var text = template;
    if (paths) |p| {
        for ([_][2][]const u8{ .{ "@BINARY@", p.binary }, .{ "@ENV_FILE@", p.env_file }, .{ "@OP@", p.op } }) |sub| {
            // JSON-escape the path before splicing it into the template text.
            const quoted = try json.Stringify.valueAlloc(arena, sub[1], .{});
            text = try std.mem.replaceOwned(u8, arena, text, sub[0], quoted[1 .. quoted.len - 1]);
        }
    }
    const root = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
    const servers = field(root, "mcpServers") orelse return error.TemplateWithoutMcpServers;
    if (servers != .object or servers.object.count() != 1) return error.TemplateNeedsExactlyOneServer;
    const name = servers.object.keys()[0];
    const value = servers.object.values()[0];
    if (value != .object or field(value, "command") == null) return error.TemplateServerWithoutCommand;
    return .{ .name = name, .value = value };
}

fn field(v: json.Value, name: []const u8) ?json.Value {
    return if (v == .object) v.object.get(name) else null;
}

fn readOptional(arena: Allocator, io: Io, path: []const u8) !?[]const u8 {
    return Dir.cwd().readFileAlloc(io, path, arena, .limited(max_file)) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
}

/// Writes `new` to `path` if it differs from `old`: the old contents go to
/// `<path>.bak`, the new ones to a temporary file renamed over `path`, which
/// keeps its permissions.
fn update(arena: Allocator, io: Io, path: []const u8, old: ?[]const u8, new: []const u8, out: *Io.Writer) !void {
    const cwd = Dir.cwd();
    if (old) |o| if (eql(o, new)) {
        try out.print("{s} is already up to date\n", .{path});
        return;
    };
    var permissions: Io.File.Permissions = .default_file;
    if (old) |o| {
        permissions = (try cwd.statFile(io, path, .{})).permissions;
        const backup = try arena.print("{s}.bak", .{path});
        try cwd.writeFile(io, .{ .sub_path = backup, .data = o, .flags = .{ .permissions = permissions } });
        try out.print("saved the previous {s} as {s}\n", .{ path, backup });
    } else if (std.fs.path.dirname(path)) |dir| {
        try cwd.createDirPath(io, dir);
    }
    const tmp = try arena.print("{s}.tmp", .{path});
    try cwd.writeFile(io, .{ .sub_path = tmp, .data = new, .flags = .{ .permissions = permissions } });
    try Dir.rename(cwd, tmp, cwd, path, io);
    try out.print("updated {s}\n", .{path});
}

// --- JSON (mcpServers) -----------------------------------------------------

fn jsonInstall(arena: Allocator, old: ?[]const u8, entry: Entry) ![]const u8 {
    var root: json.Value = if (old) |o| try parseConfig(arena, o) else .{ .object = .empty };
    const servers = try root.object.getOrPut(arena, "mcpServers");
    if (!servers.found_existing or servers.value_ptr.* != .object) servers.value_ptr.* = .{ .object = .empty };
    try servers.value_ptr.object.put(arena, entry.name, entry.value);
    return stringifyConfig(arena, root);
}

fn jsonUninstall(arena: Allocator, old: []const u8, name: []const u8) ![]const u8 {
    var root = try parseConfig(arena, old);
    const servers = root.object.getPtr("mcpServers") orelse return old;
    // Leave the file untouched (not even reformatted) when there's nothing to remove.
    if (servers.* != .object or !servers.object.orderedRemove(name)) return old;
    return stringifyConfig(arena, root);
}

fn parseConfig(arena: Allocator, text: []const u8) !json.Value {
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return .{ .object = .empty };
    const root = try json.parseFromSliceLeaky(json.Value, arena, text, .{});
    if (root != .object) return error.ConfigIsNotAJsonObject;
    return root;
}

fn stringifyConfig(arena: Allocator, root: json.Value) ![]const u8 {
    const text = try json.Stringify.valueAlloc(arena, root, .{ .whitespace = .indent_2 });
    return arena.print("{s}\n", .{text});
}

// --- TOML ([mcp_servers.<name>]) -------------------------------------------

fn tomlInstall(arena: Allocator, old: []const u8, entry: Entry) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const kept = std.mem.trimEnd(u8, try tomlRemove(arena, old, entry.name), " \t\r\n");
    if (kept.len > 0) try out.print(arena, "{s}\n\n", .{kept});

    try out.print(arena, "[mcp_servers.{s}]\n", .{entry.name});
    var subtables: std.ArrayList([]const u8) = .empty;
    var it = entry.value.object.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* == .object) {
            try subtables.append(arena, kv.key_ptr.*);
            continue;
        }
        try out.print(arena, "{s} = ", .{kv.key_ptr.*});
        try tomlValue(arena, &out, kv.value_ptr.*);
        try out.append(arena, '\n');
    }
    for (subtables.items) |key| {
        try out.print(arena, "\n[mcp_servers.{s}.{s}]\n", .{ entry.name, key });
        var sub = entry.value.object.get(key).?.object.iterator();
        while (sub.next()) |kv| {
            try out.print(arena, "{s} = ", .{kv.key_ptr.*});
            try tomlValue(arena, &out, kv.value_ptr.*);
            try out.append(arena, '\n');
        }
    }
    return out.items;
}

/// Strings, booleans, numbers and arrays of them. JSON string escapes are
/// valid TOML basic-string escapes, so strings are written as JSON.
fn tomlValue(arena: Allocator, out: *std.ArrayList(u8), v: json.Value) !void {
    switch (v) {
        .string, .bool, .integer, .float => try out.appendSlice(arena, try json.Stringify.valueAlloc(arena, v, .{})),
        .array => |a| {
            try out.append(arena, '[');
            for (a.items, 0..) |item, i| {
                if (i > 0) try out.appendSlice(arena, ", ");
                try tomlValue(arena, out, item);
            }
            try out.append(arena, ']');
        },
        else => return error.UnsupportedTemplateValue,
    }
}

/// `text` without the `[mcp_servers.<name>]` table and its subtables.
fn tomlRemove(arena: Allocator, text: []const u8, name: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var skipping = false;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (lines.index == null and line.len == 0) break; // after the final '\n'
        const t = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, t, "[")) skipping = try isServerHeader(arena, t, name);
        if (skipping) continue;
        try out.appendSlice(arena, line);
        try out.append(arena, '\n');
    }
    if (!std.mem.endsWith(u8, text, "\n") and out.items.len > 0) out.items.len -= 1;
    return out.items;
}

/// True for `[mcp_servers.<name>]`, `[mcp_servers."<name>"]` and their
/// subtables such as `[mcp_servers.<name>.env]`.
fn isServerHeader(arena: Allocator, header: []const u8, name: []const u8) !bool {
    var buf: std.ArrayList(u8) = .empty;
    for (header) |c| if (c != ' ' and c != '\t') try buf.append(arena, c);
    const h = buf.items;
    for ([_][]const u8{ try arena.print("[mcp_servers.{s}", .{name}), try arena.print("[mcp_servers.\"{s}\"", .{name}) }) |prefix| {
        if (!std.mem.startsWith(u8, h, prefix)) continue;
        const rest = h[prefix.len..];
        if (rest.len > 0 and (rest[0] == ']' or rest[0] == '.')) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------

const testing = std.testing;

test {
    _ = &main; // so `zig build test` also type-checks the command-line code
}

fn testEntry(arena: Allocator) !Entry {
    const v = try json.parseFromSliceLeaky(json.Value, arena,
        \\{"command":"/Users/me/.local/bin/things3-mcp","env":{"THINGS3_MCP_AUDIT":"1"}}
    , .{});
    return .{ .name = "things", .value = v };
}

test "auto mode: op:// outside comments selects 1Password" {
    try testing.expect(hasOpReference("A=1\nIMAP_X_PASSWORD=\"op://Vault/Item/password\"\n"));
    try testing.expect(!hasOpReference("# Values may be op:// references\nA=1\n"));
    try testing.expect(!hasOpReference("   # op://x\n\n"));
}

test "templates: paths are filled in and JSON-escaped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const paths: Paths = .{ .binary = "/Users/me/.local/bin/tp_imap_mcp", .env_file = "/Users/me/my \"mail\".env", .op = "/opt/homebrew/bin/op" };

    const op = try parseTemplate(a,
        \\{"mcpServers":{"imap":{"command":"@OP@","args":["run","--env-file","@ENV_FILE@","--","@BINARY@"]}}}
    , paths);
    try testing.expectEqualStrings("imap", op.name);
    try testing.expectEqualStrings(
        \\{"command":"/opt/homebrew/bin/op","args":["run","--env-file","/Users/me/my \"mail\".env","--","/Users/me/.local/bin/tp_imap_mcp"]}
    , try json.Stringify.valueAlloc(a, op.value, .{}));

    const sh = try parseTemplate(a,
        \\{"mcpServers":{"imap":{"command":"/bin/sh","args":["-c","set -a; . \"$0\"; exec \"$1\"","@ENV_FILE@","@BINARY@"]}}}
    , paths);
    var toml: std.ArrayList(u8) = .empty;
    try tomlValue(a, &toml, field(sh.value, "args").?);
    try testing.expectEqualStrings(
        \\["-c", "set -a; . \"$0\"; exec \"$1\"", "/Users/me/my \"mail\".env", "/Users/me/.local/bin/tp_imap_mcp"]
    , toml.items);
}

test "settings: key=value pairs" {
    const s = try Settings.parse(&.{ "binary=/b", "env-file=/e", "op=", "secrets=envfile" });
    try testing.expectEqualStrings("/b", s.binary.?);
    try testing.expectEqualStrings("/e", s.env_file.?);
    try testing.expect(s.op == null);
    try testing.expectEqual(Secrets.envfile, s.secrets);
    try testing.expectError(error.UnknownSecretsMode, Settings.parse(&.{"secrets=vault"}));
    try testing.expectError(error.Usage, Settings.parse(&.{"bogus"}));
}

test "json: adds the server and keeps the others" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const got = try jsonInstall(a,
        \\{"mcpServers":{"Wolfram":{"command":"/w"}},"other":true}
    , try testEntry(a));
    try testing.expectEqualStrings(
        \\{
        \\  "mcpServers": {
        \\    "Wolfram": {
        \\      "command": "/w"
        \\    },
        \\    "things": {
        \\      "command": "/Users/me/.local/bin/things3-mcp",
        \\      "env": {
        \\        "THINGS3_MCP_AUDIT": "1"
        \\      }
        \\    }
        \\  },
        \\  "other": true
        \\}
        \\
    , got);
    const removed = try jsonUninstall(a, got, "things");
    try testing.expect(std.mem.find(u8, removed, "things") == null);
    try testing.expect(std.mem.find(u8, removed, "Wolfram") != null);
}

test "json: a missing or empty file gets a fresh config" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const fresh = try jsonInstall(a, null, try testEntry(a));
    try testing.expect(std.mem.startsWith(u8, fresh, "{\n  \"mcpServers\": {\n    \"things\": {"));
    try testing.expectEqualStrings(fresh, try jsonInstall(a, "\n", try testEntry(a)));
}

test "toml: replaces the server's tables and keeps the rest" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const old =
        \\model = "gpt-5"
        \\
        \\[mcp_servers.things]
        \\command = "/old/path"
        \\
        \\[mcp_servers.things.env]
        \\THINGSDB = "/x"
        \\
        \\[mcp_servers.thingsish]
        \\command = "/keep"
        \\
    ;
    try testing.expectEqualStrings(
        \\model = "gpt-5"
        \\
        \\[mcp_servers.thingsish]
        \\command = "/keep"
        \\
        \\[mcp_servers.things]
        \\command = "/Users/me/.local/bin/things3-mcp"
        \\
        \\[mcp_servers.things.env]
        \\THINGS3_MCP_AUDIT = "1"
        \\
    , try tomlInstall(a, old, try testEntry(a)));
    const removed = try tomlRemove(a, old, "things");
    try testing.expect(std.mem.find(u8, removed, "/old/path") == null);
    try testing.expect(std.mem.find(u8, removed, "[mcp_servers.thingsish]") != null);
}

test "toml: quoted table names and escapes" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("a = 1\n", try tomlRemove(a, "a = 1\n[ mcp_servers.\"things\" ]\ncommand = \"/x\"\n", "things"));
    var out: std.ArrayList(u8) = .empty;
    try tomlValue(a, &out, .{ .string = "C:\\a \"b\"" });
    try testing.expectEqualStrings("\"C:\\\\a \\\"b\\\"\"", out.items);
}
