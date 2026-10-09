//! PKCE (RFC 7636, S256) and the OAuth `state` value (ADR 0020).

const std = @import("std");
const Allocator = std.mem.Allocator;

const b64 = std.base64.url_safe_no_pad.Encoder;

/// base64url of 32 random bytes: 43 characters, as RFC 7636 §4.1 recommends.
/// Uses the OS's secure source and fails closed: a predictable verifier or
/// state would defeat PKCE and the CSRF check.
pub fn randomToken(io: std.Io) std.Io.RandomSecureError![43]u8 {
    var raw: [32]u8 = undefined;
    try io.randomSecure(&raw);
    var out: [43]u8 = undefined;
    _ = b64.encode(&out, &raw);
    return out;
}

/// code_challenge = BASE64URL(SHA256(ASCII(code_verifier))).
pub fn challenge(verifier: []const u8) [43]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    var out: [43]u8 = undefined;
    _ = b64.encode(&out, &digest);
    return out;
}

const testing = std.testing;

test "RFC 7636 Appendix B test vector" {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    try testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge(verifier));
}

test "random tokens are 43 url-safe characters and differ" {
    const a = try randomToken(testing.io);
    const b = try randomToken(testing.io);
    try testing.expect(!std.mem.eql(u8, &a, &b));
    for (a) |ch| try testing.expect(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_');
}
