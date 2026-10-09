//! Certificate chain verification in Zig, for TLS backends where libetpan
//! cannot check the server's chain against a CA file: its GnuTLS backend
//! (Debian/Ubuntu's libetpan) leaves mailstream_ssl_set_server_certicate
//! unimplemented (ADR 0016). Runs after the handshake and before any
//! credential is sent; the host name is checked separately.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const Bundle = Certificate.Bundle;
const der = Certificate.der;

pub const Error = error{CertificateUntrusted};

/// Verifies `chain` (DER, leaf first, as the server sent it) up to a CA in
/// `bundle`: each certificate is valid at `now_sec` and signed by the next,
/// every certificate used as an issuer is a CA (basicConstraints cA), and
/// the chain ends at a certificate signed by one in the bundle. Extra
/// certificates after a trusted one are ignored.
pub fn verifyChain(bundle: *const Bundle, chain: []const []const u8, now_sec: i64) Error!void {
    if (chain.len == 0) return error.CertificateUntrusted;
    var subject = parse(chain[0]) catch return error.CertificateUntrusted;
    for (chain[1..]) |issuer_der| {
        if (bundle.verify(subject, now_sec)) |_| return else |_| {}
        const issuer = parse(issuer_der) catch return error.CertificateUntrusted;
        if (!isCa(issuer_der)) return error.CertificateUntrusted;
        subject.verify(issuer, now_sec) catch return error.CertificateUntrusted;
        subject = issuer;
    }
    bundle.verify(subject, now_sec) catch return error.CertificateUntrusted;
}

fn parse(bytes: []const u8) Certificate.ParseError!Certificate.Parsed {
    const cert: Certificate = .{ .buffer = bytes, .index = 0 };
    return cert.parse();
}

/// basicConstraints cA (RFC 5280 4.2.1.9). std's Certificate.Parsed does not
/// expose it, and Parsed.verify does not check it: without this, any leaf
/// certificate from a trusted CA could sign a certificate for another host.
/// False when the extension is absent or the encoding is unexpected.
fn isCa(bytes: []const u8) bool {
    return caFlag(bytes) catch false;
}

fn caFlag(bytes: []const u8) der.Element.ParseError!bool {
    const basic_constraints_oid = [_]u8{ 0x55, 0x1D, 0x13 }; // 2.5.29.19
    const cert = try der.Element.parse(bytes, 0);
    const tbs = try der.Element.parse(bytes, cert.slice.start);
    var i = tbs.slice.start;
    while (i < tbs.slice.end) {
        const field = try der.Element.parse(bytes, i);
        i = field.slice.end;
        // extensions [3] EXPLICIT SEQUENCE OF Extension
        if (field.identifier.class != .context_specific or @intFromEnum(field.identifier.tag) != 3) continue;
        const extensions = try der.Element.parse(bytes, field.slice.start);
        var j = extensions.slice.start;
        while (j < extensions.slice.end) {
            const extension = try der.Element.parse(bytes, j);
            j = extension.slice.end;
            const oid = try der.Element.parse(bytes, extension.slice.start);
            if (!std.mem.eql(u8, bytes[oid.slice.start..oid.slice.end], &basic_constraints_oid)) continue;
            var value = try der.Element.parse(bytes, oid.slice.end);
            if (value.identifier.tag == .boolean) value = try der.Element.parse(bytes, value.slice.end); // critical
            // OCTET STRING { SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL } }
            const constraints = try der.Element.parse(bytes, value.slice.start);
            if (constraints.slice.start >= constraints.slice.end) return false;
            const ca = try der.Element.parse(bytes, constraints.slice.start);
            return ca.identifier.tag == .boolean and ca.slice.end > ca.slice.start and bytes[ca.slice.start] != 0;
        }
        return false;
    }
    return false;
}

/// The CA bundle for verifyChain, read from `ca_file` on first use and kept
/// for later connections.
pub const Trust = struct {
    gpa: Allocator,
    io: std.Io,
    ca_file: []const u8,
    bundle: ?Bundle = null,

    pub fn deinit(self: *Trust) void {
        if (self.bundle) |*b| b.deinit(self.gpa);
        self.bundle = null;
    }

    pub fn get(self: *Trust) error{CaBundleUnreadable}!*const Bundle {
        if (self.bundle == null) {
            var b: Bundle = .empty;
            b.addCertsFromFilePathAbsolute(self.gpa, self.io, .now(self.io, .real), self.ca_file) catch {
                b.deinit(self.gpa);
                return error.CaBundleUnreadable;
            };
            self.bundle = b;
        }
        return &self.bundle.?;
    }
};

const testing = std.testing;

// Gmail's public chain as served on 2026-10-09 (leaf valid 2026-09-18 to
// 2026-12-11), the self-signed GTS Root R1 and an unrelated root.
const leaf = @embedFile("../testdata/tls/gmail-leaf.der");
const wr2 = @embedFile("../testdata/tls/gmail-wr2.der");
const r1_cross = @embedFile("../testdata/tls/gts-r1-cross.der");
const t_valid: i64 = 1791504000; // 2026-10-09T00:00:00Z
const t_expired: i64 = 1797033600; // 2026-12-12T00:00:00Z

fn testBundle(pem: []const u8) !Bundle {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "ca.pem", .data = pem });
    var b: Bundle = .empty;
    errdefer b.deinit(testing.allocator);
    var file = try tmp.dir.openFile(testing.io, "ca.pem", .{});
    defer file.close(testing.io);
    var reader = file.reader(testing.io, &.{});
    try b.addCertsFromFile(testing.allocator, &reader, t_valid);
    return b;
}

test "verifyChain accepts a chain that ends at a bundle CA" {
    var b = try testBundle(@embedFile("../testdata/tls/gts-root-r1.pem"));
    defer b.deinit(testing.allocator);
    try verifyChain(&b, &.{ leaf, wr2, r1_cross }, t_valid);
    try verifyChain(&b, &.{ leaf, wr2 }, t_valid);
}

test "verifyChain refuses missing or skipped intermediates, other roots and expiry" {
    var b = try testBundle(@embedFile("../testdata/tls/gts-root-r1.pem"));
    defer b.deinit(testing.allocator);
    try testing.expectError(error.CertificateUntrusted, verifyChain(&b, &.{leaf}, t_valid));
    try testing.expectError(error.CertificateUntrusted, verifyChain(&b, &.{ leaf, r1_cross }, t_valid));
    // Certificates after a trusted one are ignored: [wr2, leaf] verifies wr2.
    // Element 0 is the one the handshake proved; checkHostName then refuses
    // it for imap.gmail.com.
    try verifyChain(&b, &.{ wr2, leaf }, t_valid);
    try testing.expectError(error.CertificateUntrusted, verifyChain(&b, &.{}, t_valid));
    try testing.expectError(error.CertificateUntrusted, verifyChain(&b, &.{ leaf, wr2 }, t_expired));

    var other = try testBundle(@embedFile("../testdata/tls/unrelated-root.pem"));
    defer other.deinit(testing.allocator);
    try testing.expectError(error.CertificateUntrusted, verifyChain(&other, &.{ leaf, wr2, r1_cross }, t_valid));
}

test "isCa reads basicConstraints: intermediates are CAs, the server certificate is not" {
    try testing.expect(isCa(wr2));
    try testing.expect(isCa(r1_cross));
    try testing.expect(!isCa(leaf));
    try testing.expect(!isCa("garbage"));
}
