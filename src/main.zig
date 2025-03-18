// Imports
const std = @import("std");

// Inheritance
const Allocator = std.mem.Allocator;
const BigIntManaged = std.math.big.int.Managed;
const SplitIterator = std.mem.SplitIterator;
const eql = std.mem.eql;
const log = std.log;

const help_message: []const u8 =
    \\Encrypt or decrypt a message using RSA (not OAEP).
    \\Result will printed to standard out.
    \\
    \\Usage: 
    \\  rsa encrypt --public_key <key> (--text <text> | --file <path>)
    \\  rsa decrypt --private_key <key> (--text <text> | --file <path>)
    \\
    \\Commands:
    \\  encrypt                 Perform an encryption.
    \\  decrypt                 Perform a decryption.
    \\
    \\Options:
    \\  --public_key <key>      The public key to use for encryption.
    \\  --private_key <key>     The private key to use for decryption.
    \\
    \\  --text <text>           The text to encrypt/decrypt.
    \\  --file <path>           The path to a file to encrypt/decrypt.
    \\
;

pub fn main() !void {
    // Create allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer if (gpa.deinit() == .leak) log.err("MEMORY LEAK DETECTED", .{});

    // Get std out writer stream
    const stdout_writer = std.io.getStdOut().writer();
    _ = stdout_writer;

    // ----- PARSE ARGS -----
    var args = std.process.args();
    defer args.deinit();
    _ = args.skip(); // Skip binary executable name

    // Parse command
    var do_encrypt: bool = false;
    var do_decrypt: bool = false;
    if (args.next()) |command| {
        do_encrypt = eql(u8, command, "encrypt");
        do_decrypt = eql(u8, command, "decrypt");
    }
    // Print and exit if no valid command was supplied
    if (!do_encrypt and !do_decrypt) {
        std.debug.print(help_message, .{});
        return;
    }

    // Define variables to be collected from cli args
    var public_key: ?BigIntManaged = null;
    defer if (public_key) |*k| k.deinit();
    var private_key: ?BigIntManaged = null;
    defer if (private_key) |*k| k.deinit();
    var input_text: ?[]const u8 = null;
    var input_file: ?[]const u8 = null;

    // Iterate over all of the cli args
    while (args.next()) |arg| {
        // Parse options
        if (eql(u8, arg, "--public_key")) try getKeyArg(allocator, &public_key, &args);
        if (eql(u8, arg, "--private_key")) try getKeyArg(allocator, &private_key, &args);
        if (eql(u8, arg, "--text")) input_text = args.next();
        if (eql(u8, arg, "--file")) input_file = args.next();
    }

    var source_text: []u8 = undefined;
    // Only input text was provided
    if (input_text != null and input_file == null) {
        source_text = try allocator.alloc(u8, input_text.?.len);
        @memcpy(source_text, input_text.?);
    }
    // Only input file was provided
    else if (input_text == null and input_file != null) {
        source_text = std.fs.cwd().readFileAlloc(allocator, input_file.?, @as(usize, 0) -% 1) catch |err| {
            switch (err) {
                error.FileTooBig => {
                    log.err("File too big", .{});
                    return;
                },
                else => return err,
            }
        };
    }
    // Neither or both plain text and file path were provided
    else {
        log.err("Exactly one of either \"--text <text>\" or \"--file <path>\" must be provided. Aborting...", .{});
        return;
    }
    defer allocator.free(source_text);

    // ----- ENCRYPT -----
    if (do_encrypt) {
        std.debug.print("TODO Encrypt\n", .{});
        if (private_key) |_| log.warn("Private key provided but not required for encrypting.", .{});
    }

    // ----- DECRYPT -----
    if (do_decrypt) {
        std.debug.print("TODO Decrypt\n", .{});
        if (public_key) |_| log.warn("Public key provided but not required for decrypting.", .{});
    }
}

fn getKeyArg(allocator: Allocator, output: *?BigIntManaged, args: *std.process.ArgIterator) !void {

    // Get the next value if it exists
    var value: []const u8 = args.next() orelse return;

    // Create variable to store the integer base
    // Get the base from any existing integer affix
    var base: u8 = 10;
    if (value.len >= 2 and value[0] == '0') {
        // Obtain the number base of the value
        base = switch (value[1]) {
            'x', 'X' => 16,
            'o', 'O' => 8,
            'b', 'B' => 2,
            else => 10,
        };

        // Remove integer affix
        if (value[1] < 48 or 57 < value[1]) value = value[2..];
    }

    // Parse the value
    output.* = try BigIntManaged.init(allocator);
    output.*.?.setString(base, value) catch {
        output.*.?.deinit();
        output.* = null;
    };
}
