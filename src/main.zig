// Imports
const std = @import("std");
const ProcessedArgs = @import("./process_args.zig").ProcessedArgs;

// Inheritance
const Allocator = std.mem.Allocator;
const BigIntManaged = std.math.big.int.Managed;
const SplitIterator = std.mem.SplitIterator;
const eql = std.mem.eql;
const log = std.log;

const help_message: []const u8 =
    \\Encrypt or decrypt a message using RSA (without OAEP).
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
    var processed_args = ProcessedArgs.init(allocator) catch |err| {
        switch (err) {
            error.AccessDenied => std.log.err("File access denied, Aborting...", .{}),
            error.FileNotFound => std.log.err("Provided file does not exist. Aborting...", .{}),
            error.FileTooBig => std.log.err("The provided file is too big. Aborting...", .{}),
            error.HelpFlagSet, error.MissingCommand => std.debug.print("{s}", .{help_message}),
            error.OutOfMemory => std.log.err("System ran out of memory. Aborting...", .{}),
            error.NoSource, error.TooManySources => std.log.err(
                "Exactly one of either \"--text <text>\" or \"--file <path>\" must be provided. Aborting...",
                .{},
            ),
            error.InvalidCommand => {
                std.log.err("Not a valid command.", .{});
                std.debug.print("\n{s}", .{help_message});
            },
            else => return err,
        }
        return;
    };
    defer processed_args.deinit();

    // ----- ENCRYPT -----
    if (processed_args.do_encrypt) {
        std.debug.print("TODO Encrypt\n", .{});
        if (processed_args.private_key) |_| log.warn("Private key provided but not required for encrypting.", .{});
    }

    // ----- DECRYPT -----
    if (processed_args.do_decrypt) {
        std.debug.print("TODO Decrypt\n", .{});
        if (processed_args.public_key) |_| log.warn("Public key provided but not required for decrypting.", .{});
    }
}
