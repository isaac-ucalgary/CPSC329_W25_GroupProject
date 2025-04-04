// Imports
const std = @import("std");
const ProcessedArgs = @import("./process_args.zig").ProcessedArgs;
const crypt = @import("./crypt.zig");

// Inheritance
const Allocator = std.mem.Allocator;
const BigIntManaged = std.math.big.int.Managed;
const SplitIterator = std.mem.SplitIterator;
const PublicKey = crypt.PublicKey;
const PrivateKey = crypt.PrivateKey;
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
    \\  encrypt                     Perform an encryption.
    \\  decrypt                     Perform a decryption.
    \\
    \\Options:
    \\  --public_key <key>          The public key to use for encryption.
    \\  --private_key <key>         The private key to use for decryption.
    \\  --public_key_file <path>    The public key file to use for encryption.
    \\  --private_key_file <path>   The private key file to use for decryption.
    \\
    \\  --text <text>               The text to encrypt/decrypt.
    \\  --file <path>               The path to a file to encrypt/decrypt.
    \\
    \\
    \\RSA Public Key Rules:
    \\  - Follow the RFC 4253 standard.
    \\  - Follow the "ssh-rsa" formating.
    \\
    \\RSA Private Key Rules:
    \\  - Follow the RFC 8017 standard.
    \\  - Start with "-----BEGIN RSA PRIVATE KEY-----" at the first line.
    \\  - End with "-----END RSA PRIVATE KEY-----" on the last line.
    \\  - In between is the base 64 encoded private key following the RFC 8017
    \\    standard and is encoded using PEM.
    \\  - The base 64 key can span multiple lines or be on a single line but
    \\    all lines must be deliminated using the "\n" character.
    \\
;

pub fn main() !void {
    // Create allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer if (gpa.deinit() == .leak) log.err("MEMORY LEAK DETECTED", .{});

    // Get std out writer stream
    const stdout_writer = std.io.getStdOut().writer();

    // ----- PARSE ARGS -----
    var processed_args = ProcessedArgs.init(allocator) catch |err| {
        switch (err) {
            error.AccessDenied => std.log.err("File access denied, Aborting...", .{}),
            error.FileNotFound => std.log.err("Provided file does not exist. Aborting...", .{}),
            error.FileTooBig => std.log.err("The provided file is too big. Aborting...", .{}),
            error.HelpFlagSet, error.MissingCommand => std.debug.print("{s}", .{help_message}),
            error.MissingOptionParameter => std.log.err(
                "Missing option parameter. Use \"--help\" for usage instructions.",
                .{},
            ),
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
        // Get the public key.
        // Abort if no public or private key was provided.
        const public_key: PublicKey = processed_args.public_key orelse {
            log.err("Missing both public and private key. Cannot encrypt without at least one. Aborting...", .{});
            return;
        };

        // Encrypt the plain text to stout
        const cipher_text: []u8 = try crypt.encrypt(allocator, public_key, processed_args.source_text);
        defer allocator.free(cipher_text);

        // Print the cipher text
        try stdout_writer.print("{s}", .{cipher_text});
    }

    // ----- DECRYPT -----
    if (processed_args.do_decrypt) {
        // Get the private key.
        // Abort if no private key was provided.
        const private_key: PrivateKey = processed_args.private_key orelse {
            log.err("Missing private key. Cannot decrypt. Aborting...", .{});
            return;
        };

        // Decrypt the cipher text
        const plain_text: []u8 = try crypt.decrypt(allocator, private_key, processed_args.source_text);
        defer allocator.free(plain_text);

        // Print the plain text to stout
        try stdout_writer.print("{s}", .{plain_text});
    }
}
