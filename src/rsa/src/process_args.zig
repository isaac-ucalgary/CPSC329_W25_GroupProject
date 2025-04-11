// Imports
const std = @import("std");
const crypt = @import("./crypt.zig");

// Inheritance
const Allocator = std.mem.Allocator;
const BigIntManaged = std.math.big.int.Managed;
const PublicKey = crypt.PublicKey;
const PrivateKey = crypt.PrivateKey;
const eql = std.mem.eql;

pub const ArgParseError = error{
    MissingCommand,
    InvalidCommand,
    HelpFlagSet,
    FileTooBig,
    TooManySources,
    NoSource,
    OutOfMemory,
};

pub const ProcessedArgs = struct {
    do_encrypt: bool = false,
    do_decrypt: bool = false,
    public_key: ?PublicKey = null,
    private_key: ?PrivateKey = null,
    source_text: []u8 = undefined,
    allocator: Allocator,

    pub fn init(allocator: Allocator) !ProcessedArgs {
        // Create args container
        var processed_args = ProcessedArgs{ .allocator = allocator };

        // ----- PARSE ARGS -----
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();
        _ = args.skip(); // Skip binary executable name

        // Parse command
        if (args.next()) |command| {
            if (eql(u8, command, "--help")) return error.HelpFlagSet;
            processed_args.do_encrypt = eql(u8, command, "encrypt");
            processed_args.do_decrypt = eql(u8, command, "decrypt");
        } else {
            return error.MissingCommand;
        }
        // Print and exit if no valid command was supplied
        if (!processed_args.do_encrypt and !processed_args.do_decrypt) {
            return error.InvalidCommand;
        }

        // Define variables to be collected from cli args
        var input_text: ?[]const u8 = null;
        var input_file: ?[]const u8 = null;

        // Iterate over the rest of the cli args
        while (args.next()) |arg| {
            // Parse options
            if (eql(u8, arg, "--help")) {
                return error.HelpFlagSet;
            } else if (eql(u8, arg, "--public-key")) {
                processed_args.public_key = try PublicKey.parse(
                    allocator,
                    args.next() orelse return error.MissingOptionParameter,
                );
            } else if (eql(u8, arg, "--public-key-file")) {
                processed_args.public_key = try getKeyFromFile(
                    allocator,
                    PublicKey,
                    args.next() orelse return error.MissingOptionParameter,
                );
            } else if (eql(u8, arg, "--private-key")) {
                processed_args.private_key = try PrivateKey.parse(
                    allocator,
                    args.next() orelse return error.MissingOptionParameter,
                );
            } else if (eql(u8, arg, "--private-key-file")) {
                processed_args.private_key = try getKeyFromFile(
                    allocator,
                    PrivateKey,
                    args.next() orelse return error.MissingOptionParameter,
                );
            } else if (eql(u8, arg, "--text")) input_text = args.next() else if (eql(u8, arg, "--file")) input_file = args.next();
        }

        // Get the source text from either the input text or the input file
        if (input_text) |in_text| {
            if (input_file == null) {
                processed_args.source_text = try allocator.alloc(u8, in_text.len);
                @memcpy(processed_args.source_text, in_text);
            } else return error.TooManySources;
        } else if (input_file) |file_path| {
            processed_args.source_text = try std.fs.cwd().readFileAlloc(allocator, file_path, @as(usize, 0) -% 1);
        } else return error.NoSource;

        // If the private key was provided but the public was not, then make
        // a public key from the private key.
        if (processed_args.private_key) |private_key| {
            if (processed_args.public_key == null) {
                processed_args.public_key = try private_key.makePublicKey(allocator);
            }
        }

        // Return the processed args
        return processed_args;
    }

    pub fn deinit(self: *ProcessedArgs) void {
        self.allocator.free(self.source_text);
        if (self.public_key) |*k| k.deinit();
        if (self.private_key) |*k| k.deinit();
    }

    // Gets a public key object from a supplied file path
    fn getKeyFromFile(allocator: Allocator, Key: type, file_path: []const u8) !Key {
        // Try to get the contents of the key file
        const key_file_contents: []u8 = try std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize));
        defer allocator.free(key_file_contents);

        // Parse the key from the file contents
        return try Key.parse(allocator, key_file_contents);
    }
};
