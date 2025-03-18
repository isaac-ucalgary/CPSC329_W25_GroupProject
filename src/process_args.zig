// Imports
const std = @import("std");

// Inheritance
const Allocator = std.mem.Allocator;
const BigIntManaged = std.math.big.int.Managed;
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
    public_key: ?BigIntManaged = null,
    private_key: ?BigIntManaged = null,
    source_text: []u8 = undefined,
    allocator: Allocator,

    pub fn init(allocator: Allocator) !ProcessedArgs {
        // Create args container
        var processed_args = ProcessedArgs{ .allocator = allocator };

        // ----- PARSE ARGS -----
        var args = std.process.args();
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
            if (eql(u8, arg, "--help")) return error.HelpFlagSet;
            if (eql(u8, arg, "--public_key")) try getKeyArg(allocator, &processed_args.public_key, &args);
            if (eql(u8, arg, "--private_key")) try getKeyArg(allocator, &processed_args.private_key, &args);
            if (eql(u8, arg, "--text")) input_text = args.next();
            if (eql(u8, arg, "--file")) input_file = args.next();
        }

        if (input_text) |in_text| {
            if (input_file == null) {
                processed_args.source_text = try allocator.alloc(u8, in_text.len);
                @memcpy(processed_args.source_text, in_text);
            } else return error.TooManySources;
        } else if (input_file) |file_path| {
            processed_args.source_text = try std.fs.cwd().readFileAlloc(allocator, file_path, @as(usize, 0) -% 1);
        } else return error.NoSource;

        return processed_args;
    }

    pub fn deinit(self: *ProcessedArgs) void {
        self.allocator.free(self.source_text);
        if (self.public_key) |*k| k.deinit();
        if (self.private_key) |*k| k.deinit();
    }

    fn getKeyArg(allocator: Allocator, output: *?BigIntManaged, args: *std.process.ArgIterator) !void {

        // Get the next value if it exists
        var value: []const u8 = args.next() orelse return;

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
};
