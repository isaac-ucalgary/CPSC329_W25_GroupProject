// Imports
const std = @import("std");

// Inheritance
const BigIntManaged = std.math.big.int.Managed;
const Base64Decoder = std.base64.standard.Decoder;
const Allocator = std.mem.Allocator;

/// RSA Public Key
const PublicKey = struct {
    e: u64,
    n: BigIntManaged,

    /// Parses the RSA Public Key from the *input* string using the *RFC4716*
    /// standard.
    pub fn parse(allocator: Allocator, input: []const u8) !PublicKey {
        // Decode the input
        const base64_decoded = try allocator.alloc(u8, try Base64Decoder.calcSizeForSlice(input));
        defer allocator.free(base64_decoded);
        try Base64Decoder.decode(base64_decoded, input);

        // Create a variable for recording the position in the decoded binary
        var byte_offset: usize = 0;

        // Get the algorithm identifier
        const algorithm_identifier_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        const algorithm_identifier: []const u8 = getOffsetSlice(base64_decoded, &byte_offset, algorithm_identifier_byte_length);

        // Get the exponent
        const exponent_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        const exponent: u64 = readOffsetInt(u64, base64_decoded, &byte_offset, .{ .length = exponent_byte_length });

        // Get the modulus
        const modulus_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        const modulus: BigIntManaged = try readOffsetBigInt(allocator, base64_decoded, &byte_offset, modulus_byte_length);

        std.debug.print("Algorithm Identifier Byte Length: {d}\n", .{algorithm_identifier_byte_length});
        std.debug.print("Algorithm Identifier: {s}\n", .{algorithm_identifier});
        std.debug.print("Exponent Byte Length: {d}\n", .{exponent_byte_length});
        std.debug.print("Exponent: {d}\n", .{exponent});
        std.debug.print("Modulus Byte Length: {d}\n", .{modulus_byte_length});
        std.debug.print("Modulus: {d}\n", .{modulus});

        return PublicKey{
            .e = exponent,
            .n = modulus,
        };
    }

    pub fn deinit(self: *PublicKey) void {
        self.n.deinit();
    }
};

/// Reads the integer of type *T* from the *buffer* at the *offset*.
/// Then increments the value of *offset* by the byte size of *T*.
fn readOffsetInt(T: type, buffer: []const u8, offset: *usize, options: struct { length: usize = @sizeOf(T) }) T {
    // Get the next int of type T from the buffer after the offset
    const return_int: T = std.mem.readVarInt(
        T,
        buffer[offset.* .. offset.* + options.length],
        std.builtin.Endian.big,
    );

    // Increment the offset by the requested number of bytes from length
    offset.* += options.length;

    // Return the collected integer
    return return_int;
}

/// Reads a big integer from the *buffer* at the *offset* of *length* bytes.
/// Then increments the value of *offset* by the bytes read.
fn readOffsetBigInt(allocator: Allocator, buffer: []const u8, offset: *usize, length: usize) !BigIntManaged {

    // Create return value
    var return_value: BigIntManaged = try BigIntManaged.init(allocator);

    // Get the integer from the buffer
    for (0..length) |i| {
        try return_value.shiftLeft(&return_value, 8);
        try return_value.addScalar(&return_value, buffer[offset.* + i]);
    }

    // Increment the offset by the provided length
    offset.* += length;

    // Return the collected integer
    return return_value;
}

fn getOffsetSlice(buffer: []const u8, offset: *usize, length: usize) []const u8 {
    // Calculate the upper and lower bounds for the slice so that an out of
    // bounds error cannot occur
    const lower_bound: usize = @min(@max(offset.*, 0), buffer.len - 1);
    const upper_bound: usize = @min(@max(offset.* + length, 0), buffer.len);

    // Get the slice
    const return_slice: []const u8 = buffer[lower_bound..upper_bound];

    // Increment the offset by number of bytes returned
    offset.* += upper_bound - lower_bound;

    // Return the collected integer
    return return_slice;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var pubkey = try PublicKey.parse(
        allocator,
        //"AAAAB3NzaC1yc2EAAAADAQABAAACAQDH+UiVUz6XFRW2jqgxcEU91V7RN+UzMIkU3ZfMHYaESAizcw0iR8jFZ7/CgwEvu6AI3VPhB/53N4LmOFsO1nu0YXjfCFSFvrYHmGIcY1LMgV6XebzherHeFDr7DvbPfrpEEbmdxtJBNtaXKGYouVCWgIK9FjuitT4s21sg+awcEme9eDy0idxzQknrSesepx6+/7odxFyv9st1oLO+HGf8JuoDYjdlhG3cu4nZIXF/ziR5FlJQrz8rCIA0gNvWWKeUs+3xXPjlEsodrNYxeZtXFwKj0B/29GeB0y8LFKGElIQx2NBHJ4p1FE551j16/tanEc+HNzGjku7FYqNcxnd4DksYxNsZJg6yd+2UESWzz+MGlaKHJh0/7QPJUMmeXd7QIS03FYatseByFzl0K22NoKxBi6cBSCvxS8X4lse5ldWY4+8il86S0cG9jlayfGo7yznpJE2ZbcWmkp3M9/JPdQYZXAt+jijXNTDOVjDWm0Y88jqgcZXO4eJTSzNwfymFl6R9Te7oQYeb7gS+hH+JWBvOfZ1/NZOJP+ngtyaV3vYqiHeR19fHnRKC3/ujf5D4Z3mZsdZ2BRQrg+JKMZcvK8kGgaHfiFN9wFEchwDF10Eqv4qESH5f3JG/N8pCHOAVt+FPqUZRCakO7GbQ/XlSFwOCo5NzZDCqwYntdUDCmQ==",
        "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCnMq4mGjCKoUb2uvmmxOgIg3Zn8Tlw/FXbdelDN7nwNbJw8sW9cprdoI2JTCm+O9GIv+StQB1hWwAIpxcpTIA6cueKAqu1vWj8cild2GECFAryinuKSByqB/fdsBhS2oESeZogPkFMpR45MVZ9fQjA4KBgvXEwc+sgY4Vs0IqNqQ==",
    );

    defer pubkey.deinit();
}
