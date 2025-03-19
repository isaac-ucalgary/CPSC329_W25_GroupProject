// Imports
const std = @import("std");

// Inheritance
const BigIntManaged = std.math.big.int.Managed;
const Base64Decoder = std.base64.standard.Decoder;
const Allocator = std.mem.Allocator;
const der = std.crypto.Certificate.der;

/// RSA Public Key
pub const PublicKey = struct {
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
        std.debug.print("Modulus: {d}\n\n\n\n", .{modulus});

        return PublicKey{
            .e = exponent,
            .n = modulus,
        };
    }

    pub fn deinit(self: *PublicKey) void {
        self.n.deinit();
    }
};

pub const PrivateKey = struct {
    d: BigIntManaged,

    pub fn parse(allocator: Allocator, input: []const u8) !void {
        // Decode the input
        const base64_decoded = try allocator.alloc(u8, try Base64Decoder.calcSizeForSlice(input));
        defer allocator.free(base64_decoded);
        try Base64Decoder.decode(base64_decoded, input);

        // Create a variable for recording the position in the decoded binary
        // var byte_offset: usize = 0;

        // const algorithm_identifier_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        // const algorithm_identifier: []const u8 = getOffsetSlice(base64_decoded, &byte_offset, algorithm_identifier_byte_length);
        //

        std.debug.print("{any}\n\n", .{der.Element.parse(input, 0)});
        std.debug.print("{any}\n\n", .{der.Element.parse(input, 22)});
        std.debug.print("{any}\n\n", .{der.Element.parse(input, 2)});

        std.debug.print("{x}\n", .{base64_decoded[0..1]});
        std.debug.print("{x}\n", .{base64_decoded[1..4]});
        std.debug.print("{x}\n", .{base64_decoded[4..8]});
        std.debug.print("{x}\n", .{base64_decoded[8..20]});
        std.debug.print("{x}\n", .{base64_decoded[0..1]});
        std.debug.print("{x}\n", .{base64_decoded[0..1]});
        std.debug.print("{x}\n", .{base64_decoded[0..1]});
    }

    // pub fn init(allocator: Allocator, private_key: []const u8) !PrivateKey {
    //
    // }
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

    try PrivateKey.parse(
        allocator,
        // "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEApzKuJhowiqFG9rr5psToCIN2Z/E5cPxV23XpQze58DWycPLFvXKa3aCNiUwpvjvRiL/krUAdYVsACKcXKUyAOnLnigKrtb1o/HIpXdhhAhQK8op7ikgcqgf33bAYUtqBEnmaID5BTKUeOTFWfX0IwOCgYL1xMHPrIGOFbNCKjakAAAIIu3msE7t5rBMAAAAHc3NoLXJzYQAAAIEApzKuJhowiqFG9rr5psToCIN2Z/E5cPxV23XpQze58DWycPLFvXKa3aCNiUwpvjvRiL/krUAdYVsACKcXKUyAOnLnigKrtb1o/HIpXdhhAhQK8op7ikgcqgf33bAYUtqBEnmaID5BTKUeOTFWfX0IwOCgYL1xMHPrIGOFbNCKjakAAAADAQABAAAAgBNwBeTyGICVXU2j0RA9RghvWB2fYqErBMQ9wf+Jg/lUFMmiv7BVmYF4f9vdWeD+zU5LmMc3c/L0hF19J2kqtqFkzFF9h8pkoOA4LBf5VLEbl55Tg+9MQgy3fTKdmhStv8GaT/Syb2+bsDJsGLJQCNSOhKBHanaFiZnXNcz0u29NAAAAQQCQB8nOKcJIjdTrmHXbaKKm5K/qsTaEg0dDzUZ3RS4Xpbz7BImnMk0MsNH96saueKXow7Qltfm+wdPHsu0RQoLzAAAAQQDR+e8Fmz1XPTvaaWPmLFfLS1TMiLIP0tF52E6afWNhDaROIO11nzxxepjEb2yYqS84C3QzGuzq4GWF0L72io+TAAAAQQDL2GTdGeGFJCnthU4zgI2lsiUuEFF5/7DsI7jJ+zlmjY866Sdp6NuDLWrbV64d0yrdIFaMMZMRJvmankMekJtTAAAAEGlzYWFjc3RASXNhYWNzUEMBAg==",
        // \\-----BEGIN OPENSSH PRIVATE KEY-----
        // \\b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
        // \\NhAAAAAwEAAQAAAIEApzKuJhowiqFG9rr5psToCIN2Z/E5cPxV23XpQze58DWycPLFvXKa
        // \\3aCNiUwpvjvRiL/krUAdYVsACKcXKUyAOnLnigKrtb1o/HIpXdhhAhQK8op7ikgcqgf33b
        // \\AYUtqBEnmaID5BTKUeOTFWfX0IwOCgYL1xMHPrIGOFbNCKjakAAAIIu3msE7t5rBMAAAAH
        // \\c3NoLXJzYQAAAIEApzKuJhowiqFG9rr5psToCIN2Z/E5cPxV23XpQze58DWycPLFvXKa3a
        // \\CNiUwpvjvRiL/krUAdYVsACKcXKUyAOnLnigKrtb1o/HIpXdhhAhQK8op7ikgcqgf33bAY
        // \\UtqBEnmaID5BTKUeOTFWfX0IwOCgYL1xMHPrIGOFbNCKjakAAAADAQABAAAAgBNwBeTyGI
        // \\CVXU2j0RA9RghvWB2fYqErBMQ9wf+Jg/lUFMmiv7BVmYF4f9vdWeD+zU5LmMc3c/L0hF19
        // \\J2kqtqFkzFF9h8pkoOA4LBf5VLEbl55Tg+9MQgy3fTKdmhStv8GaT/Syb2+bsDJsGLJQCN
        // \\SOhKBHanaFiZnXNcz0u29NAAAAQQCQB8nOKcJIjdTrmHXbaKKm5K/qsTaEg0dDzUZ3RS4X
        // \\pbz7BImnMk0MsNH96saueKXow7Qltfm+wdPHsu0RQoLzAAAAQQDR+e8Fmz1XPTvaaWPmLF
        // \\fLS1TMiLIP0tF52E6afWNhDaROIO11nzxxepjEb2yYqS84C3QzGuzq4GWF0L72io+TAAAA
        // \\QQDL2GTdGeGFJCnthU4zgI2lsiUuEFF5/7DsI7jJ+zlmjY866Sdp6NuDLWrbV64d0yrdIF
        // \\aMMZMRJvmankMekJtTAAAAEGlzYWFjc3RASXNhYWNzUEMBAg==
        // \\-----END OPENSSH PRIVATE KEY-----
        "MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQDBgk/A/EEizHPP4SQIXywFFpgWuKQVnuh6rBu2asWoc44EhBFo2ST3LAuifKp6eAvsB460OIexGukdjnaUOIhxLLxj1YCzlN18p9H62gALvvI4cEL7dI1ELsaBaHEQyx07g3YWIJbSO9Zzi3sivzAynmg19mntOa8GnSwBoKJ+5aVzphk/BJLwVcicoKpjPbM2SGkEBBrDKnMhFgcfawwfieeFxb8YBB2sCWZ5XnavPlR94CnbPlyPoefbAzWk2mfE79tvCGCXlmtmiUPuQVG/dLn/MPGJ1rSmYH/qJ/gAwYdUuLZlL4C0kycWVP+fpv9A0a0t8X+Hf2leQhMW5sSRAgMBAAECggEAA3D7VR3HVMSZDKne161FnaOMud63wFCuprvX1FMqx7eiX28v1hMChsjIPjAEYiAvaheqUIcu1pX5blahwjoNJyIaCZZ67vanR7e+Ur08wfi32wwYDNvCRWOlkRiX5ioOj4fjejpDJGL/CdgBrRkEVOofRVJoCNl9RNtXtIG0Uhhgdt81ykGQKguPvDKs94xrL1zX0fVDjGqxSVgBWXwwC5yKnIrXBWnaHLN4yPvYM+2FxaeVCpzP4SMvnVZ6425ovRK915GhiaPHqPG/YEGe19ohgPdhhX7crTgW2pyTx1ST1Mmko0DZ3jTU11aD+w/D0H+v8A/5O7JD48qqdExkYQKBgQD23kgOq4I9pktrO4tr8eHVzeMh3mDw0oRdvKgaufjQeaGFKcOuLHMvaYjqMWTIfChKg0Z5tIjNCwB6c2kWVmDs6vxfxVFdl40fvVRTlBXB5rm3EWj5i3Ik5se8n/hW4hXq20mjmBaaVWHnAXGyFxmJpAsJo+Q8hjN7flaVYIJjaQKBgQDIqr6mpMijWbIdS3ecLvC8LdpriuBxua8LY+0OqdvEbFdB8WEo6n7p9wjHvXVpR6765OMeCtiYpQOqIdfLM2R3V0PIeL0/kEaC9osUl+Rfv+p8s9G+6Y1EuIJz18OyRcyh/sQX/FL4XtGxYgQR/eaN01uvIDNqZQRqLt8G5AC66QJ/QZLJkRv9fGKvpcwrPIEDe8c0jcqD9XP1tPBntrGvZbDpNnXhhGJKNk3SEGMOYjKYgTJdhfZuYAiMF/qP718CX+wLHWVMN5AJ7GReAdVT8i1XJ0l4mNBxgVvLsk7LqEhlify1kr7TQitr1fCMQsHgBq+MPwNJnMoI4sSsOwFnoQKBgDOW+jb7rH2apNk1OsYTp16p5zq41KVIWMFz6lFXyCGCvRg+B32uc/yQv1gi1FnBzTHBwMZLgY4U9pE57DHYv56S9+FFcVozLH2lBvK/bj5Tp+Rxkp4ji2c8jIVd1nkxyr9nMWD9RROHxR92lJdPkIOr8Clg/PcAi5cE/9/UpH9pAoGAeYCqvshITsEkW2DR6aNgWwTXkknumS+XqD9172GdUncjP2SrL6dHBfLSdGHXB/ogjdXtu3FElYGpl79amObJ9XAWb4pVQ9BypE8vTirZwYiLr/KO5/roLC/U/EmrfTxp9sJWtAunjZQxfSJMZtaq9CIbbdY4hqfFzZJjsjk0MEM=",
    );
}
