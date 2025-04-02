// Imports
const std = @import("std");

// Inheritance
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Base64Decoder = std.base64.standard.Decoder;
const BigIntManaged = std.math.big.int.Managed;
const der = std.crypto.Certificate.der;
const maxInt = std.math.maxInt;

/// RSA Public Key
pub const PublicKey = struct {
    exponent: u64,
    modulus: BigIntManaged,

    /// Parses the RSA Public Key from the *input* string using the *RFC4253*
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

        // Check
        if (!std.mem.eql(u8, algorithm_identifier, "ssh-rsa")) {
            return error.IncorrectAlgorithm;
        }

        // Get the exponent
        const exponent_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        const exponent: u64 = readOffsetInt(u64, base64_decoded, &byte_offset, .{ .length = exponent_byte_length });
        // const exponent: u64 = 3;

        // Get the modulus
        const modulus_byte_length: u32 = readOffsetInt(u32, base64_decoded, &byte_offset, .{});
        const modulus: BigIntManaged = try readOffsetBigInt(allocator, base64_decoded, &byte_offset, modulus_byte_length);
        // const modulus: BigIntManaged = try BigIntManaged.initSet(allocator, 187);

        return PublicKey{
            .exponent = exponent,
            .modulus = modulus,
        };
    }

    pub fn deinit(self: *PublicKey) void {
        self.modulus.deinit();
    }

    /// Returns the exponent component of the public key
    pub fn e(self: PublicKey) u64 {
        return self.exponent;
    }

    /// Returns the modulus component of the public key
    pub fn n(self: PublicKey) u64 {
        return self.modulus;
    }
};

/// RSA Private Key
pub const PrivateKey = struct {
    version: u64,
    modulus: BigIntManaged,
    public_exponent: BigIntManaged,
    private_exponent: BigIntManaged,
    prime1: BigIntManaged,
    prime2: BigIntManaged,
    exponent1: BigIntManaged,
    exponent2: BigIntManaged,
    coefficient: BigIntManaged,

    /// Parses a base 64 private key string encoded using the RFC 8017 standard
    pub fn parse(allocator: Allocator, input: []const u8) !PrivateKey {
        // Decode the input
        const base64_decoded = try allocator.alloc(u8, try Base64Decoder.calcSizeForSlice(input));
        defer allocator.free(base64_decoded);
        try Base64Decoder.decode(base64_decoded, input);

        // Get the first element of the der encoded bytes which should be an
        // der element with a sequence tag
        const der_sequence_element = try der.Element.parse(base64_decoded, 0);

        // Get the elements of the sequence
        var der_sequence: DerSequence = try DerSequence.init(allocator, der_sequence_element, base64_decoded);
        defer der_sequence.deinit();

        // Initialize the private key
        return PrivateKey{
            .version = readOffsetInt(u64, der_sequence.getElementSlice(0), 0, .{}),
            .modulus = try readOffsetBigInt(allocator, der_sequence.getElementSlice(1), 0, maxInt(usize)),
            .public_exponent = try readOffsetBigInt(allocator, der_sequence.getElementSlice(2), 0, maxInt(usize)),
            .private_exponent = try readOffsetBigInt(allocator, der_sequence.getElementSlice(3), 0, maxInt(usize)),
            .prime1 = try readOffsetBigInt(allocator, der_sequence.getElementSlice(4), 0, maxInt(usize)),
            .prime2 = try readOffsetBigInt(allocator, der_sequence.getElementSlice(5), 0, maxInt(usize)),
            .exponent1 = try readOffsetBigInt(allocator, der_sequence.getElementSlice(6), 0, maxInt(usize)),
            .exponent2 = try readOffsetBigInt(allocator, der_sequence.getElementSlice(7), 0, maxInt(usize)),
            .coefficient = try readOffsetBigInt(allocator, der_sequence.getElementSlice(8), 0, maxInt(usize)),
        };
    }

    pub fn deinit(self: *PrivateKey) void {
        self.modulus.deinit();
        self.public_exponent.deinit();
        self.private_exponent.deinit();
        self.prime1.deinit();
        self.prime2.deinit();
        self.exponent1.deinit();
        self.exponent2.deinit();
        self.coefficient.deinit();
    }

    /// Returns the modulus of the private key
    pub fn n(self: *PrivateKey) BigIntManaged {
        return self.modulus;
    }

    /// Returns the public exponent of the private key
    pub fn e(self: *PrivateKey) BigIntManaged {
        return self.public_exponent;
    }

    /// Returns the private exponent of the private key
    pub fn d(self: *PrivateKey) BigIntManaged {
        return self.private_exponent;
    }

    /// Returns the first prime of the private key
    pub fn p(self: *PrivateKey) BigIntManaged {
        return self.prime1;
    }

    /// Returns the second prime of the private key
    pub fn q(self: *PrivateKey) BigIntManaged {
        return self.prime2;
    }

    /// Returns the value for d (private exponent) modulo p-1
    pub fn dModEulerP(self: *PrivateKey) BigIntManaged {
        return self.exponent1;
    }

    /// Returns the value for d (private exponent) modulo q-1
    pub fn dModEulerQ(self: *PrivateKey) BigIntManaged {
        return self.exponent2;
    }

    /// Returns the value for the inverse of q (prime 2) modulo p (prime 1) of
    /// the private key
    pub fn inverseOfQModP(self: *PrivateKey) BigIntManaged {
        return self.coefficient;
    }
};

const DerSequence = struct {
    allocator: Allocator,
    sequence: ArrayList(der.Element),
    sequence_element: der.Element,
    bytes: []const u8,

    /// Generates an array list of DER elements that compose a DER sequence element (not recursive).
    pub fn init(allocator: Allocator, sequence_element: der.Element, bytes: []const u8) !DerSequence {
        // Check that the provided element is a sequence
        if (sequence_element.identifier.tag != der.Tag.sequence) {
            return error.ElementIsNotASequence;
        }

        // Create the DerSequence
        var der_sequence = DerSequence{
            .allocator = allocator,
            .sequence = ArrayList(der.Element).init(allocator),
            .sequence_element = sequence_element,
            .bytes = bytes,
        };
        errdefer der_sequence.deinit();

        // Get the first element of the sequence
        try der_sequence.sequence.append(try der.Element.parse(bytes, sequence_element.slice.start));

        // Get any additional elements of the sequence
        var next_element_start: u32 = der_sequence.sequence.getLast().slice.end;
        while (next_element_start < sequence_element.slice.end) {
            try der_sequence.sequence.append(try der.Element.parse(bytes, next_element_start));
            next_element_start = der_sequence.sequence.getLast().slice.end;
        }

        // Return the constructed DerSequence
        return der_sequence;
    }

    pub fn deinit(self: *DerSequence) void {
        self.sequence.deinit();
    }

    pub fn getElementSlice(self: *DerSequence, index: u32) []const u8 {
        // Get the requested element
        const element: der.Element = self.sequence.items[index];

        // Return the slice of the elements value
        return self.bytes[element.slice.start..element.slice.end];
    }
};

/// Reads the integer of type *T* from the *buffer* at the *offset*.
/// Then increments the value of *offset* by the byte size of *T*.
/// *offset* must either be either an integer or a pointer to an integer.
/// If *offset* is a pointer to an integer, that integer will be incremented by
/// either the *length* provided or by default the size of *T* or by the length
/// of the buffer less the offset, which ever is smaller.
fn readOffsetInt(T: type, buffer: []const u8, offset: anytype, options: struct { length: usize = @sizeOf(T) }) T {
    // Get the offset value
    const offset_value: u64 = switch (@TypeOf(offset)) {
        *usize => offset.*,
        comptime_int => offset,
        else => return error.UnallowedType,
    };

    // Get the safe length
    const length: u64 = @as(u64, @min(options.length, buffer.len - offset_value));

    // Get the next int of type T from the buffer after the offset
    const return_int: T = std.mem.readVarInt(
        T,
        buffer[offset_value .. offset_value + length],
        std.builtin.Endian.big,
    );

    // Increment the offset by the requested number of bytes from length
    if (@TypeOf(offset) == *usize) {
        offset.* += length;
    }

    // Return the collected integer
    return return_int;
}

/// Reads a big integer from the *buffer* at the *offset* of *length* bytes.
/// Then increments the value of *offset* by the bytes read.
/// *offset* must either be either an integer or a pointer to an integer.
/// If *offset* is a pointer to an integer, that integer will be incremented by
/// either the *length* provided or the length of the buffer less the offset,
/// which ever is smaller.
/// If the *length* is 0, assumes the whole buffer from the point of the offset
/// should be used.
fn readOffsetBigInt(allocator: Allocator, buffer: []const u8, offset: anytype, length: usize) !BigIntManaged {
    // Get the offset value
    const offset_value: u64 = switch (@TypeOf(offset)) {
        *usize => offset.*,
        comptime_int => offset,
        else => return error.UnallowedType,
    };

    // Get the safe length
    const length_safe: u64 = @as(u64, if (length == 0) (buffer.len - offset_value) else @min(length, buffer.len - offset_value));

    // Create return value
    var return_value: BigIntManaged = try BigIntManaged.init(allocator);

    // Get the integer from the buffer
    for (0..length_safe) |i| {
        try return_value.shiftLeft(&return_value, 8);
        try return_value.addScalar(&return_value, buffer[offset_value + i]);
    }

    // Increment the offset by the provided length
    if (@TypeOf(offset) == *usize) {
        offset.* += length_safe;
    }

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

fn bigIntModulo(dividend: *BigIntManaged, modulus: *BigIntManaged, residue: *BigIntManaged) !void {
    // Create the residue
    // try dividend.copy(residue.*.toConst());
    try residue.copy(dividend.toConst());

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    std.debug.print("Dividend: {s}\n", .{try dividend.toString(allocator, 10, std.fmt.Case.lower)});
    std.debug.print("Modulus: {s}\n", .{try modulus.toString(allocator, 10, std.fmt.Case.lower)});

    // Create quotient output
    var q = try dividend.clone();
    defer q.deinit();

    // Calculate the residue
    try q.divFloor(residue, dividend, modulus);

    std.debug.print("Residue: {s}\n\n", .{try residue.toString(allocator, 10, std.fmt.Case.lower)});

    // // Insure the residue is positive
    // while (!residue.*.isPositive()) {
    //     try residue.add(residue, modulus);
    // }
    //
    // // Reduce the residue until it is less than the modulus
    // while (residue.*.order(modulus.*) == std.math.Order.gt) {
    //     try residue.sub(residue, modulus);
    // }
}

// I know there are ways to speed this up using math but I don't care right now
fn bigIntPowerModulo(dividend: *BigIntManaged, exponent: anytype, modulus: *BigIntManaged, residue: *BigIntManaged) !void {
    // Create an allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Get local exponent
    var local_exponent: BigIntManaged = try BigIntManaged.init(allocator);
    defer local_exponent.deinit();
    switch (@TypeOf(exponent)) {
        u64 => try local_exponent.set(exponent),
        *u64 => try local_exponent.set(exponent.*),
        // BigIntManaged => try exponent.copy(local_exponent.toConst()),
        BigIntManaged => try local_exponent.copy(exponent.toConst()),
        // *BigIntManaged, *const BigIntManaged => try @constCast(exponent).copy(local_exponent.toConst()),
        *BigIntManaged, *const BigIntManaged => try local_exponent.copy(exponent.toConst()),
        else => {
            std.debug.print("{any}", .{@TypeOf(exponent)});
            return error.UnallowedType;
        },
    }
    // try local_exponent.set(257);

    std.debug.print("Exponent: {s}\n", .{try local_exponent.toString(allocator, 10, std.fmt.Case.lower)});

    // const local_exponent_ptr: *BigIntManaged = &local_exponent;
    // const local_exponent_const = try local_exponent.clone();

    // Create the bit mask
    var bit_mask: BigIntManaged = try BigIntManaged.initSet(allocator, 1);
    defer bit_mask.deinit();

    // Create a temporary buffer big int
    var buffer: BigIntManaged = try BigIntManaged.init(allocator);
    defer buffer.deinit();

    // Create a variable to store the x value at each step
    var x: BigIntManaged = try BigIntManaged.init(allocator);
    defer x.deinit();
    // try dividend.copy(x.toConst()); // Copy the dividend into x
    try x.copy(dividend.toConst());
    // std.debug.print("Dividend: {s}\n", .{try dividend.toString(allocator, 10, std.fmt.Case.lower)});

    // std.debug.print("{any}\n", .{@TypeOf(local_exponent)});
    // Perform the base case multiplication
    try buffer.bitAnd(&local_exponent, &bit_mask); // Isolate the desired bit of the exponent
    // If the bit is 1, then multiply
    if (!buffer.eqlZero()) {
        // try dividend.copy(residue.*.toConst());
        try residue.copy(dividend.toConst());
    } else {
        try residue.set(1);
    }

    std.debug.print("Actual Dividend: {s}\n\n", .{try dividend.toString(allocator, 10, std.fmt.Case.lower)});
    std.debug.print("Actual Residue: {s}\n\n", .{try residue.toString(allocator, 10, std.fmt.Case.lower)});
    const required_bits: usize = local_exponent.bitCountTwosComp();

    // For the rest of the bits of the exponent
    std.debug.print("{d}\n", .{required_bits});
    for (1..required_bits) |_| {

        // Shift the bit mask to the next bit
        try bit_mask.shiftLeft(&bit_mask, 1);

        // Determine if the desired bit of the exponent is populated
        try buffer.bitAnd(&local_exponent, &bit_mask);
        const exponent_bit_is_populated: bool = !buffer.eqlZero();

        // Get the new value for x
        try x.pow(&x, 2); // Raise x to the power of 2 to match moving to the next exponent bit
        try bigIntModulo(&x, modulus, &x); // Get the residue of x from the modulus
        std.debug.print("Residue x: {s}\n\n", .{try x.toString(allocator, 10, std.fmt.Case.lower)});

        // If the bit is populated, then multiply the current residue
        // value by the current binary exponential component
        if (exponent_bit_is_populated) {
            try residue.mul(residue, &x);
            try bigIntModulo(residue, modulus, residue); // Get the residue of x from the modulus
            std.debug.print("Actual Residue: {s}\n\n", .{try residue.toString(allocator, 10, std.fmt.Case.lower)});
        }
    }

    // switch (@TypeOf(exponent)) {
    //     // If the exponent is small, simply compute
    //     u64 => {
    //         // Create the residue
    //         try dividend.copy(residue.*.toConst());
    //
    //         // Get the first modulo residue
    //         try bigIntModulo(dividend, modulus, residue);
    //
    //         try residue.pow(dividend, @intCast(exponent));
    //         try bigIntModulo(dividend, modulus, residue);
    //     },
    //
    //     // Handle big ints more carefully
    //     *BigIntManaged => {
    //
    //         // Create the bit mask
    //         var bit_mask: BigIntManaged = try BigIntManaged.initSet(allocator, 1);
    //         defer bit_mask.deinit();
    //
    //         // Create a temporary buffer big int
    //         var buffer: BigIntManaged = try BigIntManaged.init(allocator);
    //         defer buffer.deinit();
    //
    //         // Create a variable to store the x value at each step
    //         var x: BigIntManaged = try BigIntManaged.init(allocator);
    //         defer x.deinit();
    //         try dividend.copy(x.toConst()); // Copy the dividend into x
    //
    //         // Perform the base case multiplication
    //         try buffer.bitAnd(exponent, bit_mask); // Isolate the desired bit of the exponent
    //         // If the bit is 1, then multiply
    //         if (!buffer.eqlZero()) {
    //             try dividend.copy(residue.*.toConst());
    //         } else {
    //             try residue.set(1);
    //         }
    //
    //         // For the rest of the bits of the exponent
    //         for (1..exponent.*.bitCountTwosComp()) |_| {
    //
    //             // Shift the bit mask to the next bit
    //             try bit_mask.shiftLeft(bit_mask, 1);
    //
    //             // Determine if the desired bit of the exponent is populated
    //             try buffer.bitAnd(exponent, bit_mask);
    //             const exponent_bit_is_populated: bool = !buffer.eqlZero();
    //
    //             // Get the new value for x
    //             try x.pow(x, 2); // Raise x to the power of 2 to match moving to the next exponent bit
    //             try x.bigIntModulo(modulus, x); // Get the residue of x from the modulus
    //
    //             // If the bit is populated, then multiply the current residue
    //             // value by the current binary exponential component
    //             if (exponent_bit_is_populated) {
    //                 try residue.mul(residue, x);
    //             }
    //         }
    //     },
    //
    //     // Don't allow other types
    //     else => {
    //         std.debug.print("{any}", .{@TypeOf(exponent)});
    //         return error.UnallowedType;
    //     },
    // }

    // // Create the residue
    // try dividend.copy(residue.*.toConst());
    //
    // // Get the first modulo residue
    // try bigIntModulo(dividend, modulus, residue);
    //
    // try residue.pow(dividend, @intCast(exponent));
    // try bigIntModulo(dividend, modulus, residue);

    // // Calculate the exponent, taking the modulo each time
    // for (0..exponent) |_| {
    //     std.debug.print("hi\n", .{});
    //     std.debug.print("Residue: {any}\n", .{residue});
    //     try residue.mul(residue, dividend);
    //     try bigIntModulo(dividend, modulus, residue);
    // }
}

pub fn encrypt(allocator: Allocator, public_key: PublicKey, message: []const u8) ![]u8 {

    // Create a big int for the cipher text
    var plain_text_int = try readOffsetBigInt(allocator, message, 0, std.math.maxInt(usize));
    defer plain_text_int.deinit();

    // Clone the plain text into the initial form of the cipher text
    var cipher_text_int = try plain_text_int.clone();
    defer cipher_text_int.deinit();

    var modulus = try public_key.modulus.clone();
    defer modulus.deinit();

    // Calculate the cipher text
    std.debug.print("{s}\n", .{try cipher_text_int.toString(allocator, 10, std.fmt.Case.lower)});
    try bigIntPowerModulo(&plain_text_int, public_key.exponent, &modulus, &cipher_text_int);
    std.debug.print("\n\nhi\n\n", .{});
    std.debug.print("{s}\n", .{try cipher_text_int.toString(allocator, 10, std.fmt.Case.lower)});

    // Convert the cipher text back to a base 16 string
    return try cipher_text_int.toString(allocator, 16, std.fmt.Case.lower);
}

pub fn decrypt(allocator: Allocator, private_key: PrivateKey, cipher_text: []const u8) ![]u8 {

    // Get the cipher text int from the cipher text
    // var cipher_text_int = try readOffsetBigInt(allocator, cipher_text, 0, std.math.maxInt(usize));
    var cipher_text_int = try BigIntManaged.init(allocator);
    defer cipher_text_int.deinit();
    try cipher_text_int.setString(16, cipher_text);
    std.debug.print("{s}\n", .{cipher_text});

    // Clone the cipher text into the initial form of the plain text
    var plain_text_int = try cipher_text_int.clone();
    defer plain_text_int.deinit();

    var modulus = try private_key.modulus.clone();
    defer modulus.deinit();

    // Calculate the cipher text
    try bigIntPowerModulo(&cipher_text_int, &private_key.private_exponent, &modulus, &plain_text_int);
    std.debug.print("Decrypted Residue: {s}\n\n", .{try plain_text_int.toString(allocator, 10, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {b}\n\n", .{try plain_text_int.toString(allocator, 10, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {s}\n\n", .{try plain_text_int.toString(allocator, 16, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {b}\n\n", .{try plain_text_int.toString(allocator, 16, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {s}\n\n", .{try plain_text_int.toString(allocator, 8, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {b}\n\n", .{try plain_text_int.toString(allocator, 8, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {s}\n\n", .{try plain_text_int.toString(allocator, 4, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {b}\n\n", .{try plain_text_int.toString(allocator, 4, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {s}\n\n", .{try plain_text_int.toString(allocator, 2, std.fmt.Case.lower)});
    std.debug.print("Decrypted Residue: {b}\n\n", .{try plain_text_int.toString(allocator, 2, std.fmt.Case.lower)});

    // const hex_plain_text: []u8 = try plain_text_int.toString(allocator, 16, std.fmt.Case.lower);
    // defer allocator.free(hex_plain_text);
    //
    // std.debug.print("Decrypted Hex: {s}\n\n", .{hex_plain_text});
    //
    // const plain_text_pre_buffer: []u8 = try allocator.alloc(u8, hex_plain_text.len);
    // defer allocator.free(plain_text_pre_buffer);
    // const plain_text_buffer: []u8 = try std.fmt.hexToBytes(plain_text_pre_buffer, hex_plain_text);

    // return plain_text;

    // // Convert the plain text text back to a string
    // return try plain_text_int.toString(allocator, 16, std.fmt.Case.lower);
    //
    //
    //

    // Convert the residue integer to a string
    var bit_mask: BigIntManaged = try BigIntManaged.initSet(allocator, std.math.maxInt(u8));
    defer bit_mask.deinit();
    std.debug.print("plain text int bit count: {d}\n", .{plain_text_int.bitCountTwosComp()});

    var plain_text: []u8 = try allocator.alloc(u8, try std.math.divCeil(usize, plain_text_int.bitCountTwosComp(), 8));

    var buffer: BigIntManaged = try BigIntManaged.init(allocator);

    std.debug.print("Plain text len: {d}\n", .{plain_text.len});

    for (0..plain_text.len) |i| {
        std.debug.print("Bit Mask: {s}\n\n", .{try bit_mask.toString(allocator, 2, std.fmt.Case.lower)});
        try buffer.bitAnd(&plain_text_int, &bit_mask);
        std.debug.print("{s}\n\n", .{try buffer.toString(allocator, 2, std.fmt.Case.lower)});
        plain_text[plain_text.len - 1 - i] = try buffer.to(u8);
        try plain_text_int.shiftRight(&plain_text_int, 8);
    }

    return plain_text;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const small_test: bool = true;

    var pubkey = if (!small_test)
        try PublicKey.parse(
            allocator,
            //"AAAAB3NzaC1yc2EAAAADAQABAAACAQDH+UiVUz6XFRW2jqgxcEU91V7RN+UzMIkU3ZfMHYaESAizcw0iR8jFZ7/CgwEvu6AI3VPhB/53N4LmOFsO1nu0YXjfCFSFvrYHmGIcY1LMgV6XebzherHeFDr7DvbPfrpEEbmdxtJBNtaXKGYouVCWgIK9FjuitT4s21sg+awcEme9eDy0idxzQknrSesepx6+/7odxFyv9st1oLO+HGf8JuoDYjdlhG3cu4nZIXF/ziR5FlJQrz8rCIA0gNvWWKeUs+3xXPjlEsodrNYxeZtXFwKj0B/29GeB0y8LFKGElIQx2NBHJ4p1FE551j16/tanEc+HNzGjku7FYqNcxnd4DksYxNsZJg6yd+2UESWzz+MGlaKHJh0/7QPJUMmeXd7QIS03FYatseByFzl0K22NoKxBi6cBSCvxS8X4lse5ldWY4+8il86S0cG9jlayfGo7yznpJE2ZbcWmkp3M9/JPdQYZXAt+jijXNTDOVjDWm0Y88jqgcZXO4eJTSzNwfymFl6R9Te7oQYeb7gS+hH+JWBvOfZ1/NZOJP+ngtyaV3vYqiHeR19fHnRKC3/ujf5D4Z3mZsdZ2BRQrg+JKMZcvK8kGgaHfiFN9wFEchwDF10Eqv4qESH5f3JG/N8pCHOAVt+FPqUZRCakO7GbQ/XlSFwOCo5NzZDCqwYntdUDCmQ==",
            // "AAAAB3NzaC1yc2EAAAADAQABAAAAgQCnMq4mGjCKoUb2uvmmxOgIg3Zn8Tlw/FXbdelDN7nwNbJw8sW9cprdoI2JTCm+O9GIv+StQB1hWwAIpxcpTIA6cueKAqu1vWj8cild2GECFAryinuKSByqB/fdsBhS2oESeZogPkFMpR45MVZ9fQjA4KBgvXEwc+sgY4Vs0IqNqQ==",
            "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDNI+SAe/DfHo/hPMDb1wf5hTGtGscD0MLmekEx7bJEulJE4TXIlOySI41b2Q+MYJhkXzVibpVGHgWG5Ji801E4LWLJo+vwt7T0raWK1z6ww5PCclgOtJPsGKXZdyPyIrpaj6RxXcJ2ccc8SgqI7lOW/P15RjsINQ8FZYPFaYDCcw==",
        )
    else
        PublicKey{
            .modulus = try BigIntManaged.initSet(allocator, 6011003),
            .exponent = 61,
        };

    defer pubkey.deinit();

    var private_key = if (!small_test)
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
            //"MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQDBgk/A/EEizHPP4SQIXywFFpgWuKQVnuh6rBu2asWoc44EhBFo2ST3LAuifKp6eAvsB460OIexGukdjnaUOIhxLLxj1YCzlN18p9H62gALvvI4cEL7dI1ELsaBaHEQyx07g3YWIJbSO9Zzi3sivzAynmg19mntOa8GnSwBoKJ+5aVzphk/BJLwVcicoKpjPbM2SGkEBBrDKnMhFgcfawwfieeFxb8YBB2sCWZ5XnavPlR94CnbPlyPoefbAzWk2mfE79tvCGCXlmtmiUPuQVG/dLn/MPGJ1rSmYH/qJ/gAwYdUuLZlL4C0kycWVP+fpv9A0a0t8X+Hf2leQhMW5sSRAgMBAAECggEAA3D7VR3HVMSZDKne161FnaOMud63wFCuprvX1FMqx7eiX28v1hMChsjIPjAEYiAvaheqUIcu1pX5blahwjoNJyIaCZZ67vanR7e+Ur08wfi32wwYDNvCRWOlkRiX5ioOj4fjejpDJGL/CdgBrRkEVOofRVJoCNl9RNtXtIG0Uhhgdt81ykGQKguPvDKs94xrL1zX0fVDjGqxSVgBWXwwC5yKnIrXBWnaHLN4yPvYM+2FxaeVCpzP4SMvnVZ6425ovRK915GhiaPHqPG/YEGe19ohgPdhhX7crTgW2pyTx1ST1Mmko0DZ3jTU11aD+w/D0H+v8A/5O7JD48qqdExkYQKBgQD23kgOq4I9pktrO4tr8eHVzeMh3mDw0oRdvKgaufjQeaGFKcOuLHMvaYjqMWTIfChKg0Z5tIjNCwB6c2kWVmDs6vxfxVFdl40fvVRTlBXB5rm3EWj5i3Ik5se8n/hW4hXq20mjmBaaVWHnAXGyFxmJpAsJo+Q8hjN7flaVYIJjaQKBgQDIqr6mpMijWbIdS3ecLvC8LdpriuBxua8LY+0OqdvEbFdB8WEo6n7p9wjHvXVpR6765OMeCtiYpQOqIdfLM2R3V0PIeL0/kEaC9osUl+Rfv+p8s9G+6Y1EuIJz18OyRcyh/sQX/FL4XtGxYgQR/eaN01uvIDNqZQRqLt8G5AC66QJ/QZLJkRv9fGKvpcwrPIEDe8c0jcqD9XP1tPBntrGvZbDpNnXhhGJKNk3SEGMOYjKYgTJdhfZuYAiMF/qP718CX+wLHWVMN5AJ7GReAdVT8i1XJ0l4mNBxgVvLsk7LqEhlify1kr7TQitr1fCMQsHgBq+MPwNJnMoI4sSsOwFnoQKBgDOW+jb7rH2apNk1OsYTp16p5zq41KVIWMFz6lFXyCGCvRg+B32uc/yQv1gi1FnBzTHBwMZLgY4U9pE57DHYv56S9+FFcVozLH2lBvK/bj5Tp+Rxkp4ji2c8jIVd1nkxyr9nMWD9RROHxR92lJdPkIOr8Clg/PcAi5cE/9/UpH9pAoGAeYCqvshITsEkW2DR6aNgWwTXkknumS+XqD9172GdUncjP2SrL6dHBfLSdGHXB/ogjdXtu3FElYGpl79amObJ9XAWb4pVQ9BypE8vTirZwYiLr/KO5/roLC/U/EmrfTxp9sJWtAunjZQxfSJMZtaq9CIbbdY4hqfFzZJjsjk0MEM=",
            // "MIIEoAIBAAKCAQEAwYJPwPxBIsxzz+EkCF8sBRaYFrikFZ7oeqwbtmrFqHOOBIQRaNkk9ywLonyqengL7AeOtDiHsRrpHY52lDiIcSy8Y9WAs5TdfKfR+toAC77yOHBC+3SNRC7GgWhxEMsdO4N2FiCW0jvWc4t7Ir8wMp5oNfZp7TmvBp0sAaCifuWlc6YZPwSS8FXInKCqYz2zNkhpBAQawypzIRYHH2sMH4nnhcW/GAQdrAlmeV52rz5UfeAp2z5cj6Hn2wM1pNpnxO/bbwhgl5ZrZolD7kFRv3S5/zDxida0pmB/6if4AMGHVLi2ZS+AtJMnFlT/n6b/QNGtLfF/h39pXkITFubEkQIDAQABAoIBAANw+1Udx1TEmQyp3tetRZ2jjLnet8BQrqa719RTKse3ol9vL9YTAobIyD4wBGIgL2oXqlCHLtaV+W5WocI6DSciGgmWeu72p0e3vlK9PMH4t9sMGAzbwkVjpZEYl+YqDo+H43o6QyRi/wnYAa0ZBFTqH0VSaAjZfUTbV7SBtFIYYHbfNcpBkCoLj7wyrPeMay9c19H1Q4xqsUlYAVl8MAucipyK1wVp2hyzeMj72DPthcWnlQqcz+EjL51WeuNuaL0SvdeRoYmjx6jxv2BBntfaIYD3YYV+3K04Ftqck8dUk9TJpKNA2d401NdWg/sPw9B/r/AP+TuyQ+PKqnRMZGECgYEA9t5IDquCPaZLazuLa/Hh1c3jId5g8NKEXbyoGrn40HmhhSnDrixzL2mI6jFkyHwoSoNGebSIzQsAenNpFlZg7Or8X8VRXZeNH71UU5QVwea5txFo+YtyJObHvJ/4VuIV6ttJo5gWmlVh5wFxshcZiaQLCaPkPIYze35WlWCCY2kCgYEAyKq+pqTIo1myHUt3nC7wvC3aa4rgcbmvC2PtDqnbxGxXQfFhKOp+6fcIx711aUeu+uTjHgrYmKUDqiHXyzNkd1dDyHi9P5BGgvaLFJfkX7/qfLPRvumNRLiCc9fDskXMof7EF/xS+F7RsWIEEf3mjdNbryAzamUEai7fBuQAuukCf0GSyZEb/Xxir6XMKzyBA3vHNI3Kg/Vz9bTwZ7axr2Ww6TZ14YRiSjZN0hBjDmIymIEyXYX2bmAIjBf6j+9fAl/sCx1lTDeQCexkXgHVU/ItVydJeJjQcYFby7JOy6hIZYn8tZK+00Ira9XwjELB4AavjD8DSZzKCOLErDsBZ6ECgYAzlvo2+6x9mqTZNTrGE6deqec6uNSlSFjBc+pRV8ghgr0YPgd9rnP8kL9YItRZwc0xwcDGS4GOFPaROewx2L+ekvfhRXFaMyx9pQbyv24+U6fkcZKeI4tnPIyFXdZ5Mcq/ZzFg/UUTh8UfdpSXT5CDq/ApYPz3AIuXBP/f1KR/aQKBgHmAqr7ISE7BJFtg0emjYFsE15JJ7pkvl6g/de9hnVJ3Iz9kqy+nRwXy0nRh1wf6II3V7btxRJWBqZe/WpjmyfVwFm+KVUPQcqRPL04q2cGIi6/yjuf66Cwv1PxJq308afbCVrQLp42UMX0iTGbWqvQiG23WOIanxc2SY7I5NDBD",
            // "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEAzSPkgHvw3x6P4TzA29cH+YUxrRrHA9DC5npBMe2yRLpSROE1yJTskiONW9kPjGCYZF81Ym6VRh4FhuSYvNNROC1iyaPr8Le09K2litc+sMOTwnJYDrST7Bil2Xcj8iK6Wo+kcV3CdnHHPEoKiO5Tlvz9eUY7CDUPBWWDxWmAwnMAAAIIZbJ/wWWyf8EAAAAHc3NoLXJzYQAAAIEAzSPkgHvw3x6P4TzA29cH+YUxrRrHA9DC5npBMe2yRLpSROE1yJTskiONW9kPjGCYZF81Ym6VRh4FhuSYvNNROC1iyaPr8Le09K2litc+sMOTwnJYDrST7Bil2Xcj8iK6Wo+kcV3CdnHHPEoKiO5Tlvz9eUY7CDUPBWWDxWmAwnMAAAADAQABAAAAgFowVoy6cOrXV/BxsmS0xDfKfE2bwTWHObj0tOcLlt2qgPLxhKDcAKo7YTGpW7Ge4kD2rtTIw24hUtK8e/5AdasQblPGgQh4HyQn3Z36kbB2mGNac88nbw1jlwEPQ/28ZH4AoTmRrcsrDBoqNNDn6zquGnF2b1B8U6s4aID4YXw5AAAAQD3GIbCm7iBOSXFLegrw/wEezvH537loOP0aGsenowlQeJpmhyEkJBnYf416u2qnPiU/EEJ4I21PtcTAxBrXVpsAAABBAO90LhCcgugml5uO6OjGrepa+S78y5/JGigcUOSCTlnQsw98uAzZpcRNTmw7QX2b8AxGcNhbrTbXkgvsAp9MjeUAAABBANtQuLpsVzBA8nhGgXJeJZ8Um3+fBYiUAsYpaT4HdeHS6hUybavKJVoZIqqiCUi3anCxEO7fv0DQ97CGYPNayXcAAAAQaXNhYWNzdEBJc2FhY3NQQwECAw==",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcnNhAAAAAwEAAQAAAIEAzSPkgHvw3x6P4TzA29cH+YUxrRrHA9DC5npBMe2yRLpSROE1yJTskiONW9kPjGCYZF81Ym6VRh4FhuSYvNNROC1iyaPr8Le09K2litc+sMOTwnJYDrST7Bil2Xcj8iK6Wo+kcV3CdnHHPEoKiO5Tlvz9eUY7CDUPBWWDxWmAwnMAAAIIZbJ/wWWyf8EAAAAHc3NoLXJzYQAAAIEAzSPkgHvw3x6P4TzA29cH+YUxrRrHA9DC5npBMe2yRLpSROE1yJTskiONW9kPjGCYZF81Ym6VRh4FhuSYvNNROC1iyaPr8Le09K2litc+sMOTwnJYDrST7Bil2Xcj8iK6Wo+kcV3CdnHHPEoKiO5Tlvz9eUY7CDUPBWWDxWmAwnMAAAADAQABAAAAgFowVoy6cOrXV/BxsmS0xDfKfE2bwTWHObj0tOcLlt2qgPLxhKDcAKo7YTGpW7Ge4kD2rtTIw24hUtK8e/5AdasQblPGgQh4HyQn3Z36kbB2mGNac88nbw1jlwEPQ/28ZH4AoTmRrcsrDBoqNNDn6zquGnF2b1B8U6s4aID4YXw5AAAAQD3GIbCm7iBOSXFLegrw/wEezvH537loOP0aGsenowlQeJpmhyEkJBnYf416u2qnPiU/EEJ4I21PtcTAxBrXVpsAAABBAO90LhCcgugml5uO6OjGrepa+S78y5/JGigcUOSCTlnQsw98uAzZpcRNTmw7QX2b8AxGcNhbrTbXkgvsAp9MjeUAAABBANtQuLpsVzBA8nhGgXJeJZ8Um3+fBYiUAsYpaT4HdeHS6hUybavKJVoZIqqiCUi3anCxEO7fv0DQ97CGYPNayXcAAAAQaXNhYWNzdEBJc2FhY3NQQwECAw==",
        )
    else
        PrivateKey{
            .prime1 = try BigIntManaged.initSet(allocator, 2003),
            .prime2 = try BigIntManaged.initSet(allocator, 3001),
            .modulus = try BigIntManaged.initSet(allocator, 6011003),
            .version = 1,
            .exponent1 = try BigIntManaged.initSet(allocator, 61),
            .exponent2 = try BigIntManaged.initSet(allocator, 5907541),
            .public_exponent = try BigIntManaged.initSet(allocator, 61),
            .private_exponent = try BigIntManaged.initSet(allocator, 5907541),
            .coefficient = try BigIntManaged.initSet(allocator, 160),
        };
    defer private_key.deinit();

    const plain_text: []const u8 = "M";

    std.debug.print("Plain text: {s}\n", .{plain_text});
    std.debug.print("Plain text binary: {b}\n\n\n", .{plain_text});

    const cipher_text: []u8 = try encrypt(allocator, pubkey, plain_text);
    defer allocator.free(cipher_text);

    std.debug.print("Cipher text: {s}\n\n\n", .{cipher_text});

    const decrypted_plain_text: []u8 = try decrypt(allocator, private_key, cipher_text);
    defer allocator.free(decrypted_plain_text);

    std.debug.print("Decrypted cipher text / Plain text: {b}\n\n\n", .{decrypted_plain_text});
    std.debug.print("Decrypted cipher text / Plain text: {s}\n\n\n", .{decrypted_plain_text});
}
