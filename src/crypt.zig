// Imports
const std = @import("std");

// Inheritance
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Base64Decoder = std.base64.standard.Decoder;
const BigIntManaged = std.math.big.int.Managed;
const der = std.crypto.Certificate.der;
const maxInt = std.math.maxInt;
const startsWith = std.mem.startsWith;
const endsWith = std.mem.endsWith;

/// RSA Public Key following the *RFC 4253* standard.
pub const PublicKey = struct {
    exponent: BigIntManaged,
    modulus: BigIntManaged,

    /// Parses the RSA Public Key from the *input* string using the ***RFC 4253***
    /// standard.
    ///
    /// Simply, the *input* key string must uphold the following:
    ///   - The string must be one single line.
    ///   - The string must start with *"ssh-rsa "*.
    ///   - The following key itself mush be base 64 encoded and follow the
    ///     *RFC 4253* standard.
    ///   - The base 64 encoded key is terminated with a space (*" "*) character.
    ///   - Any text following this terminating space character will be ignored.
    pub fn parse(allocator: Allocator, input: []const u8) !PublicKey {
        // Define the expected type of the input key
        const key_type: []const u8 = "ssh-rsa";

        // --- Check that the input is of the correct format ---
        if (!startsWith(u8, input, key_type)) return error.InvalidKeyFormat; // Check prefix

        // --- Remove the prefix ---
        var input_key_parts = std.mem.splitScalar(u8, input, ' ');
        _ = input_key_parts.first(); // Skip the key prefix
        const input_key: []const u8 = input_key_parts.next() orelse return error.InvalidKeyFormat; // Get the main key

        // --- Decode the input ---
        const base64_decoded_key = try allocator.alloc(
            u8,
            Base64Decoder.calcSizeForSlice(input_key) catch return error.InvalidKey,
        );
        defer allocator.free(base64_decoded_key);
        Base64Decoder.decode(base64_decoded_key, input_key) catch return error.InvalidKey;

        // Create a variable for recording the position in the decoded binary
        var byte_offset: usize = 0;

        // Get the algorithm identifier
        const algorithm_identifier_byte_length: u32 = readOffsetInt(u32, base64_decoded_key, &byte_offset, .{});
        const algorithm_identifier: []const u8 = getOffsetSlice(base64_decoded_key, &byte_offset, algorithm_identifier_byte_length);

        // Check the key algorithm
        if (!std.mem.eql(u8, algorithm_identifier, key_type)) return error.InvalidKeyAlgorithm;

        // Get the exponent
        const exponent_byte_length: u32 = readOffsetInt(u32, base64_decoded_key, &byte_offset, .{});
        const exponent: BigIntManaged = try readOffsetBigInt(allocator, base64_decoded_key, &byte_offset, exponent_byte_length);

        // Get the modulus
        const modulus_byte_length: u32 = readOffsetInt(u32, base64_decoded_key, &byte_offset, .{});
        const modulus: BigIntManaged = try readOffsetBigInt(allocator, base64_decoded_key, &byte_offset, modulus_byte_length);

        // Return the parsed public key
        return PublicKey{
            .exponent = exponent,
            .modulus = modulus,
        };
    }

    pub fn deinit(self: *PublicKey) void {
        self.modulus.deinit();
        self.exponent.deinit();
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

/// RSA Private Key following the *RFC 8017* standard.
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

    /// Parses a base 64 private key string encoded using the ***RFC 8017*** standard.
    ///
    /// Simply, the input string must uphold the following:
    ///   - Start with *"-----BEGIN RSA PRIVATE KEY-----"* at the first line.
    ///   - End with *"-----END RSA PRIVATE KEY-----"* on the last line.
    ///   - In between is the base 64 encoded private key following the *RFC 8017*
    ///     standard and is encoded using *PEM*.
    ///   - The base 64 key can span multiple lines or be on a single line but
    ///     all lines must be deliminated using the *"\n"* character.
    pub fn parse(allocator: Allocator, input: []const u8) !PrivateKey {
        // Define the expected prefix and suffix of the input key
        const key_prefix: []const u8 = "-----BEGIN RSA PRIVATE KEY-----\n";
        const key_suffix: []const u8 = "\n-----END RSA PRIVATE KEY-----";

        // --- Check that the input is of the correct format ---
        if (!startsWith(u8, input, key_prefix)) return error.InvalidKeyFormat; // Check prefix
        if (!endsWith(u8, input, key_suffix)) return error.InvalidKeyFormat; // Check suffix

        // --- Clean up the input key ---
        // Remove the wrapper from the input
        const unwrapped_input: []const u8 = input[key_prefix.len .. input.len - key_suffix.len];
        const input_key: []u8 = try allocator.alloc(u8, std.mem.replacementSize(u8, unwrapped_input, "\n", ""));
        _ = std.mem.replace(u8, unwrapped_input, "\n", "", input_key);

        // --- Decode the input key ---
        // -- Decode from base 64 --
        const base64_decoded_key = try allocator.alloc(
            u8,
            Base64Decoder.calcSizeForSlice(input_key) catch return error.InvalidKey,
        );
        defer allocator.free(base64_decoded_key);
        Base64Decoder.decode(base64_decoded_key, input_key) catch return error.InvalidKey;

        // -- Decode from DER --
        // Get the first element of the DER encoded bytes which should be an
        // DER element with a sequence tag
        const der_sequence_element = try der.Element.parse(base64_decoded_key, 0);

        // Get the elements of the sequence
        var der_sequence: DerSequence = try DerSequence.init(allocator, der_sequence_element, base64_decoded_key);
        defer der_sequence.deinit();

        // --- Create and return the private key ---
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

/// Calculates *residue* ≡ *dividend* modulo *modulus*.
fn bigIntModulo(dividend: *BigIntManaged, modulus: *BigIntManaged, residue: *BigIntManaged) !void {
    // Initiate the residue to the value of the dividend
    try residue.copy(dividend.toConst());

    // Create buffer for the quotient
    var quotient = try dividend.clone();
    defer quotient.deinit();

    // Calculate the residue
    try quotient.divFloor(residue, dividend, modulus);
}

/// Calculates *residue* ≡ *dividend* to the power of *exponent* modulo *modulus*.
fn bigIntPowerModulo(dividend: *BigIntManaged, exponent: anytype, modulus: *BigIntManaged, residue: *BigIntManaged) !void {
    // --- Create an allocator to use internally ---
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const inner_allocator = gpa.allocator();

    // --- Convert exponent any type to a know big int type ---
    var local_exponent: BigIntManaged = switch (@TypeOf(exponent)) {
        u8, u16, u32, u64 => try BigIntManaged.initSet(inner_allocator, exponent),
        *u8, *u16, *u32, *u64 => try BigIntManaged.initSet(inner_allocator, exponent.*),
        BigIntManaged, *BigIntManaged, *const BigIntManaged => try exponent.clone(),
        else => return error.UnallowedType,
    };
    defer local_exponent.deinit();

    // --- Create internal big ints to use in the calculations ---
    // Create a bit mask to isolate individual bits of the exponent
    var bit_mask: BigIntManaged = try BigIntManaged.initSet(inner_allocator, 1);
    defer bit_mask.deinit();

    // Create a temporary buffer big int
    var buffer: BigIntManaged = try BigIntManaged.init(inner_allocator);
    defer buffer.deinit();

    // Create a variable to store the x value at each step
    var x: BigIntManaged = try BigIntManaged.init(inner_allocator);
    defer x.deinit();
    try x.copy(dividend.toConst());

    // --- Base Case ---
    // Set initial values for the buffer and residue based on the low order bit
    // of the exponent.
    try buffer.bitAnd(&local_exponent, &bit_mask); // Isolate the desired bit of the exponent

    // If the bit is set, then set the residue to the value of the dividend, else 1.
    if (!buffer.eqlZero()) try residue.copy(dividend.toConst()) else try residue.set(1);

    // --- Remaining Exponent Bits ---
    // Loop through all the remaining bits of the exponent.
    // If the bit is set, then multiply the residue by the exponential component
    // and calculate the modulo residue.
    //
    // Leverages the fact that x^9 = x * ((x^2)^2)^2 and each step can be reduced
    // modulo n to make the calculations faster.
    for (1..local_exponent.bitCountTwosComp()) |_| {

        // Shift the bit mask to the next bit
        try bit_mask.shiftLeft(&bit_mask, 1);

        // Determine if the desired bit of the exponent is populated
        try buffer.bitAnd(&local_exponent, &bit_mask);
        const exponent_bit_is_populated: bool = !buffer.eqlZero();

        // Get the new value for x
        try x.pow(&x, 2); // Raise x to the power of 2 to match moving to the next exponent bit
        try bigIntModulo(&x, modulus, &x); // Get the residue of x from the modulus

        // If the bit is populated, then multiply the current residue value by
        // the current binary exponential component
        if (exponent_bit_is_populated) {
            try residue.mul(residue, &x);
            try bigIntModulo(residue, modulus, residue); // Get the residue of x from the modulus
        }
    }
}

/// Encrypts the provided *message* using the RSA (non-OAEP) cryptosystem and
/// the provided *public_key*.
/// Returns a *new* UTF-8 encrypted string.
///
/// Notes:
///   - The original *message* is not altered.
///   - The caller owns the returned string.
pub fn encrypt(allocator: Allocator, public_key: PublicKey, message: []const u8) ![]u8 {
    // Convert the plain text into an integer
    var plain_text_int = try charsToBigInt(allocator, message);
    defer plain_text_int.deinit();

    // Clone the plain text into the initial form of the cipher text
    var cipher_text_int = try plain_text_int.clone();
    defer cipher_text_int.deinit();

    // Create copies of the modulus and exponent from the public key
    var modulus = try public_key.modulus.clone();
    defer modulus.deinit();
    var exponent = try public_key.exponent.clone();
    defer exponent.deinit();

    // Calculate the cipher text
    try bigIntPowerModulo(&plain_text_int, &exponent, &modulus, &cipher_text_int);

    // Convert the residue integer to a string
    return try bigIntToChars(allocator, cipher_text_int);
}

/// Decrypts the provided *cipher_text* using the RSA algorithm (non-OAEP) and
/// the key provided in *private_key*.
///
/// The *cipher_text* is simply an encrypted UTF-8 string.
///
/// Notes:
///   - The original *cipher_text* is not altered.
///   - The caller owns the returned string.
pub fn decrypt(allocator: Allocator, private_key: PrivateKey, cipher_text: []const u8) ![]u8 {
    // Convert the cipher text into an integer
    var cipher_text_int = try charsToBigInt(allocator, cipher_text);
    defer cipher_text_int.deinit();

    // Clone the cipher text into the initial form of the plain text
    var plain_text_int = try cipher_text_int.clone();
    defer plain_text_int.deinit();

    // Clone the modulus from the private key
    var modulus = try private_key.modulus.clone();
    defer modulus.deinit();

    // Calculate the cipher text
    try bigIntPowerModulo(&cipher_text_int, &private_key.private_exponent, &modulus, &plain_text_int);

    // Convert the residue integer to a string and return
    return try bigIntToChars(allocator, plain_text_int);
}

/// Converts the value from a big int into its UTF-8 string representation.
/// Assumes that the big int is just a concatenation of bytes each representing
/// a UTF-8 character.
/// The original *big_int* is not modified.
/// The caller owns the resulting byte array.
fn bigIntToChars(allocator: Allocator, big_int: BigIntManaged) ![]u8 {
    // Create a copy of the big int
    var big_int_copy: BigIntManaged = try big_int.clone();
    defer big_int_copy.deinit();

    // Create a bit mask to get each UTF-8 character from the big int
    var bit_mask: BigIntManaged = try BigIntManaged.initSet(allocator, maxInt(u8));
    defer bit_mask.deinit();

    // Create a buffer big int
    var buffer: BigIntManaged = try BigIntManaged.init(allocator);
    defer buffer.deinit();

    // Get the number of bytes required to represent the big int
    const byte_count: usize = try std.math.divCeil(usize, big_int_copy.bitCountTwosComp(), 8);

    // Create the slice that will be returned
    var return_string: []u8 = try allocator.alloc(u8, byte_count);

    // Transfer each byte from the big int copy to the return string starting
    // from the lowest order byte.
    for (0..return_string.len) |i| {
        // Isolate the lowest byte of the big int copy
        try buffer.bitAnd(&big_int_copy, &bit_mask);

        // Transfer the least order byte to the return string
        return_string[return_string.len - 1 - i] = try buffer.to(u8);

        // Shift the big int copy 1 byte to the right to move the next byte
        // into the lowest position.
        try big_int_copy.shiftRight(&big_int_copy, 8);
    }

    // Return the transferred string
    return return_string;
}

/// Converts a slice of UTF-8 characters to a big int by concatenating the
/// binary values into one single big int.
fn charsToBigInt(allocator: Allocator, chars: []const u8) !BigIntManaged {
    return try readOffsetBigInt(allocator, chars, 0, maxInt(usize));
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const small_test: bool = false;

    var pubkey = if (!small_test)
        try PublicKey.parse(
            allocator,
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQClQurvmbQ3iODS/RetvLU29ErkfwpiqlOmkYxRi8bKqTTyx/Lmgv929Y6E/vJnkiIJ1nYCzpME/wKl0FQf7N4bcE+28yjB7SLZUFGUxLc8bE9FoRYPloMgwQVnVddDjb2tC8gThGP2ihRPgkpBDyKleGSDgv/gAoP/7GJQcp2/vw== Test Key",
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
            \\-----BEGIN RSA PRIVATE KEY-----
            \\MIICXAIBAAKBgQClQurvmbQ3iODS/RetvLU29ErkfwpiqlOmkYxRi8bKqTTyx/Lm
            \\gv929Y6E/vJnkiIJ1nYCzpME/wKl0FQf7N4bcE+28yjB7SLZUFGUxLc8bE9FoRYP
            \\loMgwQVnVddDjb2tC8gThGP2ihRPgkpBDyKleGSDgv/gAoP/7GJQcp2/vwIDAQAB
            \\AoGAaarP7UOqJ5gtqLqLWVs/w1OQT2mrikq+EdMelUV6Zjqq0FFozlsUXUvFROR+
            \\uhqGCSRHcKQE/TzQxJTgNUmO+ZVL+HgjcqtHetuv5t5Yah7nzfrFN6nCUs68FV8u
            \\O9lPZwRB2cHFodWA7xNe/7nfTSvnWtiLyPV6pm3d0I4DnQECQQDSeOftAJgDmchA
            \\1GTinccW+jMuhhgY4NONCZrDYI34pLkH9JpqTGzZW1y9CUmgOgRn0JcXylIYFbVS
            \\FC6kxoBnAkEAyQJq5+FUJZaErRbthgajnuyZa7NWHcfbhD2n2Rzo84zhIJt53JzX
            \\0fCJ3IeFZ+B5HYzxNYFlotuZCrBHqGDO6QJAUZ39IhTm3g6Wbz1t2cshVzGzA0mQ
            \\sqUMpFajIzygEVmfPwyFjM8SLr+VGOEvIekdqDxlOx6D8z8Hz0pwRAmN5QJAHq7z
            \\yrmmsqYrUpCxaUgSKexL7xjNCHa9l44h1Q6IsMTMiMGy9G4ss6tYIAW/439sfYpK
            \\N7Ss4xNKZUtLZPSCIQJBALoPx1Shp/P04//tY9ew7R5aoucaN/m9zcYXDvuB4D57
            \\dN3JLHAMGlEhvtLpj1Ovx8EwKLyGvZFU3q35DQvy4a4=
            \\-----END RSA PRIVATE KEY-----
            ,
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

    const plain_text: []const u8 = "Hello world";

    std.debug.print("Plain text: {s}\n", .{plain_text});

    const cipher_text: []u8 = try encrypt(allocator, pubkey, plain_text);
    defer allocator.free(cipher_text);

    std.debug.print("Cipher text (do not copy):\n{s}\n\n\n", .{cipher_text});

    const decrypted_plain_text: []u8 = try decrypt(allocator, private_key, cipher_text);
    defer allocator.free(decrypted_plain_text);

    std.debug.print("Decrypted cipher text / Plain text: {s}\n\n\n", .{decrypted_plain_text});
}
