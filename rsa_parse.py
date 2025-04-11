import os
import subprocess


def rsa_parse(
    enc_or_dec: str,
    pub_key_file: str,
    pub_key_text: str,
    priv_key_file: str,
    priv_key_text: str,
    plain_file: str,
    plain_text: str,
    ciph_file: str,
    ciph_text: str,
):
    # If all key fields are empty, break and pop up error message.
    if enc_or_dec == "encrypt":
        key_to_use: str
        key_type: str
        to_encode_type: str
        to_encode: str
        # If multiple, default to public key from file for encryption.
        if pub_key_file != "No file selected." or pub_key_file != "":
            key_to_use = pub_key_file
            key_type = "public-key-file"
        elif pub_key_text != "":
            key_to_use = pub_key_text
            key_type = "public-key-text"
        elif priv_key_file != "No file selected." or priv_key_file != "":
            key_to_use = priv_key_file
            key_type = "private-key-file"
        elif priv_key_text != "":
            key_to_use = priv_key_text
            key_type = "private-key-text"
        else:
            print("Need a key!")  # error message to gui in an Entry field.
            return False

        # Need to ensure we have only one of plain_text, plain_file:
        if ((plain_file != "No file selected.") or (plain_file != "")) and (
            plain_text != ""
        ):
            print("Can only have one plaintext to encode!")
        elif plain_text:
            # Use plaintext
            to_encode = plain_text
            to_encode_type = "--text"
        else:
            # We have a file
            to_encode_type = "--file"
            to_encode = plain_file
        # Now, make the call to zig binary.
        subprocess.run(
            [
                "./zig-out/bin/rsa",
                "encode",
                f"--{key_type}",
                key_to_use,
                to_encode_type,
                to_encode,
            ]
        )

    elif enc_or_dec == "decrypt":
        # As before, prefer key files to manual entry
        # If no private key, decryption will not work.
        key_to_use: str
        key_type: str
        to_decode_type: str
        to_decode: str
        if priv_key_file != "No file selected.":
            print("have priv key file.")
            key_type = "--file"
        elif priv_key_text != "":
            print("is priv key text")
            key_type = "--text"
        else:
            print("need a private key!")
            return False

        # If there are two things in the decode box, return an error to the user.
        if ((ciph_file != "No file selected.") or (ciph_file != "")) and (
            ciph_text != ""
        ):
            print("have duplicate ciphertexts!")
            return False
        elif ciph_text:
            to_decode_type = "--text"
            to_decode = ciph_text

        else:  # We have a file
            to_decode_type = "--file"
            to_decode = ciph_file

        # Now, make the call to zig binary.
        subprocess.run(
            [
                "./zig-out/bin/rsa",
                "decode",
                f"--{key_type}",
                key_to_use,
                to_decode_type,
                to_decode,
            ]
        )

    else:
        print("Neither encode nor decode were selected on button press (somehow)...")
        return False
