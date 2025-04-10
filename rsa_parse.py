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
        makeCall:bool = False
        key_to_use: str
        key_type: str
        to_encode_type: str
        to_encode: str
        # If multiple, default to public key from file for encryption.
        if pub_key_file != "No file selected." or pub_key_file != "":
            key_to_use = pub_key_file
            key_type = "public-key-file"
            print(f"public key file: {priv_key_file}")
        elif pub_key_text != "":
            key_to_use = pub_key_text
            key_type = "public-key-text"
            print(f"public key text: {priv_key_text}")
        elif priv_key_file != "No file selected." or priv_key_file != "":
            key_to_use = priv_key_file
            key_type = "private-key-file"
            print(f"private key file: {priv_key_file}")
        elif priv_key_text != "":
            key_to_use = priv_key_text
            key_type = "private-key-text"
            print(f"private key text: {priv_key_text}")
        else:
            return "Need a key!"

        # Need to ensure we have only one of plain_text, plain_file:
        if ((plain_file != "No file selected.") or (plain_file != "")) and (
            plain_text != ""
        ):
            return "Can only have one plaintext to encode!"
        elif plain_text != "":
            # Use plaintext
            to_encode = plain_text
            to_encode_type = "--text"
            print(f"plain_text = {plain_text}")
            makeCall = True
        elif plain_file != "No file selected." and plain_file != "":
            # We have a file
            to_encode_type = "--file"
            to_encode = plain_file
            print(f"plain_file = {plain_file}")

        if(makeCall):
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
            return True
        return "Need a plaintext to encode!"

    elif enc_or_dec == "decrypt":
        # As before, prefer key files to manual entry
        # If no private key, decryption will not work.
        key_to_use: str
        key_type: str
        to_decode_type: str
        to_decode: str
        if (priv_key_file != "No file selected.") and (priv_key_file != ""):
            print("have priv key file.")
            key_type = "--file"
            key_to_use = priv_key_file
        elif priv_key_text != "":
            print("priv key text exists")
            key_type = "--text"
            key_to_use = priv_key_text
        else:
            return "Need a private key!"

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
        return True

    else:
        return "Somehow, you didn't select encode or decode and the RSA function still ran...?"
