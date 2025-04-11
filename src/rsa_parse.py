# ----- IMPORTS -----
import os
import platform
import subprocess
from enum import Enum

# ----- CONSTANTS -----
rsa_binary_base_path: str = "./rsa/zig-out"
rsa_binary_name: str = "rsa"


# ----- ENUMS -----
class RsaCommand(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class SourceType(Enum):
    FILE = "file"
    TEXT = "text"


# ----- MAIN -----
def rsa_parse(
    rsa_command: RsaCommand,
    pub_key_type: SourceType = SourceType.TEXT,
    priv_key_type: SourceType = SourceType.TEXT,
    pub_key: str = "",
    priv_key: str = "",
    source_type: SourceType = SourceType.TEXT,
    source: str = "",
    # pub_key_file: str,
    # pub_key_text: str,
    # priv_key_file: str,
    # priv_key_text: str,
    # plain_file: str,
    # plain_text: str,
    # ciph_file: str,
    # ciph_text: str,
) -> subprocess.CompletedProcess[bytes]:
    """
    Calls the RSA binary and returns the captured results.

    Parameters
    ----------
    rsa_command : {RsaCommand.ENCRYPT, RsaCommand.DECRYPT}

    pub_key_type : {SourceType.FILE, SourceType.TEXT}

    priv_key_type : {SourceType.FILE, SourceType.TEXT}

    pub_key : str, default=""
        The supplied public key. Either raw text of a file path.
        Will be interpreted based on `pub_key_type`.

    priv_key : str, default=""
        The supplied private key. Either raw text of a file path.
        Will be interpreted based on `priv_key_type`.

    source_type : {SourceType.FILE, SourceType.TEXT}

    source : str, default=""
        The supplied source to either encrypt or decrypt. Either raw text of a file path.
        Will be interpreted based on `source_type`.

    Returns
    -------
    CompletedProcess[bytes]
         Returns the capture and outcome from running the RSA binary.
         If the binary does not exist for the current system then a `SystemError` will be thrown.

         It is up to the caller to deal with weather the RSA binary call failed or returned a
         successful encryption or decryption.

         Successful encryptions and decryptions will be in `<return>.stdout`.
    """
    # --- Get the RSA binary path ---
    rsa_binary_path: str
    possible_rsa_binary_path: str | None = getRsaBinaryPath()

    if possible_rsa_binary_path is None:
        raise SystemError("RSA binary does not exist for the current system.")
    else:
        rsa_binary_path = possible_rsa_binary_path

    # --- Generate binary call args ---
    call_args: list[str] = [
        rsa_binary_path,
        rsa_command.value,
        f"--{source_type.value}",
        source,
    ]

    # Add non blank options to the call args
    if source != "":
        call_args.append(f"--{source_type.value}")
        call_args.append(source)

    if pub_key != "":
        call_args.append(
            f"--public-key{'-file' if pub_key_type == SourceType.FILE else ''}"
        )
        call_args.append(pub_key)

    if priv_key != "":
        call_args.append(
            f"--private-key{'-file' if priv_key_type == SourceType.FILE else ''}"
        )
        call_args.append(priv_key)

    # --- Call the RSA binary ---
    return subprocess.run(
        args=call_args,
        capture_output=True,
    )

    # # If all key fields are empty, break and pop up error message.
    # if rsa_command == RsaCommand.ENCRYPT:
    #     makeCall: bool = False
    #     key_to_use: str
    #     key_type: str
    #     to_encode_type: str
    #     to_encode: str
    #
    #     # Enforce encryption only using public key
    #     # If multiple, default to public key from file for encryption.
    #     if pub_key_file != "No file selected." or pub_key_file != "":
    #         key_to_use = pub_key_file
    #         key_type = "--public-key-file"
    #         print(f"public key file: {priv_key_file}")
    #     elif pub_key_text != "":
    #         key_to_use = pub_key_text
    #         key_type = "--public-key-text"
    #         print(f"public key text: {priv_key_text}")
    #     else:
    #         return "Need a key!"
    #
    #     # Need to ensure we have only one of plain_text, plain_file:
    #     if ((plain_file != "No file selected.") or (plain_file != "")) and (
    #         plain_text != ""
    #     ):
    #         return "Can only have one plaintext to encode!"
    #     elif plain_text != "":
    #         # Use plaintext
    #         to_encode = plain_text
    #         to_encode_type = "--text"
    #         print(f"plain_text = {plain_text}")
    #         makeCall = True
    #     elif plain_file != "No file selected." and plain_file != "":
    #         # We have a file
    #         to_encode_type = "--file"
    #         to_encode = plain_file
    #         print(f"plain_file = {plain_file}")
    #         makeCall = True
    #     if makeCall:
    #         # Now, make the call to zig binary.
    #         subprocess.run(
    #             [
    #                 "./zig-out/bin/rsa",
    #                 "encode",
    #                 key_type,
    #                 key_to_use,
    #                 to_encode_type,
    #                 to_encode,
    #             ]
    #         )
    #         return True
    #     return "Need a plaintext to encode!"
    #
    # elif rsa_command == RsaCommand.DECRYPT:
    #     # As before, prefer key files to manual entry
    #     # If no private key, decryption will not work.
    #     makeCall: bool = False
    #     key_to_use: str
    #     key_type: str
    #     to_decode_type: str
    #     to_decode: str
    #     if (priv_key_file != "No file selected.") and (priv_key_file != ""):
    #         print("have priv key file.")
    #         key_type = "--file"
    #         key_to_use = priv_key_file
    #     elif priv_key_text != "":
    #         print("priv key text exists")
    #         key_type = "--text"
    #         key_to_use = priv_key_text
    #     else:
    #         return "Need a private key!"
    #
    #     # If there are two things in the decode box, return an error to the user.
    #     if ((ciph_file != "No file selected.") or (ciph_file != "")) and (
    #         ciph_text != ""
    #     ):
    #         return "Cannot have duplicate ciphertexts!"
    #     elif ciph_text:
    #         to_decode_type = "--text"
    #         to_decode = ciph_text
    #         makeCall = True
    #
    #     else:  # We have a file
    #         to_decode_type = "--file"
    #         to_decode = ciph_file
    #         makeCall = True
    #
    #     # Now, make the call to zig binary.
    #     if makeCall:
    #         subprocess.run(
    #             [
    #                 "./zig-out/bin/rsa",
    #                 "decode",
    #                 f"--{key_type}",
    #                 key_to_use,
    #                 to_decode_type,
    #                 to_decode,
    #             ]
    #         )
    #         return True
    #     return "Need a ciphertext to decode!"
    # else:
    #     return "Somehow, you didn't select encode or decode and the RSA function still ran...?"


def getRsaBinaryPath() -> str | None:
    """
    Gets the appropriate RSA binary for the current OS and architecture.

    Returns
    -------
    `str`|`None`
        Returns a `str` of the path to the RSA binary.
        If a binary for the current system does not exist, returns `None`.
    """
    # Construct the path to the rsa binary for the current system
    path: str = (
        f"{rsa_binary_base_path}/{platform.machine().lower()}-{platform.system().lower()}/{rsa_binary_name}"
    )

    # If the path to the binary if it exists
    return path if os.path.exists(path) else None
