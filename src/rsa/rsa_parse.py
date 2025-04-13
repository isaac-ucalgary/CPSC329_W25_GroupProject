# ----- IMPORTS -----
import os
import platform
import subprocess
from enum import Enum

# ----- CONSTANTS -----
rsa_binary_base_path: str = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "zig-out"
)
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

    # Adding tweaks to make this handle 'amd64' (which is just x86_64 but named different because reasons)
    machine_type: str = platform.machine().lower()
    if machine_type == "amd64":
        machine_type = "x86_64"

    path: str = (
        f"{rsa_binary_base_path}/{machine_type}-{platform.system().lower()}/{rsa_binary_name}"
    )

    # If on windows, append .exe to path
    if platform.system().lower() == "windows":
        path += ".exe"

    # If the path to the binary if it exists
    return path if os.path.exists(path) else None
