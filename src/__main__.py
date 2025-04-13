# ----- IMPORTS -----
import os

# import subprocess
import tkinter as tk
from dataclasses import dataclass

# from tkinter import *
from tkinter import Tk, filedialog, ttk

# ----- LOCAL IMPORTS -----
from frequency_analysis import frequency_analysis
from one_time_pad import OneTimePad
from rsa import rsa_parse

# import OTP here...

# ----- INHERITANCE -----
ENCRYPT = rsa_parse.RsaCommand.ENCRYPT
DECRYPT = rsa_parse.RsaCommand.DECRYPT

# ----- CONSTANTS -----
FONT: str = "Arial"


# I had to learn tkinter in 3 days after the servers wouldn't let me run torch
# This is some of the wost code I have ever written. I apologize to the person who has to read this.
# Also my apologies to whoever finds this on Isaac's github - he didn't write this abomination of procedural bloat.


# ----- MAIN -----
def main():

    # Define the base and max window sizes
    base_window_size: WindowSize = WindowSize(1000, 700)
    max_window_size: WindowSize = WindowSize(1200, 900)

    # Initiate the GUI
    gui: Gui = Gui(base_window_size, max_window_size)

    # Start the GUI
    gui.start()


# ----- GUI -----
@dataclass
class WindowSize:
    x: int
    y: int


class Gui:
    def __init__(
        self, base_window_size: WindowSize, max_window_size: WindowSize
    ) -> None:

        # Define window sizes
        self.base_window_size: WindowSize = base_window_size
        self.max_window_size: WindowSize = max_window_size

        # Create the root of the GUI
        self.root: Tk = Tk()
        self.root.geometry(f"{self.base_window_size.x}x{self.base_window_size.y}")
        self.root.title("Cryptography Toolkit")

        # Create a notebook to store all the tools
        self.notebook: ttk.Notebook = ttk.Notebook(self.root)
        self.notebook.pack(padx=10, pady=10, expand=True)

        # Create a notebook tab for each tool
        self.frames: dict[str, ttk.Frame] = {}
        for frame_name in ["Home", "Frequency Analysis", "One-Time-Pad", "RSA"]:
            # Create the frame
            self.frames[frame_name] = ttk.Frame(
                self.notebook,
                width=self.max_window_size.x,
                height=self.max_window_size.y,
            )
            self.frames[frame_name].pack(fill="both", expand=True)

            # Add frame to the notebook
            self.notebook.add(self.frames[frame_name], text=frame_name)

        # ----- PAGES -----
        self.home_page: HomePage = HomePage(self.frames["Home"])
        self.frequency_analysis_page: FrequencyAnalysisPage = FrequencyAnalysisPage(
            self.frames["Frequency Analysis"]
        )
        self.one_time_pad_page: OneTimePadPage = OneTimePadPage(
            self.frames["One-Time-Pad"]
        )
        self.rsa_page: RsaPage = RsaPage(self.frames["RSA"])

    def start(self) -> None:
        self.root.mainloop()


class HomePage:
    def __init__(self, frame: ttk.Frame) -> None:
        self.frame: ttk.Frame = frame

        self.home_label: tk.Label = tk.Label(
            self.frame,
            anchor="w",
            justify="left",
            font=(FONT, 12),
            wraplength="400",
            text="""
            This cryptography tool was developed for the CPSC 329 Final Project, by Group 5:
                James Clark
                Ethan Davies
                Gwilym Owen
                Isaac Shiells Thomas

            It implements a frequency analysis tool, a one-time pad tool, and RSA encryption and decryption.
                """,
        )
        self.home_label.place(x=25, y=25)


class FrequencyAnalysisPage:
    def __init__(self, frame: ttk.Frame) -> None:
        self.frame: ttk.Frame = frame

        self.freq_label: tk.Label = tk.Label(
            self.frame,
            anchor="w",
            justify="left",
            wraplength="300",
            font=(FONT, 10),
            text="".join(
                [
                    "About:\n",
                    "The frequency analysis tool developed in this project is designed to ",
                    "deconstruct any given text by counting the occurrences of each character or ",
                    "symbol. Essentially, the tool converts raw text into a statistical ",
                    "distribution, revealing hidden patterns within the data. By iterating over ",
                    "every character in a string and maintaining a count of its occurrences using ",
                    "Python’s dictionary data structure, the tool generates a clear frequency ",
                    "profile. This profile is particularly valuable in the context of classic ",
                    "substitution ciphers, as certain letters—such as “E” in English—tend to ",
                    "appear more frequently than others. In ciphertext, such frequency patterns ",
                    "can guide cryptanalysts in making informed guesses about the correspondence ",
                    "between encrypted symbols and common letters in the target language, thereby ",
                    "aiding the decryption process. It is specifically effective against Caesar ",
                    "ciphers, and can help decode Viegnere cipers as well.",
                ]
            ),
        )

        self.freq_input: tk.Text = tk.Text(self.frame, height=10, width=40)
        self.freq_output: tk.Text = tk.Text(self.frame, height=10, width=40)
        self.freq_buttonanalyse: tk.Button = tk.Button(
            self.frame,
            height=2,
            width=20,
            text="Analyse",
            command=lambda: self.func_frequency_analysis_input(),
        )

        self.freq_label.place(x=25, y=25)
        self.freq_input.place(relx=0.75, rely=0.05)
        self.freq_output.place(relx=0.75, rely=0.30)
        self.freq_buttonanalyse.place(relx=0.75, rely=0.55)

    # Functions dealing with input call functions in other Python files
    def func_frequency_analysis_input(self):
        input = self.freq_input.get("1.0", "end-1c")
        out = frequency_analysis.analyse_freq(input)
        self.freq_output.insert("1.0", out)


class OneTimePadPage:
    def __init__(self, frame: ttk.Frame) -> None:
        self.frame: ttk.Frame = frame

        self.otp_label: tk.Label = tk.Label(
            self.frame,
            anchor="w",
            justify="left",
            wraplength="300",
            font=(FONT, 10),
            text="".join(
                [
                    "About:\n",
                    "This OTP tool, implemented in Python, provides two complementary interfaces—text",
                    "Pad for alphanumeric messages and digitalPad for binary/hexadecimal data—anchored ",
                    "by the OTPmain menu. In text mode, the program sanitizes user input to include ",
                    "only characters from a predefined lettercodes list, then either accepts a ",
                    "user‑provided pad or generates a truly random pad of equal length (repeating it ",
                    "if necessary). Encryption maps each character to its index in lettercodes, adds ",
                    "the corresponding pad index modulo 36, and converts the result back to a ",
                    "character; decryption subtracts the pad index instead of adding it. In digital ",
                    "mode, the tool auto‑detects whether the input is binary or hexadecimal, parses ",
                    "it into an integer, and similarly accepts or generates a random key of matching ",
                    "bit‑length. It then performs a bitwise XOR between the message integer and the ",
                    "key, outputting ciphertext and pad in both binary and hexadecimal formats. Both ",
                    "modes loop to allow repeated operations until the user chooses to exit—achieving ",
                    "perfect secrecy across both text and digital data. \n",
                    "The one‑time pad achieves perfect secrecy by combining plaintext with a truly ",
                    "random, single‑use key at least as long as the message, ensuring that the ",
                    "resulting ciphertext is statistically independent of—and thus reveals no ",
                    "information about—the original text. By providing both a modular‑arithmetic ",
                    "interface for alphanumeric messages and a bitwise‑XOR interface for binary/hex ",
                    "data, this tool vividly demonstrates the three critical requirements for OTP ",
                    "security—genuinely random key generation, strict one‑time use, and secure key ",
                    "management—offering a hands‑on exploration of information‑theoretic security and ",
                    "reinforcing why one‑time pads remain the gold standard for absolute confidentiality.",
                ]
            ),
        )
        self.label1_otp: tk.Label = tk.Label(
            frame, font=("Arial", 10), text="Select OTP implementation:"
        )

        self.otp_padtype = tk.StringVar()
        self.otp_padtype.set("textpad")
        textPad_button = tk.Radiobutton(
            frame, text="Text Pad", variable=self.otp_padtype, value="textpad"
        )
        textPad_button.place(relx=0.4, rely=0.1)
        digPad_button = tk.Radiobutton(
            frame, text="Digital Pad", variable=self.otp_padtype, value="digitalpad"
        )
        digPad_button.place(relx=0.4, rely=0.13)

        label2_otp = tk.Label(
            frame,
            font=("Arial", 10),
            text="(Digital pad) Select the number format of your input:",
        )

        # Number type of text
        self.otp_text_numtype = tk.StringVar()
        otp_binary_button = tk.Radiobutton(
            frame, text="Binary", variable=self.otp_text_numtype, value="2"
        )
        otp_octal_button = tk.Radiobutton(
            frame, text="Octal", variable=self.otp_text_numtype, value="8"
        )
        otp_decimal_button = tk.Radiobutton(
            frame, text="Decimal", variable=self.otp_text_numtype, value="10"
        )
        otp_hex_button = tk.Radiobutton(
            frame, text="Hex", variable=self.otp_text_numtype, value="16"
        )

        # Number type of key
        label3_otp = tk.Label(
            frame,
            font=("Arial", 10),
            text="(Digital pad) Select the number format of your key:",
            anchor="w",
        )
        self.otp_key_numtype = tk.StringVar()
        otp_key_button_none = tk.Radiobutton(
            frame, text="No key input", variable=self.otp_key_numtype, value="0"
        )
        otp_binary_key_button = tk.Radiobutton(
            frame, text="Binary", variable=self.otp_key_numtype, value="2"
        )
        otp_octal_key_button = tk.Radiobutton(
            frame, text="Octal", variable=self.otp_key_numtype, value="8"
        )
        otp_decimal_key_button = tk.Radiobutton(
            frame, text="Decimal", variable=self.otp_key_numtype, value="10"
        )
        otp_hex_key_button = tk.Radiobutton(
            frame, text="Hex", variable=self.otp_key_numtype, value="16"
        )

        self.otp_returntype = tk.StringVar()
        otp_return_bin = tk.Radiobutton(
            frame, text="Binary", variable=self.otp_returntype, value="binary"
        )
        otp_return_hex = tk.Radiobutton(
            frame, text="Hex", variable=self.otp_returntype, value="hex"
        )
        otp_return_both = tk.Radiobutton(
            frame, text="Both", variable=self.otp_returntype, value="both"
        )

        otp_input_label = tk.Label(frame, font=("Arial", 10), text="Input:").place(
            relx=0.65, rely=0.02
        )
        otp_key_label = tk.Label(
            frame,
            font=("Arial", 10),
            text="Key: (If blank, a key will be generated and returned here)",
        )
        otp_output_label = tk.Label(frame, font=("Arial", 10), text="Output:").place(
            relx=0.65, rely=0.52
        )
        otp_outputtype_label = tk.Label(
            frame, font=("Arial", 10), text="Would you like your output in..."
        )

        # Radiobutton encode decode (only for )
        label4_otp = tk.Label(
            frame,
            font=("Arial", 10),
            text="Encrypt or decrypt? (Only checked for text pad)",
        )

        self.otp_encordec = tk.StringVar()
        encbutton = tk.Radiobutton(
            frame, text="Encrypt", variable=self.otp_encordec, value="e"
        )
        decbutton = tk.Radiobutton(
            frame, text="Decrypt", variable=self.otp_encordec, value="d"
        )

        self.otp_input = tk.Text(frame, height=10, width=40)
        self.otp_key = tk.Text(frame, height=10, width=40)
        self.otp_output = tk.Text(frame, height=10, width=40)

        self.otp_button = tk.Button(
            frame,
            height=2,
            width=20,
            text="Encrypt/Decrypt",
            # CALL FUNCTION HERE.
            command=lambda: self.func_otp_input(),
        )

        self.otp_label.place(x=25, y=25)
        self.otp_input.place(relx=0.65, rely=0.05)
        self.otp_key.place(relx=0.65, rely=0.30)
        self.otp_output.place(relx=0.65, rely=0.55)
        self.otp_button.place(relx=0.65, rely=0.85)

        self.label1_otp.place(relx=0.4, rely=0.05)
        label2_otp.place(relx=0.4, rely=0.2)
        label3_otp.place(relx=0.4, rely=0.37)
        label4_otp.place(relx=0.4, rely=0.7)

        otp_binary_button.place(relx=0.4, rely=0.23)
        otp_octal_button.place(relx=0.4, rely=0.26)
        otp_decimal_button.place(relx=0.4, rely=0.29)
        otp_hex_button.place(relx=0.4, rely=0.32)

        otp_key_button_none.place(relx=0.4, rely=0.4)
        otp_binary_key_button.place(relx=0.4, rely=0.43)
        otp_octal_key_button.place(relx=0.4, rely=0.46)
        otp_decimal_key_button.place(relx=0.4, rely=0.49)
        otp_hex_key_button.place(relx=0.4, rely=0.52)

        otp_key_label.place(relx=0.65, rely=0.27)
        otp_outputtype_label.place(relx=0.4, rely=0.57)

        encbutton.place(relx=0.4, rely=0.73)
        decbutton.place(relx=0.4, rely=0.76)

        otp_return_bin.place(relx=0.4, rely=0.6)
        otp_return_hex.place(relx=0.4, rely=0.63)
        otp_return_both.place(relx=0.4, rely=0.66)

    def func_otp_input(self):
        # Call OTP code here.
        # Check what type of OTP the user wants.
        message: str = self.otp_input.get("1.0", "end-1c")
        key: str = self.otp_key.get("1.0", "end-1c")
        if self.otp_padtype.get() == "textpad":
            # Text pad
            optype: str = self.otp_encordec.get()
            if optype == "e":
                ret1, ret2 = OneTimePad.textPad(optype, message, key)
                self.otp_key.delete("1.0", "end")
                self.otp_key.insert("1.0", ret2)
            else:
                ret1 = OneTimePad.textPad(optype, message, key)

            self.otp_output.delete("1.0", "end")
            self.otp_output.insert("1.0", ret1)

        else:
            # Digital pad
            # Get inputs from user on format of their number inputs
            base: int = int(self.otp_text_numtype.get())
            keybase: int = int(self.otp_key_numtype.get())
            # Get input type
            inttexttype = int(self.otp_text_numtype.get())
            intkeytype = int(self.otp_key_numtype.get())
            if inttexttype == 2:
                # Binary
                message = "0b" + message
            elif inttexttype == 8:
                # Octal
                message = "0" + message
            elif inttexttype == 16:
                # Hex
                message = "0x" + message

            if intkeytype == 2:
                # Bin
                key = "0b" + key
            elif intkeytype == 8:
                # Octal
                key = "0" + key
            elif intkeytype == 16:
                # Hex
                key = "0x" + key
            ret1, ret2 = OneTimePad.digitalPad(base, message, keybase, key)
            if self.otp_returntype == "binary":
                ret1 = bin(ret1)
            elif self.otp_returntype == "hex":
                ret1 = hex(ret1)
            else:
                ret1 = "Binary:" + bin(ret1) + "\nHex:" + hex(ret1)
            self.otp_output.delete("1.0", "end")

            self.otp_output.insert("1.0", ret1)
            if key == "":
                self.otp_key.delete("1.0", "end")
                if intkeytype == 2:
                    ret2 = bin(ret2)
                elif intkeytype == 8:
                    ret2 = oct(ret2)
                elif intkeytype == 16:
                    ret2 = hex(ret2)
                self.otp_key.insert("1.0", ret2)
        # Then, set output to appropriate box(es) based on user input


class RsaPage:
    def __init__(self, frame: ttk.Frame) -> None:
        self.frame: ttk.Frame = frame

        self.rsa_label: tk.Label = tk.Label(
            self.frame,
            anchor="w",
            justify="left",
            wraplength="300",
            font=(FONT, 10),
            text="".join(
                [
                    "About:\n",
                    "This RSA tool, implemented in Zig, parses and formats both public and private ",
                    "keys based on well-known standards (RFC 4253 for public keys and RFC 8017 for ",
                    "private keys). It converts text messages into big integers and then uses modular ",
                    "exponentiation to perform encryption and decryption. Key functions include ",
                    "decoding keys from base64 or PEM formats, extracting components like exponents ",
                    "and moduli, and handling large-number arithmetic (such as computing ",
                    "multiplicative inverses via the extended Euclidean algorithm), all of which work ",
                    "together to securely transform data.\n",
                    "RSA is very valuable for cryptography because it facilitates secure communication ",
                    "through the use of asymmetric key pairs—one key for encryption and a different ",
                    "one for decryption. The method relies on complex mathematical operations, ",
                    "particularly the difficulty of factoring the product of two large prime numbers, ",
                    "making it practically infeasible to reverse without the corresponding private ",
                    "key. This inherent challenge ensures that only those with the proper private key ",
                    "can decrypt and access the data. These properties make RSA a great for ",
                    "protecting data transmissions, verifying digital signatures, and supporting ",
                    "secure authentication protocols across various applications.",
                    "\n\nTo use the RSA tool:\n",
                    "Public key is used for encryption, private key for decryption. Please ensure ",
                    "that either Plaintext and Public key, OR Ciphertext and Private key are filled. ",
                    "IF THERE IS A FILEPATH IN THE OUTPUT FIELD, ANY FILE AT THAT PATH WILL BE ",
                    "OVERWRITTEN, and any text in the relevant output field may also be overwtritten. ",
                    "By default, the program looks for files. There are pre-generated key pairs in ",
                    "the folder /src/rsa/rsa_test_keys, or you can bring your own (as long as they ",
                    "follow the RFC-8017 standard)",
                ]
            ),
        )
        self.rsa_label.place(x=25, y=25)

        # Our field in the RSA window for messages and errors
        self.msg_label_rsa: tk.Label = tk.Label(
            self.frame, text="Messages and errors from the program will appear below:"
        )
        self.msg_label_rsa.place(relx=0.4, rely=0.77)
        self.str_err_message_rsa: tk.StringVar = tk.StringVar()
        self.msg_err_rsa: tk.Entry = tk.Entry(
            self.frame, textvariable=self.str_err_message_rsa, width=100
        )
        self.msg_err_rsa.place(relx=0.4, rely=0.8)

        # From this point on in RSA, we are declaring
        # Declare our 4 notebooks.
        self.note_plaintext_rsa: ttk.Notebook = ttk.Notebook(self.frame)
        self.note_plaintext_rsa.place(relx=0.4, rely=0.05, width=300, height=200)

        self.note_ciphtxt_rsa: ttk.Notebook = ttk.Notebook(self.frame)
        self.note_ciphtxt_rsa.place(relx=0.7, rely=0.05, width=300, height=200)

        self.note_privkey_rsa: ttk.Notebook = ttk.Notebook(self.frame)
        self.note_privkey_rsa.place(relx=0.7, rely=0.5, width=300, height=200)

        self.note_pubkey_rsa: ttk.Notebook = ttk.Notebook(self.frame)
        self.note_pubkey_rsa.place(relx=0.4, rely=0.5, width=300, height=200)

        # Add frames to each notebook
        self.file_plaintext_rsa: tk.Frame = tk.Frame(
            self.note_plaintext_rsa, width=300, height=200
        )
        self.text_plaintext_rsa: tk.Frame = tk.Frame(
            self.note_plaintext_rsa, width=300, height=200
        )
        self.file_plaintext_rsa.pack(fill="both", expand=True)
        self.text_plaintext_rsa.pack(fill="both", expand=True)

        self.file_ciphtext_rsa: tk.Frame = tk.Frame(
            self.note_ciphtxt_rsa, width=300, height=200
        )

        self.file_ciphtext_rsa.pack(fill="both", expand=True)

        self.file_privkey_rsa: tk.Frame = tk.Frame(
            self.note_privkey_rsa, width=300, height=200
        )
        self.text_privkey_rsa: tk.Frame = tk.Frame(
            self.note_privkey_rsa, width=300, height=200
        )
        self.file_privkey_rsa.pack(fill="both", expand=True)
        self.text_privkey_rsa.pack(fill="both", expand=True)

        self.file_pubkey_rsa: tk.Frame = tk.Frame(
            self.note_pubkey_rsa, width=300, height=200
        )
        self.text_pubkey_rsa: tk.Frame = tk.Frame(
            self.note_pubkey_rsa, width=300, height=200
        )
        self.file_pubkey_rsa.pack(fill="both", expand=True)
        self.text_pubkey_rsa.pack(fill="both", expand=True)

        # Display tabs on each notebook
        self.note_plaintext_rsa.add(self.text_plaintext_rsa, text="Plaintext from text")
        self.note_plaintext_rsa.add(self.file_plaintext_rsa, text="Plaintext from file")

        self.note_ciphtxt_rsa.add(self.file_ciphtext_rsa, text="Ciphertext from file")

        self.note_privkey_rsa.add(self.text_privkey_rsa, text="Private key from text")
        self.note_privkey_rsa.add(self.file_privkey_rsa, text="Private key from file")

        self.note_pubkey_rsa.add(self.text_pubkey_rsa, text="Public key from text")
        self.note_pubkey_rsa.add(self.file_pubkey_rsa, text="Public key from file")

        # From text options.
        self.plaintext_rsa: tk.Text = tk.Text(self.text_plaintext_rsa, wrap=tk.CHAR)
        self.plaintext_rsa.pack(expand=True, fill=tk.BOTH)
        self.privtext_rsa: tk.Text = tk.Text(self.text_privkey_rsa, wrap=tk.CHAR)
        self.privtext_rsa.pack(expand=True, fill=tk.BOTH)
        self.pubtext_rsa: tk.Text = tk.Text(self.text_pubkey_rsa, wrap=tk.CHAR)
        self.pubtext_rsa.pack(expand=True, fill=tk.BOTH)

        # For each of the "from text" frames, we add a button to select a file and field for currently selected file.
        self.in_plainfile_rsa: tk.StringVar = tk.StringVar()
        self.in_ciphfile_rsa: tk.StringVar = tk.StringVar()
        self.in_privfile_rsa: tk.StringVar = tk.StringVar()
        self.in_pubfile_rsa: tk.StringVar = tk.StringVar()

        self.label_plainfile_rsa: tk.Entry = tk.Entry(
            self.file_plaintext_rsa, textvariable=self.in_plainfile_rsa
        )
        self.label_plainfile_rsa.place(relx=0, rely=0.2, relwidth=1)

        self.get_plainfile_rsa: tk.Button = tk.Button(
            self.file_plaintext_rsa,
            text="Choose file",
            command=lambda: get_file(self.in_plainfile_rsa),
        )
        self.get_plainfile_rsa.place(relx=0.6, rely=0.5)

        self.label_ciphfile_rsa: tk.Entry = tk.Entry(
            self.file_ciphtext_rsa, textvariable=self.in_ciphfile_rsa
        )
        self.label_ciphfile_rsa.place(relx=0, rely=0.2, relwidth=1)

        self.get_ciphfile_rsa: tk.Button = tk.Button(
            self.file_ciphtext_rsa,
            text="Choose file",
            command=lambda: get_file(self.in_ciphfile_rsa),
        )
        self.get_ciphfile_rsa.place(relx=0.6, rely=0.5)

        self.label_privfile_rsa: tk.Entry = tk.Entry(
            self.file_privkey_rsa, textvariable=self.in_privfile_rsa
        )
        self.label_privfile_rsa.place(relx=0, rely=0.2, relwidth=1)

        self.get_privfile_rsa: tk.Button = tk.Button(
            self.file_privkey_rsa,
            text="Choose file",
            command=lambda: get_file(self.in_privfile_rsa),
        )
        self.get_privfile_rsa.place(relx=0.6, rely=0.5)

        self.label_pubfile_rsa: tk.Entry = tk.Entry(
            self.file_pubkey_rsa, textvariable=self.in_pubfile_rsa
        )
        self.label_pubfile_rsa.place(relx=0, rely=0.2, relwidth=1)

        self.get_pubfile_rsa: tk.Button = tk.Button(
            self.file_pubkey_rsa,
            text="Choose file",
            command=lambda: get_file(self.in_pubfile_rsa),
        )
        self.get_pubfile_rsa.place(relx=0.6, rely=0.5)

        # Encrypt/decrypt buttons
        self.rsa_encrypt: tk.Button = tk.Button(
            self.frame,
            height=2,
            width=15,
            text="Encrypt",
            command=lambda: self.func_rsa(
                rsa_parse.RsaCommand.ENCRYPT,
            ),
        )
        self.rsa_encrypt.place(relx=0.55, y=300)
        self.rsa_decrypt: tk.Button = tk.Button(
            self.frame,
            height=2,
            width=15,
            text="Decrypt",
            command=lambda: self.func_rsa(
                rsa_parse.RsaCommand.DECRYPT,
            ),
        )
        self.rsa_decrypt.place(relx=0.70, y=300)

    # Wrapper that gets relevant information, then calls rsa_parse to do the heavy lifting.
    def func_rsa(
        self,
        enc_or_dec: rsa_parse.RsaCommand,
    ):
        # Get values for this function.
        pub_key_file: str = self.in_pubfile_rsa.get()
        pub_key_text: str = self.pubtext_rsa.get("1.0", "end-1c")
        priv_key_file: str = self.in_privfile_rsa.get()
        priv_key_text: str = self.privtext_rsa.get("1.0", "end-1c")
        plain_file: str = self.in_plainfile_rsa.get()
        plain_text: str = self.plaintext_rsa.get("1.0", "end-1c")
        ciph_file: str = self.in_ciphfile_rsa.get()

        # Determine input from user
        # Default to text inputs.
        pub_key_type: rsa_parse.SourceType = rsa_parse.SourceType.TEXT
        pub_key: str = pub_key_text
        priv_key_type: rsa_parse.SourceType = rsa_parse.SourceType.TEXT
        priv_key: str = priv_key_text
        source_type: rsa_parse.SourceType = rsa_parse.SourceType.TEXT
        source: str

        # Wrap everything in a try block to send errors back to the user
        try:
            # Set variables and call function
            # Set public key type
            if pub_key_file:
                pub_key_type = rsa_parse.SourceType.FILE
                pub_key = pub_key_file

            # Set private key
            if priv_key_file:
                priv_key_type = rsa_parse.SourceType.FILE
                priv_key = priv_key_file

            # Set source depending if we are encrypting or decrypting
            source_type = rsa_parse.SourceType.TEXT  # Default
            if enc_or_dec == rsa_parse.RsaCommand.ENCRYPT:
                source = plain_text
                if plain_file:
                    source = plain_file
                    source_type = rsa_parse.SourceType.FILE
            else:
                source = ciph_file
                source_type = rsa_parse.SourceType.FILE

            # Perform RSA
            returned = rsa_parse.rsa_parse(
                enc_or_dec,
                pub_key_type,
                priv_key_type,
                pub_key,
                priv_key,
                source_type,
                source,
            )

            # Returned is an object that allows us to listen on either stdout or stderr
            if returned.stdout:
                # Get the output from RSA as both bytes and a string
                rsa_output_bytes: bytes = returned.stdout
                rsa_output_str: str = rsa_output_bytes.decode("utf-8", "ignore")

                # Inform the user that the program ran
                self.str_err_message_rsa.set("RSA Complete")

                # Get the output file path
                output_file_path: str = (
                    self.in_ciphfile_rsa.get()
                    if enc_or_dec == ENCRYPT
                    else self.in_plainfile_rsa.get()
                )

                # Write to the output file if provided
                if output_file_path:
                    with open(output_file_path, "wb") as output_file:
                        _ = output_file.write(rsa_output_bytes)

                # If decrypting, write the output to the plaintext-text-box
                if enc_or_dec == DECRYPT:
                    self.plaintext_rsa.delete("1.0", "end")
                    self.plaintext_rsa.insert("1.0", rsa_output_str)

            else:
                # There was an error on stderr
                self.str_err_message_rsa.set(returned.stderr.decode("utf-8", "ignore"))

        except Exception as e:
            self.str_err_message_rsa.set(str(e))


# For rsa, we enforce that encryption uses the public key, and decryption uses private key.


# Call OS's file manager to select the file and writes the filepath to appropriate text field
def get_file(label: tk.StringVar):
    filename = filedialog.askopenfilename(
        initialdir=os.getcwd(),
        title="Select file",
        filetypes=(
            ("Pem files", "*.pem"),
            ("Pub Pem files", "*.pem.pub"),
            ("Txt files", "*.txt*"),
            ("all files", "*.*"),
        ),
    )
    label.set(filename)


main()
