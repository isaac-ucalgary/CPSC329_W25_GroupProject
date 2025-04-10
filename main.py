import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog

# This imports the frequency analysis and OTP files
import frequency_analysis
import rsa_parse

# import OTP here...


# I had to learn tkinter in 3 days after the servers wouldn't let me run torch
# This is some of the wost code I have ever written. I apologize to the person who has to read this.
# Also my apologies to whoever finds this on Isaac's github - he didn't write this.

root = Tk()
root.geometry("1000x700")
root.title("Cryptography Toolkit")


notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10, expand=True)

# Each frame is a tab with set dimensions.
home_scr = ttk.Frame(notebook, width=1200, height=900)
freq_scr = ttk.Frame(notebook, width=1200, height=900)
otp_scr = ttk.Frame(notebook, width=1200, height=900)
rsa_scr = ttk.Frame(notebook, width=1200, height=900)

# Displays the frames
home_scr.pack(fill="both", expand=True)
freq_scr.pack(fill="both", expand=True)
rsa_scr.pack(fill="both", expand=True)
otp_scr.pack(fill="both", expand=True)

# Set notebook tab titles
notebook.add(home_scr, text="Home")
notebook.add(freq_scr, text="Frequency Analysis")
notebook.add(otp_scr, text="One-Time Pad")
notebook.add(rsa_scr, text="RSA")

# Homepage with general information----------------------------------------
home_label = Label(
    home_scr,
    anchor="w",
    justify="left",
    wraplength="300",
    text="This cryptography tool was developed for the CPSC 329 Final Project, by Group 5: \n Ethan Davies \n Gwilym Owen \n Isaac Shiells Thomas \n James Clark\n"
    + "It implements a frequency analysis tool, a one-time pad tool, and RSA encryption and decryption.",
).place(x=25, y=25)

# Frequency analysis page--------------------------------------------------
freq_label = Label(
    freq_scr,
    anchor="w",
    justify="left",
    wraplength="300",
    font=("Arial", 10),
    text="About:\nThe frequency analysis tool developed in this project is designed to deconstruct any given text by counting the occurrences of each character or symbol. Essentially, the tool converts raw text into a statistical distribution, revealing hidden patterns within the data. By iterating over every character in a string and maintaining a count of its occurrences using Python’s dictionary data structure, the tool generates a clear frequency profile. This profile is particularly valuable in the context of classic substitution ciphers, as certain letters—such as “E” in English—tend to appear more frequently than others. In ciphertext, such frequency patterns can guide cryptanalysts in making informed guesses about the correspondence between encrypted symbols and common letters in the target language, thereby aiding the decryption process. It is specifically effective against Caesar ciphers, and can help decode Viegnere cipers as well.",
)

freq_input = Text(freq_scr, height=10, width=40)
freq_output = Text(freq_scr, height=10, width=40)
freq_buttonanalyse = Button(
    freq_scr,
    height=2,
    width=20,
    text="Analyse",
    command=lambda: func_frequency_analysis_input(),
)

freq_label.place(x=25, y=25)
freq_input.place(relx=0.75, rely=0.05)
freq_output.place(relx=0.75, rely=0.30)
freq_buttonanalyse.place(relx=0.75, rely=0.55)

# One-time pad page-------------------------------------------------------
otp_label = Label(
    otp_scr,
    anchor="w",
    justify="left",
    wraplength="300",
    font=("Arial", 10),
    text="About:\nThis OTP tool, implemented in Python, provides two complementary interfaces—textPad for alphanumeric messages and digitalPad for binary/hexadecimal data—anchored by the OTPmain menu. In text mode, the program sanitizes user input to include only characters from a predefined lettercodes list, then either accepts a user‑provided pad or generates a truly random pad of equal length (repeating it if necessary). Encryption maps each character to its index in lettercodes, adds the corresponding pad index modulo 26, and converts the result back to a character; decryption subtracts the pad index instead of adding it. In digital mode, the tool auto‑detects whether the input is binary or hexadecimal, parses it into an integer, and similarly accepts or generates a random key of matching bit‑length. It then performs a bitwise XOR between the message integer and the key, outputting ciphertext and pad in both binary and hexadecimal formats. Both modes loop to allow repeated operations until the user chooses to exit—achieving perfect secrecy across both text and digital data. " + 
    "The one‑time pad achieves perfect secrecy by combining plaintext with a truly random, single‑use key at least as long as the message, ensuring that the resulting ciphertext is statistically independent of—and thus reveals no information about—the original text. By providing both a modular‑arithmetic interface for alphanumeric messages and a bitwise‑XOR interface for binary/hex data, this tool vividly demonstrates the three critical requirements for OTP security—genuinely random key generation, strict one‑time use, and secure key management—offering a hands‑on exploration of information‑theoretic security and reinforcing why one‑time pads remain the gold standard for absolute confidentiality."
)
otp_input = Text(otp_scr, height=10, width=40)
otp_output = Text(otp_scr, height=10, width=40)
otp_button = Button(
    otp_scr, height=2, width=20, text="Do the thing.", command=lambda: func_otp_input()
)

otp_label.place(x=25, y=25)
otp_input.place(relx=0.75, rely=0.05)
otp_output.place(relx=0.75, rely=0.30)
otp_button.place(relx=0.75, rely=0.55)

# RSA page-----------------------------------------------------------------
rsa_label = Label(
    rsa_scr,
    anchor="w",
    justify="left",
    wraplength="300",
    font=("Arial", 10),
    text="This RSA tool, implemented in Zig, parses and formats both public and private keys based on well-known standards (RFC 4253 for public keys and RFC 8017 for private keys). It converts text messages into big integers and then uses modular exponentiation to perform encryption and decryption. Key functions include decoding keys from base64 or PEM formats, extracting components like exponents and moduli, and handling large-number arithmetic (such as computing multiplicative inverses via the extended Euclidean algorithm), all of which work together to securely transform data." +
    "RSA is very valuable for cryptography because it facilitates secure communication through the use of asymmetric key pairs—one key for encryption and a different one for decryption. The method relies on complex mathematical operations, particularly the difficulty of factoring the product of two large prime numbers, making it practically infeasible to reverse without the corresponding private key. This inherent challenge ensures that only those with the proper private key can decrypt and access the data. These properties make RSA a great for protecting data transmissions, verifying digital signatures, and supporting secure authentication protocols across various applications."
).place(x=25, y=25)

#Info labels
pubpriv_label = Label(
    rsa_scr, font=("Arial", 10), text="Only fill one of public/private key."
).place(relx=0.5, rely=0)

# Our field in the RSA window for messages and errors
msg_label_rsa = Label(rsa_scr, text="Messages and errors from the program will appear below:")
msg_err_rsa = Entry(rsa_scr, width=60)
msg_label_rsa.place(relx=0.4, rely=0.77)
msg_err_rsa.place(relx=0.4, rely=0.8)


# From this point on in RSA, we are declaring
# Declare our 4 notebooks.
note_plaintext_rsa = ttk.Notebook(rsa_scr)
note_plaintext_rsa.place(relx=0.4, rely=0.05, width=300, height=200)

note_ciphtxt_rsa = ttk.Notebook(rsa_scr)
note_ciphtxt_rsa.place(relx=0.7, rely=0.05, width=300, height=200)

note_privkey_rsa = ttk.Notebook(rsa_scr)
note_privkey_rsa.place(relx=0.4, rely=0.5, width=300, height=200)

note_pubkey_rsa = ttk.Notebook(rsa_scr)
note_pubkey_rsa.place(relx=0.7, rely=0.5, width=300, height=200)


# Add frames to each notebook
file_plaintext_rsa = Frame(note_plaintext_rsa, width=300, height=200)
text_plaintext_rsa = Frame(note_plaintext_rsa, width=300, height=200)
file_plaintext_rsa.pack(fill="both", expand=True)
text_plaintext_rsa.pack(fill="both", expand=True)

file_ciphtext_rsa = Frame(note_ciphtxt_rsa, width=300, height=200)
text_ciphtext_rsa = Frame(note_ciphtxt_rsa, width=300, height=200)
file_ciphtext_rsa.pack(fill="both", expand=True)
text_ciphtext_rsa.pack(fill="both", expand=True)

file_privkey_rsa = Frame(note_privkey_rsa, width=300, height=200)
text_privkey_rsa = Frame(note_privkey_rsa, width=300, height=200)
file_privkey_rsa.pack(fill="both", expand=True)
text_privkey_rsa.pack(fill="both", expand=True)

file_pubkey_rsa = Frame(note_pubkey_rsa, width=300, height=200)
text_pubkey_rsa = Frame(note_pubkey_rsa, width=300, height=200)
file_pubkey_rsa.pack(fill="both", expand=True)
text_pubkey_rsa.pack(fill="both", expand=True)

# Display tabs on each notebook
note_plaintext_rsa.add(text_plaintext_rsa, text="Plaintext from text")
note_plaintext_rsa.add(file_plaintext_rsa, text="Plaintext from file")

note_ciphtxt_rsa.add(text_ciphtext_rsa, text="Ciphertext from text")
note_ciphtxt_rsa.add(file_ciphtext_rsa, text="Ciphertext from file")

note_privkey_rsa.add(text_privkey_rsa, text="Private key from text")
note_privkey_rsa.add(file_privkey_rsa, text="Private key from file")

note_pubkey_rsa.add(text_pubkey_rsa, text="Public key from text")
note_pubkey_rsa.add(file_pubkey_rsa, text="Public key from file")


# From text options.
in_plaintext_rsa = StringVar()
in_ciphtext_rsa = StringVar()

plaintext_rsa = Text(text_plaintext_rsa, wrap=CHAR)
plaintext_rsa.pack(expand=True, fill=BOTH)
ciphtext_rsa = Text(text_ciphtext_rsa, wrap=CHAR)
ciphtext_rsa.pack(expand=True, fill=BOTH)
privtext_rsa = Text(text_privkey_rsa, wrap=CHAR)
privtext_rsa.pack(expand=True, fill=BOTH)
pubtext_rsa = Text(text_pubkey_rsa, wrap=CHAR)
pubtext_rsa.pack(expand=True, fill=BOTH)


# For each of the "from text" frames, we add a button to select a file and field for currently selected file.
in_plainfile_rsa = StringVar()
in_ciphfile_rsa = StringVar()
in_privfile_rsa = StringVar()
in_pubfile_rsa = StringVar()

in_plainfile_rsa.set("No file selected.")
in_ciphfile_rsa.set("No file selected.")
in_privfile_rsa.set("No file selected.")
in_pubfile_rsa.set("No file selected.")

label_plainfile_rsa = Entry(file_plaintext_rsa, textvariable=in_plainfile_rsa).place(
    relx=0, rely=0.2, relwidth=1
)
get_plainfile_rsa = Button(
    file_plaintext_rsa, text="Choose file", command=lambda: get_file(in_plainfile_rsa)
).place(relx=0.6, rely=0.5)

label_ciphfile_rsa = Entry(file_ciphtext_rsa, textvariable=in_ciphfile_rsa).place(
    relx=0, rely=0.2, relwidth=1
)
get_ciphfile_rsa = Button(
    file_ciphtext_rsa, text="Choose file", command=lambda: get_file(in_ciphfile_rsa)
).place(relx=0.6, rely=0.5)

label_privfile_rsa = Entry(file_privkey_rsa, textvariable=in_privfile_rsa).place(
    relx=0, rely=0.2, relwidth=1
)
get_privfile_rsa = Button(
    file_privkey_rsa, text="Choose file", command=lambda: get_file(in_privfile_rsa)
).place(relx=0.6, rely=0.5)

label_pubfile_rsa = Entry(file_pubkey_rsa, textvariable=in_pubfile_rsa).place(
    relx=0, rely=0.2, relwidth=1
)
get_pubfile_rsa = Button(
    file_pubkey_rsa, text="Choose file", command=lambda: get_file(in_pubfile_rsa)
).place(relx=0.6, rely=0.5)

# Encrypt/decrypt buttons
rsa_encrypt = Button(
    rsa_scr,
    height=2,
    width=20,
    text="Encrypt",
    command=lambda: func_rsa(
        "encrypt",
    ),
).place(relx=0.6, y=600)
rsa_decrypt = Button(
    rsa_scr,
    height=2,
    width=20,
    text="Decrypt",
    command=lambda: func_rsa(
        "decrypt",
    ),
).place(relx=0.72, y=600)


# Functions dealing with input call functions in other Python files
def func_frequency_analysis_input():
    input = freq_input.get("1.0", "end-1c")
    out = frequency_analysis.analyse_freq(input)
    freq_output.insert("1.0", out)


def func_otp_input():
    input = otp_input.get("1.0", "end-1c")
    # Call OTP code here.
    out = "hello"  # one-time pad output goes here
    otp_output.insert("1.0", out)



#Wrapper that gets relevant information, then calls rsa_parse to do the heavy lifting.
def func_rsa(
    enc_or_dec: str,
):
    # Get values for this function.
    pub_key_file: str = in_pubfile_rsa.get()
    pub_key_text: str = pubtext_rsa.get("1.0", "end-1c")
    priv_key_file: str = in_privfile_rsa.get()
    priv_key_text: str = privtext_rsa.get("1.0", "end-1c")
    plain_file: str = in_plainfile_rsa.get()
    plain_text: str = plaintext_rsa.get("1.0", "end-1c")
    ciph_file: str = in_ciphfile_rsa.get()
    ciph_text: str = ciphtext_rsa.get("1.0", "end-1c")
    # Here, returned will be True if fn passed, or an error message if there was a failure.
    returned = rsa_parse.rsa_parse(enc_or_dec, pub_key_file, pub_key_text, priv_key_file, priv_key_text, plain_file, plain_text, ciph_file, ciph_text)
    print(f"rsaparse returned = {returned}")
    if(str(returned) == "True"):
        print("RSA WORKED!!!!!!!!")

    else:
        print("There was an error in the rsa function!")




# This calls your OS's file manager to select the file and writes the filepath to appropriate text field
def get_file(label: StringVar):
    filename = filedialog.askopenfilename(
        initialdir="/",
        title="Select file",
        filetypes=(
            ("Pem files", "*.pem*"),
            ("Pub files", "*.pub*"),
            ("Txt files", "*.txt*"),
            ("all files", "*.*"),
        ),
    )
    label.set(filename)


# Determine where we are taking input from and call accordingly.


# Remember to add stuff to the frame or it wont display


root.mainloop()
