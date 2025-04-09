from tkinter import *
from tkinter import ttk

import frequency_analysis

root = Tk()
root.geometry("1000x700")
root.title("Cryptography Toolkit")


notebook = ttk.Notebook(root)
notebook.pack(padx=10, pady=10, expand=True)

# Each frame is a tab with set dimensions.
home_scr = ttk.Frame(notebook, width=1200, height=900)
freq_scr = ttk.Frame(notebook, width=1200, height=900)
rsa_scr = ttk.Frame(notebook, width=1200, height=900)
otp_scr = ttk.Frame(notebook, width=1200, height=900)

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
    text="Welcome to our homepage!",
).place(x=25, y=25)

# Frequency analysis page--------------------------------------------------
freq_label = Label(
    freq_scr,
    anchor="w",
    justify="left",
    wraplength="300",
    font=("Arial", 12),
    text="About:\nThe frequency analysis tool developed in this project is designed to deconstruct any given text by counting the occurrences of each character or symbol. Essentially, the tool converts raw text into a statistical distribution, revealing hidden patterns within the data. By iterating over every character in a string and maintaining a count of its occurrences using Python’s dictionary data structure, the tool generates a clear frequency profile. This profile is particularly valuable in the context of classic substitution ciphers, as certain letters—such as “E” in English—tend to appear more frequently than others. In ciphertext, such frequency patterns can guide cryptanalysts in making informed guesses about the correspondence between encrypted symbols and common letters in the target language, thereby aiding the decryption process. It is specifically effective against Caesar ciphers, and can help decode Viegnere cipers as well.",
)

freq_input = Text(freq_scr, height=10, width=40)
freq_output = Text(freq_scr, height=10, width=40)
freq_buttonanalyse = Button(
    freq_scr,
    height=2,
    width=20,
    text="Analyse",
    command=lambda: frequency_analysis_input(),
)

freq_label.place(x=25, y=25)
freq_input.place(x=800, y=25)
freq_output.place(x=800, y=200)
freq_buttonanalyse.place(x=840, y=400)


# Functions dealing with input call functions in other Python files
def frequency_analysis_input():
    input = freq_input.get("1.0", "end-1c")
    out = frequency_analysis.analyse_freq(input)
    freq_output.insert("1.0", out)


# Remember to add stuff to the frame or it wont display


root.mainloop()
