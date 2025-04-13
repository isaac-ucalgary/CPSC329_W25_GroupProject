# One Time Pad functions
import random


class LetterCodes:
    lettercodes: list[str] = [
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
    ]

    @staticmethod
    def getIndex(char: str) -> int:
        return LetterCodes.lettercodes.index(char)

    @staticmethod
    def getChar(index: int) -> str:
        return LetterCodes.lettercodes[index % len(LetterCodes.lettercodes)]

    @staticmethod
    def shiftChar(base: str, shift: str, reverse: bool = False) -> str:
        return LetterCodes.lettercodes[
            (
                LetterCodes.getIndex(base)
                + ((1 - 2 * int(reverse)) * LetterCodes.getIndex(shift))
            )
            % len(LetterCodes.lettercodes)
        ]

    @staticmethod
    def shiftString(base: str, shift: str, reverse: bool = False) -> str:
        return "".join(
            [LetterCodes.shiftChar(b, s, reverse) for b, s in zip(base, shift)]
        )

    @staticmethod
    def filter(input_string: str) -> str:
        return "".join([c for c in input_string if c in LetterCodes.lettercodes])


# optype is "e" or "d" for encode or decode, text is the message and key is the key
def textPad(optype: str, text: str, key: str):

    # optype: str = ""
    # while not optype.lower() in ["q", "d", "e"]:
    # optype = input("Would you like to encode(e) or decode(d) or quit(q)")

    if optype == "e":
        # temp: str = input("Please enter the message you want to send: ").lower()
        plaintext: str = LetterCodes.filter(text)
        # Message text is now trimmed to usable characters

        # temp = input(
        #    "Please enter the one time pad you want to use, or leave this blank to generate one: "
        # )
        onetime: str = LetterCodes.filter(text)

        # If the one time pad is blank or invalid, generate one
        if onetime == "":
            onetime = "".join(
                [random.choice(LetterCodes.lettercodes) for _ in plaintext]
            )

        # THIS VIOLATES A CONDITION FOR PERFECT SECRECY!!!! DO NOT DO THIS!!!
        # if its valid but too short, loop it until its long enough
        while len(onetime) < len(plaintext):
            onetime += onetime

        # Encoding time
        ciphertext: str = LetterCodes.shiftString(plaintext, onetime)

        # Output
        # print(f"Ciphertext is: {ciphertext}\nOne time pad is: {onetime}")
        # textPad()
        return ciphertext, onetime

    elif optype == "d":
        # temp = input("Please enter the ciphertext: ").lower()
        # ciphertext = LetterCodes.filter(temp)
        ciphertext = text
        # Message text is now trimmed to usable characters

        # temp = input("Please enter the one time pad you want to use: ")
        # onetime = LetterCodes.filter(temp)
        onetime = key
        # Decoding time
        plaintext = LetterCodes.shiftString(ciphertext, onetime, reverse=True)
        return plaintext
        # output
        # print(f"Plaintext is: {plaintext}")
        # textPad()


def digitalEnter(prompt: str, rand_if_empty_length: int = -1) -> tuple[str, str, int]:
    print(prompt)

    # Parse the number
    unciphered: int
    base_type: str
    while True:
        # Get the number from the user
        temp: str = input("Input number (empty for help): ")

        # Return a random int of the desired length if allowed
        if temp == "" and rand_if_empty_length > 0:
            rand_bits: int = random.getrandbits(rand_if_empty_length)
            return "b", bin(rand_bits), rand_bits

        # Provide help info for number input
        while temp == "":
            print(
                'For binary numbers, prefix with "0b".'
                + '\nFor hexadecimal numbers, prefix with "0x".'
                + '\nFor octal numbers, prefix with "0".'
                + "\nFor decimal numbers, no prefix is required."
            )
            temp = input("Input number (empty for help): ")

        # --- Parse the number ---
        # Get base for parsing the number
        base_type = "d"
        base: int = 10  # Default to decimal
        if len(temp) >= 2 and temp[0] == "0":
            match temp[1]:
                case "b":
                    base = 2  # Binary
                    temp = temp[2:]
                    base_type = "b"
                case "x":
                    base = 16  # Hexadecimal
                    temp = temp[2:]
                    base_type = "x"
                case _:
                    base = 8  # Octal
                    temp = temp[1:]
                    base_type = "o"

        try:
            unciphered = int(temp, base)
        except:
            print("Parse failed. Please try again.")
        else:
            break

    return base_type, temp, unciphered


# base is the base of the message, num is the message, baseo is the base of the key and key is the key.
def digitalPad(base: int, num: str, baseo: int, key: str):
    # optype = input("Would you like to encode(e) or decode(d) or quit(q)? ")

    # Select the appropriate prompt message an output text type depending on the operation
    # text_prompt: str
    # text_generated: str
    # match optype:
    # case "e":
    # text_prompt = "Please enter the message."
    # text_generated = "Ciphertext"
    # case "d":
    # text_prompt = "Please enter the ciphertext."
    # text_generated = "Plaintext"
    # case _:
    # text_prompt = ""
    # text_generated = ""

    # if optype in ["e", "d"]:
    # text_type, text_raw, text = digitalEnter(text_prompt)
    # _, _, onetime = digitalEnter(
    # "Please enter the key to use or leave it  blank to generate one.",
    # rand_if_empty_length=(len(bin(text)) - 2),
    # )
    text = int(num, base)
    if key == "":
        mlen = len(num)
        if base == 8:
            mlen = mlen * 3
        elif base == 16:
            mlen = mlen * 4
        elif base == 10:
            mlen = len(bin(text)) - 2
        rand_bits: int = random.getrandbits(mlen)
        onetime = rand_bits
    else:
        onetime = int(key, baseo)

    # Encode/Decode
    bits = text ^ onetime
    # print(bin(bits)[2:].zfill(16))

    # Output
    # length = len(text_raw * (1 if text_type == "b" else 4))

    return bits, onetime
    # print(
    # f"{text_generated} in binary: {bin(bits)[2:].zfill(length)}"
    # + f"\nOne time pad in binary: {bin(onetime)[2:].zfill(length)}"
    # + f"\n{text_generated} in Hex: {hex(bits)[2:]}"
    # + f"\nOne time pad in hex: {hex(onetime)[2:]}"
    # )

    # loop /exit
    # digitalPad()


def OTPmain():
    print("A one time pad //DESC HERE//")
    choice = ""
    while not choice.lower() in ["t", "d", "e"]:
        choice = input("Text or digital? (t for text, d for digital e for exit)")
    if choice == "t":
        # descriptive paragraph only happens once, then go to the actual program
        print("This is the first iteration of a one-time pad //DESC HERE")
        textPad()
    elif choice == "d":
        # descriptive paragraph only happens once, then go to the actual program
        print("A digital one time pad is the modern version//DESC HERE")
        digitalPad()
    else:
        print("Exiting")
