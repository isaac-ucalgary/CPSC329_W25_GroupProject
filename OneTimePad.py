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


def textPad():
    optype: str = ""
    while not optype.lower() in ["q", "d", "e"]:
        optype = input("Would you like to encode(e) or decode(d) or quit(q)")

    if optype == "e":
        temp: str = input("Please enter the message you want to send:").lower()
        plaintext: str = LetterCodes.filter(temp)
        # Message text is now trimmed to usable characters

        temp = input(
            "Please enter the one time pad you want to use, or leave this blank to generate one:"
        )
        onetime: str = LetterCodes.filter(temp)

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
        print(f"Ciphertext is: {ciphertext}\nOne time pad is: {onetime}")
        textPad()

    if optype == "d":
        temp = input("Please enter the ciphertext").lower()
        ciphertext = LetterCodes.filter(temp)
        # Message text is now trimmed to usable characters

        temp = input("Please enter the one time pad you want to use: ")
        onetime = LetterCodes.filter(temp)
        # Decoding time
        plaintext = LetterCodes.shiftString(ciphertext, onetime, reverse=True)

        # output
        print(f"Plaintext is: {plaintext}")
        textPad()


def digitalEnter():
    temp = input("Input as either binary or hexadecimal: ")
    unciphered = ""
    try:
        unciphered = int(temp, 2)
        return ["b", temp], unciphered
    except:
        try:
            unciphered = int(temp, 16)
            return ["h", temp], unciphered
        except:
            print("that is not valid binary or hex")
            temp = input("(e)to exit or enter to continue")
            if temp == "e":
                digitalPad()
            else:
                _ = digitalEnter()


def digitalPad():
    optype = input("Would you like to encode(e) or decode(d)? ")
    if optype == "e":
        print("Please enter the message: ")
        ptype, plaintext = digitalEnter()
        print("Please enter the key to use or leave it  blank to generate one: ")
        otype, onetime = digitalEnter()
        if onetime == "":
            onetime = random.getrandbits(len(plaintext))
            print(bin(onetime)[2:].zfill(16))

        # Encoding time
        cipherBits = plaintext ^ onetime
        print(bin(cipherBits)[2:].zfill(16))

        # output
        # if ptype[0] == "b":
        #     length = len(ptype[1])
        # else:
        #     length = len(ptype[1] * 4)
        length = len(ptype[1] * (1 if ptype[0] == "b" else 4))

        print(
            f"Ciphertext in binary: {bin(cipherBits)[2:].zfill(length)}"
            + f"One time pad in binary: {bin(onetime)[2:].zfill(length)}"
            + f"Ciphertext in Hex: {hex(cipherBits)[2:]}"
            + f"one time pad in hex: {hex(onetime)[2:]}"
        )

        # loop /exit
        digitalPad()
    if optype == "d":
        print("Please enter the ciphertext: ")
        ptype, ciphertext = digitalEnter()
        print("Please enter the key to use or leave it  blank to generate one: ")
        otype, onetime = digitalEnter()
        if onetime == "":
            onetime = random.getrandbits(len(plaintext))
            # print(bin(onetime)[2:].zfill(16))
        # if its valid but too short, loop it until its long enough
        # while(len(otype[1])<len(ptype[1])):
        #    onetime += onetime
        # Encoding time
        plainBits = ciphertext ^ onetime
        print(bin(plainBits)[2:].zfill(16))

        # output
        # if ptype[0] == "b":
        #     length = len(ptype[1])
        # else:
        #     length = len(ptype[1] * 4)
        length = len(ptype[1] * (1 if ptype[0] == "b" else 4))

        print(
            f"Plaintext in binary: {bin(plainBits)[2:].zfill(length)}"
            + f"One time pad in binary: {bin(onetime)[2:].zfill(length)}"
            + f"Plaintext in Hex: {hex(plainBits)[2:]}"
            + f"One time pad in hex: {hex(onetime)[2:]}"
        )

        # loop /exit
        digitalPad()


def OTPmain():
    print("A one time pad //DESC HERE//")
    choice = ""
    while not choice.lower() in ["t", "d", "e"]:
        choice = input("Text or digital? (t for text, d for digital e for exit")
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


OTPmain()
