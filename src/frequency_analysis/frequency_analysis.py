# performs frequency analysis on the string passed to it.
# we can wrap this with file i/o and other options later, if needed.
# But, we can just call it with a string the user puts in a textbox on the web frontend
# This will return ???
def analyse_freq(string: str):
    out: str = ""
    frequencies: dict[str, int] = {}
    # Add and increment a letter in the dictionary. Will work for any recognized letter
    for s in string:
        if s in frequencies:
            frequencies[s] += 1
        else:
            frequencies.update({s: 1})
    # Format dict into a string we can return to the website.
    for f in frequencies:
        out += f"{f} : {frequencies[f]}\n"
    return out


# Test function.
# analyse_freq(input("Enter the string to frequency analyse: "))
