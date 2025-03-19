# performs frequency analysis the string passed to it. we can wrap this with file i/o and other options later, if needed.
# But, we can just call it with a string the user puts in a textbox on the web frontend
# This will return ???
def analyse_freq(string):
    frequencies = {}
    # Add and increment a letter in the dictionary. Will work for any recognized letter
    for s in string:
        if s in frequencies:
            frequencies[s] += 1
        else: 
            frequencies.update({s : 1})
    for f in frequencies:
        print(f"{f} : {frequencies[f]}")


analyse_freq("The quick brown fox jumps over the lazy dog.")