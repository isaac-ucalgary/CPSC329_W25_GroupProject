#One Time Pad functions
import random

lettercodes = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9"]

def textPad():
    optype = ""
    while not optype.lower() in ["q","d","e"]:
        optype = input("would you like to encode(e) or decode(d) or quit(q)")
    if optype =="e":
        temp = input("please enter the message you want to send")
        temp = temp.lower()
        plaintext = ""
        for char in temp:
            if(char in lettercodes):
                plaintext += char
        # message text is now trimmed to usable characters
        
        temp = input("please enter the one time pad you want to use, or leave this blank to generate one")
        onetime = ""
        for char in temp:
            if(char in lettercodes):
                onetime += char
        #If the one time pad is blank or invalid, generate one
        if onetime == "":
            for i in range(0,len(plaintext)):
                rand =random.randint(0,35)
                onetime += lettercodes[rand]
        # if its valid but too short, loop it until its long enough
        while(len(onetime)<len(plaintext)):
            onetime += onetime
        # Encoding time
        ciphertext = ""
        for i in range(0,len(plaintext)):
            mvalue = lettercodes.index(plaintext[i])
            pvalue = lettercodes.index(onetime[i])
            ciphertext +=lettercodes[(mvalue+pvalue)%36]

        #output
        print("ciphertext is:")
        print(ciphertext)
        print("one time pad is:")
        print(onetime)
        textPad()

    if optype =="d":
        temp = input("please enter the ciphertext")
        temp = temp.lower()
        ciphertext = ""
        for char in temp:
            if(char in lettercodes):
                ciphertext += char
        # message text is now trimmed to usable characters
        
        temp = input("please enter the one time pad you want to use: ")
        onetime = ""
        for char in temp:
            if(char in lettercodes):
                onetime += char
        # Decoding time
        plaintext = ""
        for i in range(0,len(ciphertext)):
            mvalue = lettercodes.index(ciphertext[i])
            pvalue = lettercodes.index(onetime[i])
            plaintext +=lettercodes[(mvalue-pvalue)%36]

        #output
        print("plaintext is:")
        print(plaintext)
        textPad()
def digitalEnter():
    temp = input("input as either binary or hexadecimal")
    unciphered = ""
    try:
        unciphered = int(temp, 2)
        return ["b",temp],unciphered
    except:
        try:
            unciphered = int(temp, 16)
            return ["h",temp],unciphered
        except:
            print("that is not valid binary or hex")
            temp=input("(e)to exit or enter to continue")
            if temp=="e":
                digitalPad()
            else:
                digitalEnter()
            
def digitalPad():
    optype = input("would you like to encode(e) or decode(d)? ")
    if optype =="e":
        print("Please enter the message")
        ptype, plaintext = digitalEnter()
        print("please enter the key to use or leave it  blank to generate one")
        otype, onetime = digitalEnter()
        if onetime == "":
            onetime = random.getrandbits(len(plaintext))
            print(bin(onetime)[2:].zfill(16))
 
        # Encoding time
        cipherBits = plaintext ^ onetime
        print(bin(cipherBits)[2:].zfill(16))

        #output
        if ptype[0]=="b":
            length = len(ptype[1])
        else:
            length = len(ptype[1]*4)
        
        print("ciphertext in binary: ")
        print(bin(cipherBits)[2:].zfill(length))
        print("one time pad in binary: ")
        print(bin(onetime)[2:].zfill(length))
        print("ciphertext in Hex: ")
        print(hex(cipherBits)[2:])                              
        print("one time pad in hex: ")
        print(hex(onetime)[2:])

        #loop /exit
        digitalPad()
    if optype =="d":
        print("Please enter the ciphertext")
        ptype, ciphertext = digitalEnter()
        print("please enter the key to use or leave it  blank to generate one")
        otype, onetime = digitalEnter()
        if onetime == "":
            onetime = random.getrandbits(len(plaintext))
            #print(bin(onetime)[2:].zfill(16))
        # if its valid but too short, loop it until its long enough
        #while(len(otype[1])<len(ptype[1])):
        #    onetime += onetime
        # Encoding time
        plainBits = ciphertext ^ onetime
        print(bin(plainBits)[2:].zfill(16))

        #output
        if ptype[0]=="b":
            length = len(ptype[1])
        else:
            length = len(ptype[1]*4)
        print("plaintext in binary: ")
        print(bin(plainBits)[2:].zfill(length))
        print("one time pad in binary: ")
        print(bin(onetime)[2:].zfill(length))
        print("plaintext in Hex: ")
        print(hex(plainBits)[2:])                              
        print("one time pad in hex: ")
        print(hex(onetime)[2:])


        #loop /exit
        digitalPad()

def OTPmain():
    print("a one time pad //DESC HERE//")
    choice = ""
    while not choice.lower() in ["t","d","e"]:
        choice = input("text or digital? (t for text, d for digital e for exit")
    if choice =="t":
        #descriptive paragraph only happens once, then go to the actual program
        print("This is the first iteration of a one-time pad //DESC HERE")
        textPad()
    elif choice == "d":
        #descriptive paragraph only happens once, then go to the actual program
        print("a digital one time pad is the modern version//DESC HERE")
        digitalPad()
    else:
        print("exiting")

OTPmain()
