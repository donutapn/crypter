import time,hashlib,codecs,base64,os

time.sleep(0.3)
print('************************************')
time.sleep(0.3)
print('*                                  *')
time.sleep(0.3)
print('*   Welcome to crypter1.6          *')
time.sleep(0.3)
print('*   Create by Apinut Chompoonuch   *')
time.sleep(0.3)
print('*   Use "help" to see command      *')
time.sleep(0.3)
print('*                Be nice!          *')
time.sleep(0.3)
print('*                                  *')
time.sleep(0.3)
print('************************************')

def runbase91():
    runner = input("Do you want to install now(You must be root)[Y/n]\n>>")
    if runner in ['Y','y']:
        runmodule = os.popen('pip3 install base91').read()
        for i in range(10):
            print('.',end = '')
            time.sleep(0.3)
        print('')
        print('Please check the program again.')
        return
    elif runner in ['N','n']:
        return print('OK, you can run later.')
    else:
        runbase91()

def b26(uncipher):
    hex_string = ''
    for char in range(len(uncipher)):
        hex_char = str(hex(ord(uncipher[char]))).replace('0x','')
        hex_string += hex_char
    c = int(hex_string, 16)
    x = []
    while c >= 26:
        x.append(c%26)
        c = c//26
    x.append(c)
    cipher = ''
    for i in range(len(x)-1,-1,-1):
        cipher += chr(x[i]+65)
    return cipher

def de_b26(cipher):
    c = 0
    for i in range(len(str(cipher))-1,-1,-1):
        dec = int(ord(cipher[i])-65)*(26**(len(str(cipher))-i-1))
        c += dec
    hex_string = str(hex(c)).replace('0x','')
    uncipher = ''
    for hex_char in range(0,len(hex_string)-1,2):
        char = chr(int((hex_string[hex_char]+hex_string[hex_char+1]),16))
        uncipher += char
    return uncipher

username = ''
while True:
    inp = input('>>')
    key = str(inp).strip().lower()
    if key == 'help':
        print('***Use these key to command***\n')
        print('find       To find word in long text                 md5        To hash text to Md5')
        print('rev        To reverse text                           unhash     To decrypt Md5(32 digits)')
        print('rep        To find and replace the text              tobi       To encode text to Binary')
        print('rot13      To rotate character(a-z,A-Z) in text      frombi     To decode Binary from text')
        print('rot47      To rotate all character in text           todec      To encode text to Decimal')
        print('alp        To turn Alphabet to number                fromdec    To decode Deciaml from text')
        print('arb        To turn Arabic number to alphabet         tohex      To encode text to Hexadecimal')
        print('upc        To turn text to uppercase                 fromhex    To decode Hexadeciaml from text')
        print('lwc        To turn text to lowercase                 tob32      To encode text to Base32')
        print('sha224     To hash text to SHA224                    fromb32    To decode Base32 from text')
        print('unhash224  To decrypt SHA224(56 digits)              tob64      To encode text to Base64')
        print('sha256     To hash text to SHA256                    fromb64    To decode Base64 from text')
        print('unhash256  To decrypt SHA256(64 digits)              tob85      To encode text to Base85')
        print('sha384     To hash text to SHA384                    fromb85    To decode Base85 from text')
        print('unhash384  To decrypt SHA384(96 digits)              tob91      To encode text to Base91')
        print('sha512     To hash text to SHA512                    fromb91    To decode Base91 from text')
        print('unhash512  To decrypt SHA512(128 digits)             tomos      To encode text to Morse Code')
        print('xor        To XOR text with key                      frommos    To decode Morse Code from text')
        print('or         To OR text with key                       todna      To encode text to DNA')
        print('and        To AND text with key                      fromdna    To decode DNA from text')
        print('xorbf      To AND text with Brute Force key          bls        To Bitwise Left Shift')
        print('orbf       To AND text with Brute Force key          brs        To Bitwise Right Shift')
        print('andbf      To AND text with Brute Force key          tocs       To encode text to Caesar cipher')
        print('topp       To encode text to Phone Pad cipher        fromcs     To decode Caesar cipher from text')
        print('frompp     To decode Phone Pad cipher from text      tob26      To encode text to Base26(crypter)')
        print('                                                     fromb26    To decode Base26(crypter) from text')
        print('\nexit       To end this program')
    elif key == 'rep':
        text = input('Enter the text\n>>')
        fin = input('Enter word that you find\n>>')
        rep = input('Enter word that you replace\n>>')
        text = text.replace(fin,rep)
        print(text)
    elif key == 'md5':
        text = input('Enter the text to hash\n>>')
        hash_key = hashlib.md5(str(text).encode())
        key_checker = str(hash_key.hexdigest())
        print(key_checker)
    elif key == 'unhash':
        inp = input('Enter md5 to decrypt\n>>')
        inp = inp.strip()
        if len(inp) != 32:
            print('Error decrypt!!!\nPlease enter md5')
        else:
            breaker = False
            for i in range(1,100):
                if breaker == True:
                    break
                try:
                    wrdlst = open('wordlist\w'+str(i),'r')
                    for text in wrdlst:
                        hash_key = hashlib.md5(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.md5(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.md5(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                        text = text.upper()
                        hash_key = hashlib.md5(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.md5(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.md5(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                except FileNotFoundError as e:
                    print('Your unhashed text not in wordlist')
                    break
                except UnicodeDecodeError as e:
                    pass
    elif key == 'sha224':
        text = input('Enter the text to hash\n>>')
        hash_key = hashlib.sha224(str(text).encode())
        key_checker = str(hash_key.hexdigest())
        print(key_checker)
    elif key == 'unhash224':
        inp = input('Enter SHA224 to decrypt\n>>')
        inp = inp.strip()
        if len(inp) != 56:
            print('Error decrypt!!!\nPlease enter SHA224')
        else:
            breaker = False
            for i in range(1,100):
                if breaker == True:
                    break
                try:
                    wrdlst = open('wordlist\w'+str(i),'r')
                    for text in wrdlst:
                        hash_key = hashlib.sha224(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha224(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha224(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                        text = text.upper()
                        hash_key = hashlib.sha224(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha224(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha224(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                except FileNotFoundError as e:
                    print('Your unhashed text not in wordlist')
                    break
                except UnicodeDecodeError as e:
                    pass
    elif key == 'sha256':
        text = input('Enter the text to hash\n>>')
        hash_key = hashlib.sha256(str(text).encode())
        key_checker = str(hash_key.hexdigest())
        print(key_checker)
    elif key == 'unhash256':
        inp = input('Enter SHA256 to decrypt\n>>')
        inp = inp.strip()
        if len(inp) != 64:
            print('Error decrypt!!!\nPlease enter SHA256')
        else:
            breaker = False
            for i in range(1,100):
                if breaker == True:
                    break
                try:
                    wrdlst = open('wordlist\w'+str(i),'r')
                    for text in wrdlst:
                        hash_key = hashlib.sha256(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha256(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha256(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                        text = text.upper()
                        hash_key = hashlib.sha256(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha256(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha256(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                except FileNotFoundError as e:
                    print('Your unhashed text not in wordlist')
                    break
                except UnicodeDecodeError as e:
                    pass
    elif key == 'sha384':
        text = input('Enter the text to hash\n>>')
        hash_key = hashlib.sha384(str(text).encode())
        key_checker = str(hash_key.hexdigest())
        print(key_checker)
    elif key == 'unhash384':
        inp = input('Enter SHA384 to decrypt\n>>')
        inp = inp.strip()
        if len(inp) != 96:
            print('Error decrypt!!!\nPlease enter SHA384')
        else:
            breaker = False
            for i in range(1,100):
                if breaker == True:
                    break
                try:
                    wrdlst = open('wordlist\w'+str(i),'r')
                    for text in wrdlst:
                        hash_key = hashlib.sha384(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha384(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha384(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                        text = text.upper()
                        hash_key = hashlib.sha384(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha384(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha384(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                except FileNotFoundError as e:
                    print('Your unhashed text not in wordlist')
                    break
                except UnicodeDecodeError as e:
                    pass
    elif key == 'sha512':
        text = input('Enter the text to hash\n>>')
        hash_key = hashlib.sha512(str(text).encode())
        key_checker = str(hash_key.hexdigest())
        print(key_checker)
    elif key == 'unhash512':
        inp = input('Enter SHA512 to decrypt\n>>')
        inp = inp.strip()
        if len(inp) != 128:
            print('Error decrypt!!!\nPlease enter SHA512')
        else:
            breaker = False
            for i in range(1,100):
                if breaker == True:
                    break
                try:
                    wrdlst = open('wordlist\w'+str(i),'r')
                    for text in wrdlst:
                        hash_key = hashlib.sha512(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha512(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha512(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                        text = text.upper()
                        hash_key = hashlib.sha512(str(text).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            print('The text you find is : '+text,end = '')
                            breaker = True
                            break
                        hash_key = hashlib.sha512(str(key_checker).strip().encode())
                        key_checker = str(hash_key.hexdigest())
                        if key_checker == inp:
                            hash_key = hashlib.sha512(str(text).strip().encode())
                            key_checker = str(hash_key.hexdigest())
                            print('The text you find is : '+key_checker)
                            breaker = True
                            break
                except FileNotFoundError as e:
                    print('Your unhashed text not in wordlist')
                    break
                except UnicodeDecodeError as e:
                    pass
    elif key == 'tohex':
        text = input('Enter the text to encode\n>>')
        for char in text:
            byte_array = char.encode('utf-8')
            print(byte_array.hex(),end = '')
        print('')
    elif key == 'fromhex':
        text = input('Enter the Hex to decode\n>>')
        chk = 0
        char = ''
        lstoutp = []
        for i in range (len(text)):
            chk += 1
            char += text[i]
            if chk == 2:
                lstoutp.append(char)
                chk = 0
                char = ''
        try:
            for i in lstoutp:
                outp = bytes.fromhex(i).decode('utf-8')
                print(outp,end = '')
            print('')
        except UnicodeDecodeError as e:
            print('Cannot Decode!!!')
        except ValueError as e:
            print('Error decode!!!\nPlease enter Hexadecimal')
    elif key == 'todna':
        DNA = {'AAA':'a','AAC':'b','AAG':'c','AAT':'d','ACA':'e','ACC':'f', 'ACG':'g','ACT':'h','AGA':'i','AGC':'j','AGG':'k','AGT':'l','ATA':'m','ATC':'n','ATG':'o','ATT':'p','CAA':'q','CAC':'r','CAG':'s','CAT':'t','CCA':'u','CCC':'v','CCG':'w','CCT':'x','CGA':'y','CGC':'z','CGG':'A','CGT':'B','CTA':'C','CTC':'D','CTG':'E','CTT':'F','GAA':'G','GAC':'H','GAG':'I','GAT':'J','GCA':'K','GCC':'L','GCG':'M','GCT':'N','GGA':'O','GGC':'P','GGG':'Q','GGT':'R','GTA':'S','GTC':'T','GTG':'U','GTT':'V','TAA':'W','TAC':'X','TAG':'Y','TAT':'Z','TCA':'1','TCC':'2','TCG':'3','TCT':'4','TGA':'5','TGC':'6','TGG':'7','TGT':'8','TTA':'9','TTC':'0','TTG':' ','TTT':'.'}
        able2encode = []
        for item in DNA:
            able2encode.append(DNA[item])
        text = input('Enter the text to encode\n>>')
        for char in text:
            if char in able2encode:
                for item in DNA:
                    if char == DNA[item]:
                        print(item,end='')
            else:
                print(char,end='')
        print('')
    elif key == 'fromdna':
        DNA = {'AAA':'a','AAC':'b','AAG':'c','AAT':'d','ACA':'e','ACC':'f', 'ACG':'g','ACT':'h','AGA':'i','AGC':'j','AGG':'k','AGT':'l','ATA':'m','ATC':'n','ATG':'o','ATT':'p','CAA':'q','CAC':'r','CAG':'s','CAT':'t','CCA':'u','CCC':'v','CCG':'w','CCT':'x','CGA':'y','CGC':'z','CGG':'A','CGT':'B','CTA':'C','CTC':'D','CTG':'E','CTT':'F','GAA':'G','GAC':'H','GAG':'I','GAT':'J','GCA':'K','GCC':'L','GCG':'M','GCT':'N','GGA':'O','GGC':'P','GGG':'Q','GGT':'R','GTA':'S','GTC':'T','GTG':'U','GTT':'V','TAA':'W','TAC':'X','TAG':'Y','TAT':'Z','TCA':'1','TCC':'2','TCG':'3','TCT':'4','TGA':'5','TGC':'6','TGG':'7','TGT':'8','TTA':'9','TTC':'0','TTG':' ','TTT':'.'}
        text = input('Enter the text to encode\n>>')
        long = len(str(text).strip())
        text = text.upper().strip()
        new_text = []
        try:
            for i in range(0,len(text),3):
                dna = text[i:i+3]
                new_text.append(DNA[dna])
            for outp in new_text:
                print(outp,end = '')
            print('')
        except KeyError as e:
            print('Error decode!!!\nPlease enter only DNA')
    elif key == 'tobi':
        text = input('Enter the text to encode\n>>')
        for char in text:
            byte_array = char.encode()
            bi_int = int.from_bytes(byte_array,'big')
            bi_str = bin(bi_int)
            print((bi_str[0]+bi_str[2:]),end = ' ')
        print('')
    elif key == 'frombi':
        text = input('Enter the Binary to decode\n>>')
        word = text.split(' ')
        try:
            for i in word:
                bi_int = int(i,2)
                byte_num = bi_int.bit_length() + 7//8
                bi_array = bi_int.to_bytes(byte_num,'big')
                outp = bi_array.decode()
                print(outp[-1],end = '')
        except ValueError as e:
            print('Error decode!!!\nPlease enter Binary',end = '')
        print('')
    elif key == 'tob64':
        text = input('Enter the text to encode\n>>')
        hash_key = base64.b64encode(str(text).encode('utf-8'))
        key_checker = str(hash_key,'utf-8')
        print(key_checker)
    elif key == 'fromb64':
        text = input('Enter the Base64 to decode\n>>')
        try:
            hash_key = base64.b64decode(text.encode('ascii'))
            key_checker = str(hash_key,'ascii')
            print(key_checker)
        except NameError as e:
            print('Error decode!!!\nPlease enter Base64')
        except UnicodeDecodeError as e:
            print('Error decode!!!\nPlease enter Base64')
        except base64.binascii.Error as e:
            print('Error decode!!!\nPlease enter Base64')
    elif key == 'tob32':
        text = input('Enter the text to encode\n>>')
        hash_key = base64.b32encode(str(text).encode('utf-8'))
        key_checker = str(hash_key,'utf-8')
        print(key_checker)
    elif key == 'fromb32':
        text = input('Enter the Base32 to decode\n>>')
        try:
            hash_key = base64.b32decode(text.encode('ascii'))
            key_checker = str(hash_key,'ascii')
            print(key_checker)
        except NameError as e:
            print('Error decode!!!\nPlease enter Base32')
        except UnicodeDecodeError as e:
            print('Error decode!!!\nPlease enter Base32')
        except base64.binascii.Error as e:
            print('Error decode!!!\nPlease enter Base32')
    elif key == 'tob85':
        text = input('Enter the text to encode\n>>')
        hash_key = base64.b85encode(str(text).encode('utf-8'))
        key_checker = str(hash_key,'utf-8')
        print(key_checker)
    elif key == 'fromb85':
        text = input('Enter the Base85 to decode\n>>')
        try:
            hash_key = base64.b85decode(text.encode('ascii'))
            key_checker = str(hash_key,'ascii')
            print(key_checker)
        except NameError as e:
            print('Error decode!!!\nPlease enter Base85')
        except UnicodeDecodeError as e:
            print('Error decode!!!\nPlease enter Base85')
        except base64.binascii.Error as e:
            print('Error decode!!!\nPlease enter Base85')
    elif key == 'todec':
        text = input('Enter the text to Decimal\n>>')
        outp = ''
        for i in text:
            dec_i = ord(i)
            x = (str(dec_i) + ',')
            outp = outp+x
        print(outp[0:-1])
    elif key == 'fromdec':
        text = input('Enter the Decimal to word(seperate by ",")\n>>')
        word = text.split(',')
        try:
            for i in word:
                i = int(i)
                print(chr(i),end = '')
        except ValueError as e:
            print('Error decode!!!\nPlease enter Decimal',end = '')
        print('')
    elif key == 'rev':
        text = input('Enter the text to reverse\n>>')
        text_rev = ''
        i = (len(text) - 1)
        while i >= 0:
            text_rev = text_rev + text[i]
            i-=1
        print(text_rev)
    elif key == 'tob91':
        text = input('Enter the text to encode\n>>')
        try:
            import base91
            print(base91.encode(text.encode()))
        except ModuleNotFoundError as e:
            print("You haven't base91 module.\nPlease run as root")
            runbase91()
    elif key == 'fromb91':
        text = input('Enter the Base91 to decode\n>>')
        try:
            import base91
            outp = (base91.decode(text))
            outp = str(outp)
            outp = outp[12:]
            outp = outp[:-2]
            if outp == '':
                print('Error decode!!!\nPlease enter Base91')
            else:
                print(outp)
        except ModuleNotFoundError as e:
            print("You haven't base91 module.\nPlease run as root")
            runbase91()
    elif key == 'rot47':
        text = input('Enter the text to rotate\n>>')
        rot = input('Enter amout of rotation or "all" to see all rotation\n>>')
        chrlst = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','[','\\',']','^','_','`','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','{','|','}','~','!','"','#','$','%','&',"'",'(',')','*','+',',','-','.','/','0','1','2','3','4','5','6','7','8','9',':',';','<','=','>','?','@']
        if rot == 'all':
            for rot in range(len(chrlst)):
                new_text = ''
                for i in range (len(text)):
                    for j in range (len(chrlst)):
                        while (j + rot) >= len(chrlst):
                            rot = rot - len(chrlst)
                        if text[i] == chrlst[j]:
                            new_text = new_text + chrlst[j+rot]
                    if text[i] not in chrlst:
                        new_text = new_text + text[i]
                print(new_text)
        else:
            try:
                rot = int(rot)
                new_text = ''
                for i in range (len(text)):
                    for j in range (len(chrlst)):
                        while (j + rot) >= len(chrlst):
                            rot = rot - len(chrlst)
                        if text[i] == chrlst[j]:
                            new_text = new_text + chrlst[j+rot]
                    if text[i] not in chrlst:
                        new_text = new_text + text[i]
                print(new_text)
            except ValueError as e:
                print('Error rotate!!!\nPlease enter number for amount')
    elif key == 'rot13':
        text = input('Enter the text to rotate\n>>')
        rot = input('Enter amout of rotation or "all" to see all rotation\n>>')
        x = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
        X = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
        if rot == 'all':
            for rot in range(26):
                new_text = ''
                for i in range (len(text)):
                    for j in range (len(x)):
                        while (j + rot) >= 26:
                            rot = rot - 26
                        if text[i] == x[j]:
                            new_text = new_text + x[j+rot]
                    for k in range (len(X)):
                        while (k + rot) >= 26:
                            rot = rot - 26
                        if text[i] == X[k]:
                            new_text = new_text + X[k+rot]
                    if text[i] not in x:
                        if text[i] not in X:
                            new_text = new_text + text[i]
                print(new_text)
        else:
            try:
                rot = int(rot)
                new_text = ''
                for i in range (len(text)):
                    for j in range (len(x)):
                        while (j + rot) >= 26:
                            rot = rot - 26
                        if text[i] == x[j]:
                            new_text = new_text + x[j+rot]
                    for k in range (len(X)):
                        while (k + rot) >= 26:
                            rot = rot - 26
                        if text[i] == X[k]:
                            new_text = new_text + X[k+rot]
                    if text[i] not in x:
                        if text[i] not in X:
                            new_text = new_text + text[i]
                print(new_text)
            except ValueError as e:
                print('Error rotate!!!\nPlease enter number for amount')
    elif key == 'xor':
        text = input('Enter the text to XOR\n>>')
        key = input('Enter the Key\n>>')
        text = text.encode()
        key = key.encode()
        s = b''
        for i in range(len(text)):
            s += bytes([text[i] ^ key[i%len(key)]])
        hex_str = str(codecs.encode(s,"hex").decode())
        chk = 0
        hex_char = ''
        hex_outp = []
        print('hex  : ' + hex_str)
        for i in range (len(hex_str)):
            chk += 1
            hex_char += hex_str[i]
            if chk == 2:
                hex_outp.append(hex_char)
                chk = 0
                hex_char = ''
        print('utf8 : ',end = '')
        try:
            for i in hex_outp:
                outp = bytes.fromhex(i).decode('utf-8')
                print(outp,end = '')
            print('')
        except UnicodeDecodeError as e:
            print('Cannot Decode')
    elif key == 'or':
        text = input('Enter the text to OR\n>>')
        key = input('Enter the Key\n>>')
        text = text.encode()
        key = key.encode()
        s = b''
        for i in range(len(text)):
            s += bytes([text[i] | key[i%len(key)]])
        hex_str = str(codecs.encode(s,"hex").decode())
        chk = 0
        hex_char = ''
        hex_outp = []
        print('hex  : ' + hex_str)
        for i in range (len(hex_str)):
            chk += 1
            hex_char += hex_str[i]
            if chk == 2:
                hex_outp.append(hex_char)
                chk = 0
                hex_char = ''
        print('utf8 : ',end = '')
        try:
            for i in hex_outp:
                outp = bytes.fromhex(i).decode('utf-8')
                print(outp,end = '')
            print('')
        except UnicodeDecodeError as e:
            print('Cannot Decode')
    elif key == 'and':
        text = input('Enter the text to AND\n>>')
        key = input('Enter the Key\n>>')
        text = text.encode()
        key = key.encode()
        s = b''
        for i in range(len(text)):
            s += bytes([text[i] & key[i%len(key)]])
        hex_str = str(codecs.encode(s,"hex").decode())
        chk = 0
        hex_char = ''
        hex_outp = []
        print('hex  : ' + hex_str)
        for i in range (len(hex_str)):
            chk += 1
            hex_char += hex_str[i]
            if chk == 2:
                hex_outp.append(hex_char)
                chk = 0
                hex_char = ''
        print('utf8 : ',end = '')
        try:
            for i in hex_outp:
                outp = bytes.fromhex(i).decode('utf-8')
                print(outp,end = '')
            print('')
        except UnicodeDecodeError as e:
            print('Cannot Decode')
    elif key == 'bls':
        text = input('Enter the text to Bitwise Left Shift\n>>')
        key = input('Enter the amount to Bitwise\n>>')
        try:
            key = int(key)
            text = text.encode()
            s = b''
            for i in range(len(text)):
                s += bytes([text[i]<<key])
            hex_str = str(codecs.encode(s,"hex").decode())
            chk = 0
            hex_char = ''
            hex_outp = []
            print('hex  : ' + hex_str)
            for i in range (len(hex_str)):
                chk += 1
                hex_char += hex_str[i]
                if chk == 2:
                    hex_outp.append(hex_char)
                    chk = 0
                    hex_char = ''
            print('utf8 : ',end = '')
            try:
                for i in hex_outp:
                    outp = bytes.fromhex(i).decode('utf-8')
                    print(outp,end = '')
                print('')
            except UnicodeDecodeError as e:
                print('Cannot Decode')
        except ValueError as e:
            print('Error Bitwise!!!\nPlease enter number for amount')
    elif key == 'brs':
        text = input('Enter the text to Bitwise Right Shift\n>>')
        key = input('Enter the amount\n>>')
        try:
            key = int(key)
            text = text.encode()
            s = b''
            for i in range(len(text)):
                s += bytes([text[i]>>key])
            hex_str = str(codecs.encode(s,"hex").decode())
            chk = 0
            hex_char = ''
            hex_outp = []
            print('hex  : ' + hex_str)
            for i in range (len(hex_str)):
                chk += 1
                hex_char += hex_str[i]
                if chk == 2:
                    hex_outp.append(hex_char)
                    chk = 0
                    hex_char = ''
            print('utf8 : ',end = '')
            try:
                for i in hex_outp:
                    outp = bytes.fromhex(i).decode('utf-8')
                    print(outp,end = '')
                print('')
            except UnicodeDecodeError as e:
                print('Cannot Decode')
        except ValueError as e:
            print('Error Bitwise!!!\nPlease enter number for amount')
    elif key == 'xorbf':
        text = input('Enter the text to XOR\n>>')
        item_lst = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
        key_char = ['','']
        key_list = []
        for a in (item_lst):
            key_char[0] = a
            for b in (item_lst):
                key_char[1] = b
                new_text = key_char[0] + key_char[1]
                key_list.append(new_text)
        text = text.encode()
        for raw_key in key_list:
            key = raw_key.encode()
            s = b''
            for i in range(len(text)):
                s += bytes([text[i] ^ key[i%len(key)]])
            hex_str = str(codecs.encode(s,"hex").decode())
            chk = 0
            hex_char = ''
            hex_outp = []
            for i in range (len(hex_str)):
                chk += 1
                hex_char += hex_str[i]
                if chk == 2:
                    hex_outp.append(hex_char)
                    chk = 0
                    hex_char = ''
            print('key '+raw_key + ' : ',end = '')
            try:
                for i in hex_outp:
                    outp = bytes.fromhex(i).decode('utf-8')
                    print(outp,end = '')
                print('')
            except UnicodeDecodeError as e:
                print('Cannot Decode')
    elif key == 'orbf':
        text = input('Enter the text to OR\n>>')
        item_lst = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
        key_char = ['','']
        key_list = []
        for a in (item_lst):
            key_char[0] = a
            for b in (item_lst):
                key_char[1] = b
                new_text = key_char[0] + key_char[1]
                key_list.append(new_text)
        text = text.encode()
        for raw_key in key_list:
            key = raw_key.encode()
            s = b''
            for i in range(len(text)):
                s += bytes([text[i] | key[i%len(key)]])
            hex_str = str(codecs.encode(s,"hex").decode())
            chk = 0
            hex_char = ''
            hex_outp = []
            for i in range (len(hex_str)):
                chk += 1
                hex_char += hex_str[i]
                if chk == 2:
                    hex_outp.append(hex_char)
                    chk = 0
                    hex_char = ''
            print('key '+raw_key + ' : ',end = '')
            try:
                for i in hex_outp:
                    outp = bytes.fromhex(i).decode('utf-8')
                    print(outp,end = '')
                print('')
            except UnicodeDecodeError as e:
                print('Cannot Decode')
    elif key == 'andbf':
        text = input('Enter the text to AND\n>>')
        item_lst = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
        key_char = ['','']
        key_list = []
        for a in (item_lst):
            key_char[0] = a
            for b in (item_lst):
                key_char[1] = b
                new_text = key_char[0] + key_char[1]
                key_list.append(new_text)
        text = text.encode()
        for raw_key in key_list:
            key = raw_key.encode()
            s = b''
            for i in range(len(text)):
                s += bytes([text[i] & key[i%len(key)]])
            hex_str = str(codecs.encode(s,"hex").decode())
            chk = 0
            hex_char = ''
            hex_outp = []
            for i in range (len(hex_str)):
                chk += 1
                hex_char += hex_str[i]
                if chk == 2:
                    hex_outp.append(hex_char)
                    chk = 0
                    hex_char = ''
            print('key '+raw_key + ' : ',end = '')
            try:
                for i in hex_outp:
                    outp = bytes.fromhex(i).decode('utf-8')
                    print(outp,end = '')
                print('')
            except UnicodeDecodeError as e:
                print('Cannot Decode')
    elif key == 'alp':
        text = input('Enter the Alphabet to number\n>>')
        text = text.lower()
        text = text.replace('','-')
        for char in text:
            if char in ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']:
                rep = str(ord(char)-96)
                text = text.replace(char,rep.zfill(2))
        print(text[1:-1])
    elif key == 'arb':
        text = input('Enter the Arabic number to Alphabet(seperate by "-")\n>>')
        word = text.split('-')
        for char in word:
            try:
                if char in ['01','02','03','04','05','06','07','08','09']:
                    ord_char = int(char[1])+96
                    text = text.replace(char,chr(ord_char))
                elif int(char) in range (10,27):
                    ord_char = int(char)+96
                    text = text.replace(char,chr(ord_char))
            except ValueError as e:
                pass
        text = text.replace('-','')
        print(text)
    elif key == 'upc':
        text = input('Enter the text to uppercase\n>>')
        print(text.upper())
    elif key == 'lwc':
        text = input('Enter the text to lowercase\n>>')
        print(text.lower())
    elif key == 'find':
        print('Enter the long text(key "end" when finish)\n>>',end = '')
        lines = {}
        position = 0
        while True:
            text = input()
            if text == 'end':
                break
            else:
                position = position + 1
                seq = str(position)
                lines[text] = (seq)
        wrdlst = []
        word = input('Enter the word you find\n>>')
        for wrd in lines:
            sin_wrd = wrd.split(' ')
            for i in sin_wrd:
                if word in i:
                    print(('line ' + lines[wrd]),end = '')
                    print('\t\t',i)
        for i in range(5):
            print('.',end = '')
            time.sleep(0.2)
        print('\nFinish finding')
    elif key == 'tomos':
        text = input('Enter the text to encode\n>>')
        text = text.upper()
        morse = { 'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--','4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.', '0':'-----', ', ':'--..--', '.':'.-.-.-', '?':'..--..', '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-'}
        lst = []
        for x in morse:
            lst.append(x)
        for i in range (len(text)):
            char = text[i]
            if char in lst:
                print(morse[char],end = ' ')
            else:
                print(char,end = ' ')
        print('')
    elif key == 'frommos':
        text = input('Enter the Morse Code to decode\n>>')
        morse = { 'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--','4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.', '0':'-----', ', ':'--..--', '.':'.-.-.-', '?':'..--..', '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-'}
        word = text.split(' ')
        for x in word:
            if x in morse.values():
                for char in morse:
                    if x == morse[char]:
                        print(char,end = '')
            else:
                print(x,end = '')
        print('')
    elif key == 'tocs':
        text = input('Enter the text to encode\n>>')
        key = input('Enter amount to shift\n>>')
        try:
            key = int(key)
            outp = ''
            for ch in text:
                outp += chr((ord(ch) - 97 + key)%26 + 97)
            print(outp)
        except ValueError as e:
            print('Error Shifting!!!\nPlease enter number for amount')
    elif key == 'fromcs':
        text = input('Enter the Caesar cipher text to decode\n>>')
        key = input('Enter amount of shifting\n>>')
        try:
            key = int(key)
            outp = ''
            for ch in text:
                outp += chr((ord(ch) - 97 - key)%26 + 97)
            print(outp)
        except ValueError as e:
            print('Error Shifting!!!\nPlease enter number for amount')
    elif key == 'topp':
        text = input('Enter the text to encode\n>>')
        pad = {'2':'abc','3':'def','4':'ghi','5':'jkl','6':'mno','7':'pqrs','8':'tuv','9':'wxyx','0':' '}
        text = text.replace('','-')[1:-1].lower()
        char = text.split('-')
        for ch in char:
            for key in pad:
                if pad[key].find(ch) >= 0:
                    text = text.replace(ch,(key*(pad[key].find(ch)+1)))
        print(text)
    elif key == 'frompp':
        text = input('Enter the Phone Pad cipher to decode(seperate by "-")\n>>')
        pad = {'2':'abc','3':'def','4':'ghi','5':'jkl','6':'mno','7':'pqrs','8':'tuv','9':'wxyx','0':' '}
        try:
            char = text.split('-')
            for ch in char:
                key = ch[0]
                value = (ch.count(key)%len(pad[key]))-1
                print(pad[key][value],end='')
            print('')
        except IndexError as e:
            print('Error decode!!!\nPlease enter Phone Pad')
        except KeyError as e:
            print('Error decode!!!\nPlease enter Phone Pad')
    elif key in ['close','quit','exit']:
        print('closing',end = '')
        time.sleep(0.3)
        for i in range(3):
            time.sleep(0.3)
            print('.',end = '')
        break
    elif key == 'tob26':
        uncipher = input('Enter the text to encode\n>>')
        print(b26(uncipher))
    elif key == 'fromb26':
        cipher = input('Enter the Base26 cipher text to decode\n>>')
        try:
            print(de_b26(cipher))
        except ValueError as e:
            print('Error decode!!!\nPlease enter R0 cipher text')
    elif key == 'name':
        username = input('What is your name?\n>>')
        print('Now your name is',username+'.')
    elif key == 'hello':
        if username == '':
            username = input('Hello!!!\nWhat is your name?\n>>')
            print('Nice to meet you,',username)
        else:
            print('Hello,',username)
    elif key == 'hi':
        if username == '':
            username = input('Hi!!!\nWhat is your name?\n>>')
            print('Nice to meet you,',username)
        else:
            print('Hi,',username)
    elif key in ['donut','apinut']:
        print("The Crypter's creator.")
    elif key in ['kerd','surachan','kerdkerd']:
        print('I know you know him.')
    elif key in ['fuse','pattanasak','few']:
        print('Handsome boy from north-east side.')
    elif key in ['krit','ukrit','kritkk']:
        print('I want to have muscle like him.')
    elif 'flag' in key:
        print('I am not Capture The Flag program.\nKey "help" to see command')
    elif 'fuck' in key:
        print('Language!!!\nPlease be polite.')
    elif 'shit' in key:
        print('Language!!!\nPlease be polite.')
    elif key == '':
        print('Please key anything.')
    else:
        print('no command "'+ inp +'"\nTry to use "help" to see command')
