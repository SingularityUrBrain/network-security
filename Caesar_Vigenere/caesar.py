import array
import sys
import re
import os


def encode(f, output, shift):
    # check if encrypted file already exists
    if os.path.isfile(output):
        os.remove(output)
    offset = ord('a')
    with open(f, 'r') as f, open(output, 'a') as encf:
        for s in f:
            s = s.lower()
            s = re.sub(r'[^a-z\d]', '', s)   # remove all symbols except alphas, digits
            s = array.array('u', s)
            for i in range(len(s)):
                if str.isalpha(s[i]):
                    s[i] = chr((ord(s[i]) - offset + shift)%26 + offset)
            s = s.tounicode()
            encf.write(s)

def decode(f, output, shift):   
    # just change sign to decode encrypted file
    encode(f, output, -shift)

def print_result(f, encf, decf):
    for file, tag in [(f, 'text'), (encf, 'encrypted'), (decf, 'decrypted')]:
        print(f'{tag}:', end='\n  ')
        with open(file, 'r') as rfile:
            for s in rfile:
                print(s)

def main():
    fpath = 'text.txt' if len(sys.argv[0]) < 2 else sys.argv[1]
    enc_fpath = 'encrypted_caesar.txt'
    dec_fpath = 'decrypted_caesar.txt'
    key = int(input('key(shift): '))

    encode(fpath, enc_fpath, key)
    decode(enc_fpath, dec_fpath, key)
    print_result(fpath, enc_fpath, dec_fpath)

if __name__ == "__main__":
    main()
