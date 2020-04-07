import array
import re
import os
import sys


def encode(f, output, keyword, decode=False):
    # check if encrypted file already exist
    if os.path.isfile(output):
        os.remove(output)
    offset = ord('a')
    keyword = keyword.lower()
    k = -1 if decode else 1
    with open(f, 'r') as f, open(output, 'a') as encf:
        for s in f:
            s = s.lower()
            s = re.sub('[^a-z\d]', '', s)  # remove all symbols except alphas, digits
            s = array.array('u', s)
            for i in range(len(s)):
                if str.isalpha(s[i]):
                    # define alphabet
                    shift = ord(keyword[i%len(keyword)]) - offset
                    s[i] = chr((ord(s[i]) - offset + k*shift)%26 + offset)
            s = s.tounicode()
            encf.write(s)

def decode(f, output, keyword):
    # just change sign to decode encrypted file
    encode(f, output, keyword, True)

def print_result(f, encf, decf):
    for file, tag in [(f, 'text'), (encf, 'encrypted'), (decf, 'decrypted')]:
        print(f'{tag}:', end='\n  ')
        with open(file, 'r') as rfile:
            for s in rfile:
                print(s)

def main():
    fpath = 'text2.txt' if len(sys.argv[0]) < 2 else sys.argv[1]
    enc_fpath = 'encrypted_vigenere.txt'
    dec_fpath = 'decrypted_vigenere.txt'
    key = input('keyword: ')

    encode(fpath, enc_fpath, key)
    decode(enc_fpath, dec_fpath, key)
    print_result(fpath, enc_fpath, dec_fpath)

if __name__ == "__main__":
    main()
