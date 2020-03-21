import sys
from collections import Counter
import re
import itertools

alphabet = "abcdefghijklmnopqrstuvwxyz"

def char2num(c):
    return ord(c)-97

def decrypt(ciphertext, key):
    words = ''
    for i in range(len(ciphertext)):
        modsub = (char2num(ciphertext[i]) - char2num(key[i%len(key)]))%26
        words += alphabet[modsub]
    print(words)

def vigenere(ciphertext, key_len, test_key):
  """
  Vigenere brute force function to be used in conjunction with key_len(s)
  recommended by kasiski.py

  If test_key is specified then a result will be printed, otherwise
  only the test keys will be printed
  """

  ciphertext = ''.join(filter(str.isalpha, ciphertext))
  ciphertext = ciphertext.lower()

  # separate ciphertext into bins for every nth char from 0-key_len
  bins = []
  for i in range(key_len):
      bins.append(ciphertext[i::key_len])

  # figure out what is most likely 'e' and use that to compute other characters
  potential_keys = []
  for line in bins:
      potential_key_chars=[]
      potential_e = Counter(line).most_common()
      for char in potential_e[0:3]:
          potential_key_char = alphabet[(char2num(char[0])-char2num('e'))%26]
          potential_key_chars.append(potential_key_char)
      potential_keys.append(potential_key_chars)

  for i in itertools.product(*potential_keys):
      key = ''.join(i)
      print("Trying key:", key)
      if key == test_key:
          decrypt(ciphertext, key)

def main():
    # Example: python vigenere.py text/ciphertext.txt 5 [key] (for testing)
    if len(sys.argv) < 3:
        print('Usage: python vignere.py file key_len [key]')
        exit()

    filename = sys.argv[1]
    file = open(filename,mode='r')
    ciphertext = file.read()
    file.close()

    key_len = int(sys.argv[2])

    if len(sys.argv) == 4:
        key = sys.argv[3]
    else:
        key = ""

    vigenere(ciphertext, key_len, key)

main()
