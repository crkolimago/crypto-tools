import sys
import re
from functools import reduce
import operator

def factors(n):
    return set(reduce(list.__add__,
                ([i, n//i] for i in range(1, int(n**0.5) + 1) if n % i == 0)))

def kasiski(ciphertext):
    """
    Usage may vary, preprocessing performed.

    Note: assumes key length is greater than 3 because that would be an easy
    brute force; also assumes key length is less than 8 because that would
    be a hard brute force (although I have not verified this)
    """

    regex = re.compile('[\W_]+', re.UNICODE)
    ciphertext = regex.sub('',ciphertext)

    fd = {}
    clen = len(ciphertext)

    # find indeces of substrings of length > 2
    for cint in range(clen):
        if cint+3 <= clen:
            s = ciphertext[cint:cint+3]
            f = fd.get(s)
            if f == None:
                fd[s] = [cint]
            else:
                fd[s].append(cint)

    # multiple occurances
    r = [(f, fd[f]) for f in fd if len(fd[f]) > 1]

    # find all factors of all previous numbers
    d = {}
    for f in fd:
        l = fd[f]
        e = len(l)
        if e > 1:
            # print(f, l, end=' ')
            while e > 1:
                i1 = l[e-1]
                i2 = l[e-2]
                s = i1-i2
                # print("{0}-{1}={2}".format(i1, i2, s), end = ', ')
                for fa in factors(s):
                    if fa != 1:
                        n = d.get(fa)
                        if n == None:
                            d[fa] = 1
                        else:
                            d[fa] = n + 1
                e-=1
            # print()

    # take the most common ones
    mcf = [i[0] for i in sorted(d.items(), key=operator.itemgetter(1), reverse=True)[0:10]]

    print("Key length could be:")
    # filter out 2 and 3 because it can't be that easy
    for item in mcf:
        if item > 3 and item < 8:
            print(item)

def main():
    # Example: python kasiski.py text/ciphertext.txt
    if len(sys.argv) < 2:
        print('Usage: python kasiski.py file')
        exit()

    filename = sys.argv[1]
    file = open(filename,mode='r')
    ciphertext = file.read()
    file.close()

    kasiski(ciphertext)

main()
