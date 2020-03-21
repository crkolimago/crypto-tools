import sys
import itertools

def rail_fence_encrypt(plaintext, f):
    print('plaintext =',plaintext)
    ciphertext_letters=[]
    for i in range(f):
        while i < len(plaintext):
            ciphertext_letters.append(plaintext[i])
            i+=f
    ciphertext = ''.join(ciphertext_letters)
    print("ciphertext =", ciphertext)

def rail_fence_decrypt(ciphertext, f):
    """
    This function uses a similar mechanism to rail_fence_encrypt
    to simulate how the plaintext would be laid across the
    fence posts. It then swaps these axes to perform decryption.
    This works even when the ciphertext is not an even
    multiple of the fence post size.

    Note that text is assumed to be a string of a-z characters.
    """

    print("ciphertext =", ciphertext)

    plaintext_bins = []
    matrix = []
    for i in range(f):
        j = 0
        while i < len(ciphertext):
            i+=f
            j+=1
        plaintext_bins.append(j)

    plaintext_chars=[]
    position = 0
    for chunk in plaintext_bins:
        matrix.append(list(ciphertext[position:position+chunk]))
        position += chunk

    for row in itertools.zip_longest(*matrix):
        for char in row:
            if char != None:
                plaintext_chars.append(char)

    plaintext = ''.join(plaintext_chars)
    print('plaintext =',plaintext)

def main():
    # Example encrypt: python rail-fence.py e helloworld 5
    # Example decrypt: python rail-fence.py d hweolrllod 5
    if len(sys.argv) < 4:
        print('Usage: python rail-fence.py e|d text fences')
        exit()

    mode = sys.argv[1]
    text = sys.argv[2]
    fences = int(sys.argv[3])

    if mode == 'e':
        rail_fence_encrypt(text, fences)
    elif mode == 'd':
        rail_fence_decrypt(text, fences)

main()
