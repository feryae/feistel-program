round = 16
block_size = 8

opts = input("")
decrypt = False
encrypt = False

if opts == "-d":
    decrypt = True
    filename = "ciphertext.txt"
    outfilename = "result.txt"

elif opts == "-e":
    encrypt = True
    filename = "plaintext.txt"
    outfilename = "ciphertext.txt"

def main():

    with open(filename, "r",encoding="utf-8") as f:
        input = f.read()
    message = input

    if (encrypt):
        key = 'password'
        ciphertext = ""
        n = 8
        message = [message[i: i + n] for i in range(0, len(message), n)]

        lengthOfLastBlock = len(message[len(message) - 1])

        if (lengthOfLastBlock < block_size)  :
            for i in range(lengthOfLastBlock, block_size):
                message[len(message) - 1] += " "
        key_initial = key
        for block in message:
            L = [""] * (round + 1)
            R = [""] * (round + 1)
            L[0] = block[0:4]
            R[0] = block[4:8]

            for i in range(1, round + 1):
                L[i] = R[i - 1]
                key = subkeygen(L[i], key_initial, i)
                R[i] = xor(L[i - 1], cipherfunction(R[i - 1], i, key))
            ciphertext += (L[round] + R[round])
        output = ciphertext

    elif (decrypt):
        key = 'password'
        ciphertext = input
        message = ""
        n = block_size
        ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]

        lengthOfLastBlock = len(ciphertext[len(ciphertext) - 1])

        if (lengthOfLastBlock < block_size):
            for i in range(lengthOfLastBlock, block_size):
                ciphertext[len(ciphertext) - 1] += " "

        key_initial = key
        for block in ciphertext:
            L = [""] * (round + 1)
            R = [""] * (round + 1)
            L[round] = block[0:4]
            R[round] = block[4:8]

            for i in range(8, 0, -1):
                R[i - 1] = L[i]
                key = subkeygen(L[i], key_initial, i)
                L[i - 1] = xor(R[i], cipherfunction(L[i], i, key))
            message += (L[0] + R[0])
        output = message

    with open(outfilename, 'w+', encoding="utf-8") as fw:
        fw.write(output)


def subkeygen(s1, s2,i):
    result = bintoint(stobin(s1+s2))
    if encrypt:
        result = result << i * 7
    elif decrypt:
        result = result >> i * 7
    text = bintostr(itobin(result))
    return text

def cipherfunction(x, i, k):
    k = stobin(k)
    x = stobin(str(x))

    k = bintoint(k)
    x = bintoint(x)

    res = pow((x * k), i)
    res = itobin(res)

    return bintostr(res)

def xor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def stobin(s):
    return ''.join('{:08b}'.format(ord(c)) for c in s)

def bintoint(s):
    return int(s, 2)

def itobin(i):
    return bin(i)


# binary to string
def bintostr(b):
    n = int(b, 2)
    return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))


if __name__ == "__main__":
    main()
