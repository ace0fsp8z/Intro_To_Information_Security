#!/usr/bin/python
import binascii
import sys
import time
from des import *

def bintohex(s):
    t = ''.join(chr(int(s[i:i+8], 2)) for i in xrange(0, len(s), 8))
    return binascii.hexlify(t).upper()

def test():
    key1 = b"\0\0\0\0\0\0\0\0"
    key2 = b"\0\0\0\0\0\0\0\2"
    message1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    message2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
    test_des(key1, message1)
    test_des(key1, message2)
    test_des(key2, message1)
    test_des(key2, message2)

def test_des(key, message):
    k = des(key)
    c = k.des_encrypt(message)
    print bintohex("".join([str(e) for e in c]))

def cbc_encrypt(message, key, iv):
    """
    Args:
      message: string, bytes, cannot be unicode
      key: string, bytes, cannot be unicode
    Returns:
      ciphertext: string
    """
    # TODO: Add your code here.
    #test()
    
    #message = open('plaintext_2', 'r').read()
    #key = open('key', 'r').read()
    #iv = open('iv', 'r').read()

    #key_binary = binascii.unhexlify(key)
    key_text = binascii.unhexlify(key)
    iv_text = binascii.unhexlify(iv)

    key_binary = bin(int(binascii.hexlify(key_text), 16))
    iv_binary = bin(int(binascii.hexlify(iv_text), 16))
    message_binary = bin(int(binascii.hexlify(message), 16))

    # Remove 'b' character denoting a binary string in Python
    # Not necessary for key: key_binary = key_binary[0] + '0' + key_binary[2:]

    iv_binary = iv_binary[0] + iv_binary[2:]
    
    if len(message_binary) % 64 == 0:
        # No padding necessary
        pass
    else:
        pad_len = 64 - (len(message_binary) % 64)
        if pad_len == 1:
            message_binary += '1'
        else:
            message_binary += '1'
            while (64 - (len(message_binary) % 64)) < 64:
                message_binary += '0'
    
    # Get rid of that annoying 'b' and add a trailing zero to the padding to prepare for round 1 des encryption
    message_binary = message_binary[0] + message_binary[2:] + '0'

    # Seperate into 64 bit blocks
    plainblock_list = [message_binary[0+i:64+i] for i in range(0, len(message_binary), 64)]

    # First xor
    iv_plainblock1_xor = '{0:0{1}b}'.format(int(plainblock_list[0], 2) ^ int(iv_binary, 2), len(plainblock_list[0]))
    iv_plainblock1_xor = list(iv_plainblock1_xor)
    iv_plainblock1_xor = [int(x) for x in iv_plainblock1_xor]

    
    # First ciphertext block encryption
    k = des(key_text)
    ciphertext = k.des_encrypt(iv_plainblock1_xor)
    ciphertext_binary_list = [''.join(str(x) for x in ciphertext)]
    ciphertext_list = [ciphertext]

    # Begin chaining
    for i in range(1, len(plainblock_list)):

        plainblock_cipherblock_xor = '{0:0{1}b}'.format(int(plainblock_list[i], 2) ^ int(ciphertext_binary_list[i-1], 2), len(plainblock_list[i]))
        plainblock_cipherblock_xor = list(plainblock_cipherblock_xor)
        plainblock_cipherblock_xor = [int(x) for x in plainblock_cipherblock_xor]
        
        ciphertext = k.des_encrypt(plainblock_cipherblock_xor)
        ciphertext_binary_list.append(''.join(str(x) for x in ciphertext))
        ciphertext_list.append(ciphertext)
        

    # Concatenate ciphertext blocks
    concat_ciphertext_binary = ''.join(str(x) for y in ciphertext_list for x in y)
    #open('test3', 'w').write(bits2bytes(concat_ciphertext_binary))

    return bits2bytes(concat_ciphertext_binary)
    

def bits2bytes(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def cbc_decrypt(message, key, iv):
    """
    Args:
      message: string, bytes, cannot be unicode
      key: string, bytes, cannot be unicode
    Returns:
      plaintext: string
    """
    # TODO: Add your code here.
    # test()
    #message = open('ciphertext_2', 'r').read()
    #key = open('key', 'r').read()
    #v = open('iv', 'r').read()

    # Convert ciphertext to bit string
    message_binary = bytes2bits(message)

    # Convert key and iv to ASCII from hex
    key_text = binascii.unhexlify(key)
    iv_text = binascii.unhexlify(iv)

    # Convert iv to binary 
    iv_binary = bin(int(binascii.hexlify(iv_text), 16))

    # Remove 'b' character denoting a binary string in Python
    iv_binary = iv_binary[0] + iv_binary[2:]

    # Seperate ciphertext into blocks
    cipher_block_list = [message_binary[0+i:64+i] for i in range(0, len(message_binary), 64)]
    
    # First ciphertext block decryption
    k = des(key_text)
    decrypt1 = k.des_decrypt(cipher_block_list[0])
    decrypt1 = ''.join(str(x) for x in decrypt1)
    iv_decrypt1_xor = '{0:0{1}b}'.format(int(decrypt1, 2) ^ int(iv_binary, 2), len(decrypt1))

    # Plaintext builder string
    plaintext = iv_decrypt1_xor

    # Begin chained decryption
    for i in range(1, len(cipher_block_list)):
        decrypt = k.des_decrypt(cipher_block_list[i])
        decrypt = ''.join(str(x) for x in decrypt)
        cipherblock = ''.join(str(x) for x in cipher_block_list[i-1])
        cipherblock_decrypt_xor = '{0:0{1}b}'.format(int(decrypt, 2) ^ int(cipherblock, 2), len(decrypt))
        plaintext += cipherblock_decrypt_xor

    # Reverse plaintext binary and index to beginning of padding
    reverse_plaintext = plaintext[::-1]
    i = 0
    while reverse_plaintext[i] == '0':
        pass
        i += 1
    i += 1

    # Remove padding
    no_padding_plaintext = reverse_plaintext[i:][::-1]

    return bits2bytes(no_padding_plaintext)

def bytes2bits(s):
    result = []
    for c in s:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result

def main(argv):
    if len(argv) != 5:
        print 'Wrong number of arguments!\npython task1.py $MODE $INFILE $KEYFILE $IVFILE $OUTFILE'
        sys.exit(1)
    mode = argv[0]
    infile = argv[1]
    keyfile = argv[2]
    ivfile = argv[3]
    outfile = argv[4]
    message = None
    key = None
    iv = None
    try:
        message = open(infile, 'r').read()
        key = open(keyfile, 'r').read()
        iv = open(ivfile, 'r').read()
    except:
        print 'File Not Found'
    start = time.time()
    if mode == "enc":
        output = cbc_encrypt(message, key, iv)
    elif mode == "dec":
        output = cbc_decrypt(message, key, iv)
    else:
        print "Wrong mode!"
        sys.exit(1)
    end = time.time()
    print "Consumed CPU time=%f"% (end - start)
    open(outfile, 'w').write(output)

if __name__=="__main__":
    main(sys.argv[1:])
