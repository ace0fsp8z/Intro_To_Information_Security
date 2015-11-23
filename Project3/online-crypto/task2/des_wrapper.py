import binascii
import time
from ctypes import *
lib = cdll.LoadLibrary('./_des.so')

def des_encrypt(key, message):
    N = 64
    keyArr = (c_char*N)()
    plainArr = (c_char*N)()
    outBlk = (c_char*N)()
    for i in range(N):
        keyArr[i] = chr(key[i])
    for i in range(N):
        plainArr[i] = chr(message[i])
    lib.EncryptDES(keyArr, plainArr, outBlk)
    return ''.join([str(ord(outBlk[i])) for i in range(N)])

def des_decrypt(key, message):
    N = 64
    keyArr = (c_char*N)()
    cipherArr = (c_char*N)()
    outBlk = (c_char*N)()
    for i in range(N):
        keyArr[i] = chr(key[i])
    for i in range(N):
        cipherArr[i] = chr(message[i])
    lib.DecryptDES(keyArr, cipherArr, outBlk)
    return ''.join([str(ord(outBlk[i])) for i in range(N)])

def bintohex(s):
    t = ''.join(chr(int(s[i:i+8], 2)) for i in xrange(0, len(s), 8))
    return binascii.hexlify(t).upper()

def test_des(key, message, N = 64):
    print bintohex(des_encrypt(key, message))

def test():
    key1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    key2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0]
    message1 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
    message2 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]
    test_des(key1, message1)
    test_des(key1, message2)
    test_des(key2, message1)
    test_des(key2, message2)

if __name__=="__main__":
    start = time.time()
    test()
    end = time.time()
    print "Consumed CPU time=%f" % (end - start)
