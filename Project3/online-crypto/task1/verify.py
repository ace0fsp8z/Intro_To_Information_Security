#!/usr/bin/python
from itertools import izip
import subprocess
import sys
import tempfile

def verify(mode, inputfile, key, iv, expectedfile, language):
    temp = tempfile.NamedTemporaryFile()
    try:
        output = None
        error = None
        temp.close()
        if language.lower() == 'java':
            p = subprocess.Popen(['java', 'task1', mode, inputfile, key, iv, temp.name], stdout=subprocess.PIPE)
            output, error = p.communicate()
        elif language.lower() == 'python':
            p = subprocess.Popen(['python', 'task1.py', mode, inputfile, key, iv, temp.name], stdout=subprocess.PIPE)
            output, error = p.communicate()
        elif language.lower() in ['c++', 'cpp', 'c']:
            p = subprocess.Popen(['./task1', mode, inputfile, key, iv, temp.name], stdout=subprocess.PIPE)
            output, error = p.communicate()
        else:
            print 'Unsupported language parameter'
        if open(temp.name, 'r').read() == open(expectedfile, 'r').read():
            print 'Passes the test on input: %s, %s, %s, %s, %s' % (
                mode, inputfile, key, iv, expectedfile)
        else:
            print 'Fails the test on input: %s, %s, %s, %s, %s' % (
                mode, inputfile, key, iv, expectedfile)
    except:
        print 'Language:%s\nOutput:%s\nError:%s' % (language, output, error)

def verify_batch(language):
    key = './key'
    iv = './iv'
    plaintexts = ['./plaintext_1', './plaintext_2']
    ciphertexts = ['./ciphertext_1', './ciphertext_2']
    for plaintext, ciphertext in izip(plaintexts, ciphertexts):
        verify('enc', plaintext, key, iv, ciphertext, language)
        verify('dec', ciphertext, key, iv, plaintext, language)

if __name__ == "__main__":
    help_msg = 'Notice: If you use Java or C++, compile them before you run this verifier.'
    print help_msg
    if len(sys.argv[1:]) != 1:
        print 'Wrong number of arguments!\npython verify.py $LANGUAGE'
        sys.exit(1)
    verify_batch(sys.argv[1])
