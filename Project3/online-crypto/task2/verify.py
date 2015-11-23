#!/usr/bin/python
from itertools import izip
import subprocess
import sys
import tempfile

def verify(mode, input, expect, language):
    try:
        if language.lower() == 'java':
            p = subprocess.Popen(['java', 'task2', mode, input], stdout=subprocess.PIPE)
            output, error = p.communicate()
        elif language.lower() == 'python':
            p = subprocess.Popen(['python', 'task2.py', mode, input], stdout=subprocess.PIPE)
            output, error = p.communicate()
        elif language.lower() in ['c++', 'cpp', 'c']:
            p = subprocess.Popen(['./task2', mode, input], stdout=subprocess.PIPE)
            output, error = p.communicate()
        else:
            print 'Unsupported language parameter'
        output = output.strip().lower()
        if output == expect:
           print "Passes the test on input: %s, %s, %s" % (
                mode, input, expect)
        else:
            print "Fails the test on input: %s, %s, %s" % (
                mode, input, expect)
    except:
        raise Exception('\nOutput: %s\nError:%s' % (language, output, error))

def verify_batch(language):
    inputs = ["8080808080808080", "808080808080807f", "8080808080801f80", "8080808080801f7f",
              "808080808080b05e", "8080808010101002"]
    expecteds = ["8080808080808001", "8080808080800180", "8080808080801f01", "8080808080802080",
                "808080808080b0df", "8080808010101083"]
    for input, expect in izip(inputs, expecteds):
        verify('enum_key', input, expect, language)

if __name__ == "__main__":
    help_msg = 'Notice: If you use Java or C++, compile them before you run this verifier.'
    print help_msg
    if len(sys.argv[1:]) != 1:
        print 'Wrong number of arguments!\npython verify.py $LANGUAGE'
        sys.exit(1)
    verify_batch(sys.argv[1])
