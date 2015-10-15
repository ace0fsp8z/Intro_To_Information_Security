import sys
import re

# Checks if solution has the same structure as the template
# It also prints out stored information so the student sees that their data is being read in properly
def similarStruct(template, solution):

    # Go through the solution's structure and see if it matches to the template structure
    for k1,v1 in solution.iteritems():
        print k1

        # Phase is not in template
        if k1 not in template:
            return 0

        for k2,v2 in sorted(v1.iteritems()):
            print k2

            # Malware/Question is not in template
            if k2 not in template[k1]:
                return 0

            if isinstance(v2, dict):
                for k3, v3 in sorted(v2.iteritems()):
                    print k3
                    print v3

                    # Question is not in template
                    if k3 not in template[k1][k2]:
                        return 0
            else:
                print v2
        print ''

    return 1

# Reads in solution structure (and solution depending on flag)
def readin(fn, d, flag):
    # Dictionary to hold final contents
    d = dict()

    # Variables to keep track of current place in dictionary
    cPhase = None
    cMalware = None
    cQuestion = None

    # Open file
    fr = open(fn, 'r')

    try:
        # Read/parse file's contents
        while True:
            # Read line
            line = fr.readline()

            # If EOF
            if line == '':
                break

            # Parse line's contents

            # Remove newline character
            line = line.strip('\n\r')

            # Remove extra newlines from final dataset
            if line == '':
                continue

            # Check if this line is a phase, malware, or question
            phasePattern = '^\[phase.*\]$'
            malwarePattern = '^\[malware.*\]$'
            questionPattern = '^\[question.*\]$'

            if re.match(phasePattern, line) != None:
                d[line] = dict()
                cPhase = line
                continue

            else:
                if cPhase == '[phaseI]':
                    if re.match(malwarePattern, line) != None:
                        d[cPhase][line] = dict()
                        cMalware = line
                        continue

                    elif re.match(questionPattern, line) != None:
                        d[cPhase][cMalware][line] = list()
                        cQuestion = line

                        # Read answers to question
                        if flag == 'solution':
                            while True:
                                line = fr.readline()

                                # If EOF
                                if line == '':
                                    break

                                # Remove newline character
                                line = line.strip('\n\r')

                                # If answers are finished
                                # If blank line appears
                                if line == '':
                                    break
                                # If new phase has been reached
                                elif re.match(phasePattern, line) != None:
                                    d[line] = dict()
                                    cPhase = line
                                    break
                                # If new malware has been reached
                                elif re.match(malwarePattern, line) != None:
                                    d[cPhase][cMalware] = dict()
                                    cMalware = line
                                    break
                                # If new question has been reached
                                elif re.match(questionPattern, line) != None:
                                    d[cPhase][cMalware][line] = list()
                                    cQuestion = line
                                    continue

                                # Append answer to question
                                d[cPhase][cMalware][cQuestion].append(line)

                        continue

                elif cPhase == '[phaseII]':
                    if re.match(malwarePattern, line) != None:
                        d[cPhase][line] = list()
                        cMalware = line

                        # Read answers to question
                        if flag == 'solution':
                            while True:
                                line = fr.readline()

                                # If EOF
                                if line == '':
                                    break

                                # Remove newline character
                                line = line.strip('\n\r')

                                # If answers are finished
                                # If blank line appears
                                if line == '':
                                    break
                                # If new phase has been reached
                                elif re.match(phasePattern, line) != None:
                                    d[line] = dict()
                                    cPhase = line
                                    break
                                # If new malware has been reached
                                elif re.match(malwarePattern, line) != None:
                                    d[cPhase][cMalware] = list()
                                    cMalware = line
                                    continue

                                # Append answer to question
                                d[cPhase][cMalware].append(line)

                        continue

                elif cPhase == '[phaseIII]':
                    if re.match(malwarePattern, line) != None:
                        d[cPhase][line] = dict()
                        cMalware = line
                        continue

                    elif re.match(questionPattern, line) != None:
                        d[cPhase][cMalware][line] = list()
                        cQuestion = line

                        # Read answers to question
                        if flag == 'solution':
                            while True:
                                line = fr.readline()

                                # If EOF
                                if line == '':
                                    break

                                # Remove newline character
                                line = line.strip('\n\r')

                                # If answers are finished
                                # If blank line appears
                                if line == '':
                                    break
                                # If new phase has been reached
                                elif re.match(phasePattern, line) != None:
                                    d[line] = dict()
                                    cPhase = line
                                    break
                                # If new malware has been reached
                                elif re.match(malwarePattern, line) != None:
                                    d[cPhase][cMalware] = dict()
                                    cMalware = line
                                    break
                                # If new question has been reached
                                elif re.match(questionPattern, line) != None:
                                    d[cPhase][cMalware][line] = list()
                                    cQuestion = line
                                    continue

                                # Append answer to question
                                d[cPhase][cMalware][cQuestion].append(line)

                        continue

                elif cPhase == '[phaseIV]':
                    if re.match(questionPattern, line) != None:
                        d[cPhase][line] = list()
                        cQuestion = line

                        # Read answers to question
                        if flag == 'solution':
                            while True:
                                line = fr.readline()

                                # If EOF
                                if line == '':
                                    break

                                # Remove newline character
                                line = line.strip('\n\r')

                                # If answers are finished
                                # If blank line appears
                                if line == '':
                                    break
                                # If new phase has been reached
                                elif re.match(phasePattern, line) != None:
                                    d[line] = dict()
                                    cPhase = line
                                    break
                                # If new question has been reached
                                elif re.match(questionPattern, line) != None:
                                    d[cPhase][line] = list()
                                    cQuestion = line
                                    continue

                                # Append answer to question
                                d[cPhase][cQuestion].append(line)

                        continue

    except:
        print 'Error reading in file: ', sys.exc_info()
        fr.close()
        sys.exit(1)

    # Close file
    fr.close()

    return d

def usage():
    print 'usage: python checker.py solution-template your-solution'
    sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        usage()

    template = dict()
    testsolution = dict()

    # Read in template
    template = readin(sys.argv[1], template, None)

    # Read in test solution
    testsolution = readin(sys.argv[2], testsolution, 'solution')

#   print template
#   print ''
#   print testsolution

    # Check if their structures match up
    if similarStruct(template, testsolution) == 1:
        print 'Solution is in the correct format'
    else:
        print 'Solution is NOT in the correct format'
