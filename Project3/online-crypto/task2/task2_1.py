import sys
import des_wrapper as dw
import binascii
import time

def enum_key(current):
    """Return the next key based on the current key as hex string.

    TODO: Implement the required functions.
    """

    start_binary = bin(int(current, 16))[2:]

    startbinary_byte_blocks = [start_binary[0+i:8+i] for i in range(0, len(start_binary), 8)]

    for i in range(len(startbinary_byte_blocks)):
        startbinary_byte_blocks[i] = startbinary_byte_blocks[i][1:]

    removed_parity_binary = ''.join(str(i) for i in startbinary_byte_blocks)

    removed_parity_num = int(removed_parity_binary, 2)

    incremented_num = removed_parity_num + 1

    incremented_num_binary = bin(incremented_num)[2:]

    padding = 56 - (len(incremented_num_binary) % 56)

    incremented_num_binary = padding*'0' + bin(incremented_num)[2:]

    incremented_num_blocks = [incremented_num_binary[0+i:7+i] for i in range(0, len(incremented_num_binary), 7)]

    for i in range(len(incremented_num_blocks)):
        count_ones = 0
        for char in incremented_num_blocks[i]:
            if char == '1':
                count_ones += 1
        if count_ones % 2 == 0:
            incremented_num_blocks[i] = '1' + incremented_num_blocks[i]
        else:
            incremented_num_blocks[i] = '0' + incremented_num_blocks[i]

    add_parity_binary = ''.join(str(i) for i in incremented_num_blocks)

    hex_incremented_num = hex(int(add_parity_binary, 2))
    
    return hex_incremented_num[2:len(hex_incremented_num)-1]

def get_key(removed_parity_num):

    incremented_num = removed_parity_num + 1

    incremented_num_binary = bin(incremented_num)[2:]

    padding = 56 - (len(incremented_num_binary) % 56)

    incremented_num_binary = padding*'0' + bin(incremented_num)[2:]

    incremented_num_blocks = [incremented_num_binary[0+i:7+i] for i in range(0, len(incremented_num_binary), 7)]

    for i in range(len(incremented_num_blocks)):
        count_ones = 0
        for char in incremented_num_blocks[i]:
            if char == '1':
                count_ones += 1
        if count_ones % 2 == 0:
            incremented_num_blocks[i] = '1' + incremented_num_blocks[i]
        else:
            incremented_num_blocks[i] = '0' + incremented_num_blocks[i]

    add_parity_binary = ''.join(str(i) for i in incremented_num_blocks)

    key = [int(x) for x in add_parity_binary]

    return key

def main(argv):
    if argv[0] == 'enum_key':
        print enum_key(argv[1])
    elif argv[0] == 'crack':
        """TODO: Add your own code and do whatever you do.
        """
        message = open('plaintext', 'r').read()
        message_binary = '0' + bin(int(binascii.hexlify(message), 16))[2:]
        message_binary_list = [int(x) for x in message_binary]
        print len(message_binary_list)

        ciphertext = open('ciphertext', 'r').read()
        print len(ciphertext)

        ranges = ['8080010d80808080','8080010d7f7f7f7f']

        #start = int(enum_key(range[0]), 16)
        #end = int(enum_key(range[1]), 16)

        start_binary = bin(int(ranges[0], 16))[2:]
        end_binary = bin(int(ranges[1], 16))[2:]

        startbinary_byte_blocks = [start_binary[0+i:8+i] for i in range(0, len(start_binary), 8)]
        endbinary_byte_blocks = [end_binary[0+i:8+i] for i in range(0, len(end_binary), 8)]

        for i in range(len(startbinary_byte_blocks)):
            startbinary_byte_blocks[i] = startbinary_byte_blocks[i][1:]

        for i in range(len(endbinary_byte_blocks)):
            endbinary_byte_blocks[i] = endbinary_byte_blocks[i][1:]

        start_removed_parity_binary = ''.join(str(i) for i in startbinary_byte_blocks)
        #print len(start_removed_parity_binary)

        start = int(start_removed_parity_binary, 2)

        end_removed_parity_binary = ''.join(str(i) for i in endbinary_byte_blocks)

        end = int(end_removed_parity_binary, 2)

        #print end-start

        #print start_removed_parity_num
        #get_key(start_removed_parity_num)
        #print end_removed_parity_num
        #print end_removed_parity_num - start_removed_parity_num

        start = start + 168435456
        start_time = time.time()
        while start <= end:
            #to_hex = hex(start)[2:len(hex(start))-1]
            #key = bin(int(enum_key(to_hex), 16))[2:]
            #key_list = [int(x) for x in key]
            key_list = get_key(start)
            cracked_bytes = bits2bytes(dw.des_encrypt(key_list, message_binary_list))
            if cracked_bytes == ciphertext:
                print 'cracked'
                break
            else:
                print cracked_bytes
                print str(float(start)/float(end)) + '%'
            start +=1  
        end_time = time.time()
        print "Consumed CPU time=%f"% (end_time - start_time)

    else:
        raise Exception("Wrong mode!")

def bits2bytes(bits):
    chars = []
    for b in range(len(bits) / 8):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

if __name__=="__main__":
    main(sys.argv[1:])