from sniffeddata import chipertext 
from mydata import correct_server_answer

#changing 1 bit in ciphertext[32:] lead to an error response 
from mydata import wrong_server_answer

#changing 1 bit in ciphertext[:16] lead to an ok response
#changing 1 bit in ciphertext[16:24] lead to an ok response
#changing 1 bit in ciphertext[24:32] lead to an error response

"""
0-16 data 
16-32 data + padding
32-48 padding -> discard this block

Plaintext size 24 bytes 

CBC Padding Oracle Attack


"""

def guess_byte(p,c,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    plain = b'\x00'
    for i in range(0,256):
        # print(i)
        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += i.to_bytes(1,byteorder='big')

        # print(ca)
        for x in p:
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(ca)
        ca += get_nth_block(ciphertext,n-1,block_size)
        # print(ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ca)
        response = server.recv(1024)

        # print(response)

        if response == correct_server_answer:
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01': #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            c.insert(0,i)
            p.insert(0,p_prime)
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            # break


    return plain

if __name__ == '__main__':

    check_oracle_good_padding()
    check_oracle_bad_padding()

    ciphertext = ciphertext[:-AES.block_size]

    n = num_blocks(ciphertext,AES.block_size)
    plaintext = bytearray()
    for i in range(1,n):
        c = []
        p = []

        for j in range(0,AES.block_size):
            plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
            print(plaintext)
        ciphertext = ciphertext[:-AES.block_size]


    print(len(ciphertext))