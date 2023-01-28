from mysiffeddata import ciphertext
from mydata import HOST PORT

import decimal
from public_key import n, e #this data are public

#useful functions
def to_bytes(m,l=n.bit_length()):
    return int.to_bytes(m, l, byteorder='big')

def to_int(b):
    return int.from_bytes(b,byteorder='big')

def print_bounds(low, up):
    print("[" + str(low) + "," + str(up) + "]")


m = ciphertext

# define the upper bound with decimal
decimal.getcontext().prec = n.bit_length()
lower_bound = decimal.Decimal(0)
upper_bound = decimal.Decimal(n)
print_bounds(lower_bound,upper_bound)

# approximation loop
for i in range(n.bit_length()):

    m = (pow(2, e, n) * m) % n
    server = remote(HOST, PORT)
    server.send(to_bytes(m))
    bit = server.recv(1024)
    server.close()

    if  bit[0] == 128:
        lower_bound = (upper_bound + lower_bound) / 2
    else:
        upper_bound = (upper_bound + lower_bound) / 2
    print_bounds(lower_bound, upper_bound)


print(n.bit_length())
print(int(upper_bound))
print(to_bytes(int(upper_bound),n.bit_length()).decode())


