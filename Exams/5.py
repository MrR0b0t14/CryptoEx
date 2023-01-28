 #first modification
def __init__(self):
    self.__H = [None] * 5
        for i in range(5):
            self.__H[i] = int("0x" + sniffed_kdgst[i * 8:(i + 1) * 8],16)
        print(self.__H)

#modify padding funct
def padding(stream):
    l = len(stream)  # Bytes
    l += 512//8
    hl = [int((hex(l*8)[2:]).rjust(16, '0')[i:i+2], 16)
          for i in range(0, 16, 2)]

    l0 = (56 - l) % 64
    if not l0:
        l0 = 64

    if isinstance(stream, str):
        stream += chr(0b10000000)
        stream += chr(0)*(l0-1)
        for a in hl:
            stream += chr(a)
    elif isinstance(stream, bytes):
        stream += bytes([0b10000000])
        stream += bytes(l0-1)
        stream += bytes(hl)

    return stream