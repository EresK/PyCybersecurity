# original realization:
# https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py

def _rot_(a, n):
    return ((a << (n % 64)) + (a >> (64 - (n % 64)))) % (1 << 64)


def _keccak_f1600_on_lanes_(lanes):
    r = 1
    for rnd in range(24):
        # theta
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x+4) % 5] ^ _rot_(c[(x+1) % 5], 1) for x in range(5)]
        lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]

        # ro and pi
        (x, y) = (1, 0)
        current = lanes[x][y]
        for t in range(24):
            (x, y) = (y, (2*x+3*y) % 5)
            (current, lanes[x][y]) = (lanes[x][y], _rot_(current, (t+1)*(t+2)//2))

        # chi
        for y in range(5):
            tmp = [lanes[x][y] for x in range(5)]
            for x in range(5):
                lanes[x][y] = tmp[x] ^ ((~tmp[(x+1) % 5]) & tmp[(x+2) % 5])

        # iota
        for j in range(7):
            r = ((r << 1) ^ ((r >> 7)*0x71)) % 256
            if r & 2:
                lanes[0][0] = lanes[0][0] ^ (1 << ((1 << j)-1))
    return lanes


def _load64_(b):
    return sum((b[i] << (8*i)) for i in range(8))


def _store64_(a):
    return list((a >> (8*i)) % 256 for i in range(8))


def _keccak_f1600_(state):
    lanes = [[_load64_(state[8*(x+5*y):8*(x+5*y)+8]) for y in range(5)] for x in range(5)]
    lanes = _keccak_f1600_on_lanes_(lanes)
    state = bytearray(200)
    for x in range(5):
        for y in range(5):
            state[8*(x+5*y):8*(x+5*y)+8] = _store64_(lanes[x][y])
    return state


def sha3(input_bytes, out_len=256):
    if out_len != 224 and out_len != 256 and out_len != 384 and out_len != 512:
        return

    capacity = out_len * 2
    rate = 1600 - capacity
    state = bytearray(200)

    rate_inBytes = rate // 8
    out_len_inBytes = out_len // 8

    # padding
    padding_inBytes = rate_inBytes - len(input_bytes) % rate_inBytes
    input_message = bytearray(len(input_bytes) + padding_inBytes)
    for i in range(len(input_bytes)):
        input_message[i] = input_bytes[i]

    if padding_inBytes == 1:
        input_message[-1] = 0x86
    else:
        input_message[-padding_inBytes] = 0x06
        input_message[-1] = 0x80

    block_size = (len(input_bytes) + padding_inBytes) // rate_inBytes

    for blk in range(block_size):
        for i in range(rate_inBytes):
            state[i] ^= input_message[blk * rate_inBytes + i]
        state = _keccak_f1600_(state)

    return state[0:out_len_inBytes]


if __name__ == '__main__':
    M = bytearray(135)
    for i in range(len(M)):
        M[i] = 0x73
    val = sha3(M, 256)
    print('changed = ', bytes(val).hex())
