__ROTATE_DJ__ = [[14, 16], [52, 57],
                 [23, 40], [5, 37],
                 [25, 33], [46, 12],
                 [58, 22], [32, 32]]


def xor_key(key):
    xor = 0x1bd11bdaa9fc1a22
    for i in range(4):
        xor = xor ^ key[i]
    return xor


def rotate_left64(a, b):
    return ((a << b) | (a >> (64 - b))) % (1 << 64)


def rotate_right64(a, b):
    return ((a >> b) | (a << (64 - b))) % (1 << 64)


def mix(a, b, r):
    a = (a + b) % (1 << 64)
    b = rotate_left64(b, r) ^ a
    return a, b


def mix4(a, b, r, k0, k1):
    b = (b + k1) % (1 << 64)
    a = (a + b + k0) % (1 << 64)
    b = rotate_left64(b, r) ^ a
    return a, b


def un_mix(a, b, r):
    b = rotate_right64(b ^ a, r)
    a = (a - b) % (1 << 64)
    return a, b


def un_mix4(a, b, r, k0, k1):
    b = rotate_right64(b ^ a, r)
    a = (a - b - k0) % (1 << 64)
    b = (b - k1) % (1 << 64)
    return a, b


def encrypt256(key, tweak, message):
    b0 = message[0]
    b1 = message[1]
    b2 = message[2]
    b3 = message[3]

    k0 = key[0]
    k1 = key[1]
    k2 = key[2]
    k3 = key[3]
    k4 = xor_key(key)

    t0 = tweak[0]
    t1 = tweak[1]
    t2 = tweak[0] ^ tweak[1]

    rounds_number = 72
    ki, kj, kk, kl, km = k0, k1, k2, k3, k4
    ti, tj, tk = t0, t1, t2
    delta = 0
    i = 0
    while i < rounds_number:
        if (i % 4) == 0:
            b0, b1 = mix4(b0, b1, __ROTATE_DJ__[i % 8][0], ki, kj + ti)
            b2, b3 = mix4(b2, b3, __ROTATE_DJ__[i % 8][1], kk + tj, kl + delta)

            ki, kj, kk, kl, km = kj, kk, kl, km, ki
            ti, tj, tk = tj, tk, ti
            delta += 1
            i += 1
        else:
            b0, b3 = mix(b0, b3, __ROTATE_DJ__[i % 8][0])
            b2, b1 = mix(b2, b1, __ROTATE_DJ__[i % 8][1])
            b0, b1 = mix(b0, b1, __ROTATE_DJ__[(i+1) % 8][0])
            b2, b3 = mix(b2, b3, __ROTATE_DJ__[(i+1) % 8][1])
            b0, b3 = mix(b0, b3, __ROTATE_DJ__[(i+2) % 8][0])
            b2, b1 = mix(b2, b1, __ROTATE_DJ__[(i+2) % 8][1])
            i += 3
    
    out = [0, 0, 0, 0]
    out[0] = (b0 + k3) % (1 << 64)
    out[1] = (b1 + k4 + t0) % (1 << 64)
    out[2] = (b2 + k0 + t1) % (1 << 64)
    out[3] = (b3 + k1 + 18) % (1 << 64)

    return out


def decrypt256(key, tweak, cipher):
    b0 = cipher[0]
    b1 = cipher[1]
    b2 = cipher[2]
    b3 = cipher[3]

    k0 = key[0]
    k1 = key[1]
    k2 = key[2]
    k3 = key[3]
    k4 = xor_key(key)

    t0 = tweak[0]
    t1 = tweak[1]
    t2 = tweak[0] ^ tweak[1]

    b0 = (b0 - k3) % (1 << 64)
    b1 = (b1 - k4 - t0) % (1 << 64)
    b2 = (b2 - k0 - t1) % (1 << 64)
    b3 = (b3 - k1 - 18) % (1 << 64)

    ki, kj, kk, kl, km = k2, k3, k4, k0, k1
    ti, tj, tk = t2, t0, t1
    delta = 17
    i = 71
    while i >= 0:
        if (i % 4) == 0:
            b0, b1 = un_mix4(b0, b1, __ROTATE_DJ__[i % 8][0], ki, kj + ti)
            b2, b3 = un_mix4(b2, b3, __ROTATE_DJ__[i % 8][1], kk + tj, kl + delta)

            ki, kj, kk, kl, km = km, ki, kj, kk, kl
            ti, tj, tk = tk, ti, tj

            delta -= 1
            i -= 1
        else:
            b0, b3 = un_mix(b0, b3, __ROTATE_DJ__[i % 8][0])
            b2, b1 = un_mix(b2, b1, __ROTATE_DJ__[i % 8][1])
            b0, b1 = un_mix(b0, b1, __ROTATE_DJ__[(i-1) % 8][0])
            b2, b3 = un_mix(b2, b3, __ROTATE_DJ__[(i-1) % 8][1])
            b0, b3 = un_mix(b0, b3, __ROTATE_DJ__[(i-2) % 8][0])
            b2, b1 = un_mix(b2, b1, __ROTATE_DJ__[(i-2) % 8][1])
            i -= 3

    return [b0, b1, b2, b3]
