import threefish256 as tf


def print_cipher(c):
    c_str = ''

    print('cipher:  ', end='')
    for i in range(len(c)):
        c_str += c[i].to_bytes(8, 'little').hex()
    print(c_str)

    return c_str


def print_message(d):
    d_str = ''

    print('message: ', end='')
    for i in range(len(d)):
        d_str += d[i].to_bytes(8, 'little').hex()
    print(d_str)
    print()

    return d_str


if __name__ == '__main__':
    # message should be presented as little endian manually
    key = [0, 0, 0, 0]
    tweak = [0, 0]
    message = [0, 0, 0, 0]
    c = tf.encrypt256(key, tweak, message)
    d = tf.decrypt256(key, tweak, c)
    c_str = print_cipher(c)
    d_str = print_message(d)
    assert '84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8' == c_str
    assert '0000000000000000000000000000000000000000000000000000000000000000' == d_str


    key = [0x6161616161616161, 0x6161616161616161, 0x6161616161616161, 0x6161616161616161]
    tweak = [0x6161616161616161, 0x6161616161616161]
    message = [0x6161616161616161, 0x6161616161616161, 0x6161616161616161, 0x6161616161616161]
    c = tf.encrypt256(key, tweak, message)
    d = tf.decrypt256(key, tweak, c)
    c_str = print_cipher(c)
    d_str = print_message(d)
    assert '26e4d63f37ba6ebda94af886e07ee91008b6f92ea3b6167cb48716c5a34ed6ae' == c_str
    assert '6161616161616161616161616161616161616161616161616161616161616161' == d_str


    key = [0x3320666f2079656b, 0x20726f2034362c32, 0x6574796220383231, 0x6874676e656c2073]
    tweak = [0x31203a6b61657774, 0x2073657479622036]
    message = [0x666f206b636f6c62, 0x61732c6174616420, 0x74676e656c20656d, 0x79656b2073612068]
    c = tf.encrypt256(key, tweak, message)
    d = tf.decrypt256(key, tweak, c)
    c_str = print_cipher(c)
    d_str = print_message(d)
    assert '1cbf83be6f57d8e066bab2ea0e910b0a062cd53a979a11496145474dc0e89e86' == c_str
    assert '626c6f636b206f6620646174612c73616d65206c656e677468206173206b6579' == d_str
