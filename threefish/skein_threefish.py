from skein import threefish
import threefish_utils as tf_util


def printCipherLarge(key, tweak, message):
    t = threefish(key, tweak)
    c = []
    for i in range(len(message)):
        c += [t.encrypt_block(message[i])]

    print('cipher :', c[0].hex())
    d = t.decrypt_block(c[0])
    print('message:', d.hex())
    print()


def printCipher(key, tweak, message):
    t = threefish(key, tweak)
    c = t.encrypt_block(message)
    print('cipher :', c.hex())
    d = t.decrypt_block(c)
    print('message:', d.hex())
    print()


key = b'\x00' * 32
tweak = b'\x00' * 16
message = b'\x00' * 32
printCipher(key, tweak, message)


key = b'a' * 32
tweak = b'a' * 16
message = b'a' * 32
printCipher(key, tweak, message)


key = b'key of 32,64 or 128 bytes length'
tweak = b'tweak: 16 bytes '
message = b'block of data,same length as key'
printCipher(key, tweak, message)


key = b'\x00' * 32
tweak = b'\x00' * 16
message = tf_util.readfile('./algorithm/file_1mb')
message = tf_util.padding256(message)

message = tf_util.separate64(message)
message = tf_util.merge256(message)

printCipherLarge(key, tweak, message)
