import math
import rabin_miller
import random


def modular_inverse(a: int, b: int) -> int:
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1

    if b != 1:
        raise Exception(f'There is no modular inverse for {a} and {b}')
    if x0 < 0:
        x0 = x0 + x1

    return x0


def rsa_generate_keys(key_size: int = 1024) -> (tuple[int, int, int, int], tuple[int, int]):
    """
    :param key_size: should be positive and multiple of 8
    :return: tuple of tuples (private_key, public_key), private_key=(p, q, n, d), public_key=(n, e)
    """
    if key_size < 1 or key_size % 8 != 0:
        raise Exception('key_size must be positive and multiple by 8')

    p = rabin_miller.generate_large_prime(key_size)
    q = rabin_miller.generate_large_prime(key_size)

    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randrange(pow(2, key_size - 1), pow(2, key_size))
        if math.gcd(e, phi) == 1:
            break

    d = modular_inverse(e, phi)

    # private_key, public_key
    return (p, q, n, d), (n, e)


def rsa_encrypt(public_key: tuple[int, int], message: int) -> int:
    n = public_key[0]
    e = public_key[1]
    return pow(message, e, n)


def rsa_decrypt(private_key: tuple[int, int, int, int], cipher: int) -> int:
    n = private_key[2]
    d = private_key[3]
    return pow(cipher, d, n)
