import math
import rabin_miller
import random


class PublicKeyRSA:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e


class PrivateKeyRSA:
    def __init__(self, p: int, q: int, n: int, d: int):
        self.p = p
        self.q = q
        self.n = n
        self.d = d


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


def generate_keys(key_size: int = 1024, is_default_e: bool = True) -> (PrivateKeyRSA, PublicKeyRSA):
    """
    :param key_size: should be in range of [512, 4096] and multiple of 512
    :param is_default_e: use public exponent with default value is 65537, or generate another one. It might be the same
    :return: tuple of tuples (private_key, public_key), private_key=(p, q, n, d), public_key=(n, e)
    """
    if key_size < 1 or key_size > 4096 or (key_size % 512) != 0:
        raise Exception('key_size should be in range of [512, 4096] and multiple of 512')

    p = rabin_miller.generate_large_prime(key_size // 2)
    q = rabin_miller.generate_large_prime(key_size // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if not is_default_e:
        while True:
            e = random.randrange(pow(2, (key_size // 2) - 1), pow(2, key_size // 2))
            if math.gcd(e, phi) == 1:
                break

    d = modular_inverse(e, phi)

    return PrivateKeyRSA(p, q, n, d), PublicKeyRSA(n, e)


def encrypt(public_key: PublicKeyRSA, message: int) -> int:
    n = public_key.n
    e = public_key.e
    return pow(message, e, n)


def decrypt(private_key: PrivateKeyRSA, cipher: int) -> int:
    n = private_key.n
    d = private_key.d
    return pow(cipher, d, n)


def sign_hash(private_key: PrivateKeyRSA, hash_value: int) -> int:
    """
    :param private_key: instance of PrivateKey class
    :param hash_value: hash length should be equal of key size like for PrivateKey
    :return: sign of hash_value with PrivateKey
    """
    n = private_key.n
    d = private_key.d
    return pow(hash_value, d, n)


def verify_sign(public_key: PublicKeyRSA, signed_hash: int) -> int:
    """
    :param public_key: instance of PublicKey class
    :param signed_hash: length should be equal of key size like for PublicKey
    :return: true if original hash in signed_hash equal hash_value, false otherwise
    """
    n = public_key.n
    e = public_key.e
    return pow(signed_hash, e, n)
