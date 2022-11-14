import hashlib
import rsa
import sys
import rsa_algorithm as algo


if sys.version_info < (3, 6):
    import sha3


def int_to_bytes(num: int) -> bytes:
    bl = num.bit_length() // 8
    return num.to_bytes(bl, 'little') if (num.bit_length() % 8) == 0 else num.to_bytes(bl + 1, 'little')


def bytes_to_int(bs: bytes) -> int:
    return int.from_bytes(bs, 'little')


def load_long_text(filename: str) -> str:
    with open(filename, 'rt') as f:
        text = f.read()
    return text


def test_ciphering(message: bytes):
    key_size = 512
    private_key, public_key = algo.generate_keys(key_size)

    cipher = algo.encrypt(public_key, bytes_to_int(message))
    decrypted = algo.decrypt(private_key, cipher)

    assert bytes_to_int(message) == decrypted

    print(f'>>>>> TEST Ciphering\n'
          f'key size:   {key_size}\n'
          f'origin:     {message.hex()}\n'
          f'cipher:     {int_to_bytes(cipher).hex()}\n'
          f'cipher len: {len(int_to_bytes(cipher))}\n'
          f'decrypted:  {int_to_bytes(decrypted).hex()}\n'
          f'>>>>>\n')


def test_sign_and_verify_hash(hash_origin: bytes):
    key_size = 512
    private_key, public_key = algo.generate_keys(key_size)

    signed_hash = algo.sign_hash(private_key, bytes_to_int(hash_origin))
    hash_value = algo.verify_sign(public_key, signed_hash)

    assert hash_origin == int_to_bytes(hash_value)

    print(f'>>>>> TEST Sign and verify hash of the large file\n'
          f'key size:    {key_size}\n'
          f'hash origin: {hash_origin.hex()}\n'
          f'signed hash: {int_to_bytes(signed_hash).hex()}\n'
          f'signed len:  {len(int_to_bytes(signed_hash))}\n'
          f'hash value:  {int_to_bytes(hash_value).hex()}\n'
          f'>>>>>\n')


def test_with_rsa_keys(message: bytes):
    key_size = 512
    public_key, private_key = rsa.newkeys(key_size)

    crypto = rsa.encrypt(message, public_key)
    decrypto = rsa.decrypt(crypto, private_key)

    cipher = algo.encrypt(algo.PublicKeyRSA(public_key.n, public_key.e), bytes_to_int(message))
    decrypted = algo.decrypt(algo.PrivateKeyRSA(private_key.p,
                                                private_key.q,
                                                private_key.n,
                                                private_key.d), cipher)

    assert decrypto == int_to_bytes(decrypted)

    print(f'>>>>> TEST with rsa lib\'s keys\n'
          f'key size:      {key_size}\n'
          f'message:       {message.hex()}\n'
          f'rsa crypto:    {crypto.hex()}\n'
          f'rsa decrypto:  {decrypto.hex()}\n'
          f'alg cipher:    {int_to_bytes(cipher).hex()}\n'
          f'alg decrypted: {int_to_bytes(decrypted).hex()}\n'
          f'>>>>>\n')


def test_with_rsa_algorithm_keys(message: bytes):
    key_size = 512
    private_key, public_key = algo.generate_keys(key_size)

    crypto = rsa.encrypt(message, rsa.PublicKey(public_key.n, public_key.e))
    decrypto = rsa.decrypt(crypto, rsa.PrivateKey(private_key.n,
                                                  public_key.e,
                                                  private_key.d,
                                                  private_key.p,
                                                  private_key.q))

    cipher = algo.encrypt(public_key, bytes_to_int(message))
    decrypted = algo.decrypt(private_key, cipher)

    assert decrypto == int_to_bytes(decrypted)

    print(f'>>>>> TEST with rsa algorithm\'s keys\n'
          f'key size:      {key_size}\n'
          f'message:       {message.hex()}\n'
          f'rsa crypto:    {crypto.hex()}\n'
          f'rsa decrypto:  {decrypto.hex()}\n'
          f'alg cipher:    {int_to_bytes(cipher).hex()}\n'
          f'alg decrypted: {int_to_bytes(decrypted).hex()}\n'
          f'>>>>>\n')


if __name__ == '__main__':
    # Short message ciphering
    message_short = 'Hello, World!'
    test_ciphering(message_short.encode('utf8'))

    # Long file's hash verification
    message_long = load_long_text('./long_text')
    sha3 = hashlib.sha3_256(message_long.encode('utf8'))
    hash_long_file = sha3.digest()
    test_sign_and_verify_hash(hash_long_file)

    # Testing with keys of rsa lib and rsa_algorithm lib
    test_with_rsa_keys(message_short.encode('utf8'))
    test_with_rsa_algorithm_keys(message_short.encode('utf8'))
