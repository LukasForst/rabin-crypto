import random as rd

from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BYTES
from rabin.dto import RabinCryptoKey
from rabin.rabin import generate_key, encrypt, decrypt

TEST_ROUNDS = 100


def test_with_rounds(rounds: int):
    print('Generating key...')
    key = generate_key()
    print('Key generated!')

    for i in range(rounds):
        # test_once(rd.randint(2 ** 15, key.public.n), key=key)
        # minimal number has 16 bites, maximal must be smaller then N
        test_once(getRandomNBitInteger(rd.randint(16, MAX_ENCRYPTED_BYTES)), key=key)

        if i % (rounds / 10) == 0:
            print(f'Test {100 * i // rounds}/100')

    print(f'Test 100/100')


def test_once(plaintext: int, key: RabinCryptoKey = None):
    key = key if key else generate_key()

    ciphertext = encrypt(key.public, plaintext)
    decrypted = decrypt(key, ciphertext)

    if plaintext != decrypted:
        raise ValueError(f'Plaintext {plaintext} does not match {decrypted}.')


if __name__ == '__main__':
    test_with_rounds(TEST_ROUNDS)
    # test_once(2 ** 15)

    print('done')
