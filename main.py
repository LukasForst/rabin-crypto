import random as rd

from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BYTES
from rabin.dto import RabinCryptoKey
from rabin.padding.append_bits_strategy import AppendBitsStrategy
from rabin.rabin import RabinCryptosystem

TEST_ROUNDS = 100


def test_with_rounds(rounds: int, rabin: RabinCryptosystem = None):
    rabin = rabin if rabin else RabinCryptosystem()

    print('Generating key...')
    key = rabin.generate_key()
    print('Key generated!')

    for i in range(rounds):
        # test_once(rd.randint(2 ** 15, key.public.n), key=key)
        # minimal number has 16 bites, maximal must be smaller then N - 16
        # (because 16 bits are used as padding in AppendBitsStrategy)
        test_once(getRandomNBitInteger(rd.randint(16, MAX_ENCRYPTED_BYTES - 16)), key=key)

        if i % (rounds / 10) == 0:
            print(f'Test {100 * i // rounds}/100')

    print(f'Test 100/100')


def test_once(plaintext: int, rabin: RabinCryptosystem = None, key: RabinCryptoKey = None):
    rabin = rabin if rabin else RabinCryptosystem()
    key = key if key else rabin.generate_key()

    ciphertext = rabin.encrypt(key.public, plaintext)
    decrypted = rabin.decrypt(key, ciphertext)

    if plaintext != decrypted:
        raise ValueError(f'Plaintext {plaintext} does not match {decrypted}.')


if __name__ == '__main__':
    # test append bits strategy
    try:
        print('Testing: AppendBitsStrategy')
        test_with_rounds(TEST_ROUNDS, rabin=RabinCryptosystem(AppendBitsStrategy()))
    except ValueError as ve:
        print('AppendBitsStrategy failed!')
        print(ve)
