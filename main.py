import random as rd
from typing import Callable

from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BYTES
from rabin.dto import RabinCryptoKey
from rabin.padding.append_bits_strategy import AppendBitsStrategy
from rabin.rabin import RabinCryptosystem

TEST_ROUNDS = 100


def test_with_rounds(rounds: int,
                     test_number_generator: Callable,
                     rabin: RabinCryptosystem = None):
    rabin = rabin if rabin else RabinCryptosystem()

    print('Generating key...')
    key = rabin.generate_key()
    print('Key generated!')

    for i in range(rounds):
        test_once(test_number_generator(), key=key)

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
        padding_size = 16
        print(f'Testing: AppendBitsStrategy with size {padding_size}')
        test_with_rounds(TEST_ROUNDS,
                         rabin=RabinCryptosystem(AppendBitsStrategy(padding_size)),
                         # minimal number has to be at least padding_size big,
                         # maximal must be smaller then N - padding_size
                         # (because padding_size bits are used as padding in the padding strategy)
                         test_number_generator=lambda: getRandomNBitInteger(
                             rd.randint(padding_size, MAX_ENCRYPTED_BYTES - padding_size))
                         )
    except ValueError as ve:
        print('AppendBitsStrategy failed!')
        print(ve)
