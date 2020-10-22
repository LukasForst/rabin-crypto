import random as rd
from typing import Callable

from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BYTES
from rabin.cryptosystem import RabinCryptosystem
from rabin.dto import RabinCryptoKey
from rabin.padding.append_bits_strategy import AppendBitsStrategy


def test_with_rounds(rounds: int,
                     test_number_generator: Callable,
                     rabin: RabinCryptosystem):
    print('Generating key...')
    key = rabin.generate_key()
    print('Key generated!')

    for i in range(rounds):
        test_once(test_number_generator(), rabin=rabin, key=key)

        if i % (rounds / 10) == 0:
            print(f'Test {100 * i // rounds}% of {rounds} OK')

    print(f'Test 100% of {rounds} OK')


def test_once(plaintext: int, rabin: RabinCryptosystem, key: RabinCryptoKey):
    ciphertext = rabin.encrypt(key.public, plaintext)
    decrypted = rabin.decrypt(key, ciphertext)

    if plaintext != decrypted:
        raise ValueError(f'Plaintext {plaintext} does not match {decrypted}.')


if __name__ == '__main__':
    test_rounds = 1000
    # test append bits strategy
    try:
        padding_size = 16
        print(f'Testing: AppendBitsStrategy with size {padding_size}')
        test_with_rounds(test_rounds,
                         rabin=RabinCryptosystem(AppendBitsStrategy(padding_bits=padding_size)),
                         # minimal number has to be at least padding_size big,
                         # maximal must be smaller then N - padding_size
                         # (because padding_size bits are used as padding in the padding strategy)
                         test_number_generator=lambda: getRandomNBitInteger(
                             rd.randint(padding_size, MAX_ENCRYPTED_BYTES - padding_size))
                         )
    except ValueError as ve:
        print('AppendBitsStrategy failed!')
        print(ve)
