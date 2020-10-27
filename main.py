import random as rd
from typing import Callable

from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BITS
from rabin.cryptosystem.base import RabinCryptosystem
from rabin.cryptosystem.file import FileRabinCryptosystem
from rabin.cryptosystem.integer import IntegerRabinCryptosystem
from rabin.dto import RabinCryptoKey
from rabin.padding.copy_bits_strategy import CopyBitsStrategy
from rabin.padding.nonce_bits_strategy import NonceBitsStrategy


def generate_key(rabin: RabinCryptosystem):
    print('Generating key...')
    key = rabin.generate_key()
    print('Key generated!')
    return key


def test_with_rounds(rounds: int,
                     test_number_generator: Callable,
                     rabin: IntegerRabinCryptosystem):
    key = generate_key(rabin)
    for i in range(rounds):
        test_once(test_number_generator(), rabin=rabin, key=key)

        if i % (rounds / 10) == 0:
            print(f'Test {100 * i // rounds}% of {rounds} OK')

    print(f'Test 100% of {rounds} OK')


def test_once(plaintext: int, rabin: IntegerRabinCryptosystem, key: RabinCryptoKey):
    ciphertext = rabin.encrypt(key.public, plaintext)
    decrypted = rabin.decrypt(key, ciphertext)

    if plaintext != decrypted:
        raise ValueError(f'Plaintext {plaintext} does not match {decrypted}.')


def test_copy_bits_strategy(test_rounds: int, padding_size: int):
    print(f'Testing: CopyBitsStrategy with size {padding_size}')
    test_with_rounds(test_rounds,
                     rabin=IntegerRabinCryptosystem(CopyBitsStrategy(padding_bits=padding_size)),
                     # minimal number has to be at least padding_size big,
                     # maximal must be smaller then N - padding_size
                     # (because padding_size bits are used as padding in the padding strategy)
                     test_number_generator=lambda: getRandomNBitInteger(
                         rd.randint(padding_size, MAX_ENCRYPTED_BITS - padding_size))
                     )


def test_nonce_bits_strategy(test_rounds: int, nonce_size: int):
    print(f'Testing: NonceBitsStrategy with size {nonce_size}')
    nonce = getRandomNBitInteger(nonce_size)
    test_with_rounds(test_rounds,
                     rabin=IntegerRabinCryptosystem(NonceBitsStrategy(nonce=nonce)),
                     # maximal number must be smaller then N - nonce_size
                     # (because padding_size bits are used as padding in the padding strategy)
                     test_number_generator=lambda: getRandomNBitInteger(
                         rd.randint(1, MAX_ENCRYPTED_BITS - nonce_size))
                     )


def test_file_write_read(nonce_size: int, test_file_path: str):
    nonce = getRandomNBitInteger(nonce_size)
    cs = FileRabinCryptosystem(NonceBitsStrategy(nonce=nonce))
    key = generate_key(cs)

    encrypted = cs.encrypt(key.public, test_file_path)
    decrypted = cs.decrypt(key, encrypted)

    with open(test_file_path, 'rb') as test_file:
        original = test_file.read()
    with open(decrypted, 'rb') as decrypted_file:
        produced = decrypted_file.read()

    if original != produced:
        raise ValueError('Original is different then produced!')


if __name__ == '__main__':
    # test_copy_bits_strategy(test_rounds=300, padding_size=16)
    # test_nonce_bits_strategy(test_rounds=300, nonce_size=16)
    test_file_write_read(nonce_size=16, test_file_path='README.md')
