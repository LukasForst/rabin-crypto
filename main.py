import random as rd
import time
from typing import Callable

from Crypto.Random import get_random_bytes
from Crypto.Util.number import getRandomNBitInteger

from rabin.crypto_configuration import MAX_ENCRYPTED_BITS
from rabin.cryptosystem.base import RabinCryptosystem
from rabin.cryptosystem.file import FileRabinCryptosystem
from rabin.cryptosystem.integer import IntegerRabinCryptosystem
from rabin.dto import RabinCryptoKey
from rabin.padding.copy_bits_strategy import CopyBitsStrategy
from rabin.padding.fixed_padding_bits_strategy import FixedPaddingBitsStrategy


def generate_key(rabin: RabinCryptosystem):
    print('Generating key...')
    start = time.time()
    key = rabin.generate_key()
    end = time.time()
    print(f'Key generated - took: {end - start}s')
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


def test_fixed_padding_bits_strategy(test_rounds: int, padding_size: int):
    print(f'Testing: FixedPaddingBitsStrategy with size {padding_size}')
    nonce = getRandomNBitInteger(padding_size)
    test_with_rounds(test_rounds,
                     rabin=IntegerRabinCryptosystem(FixedPaddingBitsStrategy(padding=nonce)),
                     # maximal number must be smaller then N - padding_size
                     # (because padding_size bits are used as padding in the padding strategy)
                     test_number_generator=lambda: getRandomNBitInteger(
                         rd.randint(1, MAX_ENCRYPTED_BITS - padding_size))
                     )


def test_file_write_read(padding_size: int, test_file_path: str):
    print(f'Testing: FileRabinCryptosystem with padding size {padding_size} and file {test_file_path}')

    # generate padding
    nonce = getRandomNBitInteger(padding_size)
    cs = FileRabinCryptosystem(FixedPaddingBitsStrategy(padding=nonce))
    key = generate_key(cs)

    encrypted = cs.encrypt(key.public, test_file_path)
    # generate new padding to see that it is actually loaded from the file
    cs = FileRabinCryptosystem(FixedPaddingBitsStrategy(getRandomNBitInteger(padding_size)))
    decrypted = cs.decrypt(key, encrypted)

    with open(test_file_path, 'rb') as test_file:
        original = test_file.read()
    with open(decrypted, 'rb') as decrypted_file:
        produced = decrypted_file.read()

    if original != produced:
        raise ValueError('Original is different then produced!')

    print(f'Testing: FileRabinCryptosystem OK')


def test_generate_random_byte_file(padding_size: int, bytes_number: int):
    print(f'Testing: FileRabinCryptosystem with padding size {padding_size} '
          f'and randomly generated file of size {bytes_number} bytes')

    # generate file
    test_file_path = 'random-file-test.bin'
    random_generated_bytes = get_random_bytes(bytes_number)
    with open(test_file_path, 'wb') as f:
        f.write(random_generated_bytes)

    # generate padding
    nonce = getRandomNBitInteger(padding_size)
    cs = FileRabinCryptosystem(FixedPaddingBitsStrategy(padding=nonce))
    key = generate_key(cs)

    encrypted = cs.encrypt(key.public, test_file_path)
    # generate new padding to see that it is actually loaded from the file
    cs = FileRabinCryptosystem(FixedPaddingBitsStrategy(getRandomNBitInteger(padding_size)))
    decrypted = cs.decrypt(key, encrypted)

    with open(test_file_path, 'rb') as test_file:
        original = test_file.read()
    with open(decrypted, 'rb') as decrypted_file:
        produced = decrypted_file.read()

    if original != produced:
        raise ValueError('Original is different then produced!')
    elif random_generated_bytes != produced:
        raise ValueError('Randomly generated data are different then produced!')

    print(f'Testing: FileRabinCryptosystem OK')


if __name__ == '__main__':
    test_copy_bits_strategy(test_rounds=300, padding_size=16)
    test_fixed_padding_bits_strategy(test_rounds=300, padding_size=16)
    test_file_write_read(padding_size=16, test_file_path='README.md')
    test_file_megabytes = 10
    test_generate_random_byte_file(padding_size=16, bytes_number=1024 * test_file_megabytes)
