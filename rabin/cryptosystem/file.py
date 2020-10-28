from typing import Optional, BinaryIO

from rabin.crypto_configuration import PLAINTEXT_BLOCK_SIZE_BYTES, CIPHERTEXT_BLOCK_SIZE_BYTES
from rabin.cryptosystem.base import RabinCryptosystem
from rabin.cryptosystem.integer import IntegerRabinCryptosystem
from rabin.dto import RabinPublicKey, RabinCryptoKey
from rabin.padding.fixed_padding_bits_strategy import FixedPaddingBitsStrategy
from rabin.padding.padding_strategy import PaddingStrategy


class FileRabinCryptosystem(RabinCryptosystem):
    """
    Cryptosystem implementation suitable for encrypting and decrypting files.
    """

    def __init__(self, ps: Optional[PaddingStrategy] = None):
        super().__init__(ps)

    def encrypt(self, pk: RabinPublicKey, plaintext_file: str) -> str:
        """
        Encrypts given plaintext_file, returns path to encrypted file path.
        """
        encrypted_file_path = plaintext_file + '.enc'
        with open(plaintext_file, 'rb') as plaintext_file:
            with open(encrypted_file_path, 'wb') as encrypted_file:
                # write padding to the encrypted file as a header
                if type(self._ps) == FixedPaddingBitsStrategy:
                    encrypted_file.write(self._int_to_bytes(self._ps.padding))
                    encrypted_file.write(b'\n')

                cs = IntegerRabinCryptosystem(self._ps)

                plaintext_bytes = plaintext_file.read(PLAINTEXT_BLOCK_SIZE_BYTES)
                while plaintext_bytes:
                    # read bytes and convert them as big endian to int
                    plaintext = self._bytes_to_int(plaintext_bytes)
                    # encrypt the int
                    ciphertext = cs.encrypt(pk, plaintext)
                    # write it in bytes to the file
                    encrypted_file.write(self._int_to_bytes(ciphertext))
                    # read next bytes
                    plaintext_bytes = plaintext_file.read(PLAINTEXT_BLOCK_SIZE_BYTES)

        return encrypted_file_path

    def decrypt(self, sk: RabinCryptoKey, ciphertext_file: str) -> str:
        """
        Decrypts the given encrypted file, returns decrypted file path.
        """
        decrypted_file_path = ciphertext_file + '.dec'
        with open(ciphertext_file, 'rb') as encrypted_file:
            with open(decrypted_file_path, 'wb') as decrypted_file:
                # read header and initialize padding
                if type(self._ps) == FixedPaddingBitsStrategy:
                    self._initialize_fixed_padding(encrypted_file)

                cs = IntegerRabinCryptosystem(self._ps)

                ciphertext_bytes = encrypted_file.read(CIPHERTEXT_BLOCK_SIZE_BYTES)
                while ciphertext_bytes:
                    ciphertext = self._bytes_to_int(ciphertext_bytes)
                    # decrypt block by block
                    plaintext = cs.decrypt(sk, ciphertext)
                    # convert integer to bytes
                    plaintext_bytes = self._int_to_bytes(plaintext)
                    # write the bytes
                    decrypted_file.write(plaintext_bytes)
                    # read next bytes
                    ciphertext_bytes = encrypted_file.read(CIPHERTEXT_BLOCK_SIZE_BYTES)

        return decrypted_file_path

    def _initialize_fixed_padding(self, ciphertext_file: BinaryIO):
        padding_bytes = b''
        # read first line from the file where the padding is
        byte = ciphertext_file.read(1)
        while byte and byte != b'\n':
            padding_bytes += byte
            byte = ciphertext_file.read(1)
        # convert padding to int
        padding = self._bytes_to_int(padding_bytes)
        # initialise the padding strategy
        self._ps = FixedPaddingBitsStrategy(padding)

    @staticmethod
    def _int_to_bytes(integer: int) -> bytes:
        return integer.to_bytes((integer.bit_length() + 7) // 8, 'big') or b'\0'

    @staticmethod
    def _bytes_to_int(bts: bytes) -> int:
        return int.from_bytes(bts, 'big')
