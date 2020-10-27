from typing import Optional, TextIO

from rabin.crypto_configuration import BLOCK_SIZE_BYTES
from rabin.cryptosystem.base import RabinCryptosystem
from rabin.cryptosystem.integer import IntegerRabinCryptosystem
from rabin.dto import RabinPublicKey, RabinCryptoKey
from rabin.padding.nonce_bits_strategy import NonceBitsStrategy
from rabin.padding.padding_strategy import PaddingStrategy


class FileRabinCryptosystem(RabinCryptosystem):
    def __init__(self, ps: Optional[PaddingStrategy] = None):
        super().__init__(ps)

    def encrypt(self, pk: RabinPublicKey, plaintext_file: str) -> str:
        """
        Encrypts given plaintext_file, returns path to encrypted file path.
        """
        encrypted_file_path = plaintext_file + '.enc'
        with open(plaintext_file, 'rb') as plaintext_file:
            with open(encrypted_file_path, 'w') as encrypted_file:
                # write padding to the encrypted file as a header
                if type(self._ps) == NonceBitsStrategy:
                    encrypted_file.write(f'{self._ps.nonce}\n')

                cs = IntegerRabinCryptosystem(self._ps)

                plaintext_bytes = plaintext_file.read(BLOCK_SIZE_BYTES)
                while plaintext_bytes:
                    # read bytes and convert them as big endian to int
                    plaintext = self._bytes_to_int(plaintext_bytes)
                    # encrypt the int
                    ciphertext = cs.encrypt(pk, plaintext)
                    # write it as plain int
                    encrypted_file.write(f'{ciphertext}\n')
                    # read next bytes
                    plaintext_bytes = plaintext_file.read(BLOCK_SIZE_BYTES)

        return encrypted_file_path

    def decrypt(self, sk: RabinCryptoKey, ciphertext_file: str) -> str:
        """
        Decrypts the given encrypted file, returns decrypted file path.
        """
        decrypted_file_path = ciphertext_file + '.dec'
        with open(ciphertext_file, 'r') as encrypted_file:
            with open(decrypted_file_path, 'wb') as decrypted_file:
                # read header and initialize nonce
                if type(self._ps) == NonceBitsStrategy:
                    self._initialize_nonce(encrypted_file)

                cs = IntegerRabinCryptosystem(self._ps)

                for ciphertext in encrypted_file.readlines():
                    # decrypt block by block
                    plaintext = cs.decrypt(sk, int(ciphertext))
                    # convert integer to bytes
                    plaintext_bytes = self._int_to_bytes(plaintext)
                    # write the bytes
                    decrypted_file.write(plaintext_bytes)

        return decrypted_file_path

    @staticmethod
    def _int_to_bytes(integer: int) -> bytes:
        return integer.to_bytes((integer.bit_length() + 7) // 8, 'big') or b'\0'

    @staticmethod
    def _bytes_to_int(bts: bytes) -> int:
        return int.from_bytes(bts, 'big')

    def _initialize_nonce(self, ciphertext_file: TextIO):
        nonce = int(ciphertext_file.readline())
        self._ps = NonceBitsStrategy(nonce)
