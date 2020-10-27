from typing import Optional

from rabin.dto import RabinPublicKey, RabinCryptoKey
from rabin.padding.copy_bits_strategy import CopyBitsStrategy
from rabin.padding.padding_strategy import PaddingStrategy
from rabin.prime import generate_rabin_key


class RabinCryptosystem:
    def __init__(self, ps: Optional[PaddingStrategy] = None):
        self._ps = ps if ps else CopyBitsStrategy()

    def encrypt(self, pk: RabinPublicKey, plaintext):
        """
        Encrypts given plaintext.
        """
        raise NotImplemented('Should be overridden!')

    def decrypt(self, sk: RabinCryptoKey, ciphertext):
        """
        Decrypts the ciphertext.
        """
        raise NotImplemented('Should be overridden!')

    @staticmethod
    def generate_key() -> RabinCryptoKey:
        """
        Generates key material for the Rabin.
        """
        return generate_rabin_key()
