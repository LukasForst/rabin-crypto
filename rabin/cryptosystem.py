from typing import Optional

from rabin.dto import RabinPublicKey, RabinCryptoKey
from rabin.padding.copy_bits_strategy import CopyBitsStrategy
from rabin.padding.padding_strategy import PaddingStrategy
from rabin.prime import generate_rabin_key, euklids_algorithm


class RabinCryptosystem:
    def __init__(self, ps: Optional[PaddingStrategy] = None):
        self.ps = ps if ps else CopyBitsStrategy()

    def encrypt(self, pk: RabinPublicKey, plaintext) -> int:
        """
        Encrypts given plaintext.
        """
        plaintext = self.ps.pad_plaintext(plaintext)
        # ensure that plaintext is smaller then n
        if plaintext > pk.n:
            raise ValueError('Padded plaintext was bigger then public key N! '
                             'Can not encrypt!')
        # m^2 mod n
        return pow(plaintext, 2, pk.n)

    def decrypt(self, sk: RabinCryptoKey, ciphertext: int) -> int:
        """
        Decrypts the ciphertext.
        """
        p, q, n = sk.decompose()

        mp = self._square_root_dec(p, ciphertext)
        mq = self._square_root_dec(q, ciphertext)

        gcd, yp, yq = euklids_algorithm(p, q)
        assert gcd == 1, f'GCD of two primes must be 1 but was {gcd} for p={p},q={q}'

        r1 = (yp * p * mq + yq * q * mp) % n
        r2 = n - r1
        r3 = (yp * p * mq - yq * q * mp) % n
        r4 = n - r3

        return self.ps.extract_plaintext([r1, r2, r3, r4])

    @staticmethod
    def generate_key() -> RabinCryptoKey:
        """
        Generates key material for the Rabin.
        """
        return generate_rabin_key()

    @staticmethod
    def _square_root_dec(p: int, c: int) -> int:
        # (p + 1) / 4 will be always integer
        # because the secret keys are chosen
        # with constraint p % 4 == 3, see generate_rabin_key
        assert p % 4 == 3, f'It must hold p % 4 == 3 for Rabin crypto, but was {p % 4}'

        return pow(c, (p + 1) // 4, p)
