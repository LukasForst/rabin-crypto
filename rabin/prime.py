from typing import Tuple

import Crypto.Util.number as number

from rabin.crypto_configuration import PRIME_LENGTH_BITS
from rabin.dto import RabinCryptoKey, RabinSecretKey, RabinPublicKey


def euklids_algorithm(a: int, b: int) -> Tuple[int, int, int]:
    """
    Euklids algorithm returning GCD = X*a + Y*b.
    >>> a, b = 3, 13
    >>> gcd, ax, by = euklids_algorithm(a, b)
    >>> gcd == ax*a + by*b
    >>> True
    """
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = euklids_algorithm(b % a, a)

    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y


def generate_rabin_key(bit_len: int = PRIME_LENGTH_BITS) -> RabinCryptoKey:
    """
    Securely generate whole key material for Rabin cryptosystem.
    """
    p, q = _get_private_key_prime(bit_len), _get_private_key_prime(bit_len)
    return RabinCryptoKey(
        private=RabinSecretKey(p=p, q=q),
        public=RabinPublicKey(n=p * q)
    )


def _get_private_key_prime(bit_len: int) -> int:
    while True:
        # cryptographically secure way how to generate prime number
        # internally it uses urandom, which is suitable for cryptographic use
        p = number.getPrime(bit_len)
        if p % 4 == 3:
            return p
