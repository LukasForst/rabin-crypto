import Crypto.Util.number as number

from rabin.crypto_configuration import PRIME_LENGTH_BITS
from rabin.dto import RabinCryptoKey, RabinSecretKey, RabinPublicKey


def generate_rabin_key(bit_len: int = PRIME_LENGTH_BITS) -> RabinCryptoKey:
    p, q = _get_private_key_prime(bit_len), _get_private_key_prime(bit_len)
    return RabinCryptoKey(
        private=RabinSecretKey(p=p, q=q),
        public=RabinPublicKey(n=p * q)
    )


def _get_private_key_prime(bit_len: int) -> int:
    while True:
        p = number.getPrime(bit_len)
        if p % 4 == 3:
            return p
