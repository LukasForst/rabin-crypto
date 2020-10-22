from typing import List

from rabin.dto import RabinPublicKey, RabinCryptoKey
from rabin.prime import generate_rabin_key
from rabin.utils import euklids_algorithm


def generate_key() -> RabinCryptoKey:
    return generate_rabin_key()


def encrypt(pk: RabinPublicKey, plaintext) -> int:
    # TODO check padding
    plaintext = _pad_plaintext(plaintext)
    # m^2 mod n
    return pow(plaintext, 2, pk.n)


# plaintext is a 224-bit number
def _pad_plaintext(plaintext: int) -> int:
    binary_str = bin(plaintext)  # convert to a bit string
    output = binary_str + binary_str[-16:]  # pad the last 16 bits to the end
    return int(output, 2)  # convert back to integer


def decrypt(sk: RabinCryptoKey, ciphertext: int) -> int:
    p, q, n = sk.decompose()

    mp = _square_root_dec(p, ciphertext)
    mq = _square_root_dec(q, ciphertext)

    gcd, yp, yq = euklids_algorithm(p, q)
    assert gcd == 1, f'GCD of two primes must be 1 but was {gcd} for p={p},q={q}'

    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    padded_plaintext = _choose_candidate([r1, r2, r3, r4])
    string = bin(padded_plaintext)
    string = string[:-16]
    plaintext = int(string, 2)
    return plaintext


def _choose_candidate(candidates: List[int]) -> int:
    for i in candidates:
        binary = bin(i)
        append = binary[-16:]  # take the last 16 bits
        binary = binary[:-16]  # remove the last 16 bits
        if append == binary[-16:]:
            return i

    raise ValueError('It was not possible to determine candidate!')


def _square_root_dec(p: int, c: int) -> int:
    # (p + 1) / 4 will be always integer
    # because the secret keys are chosen
    # with constraint p % 4 == 3, see generate_rabin_key
    assert p % 4 == 3, f'It must hold p % 4 == 3 for Rabin crypto, but was {p % 4}'

    return pow(c, (p + 1) // 4, p)
