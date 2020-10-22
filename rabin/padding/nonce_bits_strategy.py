from typing import List

from rabin.padding.padding_strategy import PaddingStrategy


class NonceBitsStrategy(PaddingStrategy):
    """
    Uses given nonce as padding for the numbers.

    The benchmarks show that the nonce should be at least 16 bits big.
    """

    def __init__(self, nonce: int):
        self._nonce = bin(nonce)[2:]
        self._nonce_size = len(self._nonce)

    def pad_plaintext(self, plaintext: int) -> int:
        # convert to a binary string (b'0101')
        binary_plaintext = bin(plaintext)
        # pad the last nonce to the end
        output = binary_plaintext + self._nonce
        # convert back to integer
        return int(output, 2)

    def extract_plaintext(self, candidates: List[int]) -> int:
        # select candidate
        padded_plaintext = self._choose_candidate(candidates)
        # convert to a binary string (b'0101')
        binary_string = bin(padded_plaintext)
        # remove padding
        binary_string = binary_string[:-self._nonce_size]
        # convert back to integer
        return int(binary_string, 2)

    def _choose_candidate(self, candidates: List[int]) -> int:
        for i in candidates:
            binary = bin(i)
            # take the last _nonce_size
            nonce = binary[-self._nonce_size:]
            if nonce == self._nonce:
                return i

        raise ValueError('It was not possible to determine candidate!')
