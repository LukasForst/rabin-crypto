from typing import List

from rabin.padding.padding_strategy import PaddingStrategy


class FixedPaddingBitsStrategy(PaddingStrategy):
    """
    Uses given padding as padding for the numbers.

    The benchmarks show that the padding should be at least 16 bits big.
    """

    def __init__(self, padding: int):
        self.padding = padding
        self._padding_bits = bin(padding)[2:]
        self._padding_bits_size = len(self._padding_bits)

    def pad_plaintext(self, plaintext: int) -> int:
        # convert to a binary string (b'0101')
        binary_plaintext = bin(plaintext)
        # pad the last padding to the end
        output = binary_plaintext + self._padding_bits
        # convert back to integer
        return int(output, 2)

    def extract_plaintext(self, candidates: List[int]) -> int:
        # select candidate
        padded_plaintext = self._choose_candidate(candidates)
        # convert to a binary string (b'0101')
        binary_string = bin(padded_plaintext)
        # remove padding
        binary_string = binary_string[:-self._padding_bits_size]
        # convert back to integer
        return int(binary_string, 2)

    def _choose_candidate(self, candidates: List[int]) -> int:
        matching_candidates = []
        for i in candidates:
            binary = bin(i)
            # take the last _padding_bits_size
            nonce = binary[-self._padding_bits_size:]
            if nonce == self._padding_bits:
                matching_candidates.append(i)

        if len(matching_candidates) != 1:
            raise ValueError('It was not possible to determine candidate! '
                             f'There were {len(matching_candidates)} plaintext candidates!')

        return matching_candidates[0]
