from typing import List

from rabin.padding.padding_strategy import PaddingStrategy


class CopyBitsStrategy(PaddingStrategy):
    """
    Strategy when "padding_bits" from the end of the number
    are appended to the end of the number.

    The issue with this is, that it works only with the numbers that
    are at least "padding_bits" long.

    The "padding_bits" parameter also specifies the robustness
    of the algorithm in a way, that more bits used means that the padding
    is more robust and the probability of wrong choice of the result is lower.

    Probability of choosing wrong result is 1/2^(padding_bits + 1).

    The benchmarks show that "padding_bits" should be at least 16.
    """

    def __init__(self, padding_bits: int = 16):
        self._padding_bits = padding_bits

    def pad_plaintext(self, plaintext: int) -> int:
        # check if the binary string has enough bites
        if plaintext.bit_length() < self._padding_bits:
            raise ValueError(f'It is not possible to pad numbers '
                             f'that have less then {self._padding_bits}, '
                             f'but {plaintext.bit_length()} was given!')
        # convert to a binary string (b'0101')
        binary_string = bin(plaintext)
        # pad the last _padding_bits bits to the end
        output = binary_string + binary_string[-self._padding_bits:]
        # convert back to integer
        return int(output, 2)

    def extract_plaintext(self, candidates: List[int]) -> int:
        # select candidate
        padded_plaintext = self._choose_candidate(candidates)
        # convert to a binary string (b'0101')
        binary_string = bin(padded_plaintext)
        # remove padding
        binary_string = binary_string[:-self._padding_bits]
        # convert back to integer
        return int(binary_string, 2)

    def _choose_candidate(self, candidates: List[int]) -> int:
        for i in candidates:
            binary = bin(i)
            # take the last _padding_bits
            append = binary[-self._padding_bits:]
            # remove the last _padding_bits
            binary = binary[:-self._padding_bits]
            if append == binary[-self._padding_bits:]:
                return i

        raise ValueError('It was not possible to determine candidate!')
