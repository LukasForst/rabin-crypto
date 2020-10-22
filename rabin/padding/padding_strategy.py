from typing import List


class PaddingStrategy:
    def pad_plaintext(self, plaintext: int) -> int:
        """
        Pads given plaintext in a way that it is possible to
        recover the original value after the decryption.
        """
        raise NotImplemented('Should be overridden!')

    def extract_plaintext(self, candidates: List[int]) -> int:
        """
        Choose candidate from the 4 options, detect plaintext
        and delete padding.
        """
        raise NotImplemented('Should be overridden!')
