from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class RabinSecretKey:
    p: int
    q: int


@dataclass(frozen=True)
class RabinPublicKey:
    n: int


@dataclass(frozen=True)
class RabinCryptoKey:
    private: RabinSecretKey
    public: RabinPublicKey

    def decompose(self) -> Tuple[int, int, int]:
        """
        Returns [p, q, n].
        """
        return self.private.p, self.private.q, self.public.n
