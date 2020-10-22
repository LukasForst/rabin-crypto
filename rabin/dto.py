from dataclasses import dataclass


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
