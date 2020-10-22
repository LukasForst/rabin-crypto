from typing import Tuple


def euklids_algorithm(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1

    gcd, x1, y1 = euklids_algorithm(b % a, a)
    
    x = y1 - (b // a) * x1
    y = x1

    return gcd, x, y
