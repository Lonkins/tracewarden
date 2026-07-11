"""Small text utilities shared by detectors."""

from __future__ import annotations

import hashlib
import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Bits per character. Random base64-ish secrets sit around 4.5-6."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def digest(value: str) -> str:
    """Stable short hash for loop/repeat bookkeeping (never reversible evidence)."""
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def luhn_valid(digits: str) -> bool:
    """Luhn checksum — keeps random 16-digit numbers from flagging as cards."""
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
