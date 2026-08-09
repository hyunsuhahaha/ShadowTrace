"""Minimal ULID generator (stdlib only).

ULIDs are lexically sortable by creation time, which the tree engine relies on
for its ``(created_at, id)`` tie-break (spec 2.2). No external dependency.
"""
from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32, no I L O U


def new_ulid() -> str:
    timestamp = int(time.time() * 1000) & ((1 << 48) - 1)  # 48-bit ms
    value = (timestamp << 80) | int.from_bytes(os.urandom(10), "big")  # +80 rand
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))
