"""Attack fingerprinting: normalise attack characteristics -> SHA-256 -> compact id."""
from __future__ import annotations

from typing import Any

from .crypto import canonical, sha256_hex


def _bucket(v: float, edges: list[float]) -> int:
    for i, e in enumerate(edges):
        if v < e:
            return i
    return len(edges)


def attack_fingerprint(event_type: str, device_id: str, source: str | None, port: int | None,
                       protocol: str | None, req_rate: float, failed_auth: int) -> str:
    """Timestamp is deliberately excluded so that a *repeat* of the same attack matches."""
    norm = {
        "type": event_type,
        "device": device_id,
        "source": source or "unknown",
        "port": port or 0,
        "proto": protocol or "unknown",
        "rate_bucket": _bucket(req_rate, [2, 5, 10, 20, 40]),
        "fail_bucket": _bucket(failed_auth, [1, 3, 6, 10]),
    }
    return sha256_hex(canonical(norm))[:16]
