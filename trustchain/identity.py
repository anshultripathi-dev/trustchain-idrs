"""Device-bound identity: signed envelopes with timestamp + single-use nonce (Modules A/B).

Envelope wire format (friendly to firmware: the device signs the exact payload string):

    {"device_id": "...", "payload": "<canonical JSON string>", "signature": "<hex DER ECDSA-P256>"}

payload = {"device_id", "timestamp", "nonce", ...metrics}
"""
from __future__ import annotations

import json
import secrets
from collections import OrderedDict
from typing import Any

from .crypto import KeyPair, canonical, verify
from .ledger.contract import SecurityContract


class DeviceIdentity:
    """Device side: holds the private key and signs outgoing telemetry."""

    def __init__(self, device_id: str, keypair: KeyPair):
        self.device_id = device_id
        self.keypair = keypair

    def sign(self, metrics: dict[str, Any], timestamp: float, nonce: str | None = None, claimed_id: str | None = None) -> dict[str, Any]:
        did = claimed_id or self.device_id
        body = {"device_id": did, "timestamp": round(timestamp, 3), "nonce": nonce or secrets.token_hex(6), **metrics}
        payload = canonical(body).decode()
        return {"device_id": did, "payload": payload, "signature": self.keypair.sign(payload.encode())}


class NonceCache:
    def __init__(self, max_items: int = 5000):
        self._d: OrderedDict[str, float] = OrderedDict()
        self.max = max_items

    def seen(self, key: str) -> bool:
        return key in self._d

    def add(self, key: str, ts: float) -> None:
        self._d[key] = ts
        while len(self._d) > self.max:
            self._d.popitem(last=False)


class Verdict:
    __slots__ = ("ok", "reason", "device_id", "metrics", "ts")

    def __init__(self, ok: bool, reason: str, device_id: str | None, metrics: dict[str, Any] | None = None, ts: float = 0.0):
        self.ok, self.reason, self.device_id, self.metrics, self.ts = ok, reason, device_id, metrics, ts


class IdentityVerifier:
    """Gateway side: checks registry membership, signature, freshness and nonce uniqueness."""

    def __init__(self, contract: SecurityContract, clock, window_s: float = 30.0):
        self.contract = contract
        self.clock = clock
        self.window_s = window_s
        self.nonces = NonceCache()

    def verify(self, env: dict[str, Any]) -> Verdict:
        did = env.get("device_id")
        try:
            payload = json.loads(env["payload"])
            sig = env["signature"]
        except (KeyError, ValueError, TypeError):
            return Verdict(False, "MALFORMED", did)
        dev = self.contract.get_device(did) if did else None
        if dev is None or dev.get("unregistered") or not dev.get("pubkey"):
            return Verdict(False, "UNKNOWN_DEVICE", did)
        if payload.get("device_id") != did or not verify(dev["pubkey"], env["payload"].encode(), sig):
            return Verdict(False, "BAD_SIGNATURE", did)
        ts = float(payload.get("timestamp", 0))
        if abs(self.clock.now() - ts) > self.window_s:
            return Verdict(False, "STALE_TIMESTAMP", did)
        key = f"{did}:{payload.get('nonce')}"
        if self.nonces.seen(key):
            return Verdict(False, "REPLAY", did)
        self.nonces.add(key, ts)
        return Verdict(True, "OK", did, payload, ts)
