"""Automated response (Module F): command authorisation under quarantine, blocklist."""
from __future__ import annotations

from typing import Any

# Commands each device kind understands (used by the command-enforcement demo).
COMMANDS = {
    "smart_home_node": ["lock", "unlock", "led_on", "led_off"],
    "bulb": ["on", "off"],
    "fan": ["on", "off"],
    "security_node": ["test_alarm", "clear_alarm"],
    "door_sensor": [],
}
# Minimum trust the *originating device* needs to issue a command through the gateway.
MIN_TRUST = {"unlock": 70}
DEFAULT_MIN_TRUST = 40

LOCK_POLICY = (
    "FAIL-SECURE: remote/network commands are blocked, the lock keeps its current state, and local "
    "keypad / mechanical override stays available so nobody is locked in or out."
)


class Blocklist:
    def __init__(self, ttl_s: float = 120.0):
        self.ttl = ttl_s
        self._d: dict[str, float] = {}

    def add(self, source: str, now: float) -> bool:
        new = source not in self._d or self._d[source] < now
        self._d[source] = now + self.ttl
        return new

    def blocked(self, source: str | None, now: float) -> bool:
        return bool(source) and self._d.get(source, 0) > now

    def entries(self, now: float) -> list[dict[str, Any]]:
        return [{"source": s, "expires_in": round(t - now, 1)} for s, t in self._d.items() if t > now]

    def clear(self) -> None:
        self._d.clear()
