"""Automated response (Module F): command authorisation under quarantine, blocklist."""
from __future__ import annotations

from typing import Any

# Commands each device *type* understands (used for dashboard control and the gateway enforcement demo).
COMMANDS: dict[str, list[str]] = {
    "smart_home_node": ["lock", "unlock", "led_on", "led_off"],
    "security_node": ["test_alarm", "clear_alarm"],
    "door_sensor": [],
    "bulb": ["on", "off"],
    "fan": ["on", "off"],
    "tv": ["on", "off"],
    "soundbar": ["on", "off", "mute"],
    "robot_vacuum": ["start", "dock"],
    "blinds": ["open", "close"],
    "air_purifier": ["on", "off"],
    "fridge": ["boost_cool", "normal"],
    "oven": ["preheat", "off"],
    "dishwasher": ["start", "stop"],
    "coffee_machine": ["brew", "off"],
    "router": ["reboot"],
    "thermostat": ["eco", "comfort"],
    "smoke_detector": ["test"],
    "smart_bed": ["warm", "off"],
    "ac": ["on", "off", "eco"],
    "smart_speaker": ["on", "off"],
    "water_heater": ["on", "off", "boost"],
    "shower": ["start", "stop"],
    "smart_mirror": ["on", "off"],
    "leak_sensor": [],
    "nas": [],
    "printer": [],
    "washer": ["start", "stop"],
    "dryer": ["start", "stop"],
    "energy_meter": [],
    "home_battery": ["grid_charge", "hold"],
    "solar_inverter": [],
    "garage_door": ["open", "close"],
    "ev_charger": ["start", "stop"],
    "irrigation": ["start", "stop"],
    "pool_pump": ["start", "stop"],
    "doorbell": [],
    "camera": ["privacy_on", "privacy_off"],
}

# Minimum trust the *originating device* needs to issue a command through the gateway.
MIN_TRUST = {"unlock": 70, "open": 70, "preheat": 60, "reboot": 70, "privacy_off": 60}
DEFAULT_MIN_TRUST = 40

# Commands that REDUCE hazard are still honoured when the target is quarantined, so isolating a device
# can never leave it stuck in a dangerous state (oven on, pool pump running, garage door open ...).
ALLOW_WHEN_QUARANTINED: dict[str, set[str]] = {
    "smart_home_node": {"lock"},
    "garage_door": {"close"},
    "oven": {"off"},
    "water_heater": {"off"},
    "shower": {"stop"},
    "ev_charger": {"stop"},
    "pool_pump": {"stop"},
    "irrigation": {"stop"},
    "dishwasher": {"stop"},
    "washer": {"stop"},
    "dryer": {"stop"},
    "coffee_machine": {"off"},
    "smart_bed": {"off"},
    "robot_vacuum": {"dock"},
    "blinds": {"close"},
}

LOCK_POLICY = (
    "FAIL-SECURE: remote/network commands are blocked, the lock keeps its current state, and local "
    "keypad / mechanical override stays available so nobody is locked in or out."
)

QUARANTINE_POLICY = {
    "fail-secure": "FAIL-SECURE: keeps its current state; remote open/unlock is blocked, a remote close/lock is still honoured, and local access keeps working.",
    "fail-safe-off": "FAIL-SAFE: remote start is blocked, but a remote OFF / stop is still honoured so the device can always be made safe.",
    "keep-running": "KEEP-RUNNING: the service is never interrupted (cooling, connectivity, alarms, backups); only remote control commands are blocked.",
    "standard": "Remote commands are blocked while the device is quarantined.",
}


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
