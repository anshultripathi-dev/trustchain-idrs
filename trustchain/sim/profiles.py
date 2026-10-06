"""Device profiles and the traffic generator shared by the live simulator and ML training.

Everything a device reports per tick is a flat `sample` dict:

    req_rate, bad_req_rate, failed_auth, endpoints_hit, primary, rssi
    (+ temperature / humidity for the smart-home node)
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

import numpy as np

ATTACKS = {
    "BRUTE_FORCE": {"label": "Brute-force PIN", "layer": "traffic", "desc": "Repeated wrong PIN attempts against the smart lock."},
    "REQUEST_FLOOD": {"label": "Request flood", "layer": "traffic", "desc": "High-volume HTTP flood against the device."},
    "SERVICE_PROBING": {"label": "Service probing", "layer": "traffic", "desc": "Port / endpoint scan generating many bad requests."},
    "SENSOR_ANOMALY": {"label": "Sensor manipulation", "layer": "traffic", "desc": "Abnormal temperature / sensor values (spoofed or tampered sensor)."},
    "STEALTH_SURGE": {"label": "Low-and-slow surge", "layer": "traffic", "desc": "Stays under every static threshold; only visible against the time-of-day baseline."},
    "REPLAY": {"label": "Replay attack", "layer": "crypto", "desc": "Re-sends a previously captured, validly signed message."},
    "SPOOFING": {"label": "Identity spoofing", "layer": "crypto", "desc": "Claims a registered device ID but signs with a different key."},
    "ROGUE_DEVICE": {"label": "Rogue device joins", "layer": "crypto", "desc": "An unregistered node tries to join the network."},
}
TRAFFIC_ATTACKS = [k for k, v in ATTACKS.items() if v["layer"] == "traffic"]


@dataclass(frozen=True)
class Profile:
    kind: str
    name: str
    req_lo: float          # req/s at quietest hour
    req_hi: float          # req/s at busiest hour
    primary_name: str
    primary_lo: float
    primary_hi: float
    primary_sd: float
    has_env: bool = False  # reports temperature/humidity
    rssi: float = -58.0


PROFILES: dict[str, Profile] = {
    "smart_home_node": Profile("smart_home_node", "ESP-1 Smart Home Node", 0.8, 4.5, "temperature", 24.0, 31.0, 0.5, True, -55),
    "security_node": Profile("security_node", "ESP-2 Security Node", 0.3, 1.6, "uptime_load", 8.0, 14.0, 0.8, False, -52),
    "bulb": Profile("bulb", "Smart Bulb", 0.2, 1.2, "power_w", 2.0, 9.0, 0.4, False, -63),
    "fan": Profile("fan", "Smart Fan", 0.2, 1.0, "rpm_pct", 10.0, 60.0, 3.0, False, -66),
    "door_sensor": Profile("door_sensor", "Door Sensor", 0.1, 0.9, "events_per_min", 0.2, 3.0, 0.3, False, -61),
}


def activity(hour: float) -> float:
    """0..1 household activity; quietest ~06:00, busiest ~18:00."""
    return 0.5 * (1 + math.cos(2 * math.pi * (hour - 18.0) / 24.0))


def normal_sample(p: Profile, hour: float, rng: np.random.Generator) -> dict[str, Any]:
    a = activity(hour)
    req = p.req_lo + (p.req_hi - p.req_lo) * a
    req *= max(0.2, 1 + rng.normal(0, 0.12))
    if rng.random() < 0.01:                      # benign burst (user opens the app)
        req *= rng.uniform(1.6, 2.2)
    primary = p.primary_lo + (p.primary_hi - p.primary_lo) * a + rng.normal(0, p.primary_sd)
    s: dict[str, Any] = {
        "req_rate": round(max(0.0, req), 3),
        "bad_req_rate": round(float(max(0.0, rng.normal(0.15, 0.2))), 3),
        "failed_auth": int(rng.random() < 0.01),  # a fat-fingered PIN now and then
        "endpoints_hit": int(rng.integers(1, 4)),
        "primary": round(float(primary), 3),
        "rssi": round(float(p.rssi + rng.normal(0, 2)), 1),
    }
    if p.has_env:
        s["temperature"] = s["primary"]
        s["humidity"] = round(float(55 + 12 * math.sin(2 * math.pi * (hour - 9) / 24) + rng.normal(0, 2)), 1)
    return s


def apply_attack(sample: dict[str, Any], attack: str, p: Profile, hour: float, rng: np.random.Generator) -> dict[str, Any]:
    s = dict(sample)
    if attack == "BRUTE_FORCE":
        s["failed_auth"] = int(rng.integers(3, 7))
        s["req_rate"] = round(s["req_rate"] + rng.uniform(1.5, 4.0), 3)
        s["bad_req_rate"] = round(s["bad_req_rate"] + rng.uniform(0.5, 2.0), 3)
    elif attack == "REQUEST_FLOOD":
        s["req_rate"] = round(float(rng.uniform(18, 45)), 3)
        s["bad_req_rate"] = round(s["bad_req_rate"] + rng.uniform(0, 2.5), 3)
        s["endpoints_hit"] = int(rng.integers(1, 5))
    elif attack == "SERVICE_PROBING":
        s["req_rate"] = round(s["req_rate"] + rng.uniform(2.0, 5.0), 3)
        s["bad_req_rate"] = round(float(rng.uniform(6, 14)), 3)
        s["endpoints_hit"] = int(rng.integers(9, 26))
    elif attack == "SENSOR_ANOMALY":
        shift = rng.choice([-1, 1]) * rng.uniform(12, 26)
        s["primary"] = round(s["primary"] + shift, 3)
        if p.has_env:
            s["temperature"] = s["primary"]
            s["humidity"] = round(min(99.0, s["humidity"] + rng.uniform(5, 30)), 1)
        s["req_rate"] = round(s["req_rate"] * rng.uniform(1.0, 1.6), 3)
    elif attack == "STEALTH_SURGE":
        # Stays below the static flood threshold (10 req/s) but is a many-sigma surge
        # relative to what this device normally does at this hour.
        if activity(hour) < 0.35:   # quiet hours: a few req/s is already a huge deviation
            req = max(s["req_rate"] * rng.uniform(3.0, 4.5), rng.uniform(5.2, 7.5))
        else:
            req = s["req_rate"] * rng.uniform(1.9, 2.4) + 3.0
        s["req_rate"] = round(float(min(req, 9.0)), 3)
        s["bad_req_rate"] = round(s["bad_req_rate"] + rng.uniform(0.4, 1.4), 3)
        s["endpoints_hit"] = int(rng.integers(4, 8))
    return s


def attack_source(attack: str, rng: np.random.Generator, fixed: str | None = None) -> dict[str, Any]:
    """Network metadata the gateway would observe for an attack session."""
    ports = {"BRUTE_FORCE": 80, "REQUEST_FLOOD": 80, "SERVICE_PROBING": 0, "SENSOR_ANOMALY": 80, "STEALTH_SURGE": 80,
             "REPLAY": 80, "SPOOFING": 80, "ROGUE_DEVICE": 80}
    proto = {"SERVICE_PROBING": "TCP-SYN"}.get(attack, "HTTP")
    return {"source": fixed or f"192.168.1.{int(rng.integers(40, 250))}", "port": ports.get(attack, 80), "protocol": proto}
