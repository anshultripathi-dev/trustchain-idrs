"""Trust & risk engine (Module D).

risk = bounded noisy-OR of five signals, so every signal can only push risk up and the
result stays in [0, 1]:

    rule severity · ML anomaly · baseline deviation · low trust · ledger-integrity status
"""
from __future__ import annotations

from typing import Any

# base trust penalty per event class (calibrate through testing -- these are policy values)
TRUST_DELTA = {
    "BRUTE_FORCE": 15,
    "SERVICE_PROBING": 20,
    "REQUEST_FLOOD": 22,
    "SENSOR_ANOMALY": 12,
    "STEALTH_SURGE": 14,
    "ML_BEHAVIOR_ANOMALY": 10,
    "REPLAY": 25,
    "SPOOFING": 35,
    "ROGUE_DEVICE": 40,
    "AUDIT_TAMPERING": 30,
}
DEFAULT_DELTA = 10

W_RULE, W_ML, W_BASE, W_TRUST, W_INTEGRITY = 0.80, 0.50, 0.55, 0.40, 0.90
BANDS = [(0.25, "SAFE"), (0.50, "SUSPICIOUS"), (0.92, "HIGH"), (1.01, "CRITICAL")]
BAND_SEVERITY = {"SAFE": "LOW", "SUSPICIOUS": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
REGEN_PER_STEP = 2.0
REGEN_EVERY_CLEAN_TICKS = 6
REGEN_COOLDOWN_TICKS = 20


def risk_score(rule: float, ml: float, baseline_dev: float, trust: float, integrity_open: bool) -> tuple[float, dict[str, float]]:
    trust_pen = max(0.0, min(1.0, (100.0 - trust) / 100.0))
    parts = {
        "rule": W_RULE * max(0.0, min(1.0, rule)),
        "ml": W_ML * max(0.0, min(1.0, ml)),
        "baseline": W_BASE * max(0.0, min(1.0, baseline_dev)),
        "trust": W_TRUST * trust_pen,
        "integrity": W_INTEGRITY * (1.0 if integrity_open else 0.0),
    }
    keep = 1.0
    for v in parts.values():
        keep *= 1.0 - v
    return round(1.0 - keep, 4), {k: round(v, 3) for k, v in parts.items()}


def band(risk: float) -> str:
    for limit, name in BANDS:
        if risk < limit:
            return name
    return "CRITICAL"


def baseline_deviation(req_z: float, primary_z: float, warm: bool) -> float:
    """Map |z| to 0..1: |z|<=3 is normal variation, saturating at |z|=12."""
    if not warm:
        return 0.0
    z = max(abs(req_z), abs(primary_z))
    return max(0.0, min(1.0, (z - 3.0) / 9.0))


def penalty(event_type: str, repeat_count: int) -> float:
    base = TRUST_DELTA.get(event_type, DEFAULT_DELTA)
    return base * (1.0 + 0.5 * min(repeat_count, 3))   # attack memory amplifies the penalty


class TrustTracker:
    """Live per-device trust with slow, bounded regeneration while behaving cleanly."""

    def __init__(self) -> None:
        self.clean_ticks: dict[str, int] = {}
        self.since_event: dict[str, int] = {}

    def note_event(self, device_id: str) -> None:
        self.clean_ticks[device_id] = 0
        self.since_event[device_id] = 0

    def note_clean(self, device_id: str) -> bool:
        """Returns True when a regeneration step is due."""
        self.since_event[device_id] = self.since_event.get(device_id, 10**6) + 1
        if self.since_event[device_id] < REGEN_COOLDOWN_TICKS:
            return False
        n = self.clean_ticks.get(device_id, 0) + 1
        self.clean_ticks[device_id] = n
        if n >= REGEN_EVERY_CLEAN_TICKS:
            self.clean_ticks[device_id] = 0
            return True
        return False
