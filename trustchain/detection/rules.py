"""Deterministic rules: the static, threshold-based detectors from the original IDS."""
from __future__ import annotations

from typing import Any

REQUEST_FLOOD_THRESHOLD = 10.0
BAD_REQUEST_THRESHOLD = 5.0
PROBE_ENDPOINTS_THRESHOLD = 8
BRUTE_FORCE_THRESHOLD = 3
TEMPERATURE_HIGH = 40.0
TEMPERATURE_LOW = 0.0
HUMIDITY_HIGH = 90.0

SEVERITY = {  # 0..1, feeds the risk formula
    "BRUTE_FORCE": 0.85,
    "REQUEST_FLOOD": 0.75,
    "SERVICE_PROBING": 0.65,
    "SENSOR_ANOMALY": 0.6,
    "REPLAY": 0.8,
    "SPOOFING": 0.9,
    "ROGUE_DEVICE": 0.9,
    "AUDIT_TAMPERING": 0.95,
    "STEALTH_SURGE": 0.55,
    "ML_BEHAVIOR_ANOMALY": 0.5,
}


def static_rules(s: dict[str, Any]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    if s.get("req_rate", 0) >= REQUEST_FLOOD_THRESHOLD:
        hits.append({"type": "REQUEST_FLOOD", "severity": SEVERITY["REQUEST_FLOOD"], "why": f"req_rate {s['req_rate']:.1f}/s ≥ {REQUEST_FLOOD_THRESHOLD:g}"})
    if s.get("bad_req_rate", 0) >= BAD_REQUEST_THRESHOLD or s.get("endpoints_hit", 0) >= PROBE_ENDPOINTS_THRESHOLD:
        hits.append({"type": "SERVICE_PROBING", "severity": SEVERITY["SERVICE_PROBING"], "why": f"bad_req {s.get('bad_req_rate', 0):.1f}/s, {s.get('endpoints_hit', 0)} endpoints"})
    if s.get("failed_auth", 0) >= BRUTE_FORCE_THRESHOLD:
        hits.append({"type": "BRUTE_FORCE", "severity": SEVERITY["BRUTE_FORCE"], "why": f"{s['failed_auth']} failed PIN attempts in window"})
    t = s.get("temperature")
    if t is not None and (t > TEMPERATURE_HIGH or t < TEMPERATURE_LOW):
        hits.append({"type": "SENSOR_ANOMALY", "severity": SEVERITY["SENSOR_ANOMALY"], "why": f"temperature {t:.1f}°C outside {TEMPERATURE_LOW:g}–{TEMPERATURE_HIGH:g}"})
    h = s.get("humidity")
    if h is not None and h > HUMIDITY_HIGH and not any(x["type"] == "SENSOR_ANOMALY" for x in hits):
        hits.append({"type": "SENSOR_ANOMALY", "severity": 0.45, "why": f"humidity {h:.0f}% > {HUMIDITY_HIGH:g}"})
    return sorted(hits, key=lambda x: -x["severity"])
