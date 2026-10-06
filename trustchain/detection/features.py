"""Feature engineering shared by training and live inference."""
from __future__ import annotations

from typing import Any

import numpy as np

from .baseline import Baseline

FEATURES = ["req_rate", "bad_req_rate", "failed_auth", "endpoints_hit", "primary_z", "req_z"]


def extract(baseline: Baseline, key: str, hour: float, s: dict[str, Any]) -> tuple[np.ndarray, dict[str, Any]]:
    req_z, warm_r = baseline.z(key, hour, "req_rate", float(s["req_rate"]))
    prim_z, warm_p = baseline.z(key, hour, "primary", float(s["primary"]))
    vec = np.array([
        float(s["req_rate"]),
        float(s["bad_req_rate"]),
        float(s["failed_auth"]),
        float(s["endpoints_hit"]),
        abs(prim_z),
        req_z,
    ])
    return vec, {"req_z": round(req_z, 2), "primary_z": round(prim_z, 2), "warm": bool(warm_r and warm_p)}
