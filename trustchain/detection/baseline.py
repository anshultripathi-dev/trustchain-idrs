"""Adaptive per-device, per-hour behavioural baseline (Welford statistics).

The same raw value is scored against what *this device* normally does at *this hour*,
instead of one fixed global threshold. Until enough samples exist the baseline reports
`warm=False` and the system leans on rules (honest cold-start behaviour).
"""
from __future__ import annotations

import json
import math
import threading
from typing import Any

import numpy as np

from ..sim.profiles import PROFILES, Profile, normal_sample

METRICS = ("req_rate", "primary")
SD_FLOOR = {"req_rate": 0.15, "primary": 0.3}
MAX_N = 600           # cap so the baseline keeps adapting to slow drift
MIN_N = 12            # per hour bucket before it is trusted


class Baseline:
    def __init__(self) -> None:
        self._s: dict[str, list[float]] = {}   # "key|metric|hour" -> [n, mean, M2]
        self._lock = threading.Lock()

    @staticmethod
    def _k(key: str, metric: str, h: int) -> str:
        return f"{key}|{metric}|{h % 24}"

    def update(self, key: str, hour: float, sample: dict[str, Any]) -> None:
        h = int(hour) % 24
        with self._lock:
            for m in METRICS:
                v = float(sample.get(m, 0.0))
                st = self._s.setdefault(self._k(key, m, h), [0.0, 0.0, 0.0])
                n, mean, m2 = st
                if n >= MAX_N:                       # exponential forgetting
                    a = 1.0 / MAX_N
                    d = v - mean
                    mean += a * d
                    m2 = (1 - a) * (m2 + a * d * d * n)
                else:
                    n += 1
                    d = v - mean
                    mean += d / n
                    m2 += d * (v - mean)
                st[0], st[1], st[2] = n, mean, m2

    def _stat(self, key: str, metric: str, h: int) -> tuple[float, float, float]:
        st = self._s.get(self._k(key, metric, h))
        if not st or st[0] < 2:
            return 0.0, 0.0, 0.0
        n, mean, m2 = st
        return n, mean, math.sqrt(max(m2 / (n - 1), 0.0))

    def expected(self, key: str, hour: float, metric: str) -> tuple[float, float, float]:
        """Interpolate between neighbouring hour buckets -> (mean, sd, min_n)."""
        h0 = int(math.floor(hour - 0.5)) % 24
        h1 = (h0 + 1) % 24
        frac = (hour - 0.5) - math.floor(hour - 0.5)
        n0, m0, s0 = self._stat(key, metric, h0)
        n1, m1, s1 = self._stat(key, metric, h1)
        if n0 == 0 or n1 == 0:
            return 0.0, 0.0, min(n0, n1)
        mean = (1 - frac) * m0 + frac * m1
        sd = max((1 - frac) * s0 + frac * s1, SD_FLOOR[metric], 0.04 * abs(mean))
        return mean, sd, min(n0, n1)

    def z(self, key: str, hour: float, metric: str, value: float) -> tuple[float, bool]:
        mean, sd, n = self.expected(key, hour, metric)
        if n < MIN_N or sd == 0:
            return 0.0, False
        return max(-25.0, min(25.0, (value - mean) / sd)), True

    def curve(self, key: str, metric: str = "req_rate") -> list[dict[str, float]]:
        out = []
        for h in range(24):
            mean, sd, n = self.expected(key, h + 0.5, metric)
            out.append({"hour": h, "mean": round(mean, 3), "sd": round(sd, 3), "n": n})
        return out

    def to_json(self) -> str:
        return json.dumps(self._s)

    def load_json(self, text: str) -> None:
        self._s = {k: list(v) for k, v in json.loads(text).items()}


def warm_baseline(baseline: Baseline, key: str, profile: Profile, days: int, rng: np.random.Generator,
                  step_minutes: float = 5.0) -> None:
    """Seed a baseline with synthetic normal behaviour (stands in for weeks of real learning)."""
    ticks = int(days * 24 * 60 / step_minutes)
    for i in range(ticks):
        hour = ((i * step_minutes) / 60.0) % 24
        baseline.update(key, hour, normal_sample(profile, hour, rng))
