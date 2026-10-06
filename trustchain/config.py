"""Runtime configuration (environment driven; no network credentials in the repo)."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv() -> None:
    path = os.path.join(ROOT, ".env")
    if not os.path.exists(path):
        return
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()


class Clock:
    """Wall clock for live runs; virtual clock for fast headless evaluation."""

    def __init__(self, virtual: bool = False, start: float | None = None):
        self.virtual = virtual
        self._t = start if start is not None else 1_800_000_000.0

    def now(self) -> float:
        return self._t if self.virtual else time.time()

    def advance(self, seconds: float) -> None:
        if self.virtual:
            self._t += seconds


@dataclass
class Settings:
    mode: str = field(default_factory=lambda: os.getenv("TRUSTCHAIN_MODE", "sim"))
    host: str = field(default_factory=lambda: os.getenv("TRUSTCHAIN_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("TRUSTCHAIN_PORT", "8000")))
    admin_token: str = field(default_factory=lambda: os.getenv("TRUSTCHAIN_ADMIN_TOKEN", "admin"))
    demo_mode: bool = field(default_factory=lambda: os.getenv("TRUSTCHAIN_DEMO", "1") == "1")
    esp32_smart_home_ip: str = field(default_factory=lambda: os.getenv("ESP32_SMART_HOME_IP", ""))
    esp32_security_ip: str = field(default_factory=lambda: os.getenv("ESP32_SECURITY_IP", ""))
    data_dir: str = field(default_factory=lambda: os.getenv("TRUSTCHAIN_DATA", os.path.join(ROOT, "data")))
    model_dir: str = field(default_factory=lambda: os.path.join(ROOT, "models"))
    real_ml: bool = field(default_factory=lambda: os.getenv("TRUSTCHAIN_REAL_ML", "0") == "1")
    in_memory: bool = False
    virtual_clock: bool = False
    tick_seconds: float = 1.0
    sim_minutes_per_tick: float = 5.0   # simulated household time per tick (a day ~ 5 min)
    validators: int = 3
    replay_window_s: float = 30.0
    event_cooldown_s: float = 8.0
    ml_confirmations: int = 2
    recovery_clean_ticks: int = 8
    integrity_interval_s: float = 12.0

    @property
    def ledger_dir(self) -> str:
        return os.path.join(self.data_dir, "ledger")

    @property
    def key_dir(self) -> str:
        return os.path.join(self.data_dir, "keys")
