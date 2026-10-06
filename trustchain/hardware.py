"""Physical layer: response node (ESP-2) and legacy telemetry source (ESP-1).

`SimResponseNode` mirrors what the real ESP32 #2 firmware does (red/green LED, buzzer, LCD),
so the dashboard can render it without hardware. `Esp32ResponseNode` talks to the real
board using the existing endpoints (/alert?type=, /safe, /status).
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

import requests


class SimResponseNode:
    kind = "simulated"

    def __init__(self) -> None:
        self.state: dict[str, Any] = self._safe()
        self.reachable = True
        self.last_command: str | None = None
        self.history: list[dict[str, Any]] = []

    @staticmethod
    def _safe() -> dict[str, Any]:
        return {"mode": "SAFE", "type": None, "green_led": True, "red_led": False, "buzzer": False,
                "lcd": ["TrustChain IDRS", "SAFE - monitoring"]}

    def alert(self, kind: str, lcd_line: str | None = None) -> bool:
        self.state = {"mode": "ALERT", "type": kind, "green_led": False, "red_led": True, "buzzer": True,
                      "lcd": ["!! INTRUSION !!", (lcd_line or kind)[:16]]}
        self._log(f"alert:{kind}")
        return True

    def safe(self) -> bool:
        self.state = self._safe()
        self._log("safe")
        return True

    def _log(self, cmd: str) -> None:
        self.last_command = cmd
        self.history = (self.history + [{"ts": time.time(), "cmd": cmd}])[-30:]

    def snapshot(self) -> dict[str, Any]:
        return {**self.state, "kind": self.kind, "reachable": self.reachable, "last_command": self.last_command}


class Esp32ResponseNode(SimResponseNode):
    kind = "esp32"

    def __init__(self, ip: str, timeout: float = 3.0):
        super().__init__()
        self.ip, self.timeout = ip, timeout
        self.remote: dict[str, Any] | None = None
        self._monitor: threading.Thread | None = None

    def start_monitor(self, interval: float = 3.0) -> None:
        """Refresh /status in the background so dashboards never wait on the network."""
        def loop():
            while True:
                r = self._get("/status")
                if r is not None and r.ok:
                    try:
                        self.remote = r.json()
                    except ValueError:
                        self.remote = {"raw": r.text[:120]}
                time.sleep(interval)
        self._monitor = threading.Thread(target=loop, daemon=True, name="esp2-monitor")
        self._monitor.start()

    def _get(self, path: str, **params) -> requests.Response | None:
        try:
            r = requests.get(f"http://{self.ip}{path}", params=params or None, timeout=self.timeout)
            self.reachable = r.ok
            return r
        except requests.RequestException:
            self.reachable = False
            return None

    def alert(self, kind: str, lcd_line: str | None = None) -> bool:
        ok = self._get("/alert", type=kind) is not None
        super().alert(kind, lcd_line)
        return ok

    def safe(self) -> bool:
        ok = self._get("/safe") is not None
        super().safe()
        return ok

    def snapshot(self) -> dict[str, Any]:
        snap = super().snapshot()
        snap["remote"] = self.remote
        return snap


class LegacyEsp32Source:
    """Polls the existing ESP32 #1 firmware (/security/status) and converts the cumulative
    counters it exposes into per-tick metrics. The firmware does not sign messages, so the
    gateway attests on its behalf (flagged as `gateway_attested` in the event details).

    `failed_auth` is the number of wrong PINs seen in the last `fail_window_s` seconds: a human
    typing at a keypad needs several seconds per attempt, so per-poll deltas would never reach the
    brute-force threshold."""

    def __init__(self, ip: str, timeout: float = 2.0, fail_window_s: float = 30.0):
        self.ip, self.timeout, self.fail_window_s = ip, timeout, fail_window_s
        self.connected = False
        self.last_raw: dict[str, Any] | None = None
        self._last_total: int | None = None
        self._last_t: float | None = None
        self._last_failed: int | None = None
        self._fails: deque = deque()          # (timestamp, new failures)
        self._latest: dict[str, Any] | None = None
        self._thread: threading.Thread | None = None

    # -- background polling: keeps network I/O out of the engine lock ----------------------
    def start(self, interval: float = 1.0) -> None:
        def loop():
            while True:
                t0 = time.time()
                sample = self.fetch()
                if sample is not None:
                    self._latest = sample
                time.sleep(max(0.05, interval - (time.time() - t0)))
        self._thread = threading.Thread(target=loop, daemon=True, name="esp1-poller")
        self._thread.start()

    def poll(self) -> dict[str, Any] | None:
        if self._thread is None:
            return self.fetch()
        sample, self._latest = self._latest, None
        return sample

    def fetch(self) -> dict[str, Any] | None:
        try:
            r = requests.get(f"http://{self.ip}/security/status", timeout=self.timeout)
            r.raise_for_status()
            raw = r.json()
        except (requests.RequestException, ValueError):
            self.connected = False
            return None
        self.connected = True
        self.last_raw = raw
        now = time.time()
        total = int(raw.get("total_requests", 0))
        failed = int(raw.get("failed_pin_attempts", 0))
        rate = 0.0
        if self._last_total is not None and self._last_t and total >= self._last_total and now > self._last_t:
            rate = (total - self._last_total) / (now - self._last_t)
        if self._last_failed is not None and failed > self._last_failed:
            self._fails.append((now, failed - self._last_failed))
        while self._fails and now - self._fails[0][0] > self.fail_window_s:
            self._fails.popleft()
        self._last_total, self._last_t, self._last_failed = total, now, failed
        temp = float(raw.get("temperature", 0))
        return {
            "req_rate": round(rate, 3),
            "bad_req_rate": 0.0,           # firmware exposes no bad-request counter
            "failed_auth": sum(n for _, n in self._fails),
            "endpoints_hit": 1,
            "primary": temp,
            "temperature": temp,
            "humidity": float(raw.get("humidity", 0)),
            "rssi": float(raw.get("wifi_rssi", -60)),
        }
