"""Legacy ESP32 adapters against a mocked device (no hardware needed)."""
import requests

from trustchain.hardware import Esp32ResponseNode, LegacyEsp32Source


class Resp:
    def __init__(self, payload=None, ok=True, text=""):
        self._p, self.ok, self.text = payload, ok, text

    def json(self):
        return self._p

    def raise_for_status(self):
        pass


def test_legacy_source_converts_cumulative_counters(monkeypatch):
    seq = iter([
        {"total_requests": 100, "failed_pin_attempts": 2, "temperature": 28.5, "humidity": 55, "wifi_rssi": -60},
        {"total_requests": 160, "failed_pin_attempts": 6, "temperature": 28.7, "humidity": 55, "wifi_rssi": -61},
        {"total_requests": 5, "failed_pin_attempts": 0, "temperature": 28.7, "humidity": 55, "wifi_rssi": -61},   # reboot
    ])
    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp(next(seq)))
    t = iter([1000.0, 1002.0, 1004.0])
    monkeypatch.setattr("trustchain.hardware.time.time", lambda: next(t))
    src = LegacyEsp32Source("10.0.0.1")
    first = src.poll()
    assert first["req_rate"] == 0.0 and first["failed_auth"] == 0        # no history yet
    second = src.poll()
    assert second["req_rate"] == 30.0 and second["failed_auth"] == 4
    third = src.poll()                                                    # counters went backwards: no fake spike
    assert third["req_rate"] == 0.0


def test_slow_human_pin_attempts_accumulate_in_rolling_window(monkeypatch):
    """Wrong PINs typed ~6 s apart must still add up to a brute-force signal, then age out."""
    totals = [0, 1, 2, 3, 3, 3]
    seq = iter([{"total_requests": 0, "failed_pin_attempts": n, "temperature": 28, "humidity": 50, "wifi_rssi": -50} for n in totals])
    monkeypatch.setattr(requests, "get", lambda *a, **k: Resp(next(seq)))
    t = iter([0.0, 6.0, 12.0, 18.0, 40.0, 60.0])
    monkeypatch.setattr("trustchain.hardware.time.time", lambda: next(t))
    src = LegacyEsp32Source("10.0.0.1", fail_window_s=30.0)
    got = [src.poll()["failed_auth"] for _ in totals]
    assert got[:4] == [0, 1, 2, 3]            # reaches the rule threshold (3)
    assert got[4] == 2 and got[5] == 0        # attempts age out of the 30 s window


def test_legacy_source_reports_disconnect(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(requests, "get", boom)
    src = LegacyEsp32Source("10.0.0.1")
    assert src.poll() is None and not src.connected


def test_response_node_uses_original_endpoints(monkeypatch):
    calls = []
    monkeypatch.setattr(requests, "get", lambda url, params=None, timeout=None: calls.append((url, params)) or Resp({}, True))
    n = Esp32ResponseNode("10.0.0.2")
    n.alert("BRUTE_FORCE", "BRUTE_FORCE")
    n.safe()
    assert calls == [("http://10.0.0.2/alert", {"type": "BRUTE_FORCE"}), ("http://10.0.0.2/safe", None)]
    assert n.snapshot()["mode"] == "SAFE"


def test_unreachable_response_node_does_not_raise(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("down")
    monkeypatch.setattr(requests, "get", boom)
    n = Esp32ResponseNode("10.0.0.2")
    assert n.alert("X") is False and not n.reachable
