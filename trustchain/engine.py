"""TrustChain-IDRS engine: the closed loop

    signed telemetry -> gateway verification -> rules + baseline + ML -> risk / trust
        -> ledger commit -> quarantine state machine -> physical response
        -> integrity check -> trust   (ledger tampering lowers device trust)
"""
from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from .config import Clock, Settings
from .crypto import KeyPair, canonical, load_or_create_key, sha256_hex
from .detection.baseline import Baseline, warm_baseline
from .detection.features import extract
from .detection.rules import SEVERITY, static_rules
from .detection.train import ensure_model
from .fingerprint import attack_fingerprint
from .hardware import Esp32ResponseNode, LegacyEsp32Source, SimResponseNode
from .identity import DeviceIdentity, IdentityVerifier
from .integrity import IntegrityChecker
from .ledger.chain import LedgerError, LedgerNetwork, LedgerNode
from .ledger.contract import ACTIVE, QUARANTINED, RECOVERY_PENDING, SEVERITIES, ContractError, SecurityContract, escalate
from .response import (ALLOW_WHEN_QUARANTINED, COMMANDS, DEFAULT_MIN_TRUST, LOCK_POLICY, MIN_TRUST, QUARANTINE_POLICY,
                       Blocklist)
from .sim.home import CATEGORIES, ROOMS, DeviceSpec, catalog
from .sim.profiles import ATTACKS, PROFILES, Profile, apply_attack, attack_source, normal_sample
from .store import LocalStore, event_hash
from .trust import (BAND_SEVERITY, REGEN_PER_STEP, TrustTracker, band, baseline_deviation, penalty,
                    risk_score)

CORE_SPECS = catalog("core")
DEVICES = [(d.id, d.name, d.kind) for d in CORE_SPECS]       # the five original devices
SMART_HOME_ID = CORE_SPECS[0].id
INITIAL_STATE = {
    "smart_home_node": {"lock": "LOCKED", "led": "OFF"}, "security_node": {"alarm": "IDLE"}, "door_sensor": {"door": "CLOSED"},
    "bulb": {"power": "ON"}, "fan": {"power": "OFF"}, "tv": {"power": "ON"}, "soundbar": {"power": "ON"},
    "robot_vacuum": {"cycle": "DOCKED"}, "blinds": {"position": "OPEN"}, "air_purifier": {"power": "ON"},
    "fridge": {"mode": "NORMAL"}, "oven": {"power": "OFF"}, "dishwasher": {"cycle": "IDLE"}, "coffee_machine": {"power": "OFF"},
    "router": {"uplink": "UP"}, "thermostat": {"mode": "COMFORT"}, "smoke_detector": {"alarm": "CLEAR"},
    "smart_bed": {"power": "OFF"}, "ac": {"power": "ON", "mode": "ECO"}, "smart_speaker": {"power": "ON"},
    "water_heater": {"power": "ON"}, "shower": {"cycle": "IDLE"}, "smart_mirror": {"power": "OFF"}, "leak_sensor": {"leak": "DRY"},
    "nas": {"backup": "OK"}, "printer": {"state": "IDLE"}, "washer": {"cycle": "IDLE"}, "dryer": {"cycle": "IDLE"},
    "energy_meter": {"grid": "IMPORT"}, "home_battery": {"mode": "HOLD"}, "solar_inverter": {"mode": "GENERATING"},
    "garage_door": {"position": "CLOSED"}, "ev_charger": {"cycle": "IDLE"}, "irrigation": {"cycle": "IDLE"},
    "pool_pump": {"cycle": "STOPPED"}, "doorbell": {"state": "IDLE"}, "camera": {"privacy": "OFF", "recording": "ON"},
}
COMMAND_EFFECT = {
    "lock": ("lock", "LOCKED"), "unlock": ("lock", "UNLOCKED"), "led_on": ("led", "ON"), "led_off": ("led", "OFF"),
    "on": ("power", "ON"), "off": ("power", "OFF"), "test_alarm": ("alarm", "TEST"), "clear_alarm": ("alarm", "IDLE"),
    "mute": ("sound", "MUTED"), "start": ("cycle", "RUNNING"), "stop": ("cycle", "STOPPED"), "dock": ("cycle", "DOCKED"),
    "open": ("position", "OPEN"), "close": ("position", "CLOSED"), "boost_cool": ("mode", "BOOST"), "normal": ("mode", "NORMAL"),
    "preheat": ("power", "PREHEATING"), "brew": ("power", "BREWING"), "reboot": ("uplink", "REBOOTING"), "eco": ("mode", "ECO"),
    "comfort": ("mode", "COMFORT"), "test": ("alarm", "TESTING"), "warm": ("mode", "WARMING"), "boost": ("power", "BOOST"),
    "grid_charge": ("mode", "GRID CHARGE"), "hold": ("mode", "HOLD"), "privacy_on": ("privacy", "ON"), "privacy_off": ("privacy", "OFF"),
}
ACTION_FOR = {"LOW": "LOGGED", "MEDIUM": "ALERT_USER", "HIGH": "BLOCK_SOURCE", "CRITICAL": "QUARANTINE_DEVICE"}
SEV_WEIGHT = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 1.0, "CRITICAL": 1.0}
CRYPTO_REASON_TO_EVENT = {"UNKNOWN_DEVICE": "ROGUE_DEVICE", "BAD_SIGNATURE": "SPOOFING", "REPLAY": "REPLAY", "STALE_TIMESTAMP": "REPLAY"}
VICTIM_EVENTS = {"SPOOFING", "REPLAY"}   # attacker-originated: must not let an outsider quarantine a victim


def _clean(obj: Any) -> Any:
    """JSON round-trip with numpy support so hashes are stable across store/reload."""
    return json.loads(json.dumps(obj, default=lambda o: o.item() if hasattr(o, "item") else str(o)))


@dataclass
class DeviceRuntime:
    id: str
    name: str
    kind: str
    profile: Profile
    identity: DeviceIdentity
    legacy: LegacyEsp32Source | None = None
    spec: DeviceSpec | None = None
    history: deque = field(default_factory=lambda: deque(maxlen=240))
    last: dict[str, Any] = field(default_factory=dict)
    last_env: dict[str, Any] | None = None
    ml_streak: int = 0
    clean_streak: int = 0
    last_event_ts: dict[str, float] = field(default_factory=dict)
    blocked_msgs: int = 0
    suppressed: int = 0
    online: bool = True
    state: dict[str, Any] = field(default_factory=dict)


class Engine:
    def __init__(self, settings: Settings | None = None, model=None, seed: int | None = None, start_hour: float | None = None):
        self.s = settings or Settings()
        self.clock = Clock(virtual=self.s.virtual_clock)
        self.rng = np.random.default_rng(seed)
        self.lock = threading.RLock()
        self.tick = 0
        self.version = 0
        self.running = False
        self._thread: threading.Thread | None = None
        self.started_at = self.clock.now()

        lt = time.localtime()
        self.sim_minute = (start_hour * 60.0) if start_hour is not None else lt.tm_hour * 60.0 + lt.tm_min
        if self.s.mode == "hybrid":
            self.s.sim_minutes_per_tick = self.s.tick_seconds / 60.0   # real time

        # ---- ledger + contract ------------------------------------------------------
        mem = self.s.in_memory
        nodes = []
        for i in range(self.s.validators):
            nid = f"node-{i + 1}"
            key = load_or_create_key(None if mem else os.path.join(self.s.key_dir, f"{nid}.pem"))
            if not mem:
                os.makedirs(self.s.ledger_dir, exist_ok=True)
            nodes.append(LedgerNode(nid, key, ":memory:" if mem else os.path.join(self.s.ledger_dir, f"{nid}.db")))
        self.network = LedgerNetwork(nodes, self.clock)
        self.network.init_genesis()
        self.contract = SecurityContract(self.network)
        self.contract.rebuild()

        # ---- services ----------------------------------------------------------------
        self.store = LocalStore(":memory:" if mem else os.path.join(self.s.data_dir, "local.db"))
        self.verifier = IdentityVerifier(self.contract, self.clock, self.s.replay_window_s)
        self.baseline = Baseline()
        self.model = model or ensure_model(self.s.model_dir)
        self.integrity = IntegrityChecker(self.contract, self.network, self.store, self.clock)
        self.blocklist = Blocklist()
        self.tracker = TrustTracker()
        self.attacks: list[dict[str, Any]] = []
        self.attack_log: deque = deque(maxlen=60)
        self.feed: deque = deque(maxlen=400)
        self.seq = 0
        self.system_alerts: deque = deque(maxlen=50)
        self.counters = {"messages": 0, "dropped_blocked": 0, "crypto_rejects": 0, "events": 0, "commands_blocked": 0}
        self._last_integrity = self.clock.now()
        self._high_event_ts: deque = deque(maxlen=20)
        self._phys_key: tuple | None = None
        self._rogue_last: dict[str, float] = {}
        self._manual_until = 0.0     # a manual hardware test pauses auto-resync briefly
        self._last_resync = 0.0
        self.node = Esp32ResponseNode(self.s.esp32_security_ip) if (self.s.mode == "hybrid" and self.s.esp32_security_ip) else SimResponseNode()

        self.runtimes: dict[str, DeviceRuntime] = {}
        self._bootstrap_devices()
        if isinstance(self.node, Esp32ResponseNode) and not self.s.virtual_clock:
            self.node.start_monitor()
        self._actuate(self.node.safe)

    # =============================================================================
    # bootstrap
    # =============================================================================
    def _bootstrap_devices(self) -> None:
        mem = self.s.in_memory
        for spec in catalog(self.s.home):
            did = spec.id
            safe = did.replace(":", "_")
            key = load_or_create_key(None if mem else os.path.join(self.s.key_dir, "devices", f"{safe}.pem"))
            existing = self.contract.get_device(did)
            if existing is None or existing.get("unregistered"):
                fw = sha256_hex(f"firmware-v1.0:{spec.dtype}:{did}")
                self.contract.registerDevice(did, spec.name, spec.dtype, key.public_hex, fw)
            legacy = None
            if self.s.mode == "hybrid" and did == SMART_HOME_ID and self.s.esp32_smart_home_ip:
                legacy = LegacyEsp32Source(self.s.esp32_smart_home_ip)
                if not self.s.virtual_clock:
                    legacy.start(self.s.tick_seconds)
            rt = DeviceRuntime(did, spec.name, spec.dtype, spec.profile(), DeviceIdentity(did, key), legacy, spec=spec)
            rt.state = dict(INITIAL_STATE.get(spec.dtype, {}))
            self.runtimes[did] = rt
            if legacy is None:   # seed the behavioural baseline (a real device learns its own online)
                warm_baseline(self.baseline, did, rt.profile, 7, np.random.default_rng(self.rng.integers(1 << 30)), 10.0)
        self._post_feed("SYSTEM", "TrustChain-IDRS online", {"devices": len(self.runtimes), "mode": self.s.mode})

    # =============================================================================
    # run loop
    # =============================================================================
    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="trustchain-engine")
        self._thread.start()

    def stop(self) -> None:
        self.running = False

    def _loop(self) -> None:
        while self.running:
            t0 = time.time()
            try:
                self.step()
            except Exception as exc:  # keep the monitor alive; surface the fault
                self._post_feed("SYSTEM", f"engine error: {type(exc).__name__}: {exc}", {})
            time.sleep(max(0.0, self.s.tick_seconds - (time.time() - t0)))

    # =============================================================================
    # one tick
    # =============================================================================
    def step(self) -> None:
        with self.lock:
            self.tick += 1
            self.clock.advance(self.s.tick_seconds)
            self.sim_minute = (self.sim_minute + self.s.sim_minutes_per_tick) % 1440.0
            hour = self.sim_minute / 60.0
            now = self.clock.now()
            deferred: list = []
            for rt in self.runtimes.values():
                self._tick_device(rt, hour, now, deferred)
            self._flush(deferred, hour, now)
            self._inject_crypto_attacks(hour, now)
            self._age_attacks(now)
            self._reconcile_physical(now)
            if now - self._last_integrity >= self.s.integrity_interval_s:
                self.run_integrity()
            self.version += 1

    def _traffic_attack(self, device_id: str) -> dict[str, Any] | None:
        for a in self.attacks:
            if a["layer"] == "traffic" and a["device_id"] == device_id and a["ticks_left"] > 0:
                return a
        return None

    def _tick_device(self, rt: DeviceRuntime, hour: float, now: float, deferred: list | None = None) -> None:
        atk = None
        if rt.legacy is not None:
            sample = rt.legacy.poll()
            rt.online = rt.legacy.connected
            if sample is None:
                return
        else:
            sample = normal_sample(rt.profile, hour, self.rng)
            atk = self._traffic_attack(rt.id)
            if atk:
                sample = apply_attack(sample, atk["type"], rt.profile, hour, self.rng)
        env = rt.identity.sign(sample, now)
        rt.last_env = env
        meta = ({"source": atk["source"], "port": atk["port"], "protocol": atk["protocol"], "injected": False} if atk
                else {"source": "device", "port": 0, "protocol": "HTTP", "injected": False})
        self._ingest(env, meta, hour, now, attested=rt.legacy is not None, deferred=deferred)

    # =============================================================================
    # gateway ingest
    # =============================================================================
    def _ingest(self, env: dict[str, Any], meta: dict[str, Any], hour: float, now: float, attested: bool = False,
                deferred: list | None = None) -> None:
        self.counters["messages"] += 1
        if meta.get("injected") and self.blocklist.blocked(meta.get("source"), now):
            self.counters["dropped_blocked"] += 1
            self._note_attack(env.get("device_id"), dropped=True)
            return
        v = self.verifier.verify(env)
        if not v.ok:
            self.counters["crypto_rejects"] += 1
            self._on_crypto_failure(v.reason, v.device_id, meta, now)
            return
        rt = self.runtimes.get(v.device_id)
        if rt is None:
            return
        sample = {k: val for k, val in v.metrics.items() if k not in ("device_id", "timestamp", "nonce")}
        if deferred is not None:        # scored together with the rest of this tick's devices
            deferred.append((rt, sample, meta, attested))
            return
        self._analyse(rt, sample, hour, meta, now, attested)

    def _flush(self, deferred: list, hour: float, now: float) -> None:
        """Extract features for every verified message, run ONE batched ML inference, then decide."""
        if not deferred:
            return
        feats = [extract(self.baseline, rt.id, hour, sample) for rt, sample, _, _ in deferred]
        scores = self.model.score_batch(np.vstack([f[0] for f in feats]))
        for (rt, sample, meta, attested), (vec, fi), ml in zip(deferred, feats, scores):
            self._analyse(rt, sample, hour, meta, now, attested, pre=(vec, fi, ml))

    # =============================================================================
    # detection + decision
    # =============================================================================
    def _analyse(self, rt: DeviceRuntime, sample: dict[str, Any], hour: float, meta: dict[str, Any], now: float, attested: bool,
                 pre: tuple | None = None) -> None:
        dev = self.contract.get_device(rt.id)
        trust = dev["trust"]
        status = dev["status"]
        if pre is not None:
            vec, fi, ml = pre
        else:
            vec, fi = extract(self.baseline, rt.id, hour, sample)
            ml = self.model.score(vec)
        rules = static_rules(sample)

        # Real hardware: the models were trained on simulated devices, so until they are retrained on
        # real telemetry the ML layer only *observes* (shadow mode) and rules alone raise events.
        shadow = rt.legacy is not None and not self.s.real_ml
        ml_flag = (ml["if_anomaly"] or ml["cls_attack"]) and not shadow
        rt.ml_streak = rt.ml_streak + 1 if ml_flag else 0
        etype, rule_sev = None, 0.0
        if rules:
            etype, rule_sev = rules[0]["type"], rules[0]["severity"]
        elif rt.ml_streak >= self.s.ml_confirmations:
            etype = ml["cls"] if ml["cls_attack"] else "ML_BEHAVIOR_ANOMALY"
            rule_sev = 0.0
        ml_comp = max(ml["ml_risk"], ml["cls_conf"] * 0.85 if ml["cls_attack"] else 0.0)
        bdev = baseline_deviation(fi["req_z"], fi["primary_z"], fi["warm"])
        # Risk reflects *confirmed* evidence: a rule hit, or ML flagged on consecutive ticks. A single noisy tick
        # must not paint a healthy device "suspicious" (and ML-only evidence is advisory on real hardware).
        confirmed = bool(rules) or rt.ml_streak >= self.s.ml_confirmations
        if shadow or not confirmed:
            ml_comp = bdev = 0.0
        integrity_open = self.contract.unresolved_integrity.get(rt.id, 0) > 0
        risk, parts = risk_score(rule_sev, ml_comp, bdev, trust, integrity_open)
        bnd = band(risk)

        rt.last = {"sample": sample, "ml": ml, "rules": rules, "fi": fi, "risk": risk, "band": bnd, "parts": parts,
                   "ts": now, "hour": hour, "etype": etype, "attested": attested}
        rt.history.append({"t": round(now, 1), "hour": round(hour, 2), "risk": risk, "req": sample["req_rate"],
                           "primary": sample["primary"], "trust": trust, "band": bnd, "if": round(ml["if_score"], 3)})

        if status != ACTIVE:          # quarantined: observe, do not forward, accumulate recovery evidence
            rt.blocked_msgs += 1
            rt.clean_streak = rt.clean_streak + 1 if etype is None else 0
            return
        if etype is None:
            rt.clean_streak += 1
            if risk < 0.25 and not integrity_open:
                self.baseline.update(rt.id, hour, sample)
            if trust < 100 and self.tracker.note_clean(rt.id):
                self.contract.updateTrustScore(rt.id, min(100.0, trust + REGEN_PER_STEP), "REGENERATION (clean behaviour)")
            return
        rt.clean_streak = 0
        detectors = {"rules": rules, "ml": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in ml.items()},
                     "baseline": fi, "risk_parts": parts, "ml_streak": rt.ml_streak}
        # Weak, unexplained evidence (no rule hit, low overall risk) may alert the user but must never escalate
        # to blocking or quarantine on its own: that needs a rule hit or strong multi-signal risk.
        weak = (not rules and risk < 0.5) or etype == "ML_BEHAVIOR_ANOMALY"
        self._raise_event(rt.id, etype, risk, meta, sample, detectors, now, attested=attested, weak=weak)

    # =============================================================================
    # event creation: local store + ledger + trust + response
    # =============================================================================
    def _raise_event(self, device_id: str, etype: str, risk: float, meta: dict[str, Any], sample: dict[str, Any],
                     detectors: dict[str, Any], now: float, attested: bool = False, forced_severity: str | None = None,
                     extra: dict[str, Any] | None = None, weak: bool = False) -> dict[str, Any] | None:
        rt = self.runtimes.get(device_id)
        if rt is not None:
            last = rt.last_event_ts.get(etype)
            if last is not None and now - last < self.s.event_cooldown_s:
                rt.suppressed += 1
                return None
            rt.last_event_ts[etype] = now
        dev = self.contract.get_device(device_id)
        unregistered = dev is None or dev.get("unregistered")
        if dev is not None and dev["status"] != ACTIVE:
            return None
        trust_before = 0.0 if unregistered else dev["trust"]
        victim = etype in VICTIM_EVENTS

        fp = attack_fingerprint(etype, device_id, meta.get("source"), meta.get("port"), meta.get("protocol"),
                                float(sample.get("req_rate", 0)), int(sample.get("failed_auth", 0)))
        mem = self.contract.assess_recurrence(fp, meta.get("source"), etype, now)
        sev = BAND_SEVERITY[band(risk)]
        sev = escalate(sev, mem["escalate_levels"])
        if victim:
            sev = SEVERITIES[min(SEVERITIES.index(sev), SEVERITIES.index("HIGH"))]
        if weak:
            sev = SEVERITIES[min(SEVERITIES.index(sev), SEVERITIES.index("MEDIUM"))]
        if forced_severity:
            sev = forced_severity

        pen = 0.0 if unregistered else penalty(etype, mem["repeat_count"]) * SEV_WEIGHT[sev] * (0.4 if victim else 1.0)
        trust_after = max(0.0, round(trust_before - pen, 1))
        quarantine = (not victim and sev == "CRITICAL") or (not unregistered and trust_after < self.contract.policy["quarantine_below"] and not victim)
        if unregistered:
            quarantine = True
        action = "QUARANTINE_DEVICE" if quarantine else ACTION_FOR[sev]

        event_id = self.store.next_event_id()
        details = _clean({"detectors": detectors, "sample": sample, "network": meta, "repeat_count": mem["repeat_count"],
                          "base_severity": BAND_SEVERITY[band(risk)], "gateway_attested": attested, **(extra or {})})
        rec = {"event_id": event_id, "ts": round(now, 3), "device_id": device_id, "event_type": etype, "severity": sev,
               "risk_score": round(risk, 3), "source": meta.get("source"), "fingerprint": fp,
               "trust_after": trust_after, "action": action}
        rec["event_hash"] = event_hash({**rec, "details": details})
        self.store.save_event(rec, details)
        block = self.contract.recordAttack({**rec, "port": meta.get("port"), "protocol": meta.get("protocol"),
                                            "repeat_count": mem["repeat_count"], "details_hash": sha256_hex(canonical(details))})
        self.store.set_chain_block(event_id, block.index)
        self.counters["events"] += 1
        self.tracker.note_event(device_id)
        self._note_attack(device_id, etype=etype, event_id=event_id, now=now)

        if not unregistered and trust_after != trust_before:
            self.contract.updateTrustScore(device_id, trust_after, f"{etype} [{sev}] -{pen:.0f}")
        if meta.get("source") and meta["source"] not in ("device", "lan", "local-db") and action in ("BLOCK_SOURCE", "QUARANTINE_DEVICE"):
            if self.blocklist.add(meta["source"], now):
                self._post_feed("BLOCK", f"Source {meta['source']} blocked at gateway", {"source": meta["source"], "device_id": device_id})
        if quarantine:
            reason = "unregistered device" if unregistered else (f"trust {trust_after:.0f} < {self.contract.policy['quarantine_below']}"
                                                                  if trust_after < self.contract.policy["quarantine_below"] else f"{etype} escalated to CRITICAL")
            self.contract.quarantineDevice(device_id, reason)
            if rt:
                rt.clean_streak = 0
            self._post_feed("QUARANTINE", f"{self._name(device_id)} quarantined — {reason}", {"device_id": device_id, "event_id": event_id})
        if sev in ("HIGH", "CRITICAL"):
            self._high_event_ts.append((now, etype))
        self._post_feed("EVENT", f"{etype} on {self._name(device_id)}", {**rec, "repeat_count": mem["repeat_count"], "block": block.index})
        return rec

    def _name(self, device_id: str) -> str:
        rt = self.runtimes.get(device_id)
        if rt:
            return rt.name
        d = self.contract.get_device(device_id)
        return d["name"] if d else device_id

    # =============================================================================
    # crypto-layer failures
    # =============================================================================
    def _on_crypto_failure(self, reason: str, device_id: str | None, meta: dict[str, Any], now: float) -> None:
        etype = CRYPTO_REASON_TO_EVENT.get(reason)
        if etype is None or not device_id:
            return
        dev = self.contract.get_device(device_id)
        if dev is not None and dev["status"] != ACTIVE:
            self._note_attack(device_id, dropped=True)
            return
        if etype == "ROGUE_DEVICE":
            if self._rogue_last.get(device_id) and now - self._rogue_last[device_id] < self.s.event_cooldown_s:
                return
            self._rogue_last[device_id] = now
        trust = 0.0 if (dev is None or dev.get("unregistered")) else dev["trust"]
        integ = self.contract.unresolved_integrity.get(device_id, 0) > 0
        risk, parts = risk_score(SEVERITY[etype], 0.0, 0.0, trust, integ)
        forced = "CRITICAL" if etype == "ROGUE_DEVICE" else None
        self._raise_event(device_id, etype, risk, meta, {"req_rate": 0, "failed_auth": 0}, {"gateway_reject": reason, "risk_parts": parts},
                          now, forced_severity=forced)

    # =============================================================================
    # attack simulation
    # =============================================================================
    def launch_attack(self, atype: str, device_id: str | None = None, duration: int | None = None) -> dict[str, Any]:
        with self.lock:
            if atype not in ATTACKS:
                raise ValueError(f"unknown attack {atype}")
            layer = ATTACKS[atype]["layer"]
            if atype == "ROGUE_DEVICE":
                device_id = f"did:trustchain:rogue:{self.rng.integers(0x10000, 0xFFFFF):x}"
            else:
                if device_id is None:
                    device_id = SMART_HOME_ID
                rt = self.runtimes.get(device_id)
                if rt is None:
                    raise ValueError("unknown device")
                if rt.legacy is not None and layer == "traffic":
                    raise ValueError("this device is real hardware; generate real traffic against it instead of simulating")
            src = attack_source(atype, self.rng)
            ticks = duration or (14 if layer == "crypto" else 30)
            a = {"id": f"ATK-{len(self.attack_log) + len(self.attacks) + 1:03d}", "type": atype, "layer": layer,
                 "device_id": device_id, "ticks_left": ticks, "ticks_total": ticks, "started_tick": self.tick,
                 "started_at": self.clock.now(), "first_event_tick": None, "first_event_type": None,
                 "events": [], "dropped": 0, "attacker_key": KeyPair.generate() if layer == "crypto" else None, **src}
            self.attacks.append(a)
            self._post_feed("ATTACK", f"Simulated {ATTACKS[atype]['label']} launched against {self._name(device_id)}",
                            {"attack_id": a["id"], "type": atype, "device_id": device_id, "source": a["source"]})
            return self._attack_view(a)

    def stop_attacks(self) -> int:
        with self.lock:
            n = len(self.attacks)
            for a in list(self.attacks):
                a["ticks_left"] = 0
            self._age_attacks(self.clock.now(), force=True)
            return n

    def _inject_crypto_attacks(self, hour: float, now: float) -> None:
        for a in self.attacks:
            if a["layer"] != "crypto" or a["ticks_left"] <= 0:
                continue
            meta = {"source": a["source"], "port": a["port"], "protocol": a["protocol"], "injected": True}
            rt = self.runtimes.get(a["device_id"])
            if a["type"] == "REPLAY" and rt and rt.last_env:
                self._ingest(dict(rt.last_env), meta, hour, now)
            elif a["type"] == "SPOOFING" and rt:
                ident = DeviceIdentity(rt.id, a["attacker_key"])
                self._ingest(ident.sign({"req_rate": 1.0, "bad_req_rate": 0.0, "failed_auth": 0, "endpoints_hit": 1,
                                         "primary": 99.0, "rssi": -50}, now), meta, hour, now)
            elif a["type"] == "ROGUE_DEVICE":
                ident = DeviceIdentity(a["device_id"], a["attacker_key"])
                self._ingest(ident.sign({"req_rate": 1.0, "bad_req_rate": 0.0, "failed_auth": 0, "endpoints_hit": 1,
                                         "primary": 20.0, "rssi": -60}, now), meta, hour, now)

    def _note_attack(self, device_id: str | None, etype: str | None = None, event_id: str | None = None,
                     dropped: bool = False, now: float | None = None) -> None:
        for a in self.attacks:
            if a["device_id"] != device_id or a["ticks_left"] <= 0:
                continue
            if dropped:
                a["dropped"] += 1
            elif event_id:
                a["events"].append(event_id)
                if a["first_event_tick"] is None:
                    a["first_event_tick"] = self.tick
                    a["first_event_type"] = etype

    def _age_attacks(self, now: float, force: bool = False) -> None:
        done = []
        for a in self.attacks:
            if not force:
                a["ticks_left"] -= 1
            if a["ticks_left"] <= 0:
                done.append(a)
        for a in done:
            self.attacks.remove(a)
            detected = a["first_event_tick"] is not None
            self.attack_log.appendleft({
                "id": a["id"], "type": a["type"], "device_id": a["device_id"], "source": a["source"],
                "detected": detected, "first_event_type": a["first_event_type"],
                "classified_correctly": bool(detected and (a["first_event_type"] == a["type"])),
                "detection_latency_ticks": (a["first_event_tick"] - a["started_tick"]) if detected else None,
                "events": a["events"], "dropped_by_blocklist": a["dropped"], "duration_ticks": a["ticks_total"],
            })
            self._post_feed("ATTACK", f"{ATTACKS[a['type']]['label']} ended — {'detected' if detected else 'NOT detected'}", {"attack_id": a["id"]})

    def _attack_view(self, a: dict[str, Any]) -> dict[str, Any]:
        return {k: a[k] for k in ("id", "type", "layer", "device_id", "source", "port", "protocol", "ticks_left", "ticks_total",
                                  "first_event_type", "events", "dropped")} | {"label": ATTACKS[a["type"]]["label"]}

    # =============================================================================
    # physical response (ESP-2)
    # =============================================================================
    def _actuate(self, fn, *args) -> None:
        if isinstance(self.node, Esp32ResponseNode):
            threading.Thread(target=fn, args=args, daemon=True).start()
        else:
            fn(*args)

    def _reconcile_physical(self, now: float) -> None:
        quarantined = [d for d in self.contract.devices.values() if d["status"] in (QUARANTINED, RECOVERY_PENDING)]
        recent = [t for ts, t in self._high_event_ts if now - ts < 12]
        if quarantined:
            key = ("ALERT", "QUARANTINE", len(quarantined))
            lcd = f"{len(quarantined)} QUARANTINED"
        elif recent:
            key = ("ALERT", recent[-1], 0)
            lcd = recent[-1]
        else:
            key, lcd = ("SAFE", None, 0), None
        if key != self._phys_key:
            self._phys_key = key
            if key[0] == "ALERT":
                self._actuate(self.node.alert, key[1] if key[1] != "QUARANTINE" else "QUARANTINE", lcd)
            else:
                self._actuate(self.node.safe)
            self._post_feed("PHYSICAL", "Alarm ACTIVE on ESP-2" if key[0] == "ALERT" else "ESP-2 returned to SAFE", {"state": key[0]})
        self._resync_real_node(key[0] == "ALERT", key[1], lcd, now)

    def _resync_real_node(self, want_alert: bool, kind, lcd, now: float) -> None:
        """Self-heal: if the real ESP-2 disagrees with the system state (e.g. it was unreachable when
        the command was sent, or was left in alarm by an earlier run), send the right command again."""
        node = self.node
        if not isinstance(node, Esp32ResponseNode) or not node.reachable or not node.remote:
            return
        if now < self._manual_until or now - self._last_resync < 5.0:
            return
        actual = bool(node.remote.get("intrusion_active"))
        if actual != want_alert:
            self._last_resync = now
            self._post_feed("PHYSICAL", f"ESP-2 out of sync (alarm={'on' if actual else 'off'}) — re-sending {'ALERT' if want_alert else 'SAFE'}", {})
            if want_alert:
                self._actuate(node.alert, kind if kind != "QUARANTINE" else "QUARANTINE", lcd)
            else:
                self._actuate(node.safe)

    # =============================================================================
    # integrity (ledger -> trust feedback)
    # =============================================================================
    def run_integrity(self) -> dict[str, Any]:
        with self.lock:
            self._last_integrity = self.clock.now()
            report = self.integrity.run()
            now = self.clock.now()
            for m in report["new_mismatches"]:
                self._on_tamper(m, now)
            for nf in report["new_node_faults"]:
                try:
                    self.network.submit("INTEGRITY_ALERT", {"event_id": None, "device_id": None, "kind": "NODE_TAMPER",
                                                           "node": nf["node"], "first_bad_index": nf["first_bad_index"]})
                except LedgerError:
                    pass
                self.system_alerts.appendleft({"ts": now, "kind": "NODE_TAMPER", "node": nf["node"], "first_bad_index": nf["first_bad_index"]})
                self._post_feed("INTEGRITY", f"Ledger node {nf['node']} failed audit (first bad block {nf['first_bad_index']})", nf)
            self.version += 1
            return report

    def _on_tamper(self, m: dict[str, Any], now: float) -> None:
        """Feedback: ledger-integrity mismatch lowers the implicated device's trust."""
        self.contract.recordIntegrityAlert(m["event_id"], m["device_id"], m["kind"], m["expected_hash"], m["found_hash"])
        self._post_feed("INTEGRITY", f"{m['kind']} on {m['event_id']} — local log differs from ledger", m)
        dev = self.contract.get_device(m["device_id"])
        if dev is None or dev["status"] != ACTIVE:
            return
        risk, parts = risk_score(SEVERITY["AUDIT_TAMPERING"], 0.0, 0.0, dev["trust"], True)
        self._raise_event(m["device_id"], "AUDIT_TAMPERING", risk, {"source": "local-db", "port": 0, "protocol": "FS"},
                          {"req_rate": 0, "failed_auth": 0}, {"tampered_event": m["event_id"], "kind": m["kind"], "risk_parts": parts},
                          now, forced_severity="CRITICAL")

    def tamper_local(self, event_id: str | None = None, mode: str = "edit") -> dict[str, Any]:
        """Demo: an intruder edits the local security log to hide an attack."""
        with self.lock:
            if event_id is None:
                evs = [e for e in self.store.list_events(50) if e["event_type"] != "AUDIT_TAMPERING" and not self.contract.events.get(e["event_id"], {}).get("integrity_flagged")]
                if not evs:
                    raise ValueError("no untampered security event exists yet — launch an attack first")
                event_id = evs[0]["event_id"]
            ev = self.store.get_event(event_id)
            if ev is None:
                raise ValueError("unknown event")
            before = {"severity": ev["severity"], "risk_score": ev["risk_score"], "action": ev["action"]}
            if mode == "delete":
                self.store.raw_delete(event_id)
            else:
                self.store.raw_update(event_id, "severity", "LOW")
                self.store.raw_update(event_id, "risk_score", 0.05)
                self.store.raw_update(event_id, "action", "LOGGED")
            self._post_feed("TAMPER", f"[simulation] local log {'deleted' if mode == 'delete' else 'edited'}: {event_id}", {"event_id": event_id})
            return {"event_id": event_id, "mode": mode, "before": before}

    def tamper_ledger(self, node_id: str = "node-2", index: int | None = None) -> dict[str, Any]:
        """Demo: an intruder edits one validator's copy of the chain."""
        with self.lock:
            node = self.network.node(node_id)
            if index is None:
                index = next((b.index for b in reversed(node.blocks()) if b.tx_type == "ATTACK_EVENT"), node.height() - 1)
            blk = node.get(index)
            if blk is None or index == 0:
                raise ValueError("invalid block index")
            d = blk.to_dict()
            if "severity" in d["payload"]:
                d["payload"]["severity"] = "LOW"
            else:
                d["payload"]["tampered"] = True
            node.overwrite_raw(index, d)
            self._post_feed("TAMPER", f"[simulation] {node_id} block #{index} modified directly in storage", {"node": node_id, "index": index})
            return {"node": node_id, "index": index}

    def repair_record(self, event_id: str) -> dict[str, Any]:
        """Restore a tampered local record's hashed fields from the ledger payload."""
        with self.lock:
            ev = self.contract.events.get(event_id)
            if ev is None:
                raise ValueError("event is not on the ledger")
            local = self.store.get_event(event_id)
            if local is None:
                raise ValueError("record deleted — only the hashed fields survive on-chain; cannot rebuild details")
            for col in ("severity", "risk_score", "event_type", "action", "source", "trust_after"):
                self.store.raw_update(event_id, col, ev[col] if col in ev else local[col])
            ok = event_hash(self.store.get_event(event_id)) == ev["event_hash"]
            self._post_feed("INTEGRITY", f"Local record {event_id} repaired from ledger" if ok else f"Repair of {event_id} incomplete", {"event_id": event_id})
            return {"event_id": event_id, "repaired": ok}

    # =============================================================================
    # quarantine state machine: ACTIVE -> QUARANTINED -> RECOVERY_PENDING -> ACTIVE
    # =============================================================================
    def manual_quarantine(self, device_id: str, admin: str = "admin") -> dict[str, Any]:
        with self.lock:
            self.contract.quarantineDevice(device_id, f"manual quarantine by {admin}")
            rt = self.runtimes.get(device_id)
            if rt:
                rt.clean_streak = 0
            self._post_feed("QUARANTINE", f"{self._name(device_id)} quarantined by {admin}", {"device_id": device_id})
            self._reconcile_physical(self.clock.now())
            self.version += 1
            return {"device_id": device_id, "status": QUARANTINED}

    def recovery_check(self, device_id: str) -> dict[str, Any]:
        with self.lock:
            dev = self.contract.get_device(device_id)
            if dev is None:
                raise ValueError("unknown device")
            if dev["status"] != QUARANTINED:
                raise ValueError(f"device is {dev['status']}, not QUARANTINED")
            rt = self.runtimes.get(device_id)
            report = self.integrity.run()
            checks = {
                "identity_registered": {"ok": self.contract.verifyDevice(device_id),
                                        "detail": "device key is enrolled on the ledger" if self.contract.verifyDevice(device_id) else "unregistered device must be enrolled by an admin first"},
                "behaving_normally": {"ok": bool(rt and rt.clean_streak >= self.s.recovery_clean_ticks),
                                      "detail": f"{rt.clean_streak if rt else 0}/{self.s.recovery_clean_ticks} consecutive clean observations"},
                "no_active_attack": {"ok": not any(a["device_id"] == device_id and a["ticks_left"] > 0 for a in self.attacks),
                                     "detail": "no attack currently targeting this device"},
                "ledger_consistent": {"ok": report["ledger"]["consistent"], "detail": "all validators agree and verify"},
            }
            passed = all(c["ok"] for c in checks.values())
            if passed:
                self.contract.recordRecoveryVerified(device_id, {k: v["ok"] for k, v in checks.items()})
                self._post_feed("RECOVERY", f"{self._name(device_id)} passed security verification — awaiting admin approval", {"device_id": device_id})
            self.version += 1
            return {"device_id": device_id, "passed": passed, "checks": checks, "status": self.contract.get_device(device_id)["status"]}

    def approve_recovery(self, device_id: str, admin: str, notes: str = "") -> dict[str, Any]:
        with self.lock:
            block = self.contract.restoreDevice(device_id, admin, notes)
            rt = self.runtimes.get(device_id)
            if rt:
                rt.clean_streak = 0
                rt.ml_streak = 0
                rt.last_event_ts.clear()
            self.tracker.note_event(device_id)
            self._post_feed("RESTORE", f"{self._name(device_id)} restored by {admin}", {"device_id": device_id, "block": block.index})
            self._reconcile_physical(self.clock.now())
            self.version += 1
            return {"device_id": device_id, "status": ACTIVE, "block": block.index}

    # =============================================================================
    # command enforcement through the gateway
    # =============================================================================
    def send_command(self, to_device: str, command: str, from_device: str | None = None) -> dict[str, Any]:
        """from_device=None means the (authenticated) dashboard/admin."""
        with self.lock:
            tgt = self.contract.get_device(to_device)
            rt = self.runtimes.get(to_device)
            if tgt is None or rt is None:
                raise ValueError("unknown target device")
            if command not in COMMANDS.get(rt.kind, []):
                raise ValueError(f"{rt.name} does not support '{command}'")
            result = {"to": to_device, "from": from_device or "dashboard", "command": command}
            verdict, reason = True, "allowed"
            src = self.contract.get_device(from_device) if from_device else None
            if from_device and src is None:
                verdict, reason = False, "originating device is not registered"
            elif src is not None and src["status"] != ACTIVE:
                verdict, reason = False, f"originating device is {src['status']} — outbound commands blocked"
            elif tgt["status"] != ACTIVE:
                mode = rt.spec.fail_mode if rt.spec else "standard"
                if command in ALLOW_WHEN_QUARANTINED.get(rt.kind, ()) and (src is None or src["trust"] >= DEFAULT_MIN_TRUST):
                    verdict, reason = True, f"allowed: '{command}' reduces risk, so it is honoured even while {tgt['status']}"
                else:
                    verdict = False
                    reason = f"target is {tgt['status']} — inbound command blocked. " + QUARANTINE_POLICY.get(mode, "")
            elif src is not None and src["trust"] < MIN_TRUST.get(command, DEFAULT_MIN_TRUST):
                verdict, reason = False, f"origin trust {src['trust']:.0f} below {MIN_TRUST.get(command, DEFAULT_MIN_TRUST)} required for '{command}'"
            if verdict:
                self._apply_command(rt, command)
            else:
                self.counters["commands_blocked"] += 1
            result.update(allowed=verdict, reason=reason, state=rt.state)
            self._post_feed("COMMAND", f"{'ALLOWED' if verdict else 'BLOCKED'}: {result['from'].split(':')[-1] if from_device else 'dashboard'} → {rt.name}.{command}", result)
            self.version += 1
            return result

    @staticmethod
    def _apply_command(rt: DeviceRuntime, command: str) -> None:
        key, value = COMMAND_EFFECT.get(command, ("last_command", command))
        rt.state[key] = value

    # =============================================================================
    # views
    # =============================================================================
    def _post_feed(self, kind: str, msg: str, data: dict[str, Any]) -> None:
        self.seq += 1
        self.feed.appendleft({"seq": self.seq, "ts": self.clock.now(), "kind": kind, "msg": msg, "data": _clean(data)})

    def sim_clock(self) -> dict[str, Any]:
        m = int(self.sim_minute)
        return {"hour": round(self.sim_minute / 60.0, 2), "label": f"{m // 60:02d}:{m % 60:02d}",
                "minutes_per_tick": self.s.sim_minutes_per_tick, "tick": self.tick}

    def set_sim_hour(self, hour: float) -> None:
        with self.lock:
            self.sim_minute = (hour % 24) * 60.0
            self.version += 1

    def device_view(self, rt: DeviceRuntime, series: int = 90) -> dict[str, Any]:
        d = self.contract.get_device(rt.id) or {}
        last = rt.last or {}
        smp = last.get("sample", {})
        atk = next((self._attack_view(a) for a in self.attacks if a["device_id"] == rt.id and a["ticks_left"] > 0), None)
        v = {"id": rt.id, "name": rt.name, "kind": rt.kind, "status": d.get("status", "?"), "trust": d.get("trust", 0),
             "risk": last.get("risk", 0.0), "band": last.get("band", "SAFE"), "primary_name": rt.profile.primary_name,
             "sample": smp, "ml": last.get("ml"), "baseline": last.get("fi"), "risk_parts": last.get("parts"),
             "rules": [r["type"] for r in last.get("rules", [])], "blocked_msgs": rt.blocked_msgs, "suppressed": rt.suppressed,
             "online": rt.online, "real_hardware": rt.legacy is not None, "attack": atk, "state": rt.state,
             "ml_mode": "shadow" if (rt.legacy is not None and not self.s.real_ml) else "active",
             "clean_streak": rt.clean_streak, "recovery_needed": self.s.recovery_clean_ticks,
             "integrity_open": self.contract.unresolved_integrity.get(rt.id, 0), "quarantine": d.get("quarantine"),
             "recovery": d.get("recovery"), "registered_block": d.get("registered_block"),
             "pubkey": d.get("pubkey"), "firmware_hash": d.get("firmware_hash"),
             "series": list(rt.history)[-series:]}
        sp = rt.spec
        if sp is not None:
            room = next(r for r in ROOMS if r["id"] == sp.room)
            v.update(dtype=sp.dtype, room=sp.room, room_name=room["name"], category=sp.category, value_usd=sp.value_usd,
                     icon=sp.icon, model=sp.model, critical=sp.critical, fail_mode=sp.fail_mode,
                     fail_policy=QUARANTINE_POLICY.get(sp.fail_mode, ""), commands=COMMANDS.get(rt.kind, []))
        if rt.kind == "smart_home_node":
            v["lock_policy"] = LOCK_POLICY
        return v

    def _cached_audit(self, now: float) -> dict[str, Any]:
        """Full chain verification is O(blocks x validators); refresh it when the chain grows or every few seconds."""
        sig = (self.contract.height, int(now // 3))
        if getattr(self, "_audit_sig", None) != sig:
            self._audit, self._audit_sig = self.network.audit(), sig
        return self._audit

    def unknown_devices(self) -> list[dict[str, Any]]:
        out = []
        for d in self.contract.list_devices():
            if d.get("unregistered"):
                out.append({"id": d["device_id"], "name": d["name"], "kind": "unknown", "status": d["status"], "trust": d["trust"],
                            "unregistered": True, "quarantine": d.get("quarantine")})
        return out

    def overview(self) -> dict[str, Any]:
        with self.lock:
            now = self.clock.now()
            devs = [self.device_view(rt, 40) for rt in self.runtimes.values()]
            unknown = self.unknown_devices()
            quarantined = [d for d in devs + unknown if d["status"] in (QUARANTINED, RECOVERY_PENDING)]
            levels = ["SAFE", "SUSPICIOUS", "HIGH", "CRITICAL"]
            top = max((levels.index(d["band"]) for d in devs if d["status"] == ACTIVE), default=0)
            if quarantined:
                top = max(top, levels.index("HIGH"))
            net = self._cached_audit(now)
            levels_ix = {n: i for i, n in enumerate(levels)}
            rooms = []
            for r in ROOMS:
                members = [d for d in devs if d.get("room") == r["id"]]
                if not members:
                    continue
                worst = max((levels_ix[d["band"]] for d in members if d["status"] == ACTIVE), default=0)
                nq = sum(1 for d in members if d["status"] != ACTIVE)
                rooms.append({**r, "devices": [d["id"] for d in members], "count": len(members), "value_usd": sum(d["value_usd"] for d in members),
                              "quarantined": nq, "worst_band": levels[max(worst, levels_ix["HIGH"] if nq else 0)],
                              "attacks": sum(1 for d in members if d.get("attack"))})
            value = sum(d.get("value_usd", 0) for d in devs)
            value_q = sum(d.get("value_usd", 0) for d in devs if d["status"] != ACTIVE)
            return {
                "mode": self.s.mode, "now": now, "tick": self.tick, "sim": self.sim_clock(),
                "threat_level": levels[top], "devices": devs, "unknown_devices": unknown, "rooms": rooms,
                "categories": CATEGORIES, "home": {"devices": len(devs), "value_usd": value, "value_quarantined_usd": value_q,
                                                   "critical": sum(1 for d in devs if d.get("critical"))},
                "kpis": {"devices": len(devs), "quarantined": len(quarantined), "avg_trust": round(sum(d["trust"] for d in devs) / max(len(devs), 1), 1),
                         "events": self.store.count(), "chain_height": self.contract.height, "ledger_consistent": net["consistent"],
                         "integrity_status": self.integrity.last_report.get("status"), **self.counters},
                "ledger": {"consistent": net["consistent"], "height": net["height"], "quorum": net["quorum"],
                           "nodes": [{k: n[k] for k in ("node", "valid", "height", "head_hash", "online", "matches_majority", "first_bad_index", "diverges_at")} for n in net["nodes"]]},
                "physical": self.node.snapshot(), "attacks": [self._attack_view(a) for a in self.attacks],
                "attack_log": list(self.attack_log)[:12], "blocklist": self.blocklist.entries(now),
                "system_alerts": list(self.system_alerts)[:5],
                "baseline_ready": True, "model": {"trained_at": self.model.metrics.get("trained_at"), "threshold": self.model.threshold},
            }
