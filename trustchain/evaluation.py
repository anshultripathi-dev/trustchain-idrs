"""Headless evaluation: runs every attack scenario on fresh in-memory engines (virtual clock)
and reports detection rate, classification accuracy, latency, response outcome and the
false-positive rate on clean traffic. Results describe the *simulator*, not a real home."""
from __future__ import annotations

import time
from typing import Any

import numpy as np

from .config import Settings
from .engine import SMART_HOME_ID, Engine
from .ledger.contract import QUARANTINED
from .sim.profiles import ATTACKS

TRIALS_DEFAULT = 5


def _engine(model, seed: int, hour: float) -> Engine:
    return Engine(Settings(in_memory=True, virtual_clock=True, home="core"), model=model, seed=seed, start_hour=hour)


def run_clean(model, ticks: int = 1200, seed: int = 11) -> dict[str, Any]:
    e = _engine(model, seed, 6.0)
    for _ in range(ticks):
        e.step()
    n_events = e.store.count()
    return {"ticks": ticks, "device_ticks": ticks * len(e.runtimes), "false_events": n_events,
            "false_positive_rate": round(n_events / (ticks * len(e.runtimes)), 6),
            "false_quarantines": sum(1 for d in e.contract.list_devices() if d["status"] == QUARANTINED),
            "sim_days": round(ticks * e.s.sim_minutes_per_tick / 1440, 2)}


def run_home_clean(model, ticks: int = 1728, seeds=(1, 2, 3)) -> dict[str, Any]:
    """Clean traffic on the FULL smart home (every device, every room): alert noise and false quarantines."""
    sev: dict[str, int] = {}
    events = quarantines = device_ticks = 0
    for seed in seeds:
        e = Engine(Settings(in_memory=True, virtual_clock=True, home="full"), model=model, seed=seed, start_hour=6.0)
        for _ in range(ticks):
            e.step()
        device_ticks += ticks * len(e.runtimes)
        for ev in e.store.list_events(10_000):
            sev[ev["severity"]] = sev.get(ev["severity"], 0) + 1
        events += e.store.count()
        quarantines += sum(1 for d in e.contract.list_devices() if d["status"] == QUARANTINED)
    days = len(seeds) * ticks * e.s.sim_minutes_per_tick / 1440
    return {"devices": len(e.runtimes), "device_ticks": device_ticks, "sim_days": round(days, 1), "events": events,
            "events_per_sim_day": round(events / days, 2), "by_severity": sev, "false_quarantines": quarantines}


def run_scenario(model, atype: str, trial: int) -> dict[str, Any]:
    night = atype == "STEALTH_SURGE"
    e = _engine(model, 1000 + trial * 17 + hash(atype) % 997, 2.0 if night else 14.0)
    for _ in range(20):
        e.step()
    device = None if atype == "ROGUE_DEVICE" else SMART_HOME_ID
    a = e.launch_attack(atype, device)
    for _ in range(a["ticks_total"] + 6):
        e.step()
    log = next((x for x in e.attack_log if x["id"] == a["id"]), None) or {}
    dev = e.contract.get_device(log.get("device_id") or SMART_HOME_ID) or {}
    return {"detected": bool(log.get("detected")), "classified": bool(log.get("classified_correctly")),
            "latency_ticks": log.get("detection_latency_ticks"), "events": len(log.get("events", [])),
            "quarantined": dev.get("status") in (QUARANTINED, "RECOVERY_PENDING"), "trust_after": dev.get("trust"),
            "ledger_consistent": e.network.audit()["consistent"]}


def run_tamper(model, kind: str, trial: int) -> dict[str, Any]:
    e = _engine(model, 5000 + trial, 14.0)
    for _ in range(10):
        e.step()
    e.launch_attack("BRUTE_FORCE", SMART_HOME_ID)
    for _ in range(12):
        e.step()
    e.stop_attacks()
    trust_before = e.contract.get_device(SMART_HOME_ID)["trust"]
    status_before = e.contract.get_device(SMART_HOME_ID)["status"]
    if kind == "LOG_TAMPERING":
        e.tamper_local()
        rep = e.run_integrity()
        dev = e.contract.get_device(SMART_HOME_ID)
        return {"detected": bool(rep["mismatches"]), "trust_before": trust_before, "trust_after": dev["trust"],
                "device_status_before": status_before, "quarantined": dev["status"] == QUARANTINED}
    e.tamper_ledger("node-2")
    rep = e.run_integrity()
    bad = next(n for n in rep["ledger"]["nodes"] if n["node"] == "node-2")
    e.network.submit("SYSTEM_NOTE", {"note": "post-tamper write"})   # chain keeps working on remaining quorum
    return {"detected": not bad["valid"], "network_continues": True, "first_bad_index": bad["first_bad_index"]}


def evaluate(model, trials: int = TRIALS_DEFAULT, progress=None) -> dict[str, Any]:
    t0 = time.time()
    out: dict[str, Any] = {"synthetic": True, "trials": trials, "scenarios": {}, "tamper": {}}
    out["clean"] = run_clean(model)
    if progress:
        progress("clean")
    out["home_clean"] = run_home_clean(model)
    if progress:
        progress("home_clean")
    for atype in ATTACKS:
        rows = [run_scenario(model, atype, t) for t in range(trials)]
        lat = [r["latency_ticks"] for r in rows if r["latency_ticks"] is not None]
        out["scenarios"][atype] = {
            "label": ATTACKS[atype]["label"], "layer": ATTACKS[atype]["layer"],
            "detection_rate": round(sum(r["detected"] for r in rows) / trials, 3),
            "classification_rate": round(sum(r["classified"] for r in rows) / trials, 3),
            "mean_latency_ticks": round(float(np.mean(lat)), 2) if lat else None,
            "quarantine_rate": round(sum(r["quarantined"] for r in rows) / trials, 3),
            "ledger_consistent": all(r["ledger_consistent"] for r in rows),
        }
        if progress:
            progress(atype)
    for kind in ("LOG_TAMPERING", "LEDGER_NODE_TAMPERING"):
        rows = [run_tamper(model, kind, t) for t in range(trials)]
        out["tamper"][kind] = {"detection_rate": round(sum(r["detected"] for r in rows) / trials, 3),
                               "quarantine_rate": round(sum(r.get("quarantined", False) for r in rows) / trials, 3)}
        if progress:
            progress(kind)
    out["seconds"] = round(time.time() - t0, 1)
    out["finished_at"] = time.time()
    return out
