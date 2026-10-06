"""Security smart contract: deterministic state machine whose state is derived entirely
by replaying the ledger. Functions mirror the architecture proposal:

    registerDevice / verifyDevice / recordAttack / updateTrustScore /
    quarantineDevice / verifyAttackRecord / restoreDevice
"""
from __future__ import annotations

import copy
import threading
from typing import Any

from .chain import Block, LedgerError, LedgerNetwork

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

ACTIVE = "ACTIVE"
QUARANTINED = "QUARANTINED"
RECOVERY_PENDING = "RECOVERY_PENDING"

DEFAULT_POLICY = {
    "trust_baseline": 100,
    "quarantine_below": 20,     # IF trust_score < 20 THEN quarantine
    "restore_trust": 60,
    "recurrence_window_s": 3600,
    "repeat_escalate_1": 1,     # >=1 prior related event -> severity +1
    "repeat_escalate_2": 3,     # >=3 prior related events -> severity +2
}


def escalate(severity: str, levels: int) -> str:
    i = SEVERITIES.index(severity) if severity in SEVERITIES else 0
    return SEVERITIES[min(len(SEVERITIES) - 1, i + levels)]


class ContractError(Exception):
    pass


class SecurityContract:
    def __init__(self, network: LedgerNetwork, policy: dict[str, Any] | None = None):
        self.network = network
        self.policy = {**DEFAULT_POLICY, **(policy or {})}
        self._lock = threading.RLock()
        self._reset_state()
        network.on_commit.append(self._on_commit)

    # ---- state ------------------------------------------------------------------------
    def _reset_state(self) -> None:
        self.devices: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.event_order: list[str] = []
        self.fingerprints: dict[str, dict[str, Any]] = {}
        self.sources: dict[str, dict[str, Any]] = {}
        self.trust_history: dict[str, list[dict[str, Any]]] = {}
        self.integrity_alerts: list[dict[str, Any]] = []
        self.unresolved_integrity: dict[str, int] = {}
        self.tx_counts: dict[str, int] = {}
        self.height = 0

    def rebuild(self) -> None:
        """Replay the whole ledger (used on start-up and after chain repair)."""
        with self._lock:
            self._reset_state()
            for b in self.network.iter_blocks():
                self._apply(b)

    def _on_commit(self, block: Block) -> None:
        with self._lock:
            self._apply(block)

    def _apply(self, b: Block) -> None:
        p = b.payload
        t = b.tx_type
        self.height = b.index + 1
        self.tx_counts[t] = self.tx_counts.get(t, 0) + 1
        if t == "GENESIS":
            self.policy = {**self.policy, **b.payload.get("policy", {})}
        elif t == "REGISTER_DEVICE":
            self.devices[p["device_id"]] = {
                "device_id": p["device_id"],
                "name": p.get("name", p["device_id"]),
                "kind": p.get("kind", "device"),
                "pubkey": p["pubkey"],
                "firmware_hash": p.get("firmware_hash"),
                "status": ACTIVE,
                "trust": self.policy["trust_baseline"],
                "registered_at": b.timestamp,
                "registered_block": b.index,
                "unregistered": False,
                "quarantine": None,
            }
            self.trust_history[p["device_id"]] = [
                {"ts": b.timestamp, "trust": self.policy["trust_baseline"], "reason": "REGISTERED", "block": b.index}
            ]
        elif t == "ATTACK_EVENT":
            d = self.devices.get(p["device_id"])
            if d is None:  # sighting of an unregistered node
                d = self.devices[p["device_id"]] = {
                    "device_id": p["device_id"], "name": f"Unknown {p['device_id'][-8:]}",
                    "kind": "unknown", "pubkey": None, "firmware_hash": None,
                    "status": ACTIVE, "trust": 0, "registered_at": None,
                    "registered_block": None, "unregistered": True, "quarantine": None,
                }
                self.trust_history[p["device_id"]] = []
            rec = {**p, "block": b.index, "block_hash": b.hash, "committed_at": b.timestamp}
            self.events[p["event_id"]] = rec
            self.event_order.append(p["event_id"])
            fp = self.fingerprints.setdefault(
                p["fingerprint"],
                {"fingerprint": p["fingerprint"], "count": 0, "first_ts": p["ts"], "last_ts": p["ts"],
                 "event_type": p["event_type"], "devices": [], "sources": []},
            )
            fp["count"] += 1
            fp["last_ts"] = p["ts"]
            if p["device_id"] not in fp["devices"]:
                fp["devices"].append(p["device_id"])
            if p.get("source") and p["source"] not in fp["sources"]:
                fp["sources"].append(p["source"])
            src = p.get("source")
            if src:
                s = self.sources.setdefault(
                    src, {"source": src, "count": 0, "first_ts": p["ts"], "last_ts": p["ts"], "types": []}
                )
                s["count"] += 1
                s["last_ts"] = p["ts"]
                if p["event_type"] not in s["types"]:
                    s["types"].append(p["event_type"])
        elif t == "TRUST_UPDATE":
            d = self.devices.get(p["device_id"])
            if d is not None:
                d["trust"] = p["trust"]
                self.trust_history.setdefault(p["device_id"], []).append(
                    {"ts": b.timestamp, "trust": p["trust"], "reason": p.get("reason", ""), "block": b.index}
                )
        elif t == "QUARANTINE":
            d = self.devices.get(p["device_id"])
            if d is not None:
                d["status"] = QUARANTINED
                d["quarantine"] = {"since": b.timestamp, "reason": p.get("reason", ""), "block": b.index}
        elif t == "RECOVERY_VERIFIED":
            d = self.devices.get(p["device_id"])
            if d is not None:
                d["status"] = RECOVERY_PENDING
                d["recovery"] = {"checks": p.get("checks", {}), "block": b.index, "ts": b.timestamp}
        elif t == "RESTORE":
            d = self.devices.get(p["device_id"])
            if d is not None:
                d["status"] = ACTIVE
                d["trust"] = p["trust"]
                d["quarantine"] = None
                d.pop("recovery", None)
                d["restored_by"] = p.get("admin")
                self.unresolved_integrity.pop(p["device_id"], None)
                self.trust_history.setdefault(p["device_id"], []).append(
                    {"ts": b.timestamp, "trust": p["trust"], "reason": f"RESTORED by {p.get('admin')}", "block": b.index}
                )
        elif t == "INTEGRITY_ALERT":
            self.integrity_alerts.append({**p, "block": b.index, "ts": b.timestamp})
            dev = p.get("device_id")
            if dev:
                self.unresolved_integrity[dev] = self.unresolved_integrity.get(dev, 0) + 1
            if p.get("event_id") in self.events:
                self.events[p["event_id"]]["integrity_flagged"] = True

    # ---- read-only functions ---------------------------------------------------------------
    def get_device(self, device_id: str) -> dict[str, Any] | None:
        with self._lock:
            d = self.devices.get(device_id)
            return copy.deepcopy(d) if d else None

    def list_devices(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(list(self.devices.values()))

    def verifyDevice(self, device_id: str, pubkey: str | None = None) -> bool:
        with self._lock:
            d = self.devices.get(device_id)
            if d is None or d.get("unregistered"):
                return False
            return pubkey is None or d["pubkey"] == pubkey

    def verifyAttackRecord(self, event_id: str, recomputed_hash: str) -> dict[str, Any]:
        with self._lock:
            ev = self.events.get(event_id)
            if ev is None:
                return {"event_id": event_id, "result": "NOT_ON_CHAIN", "match": False}
            match = ev["event_hash"] == recomputed_hash
            return {
                "event_id": event_id,
                "result": "MATCH" if match else "MISMATCH",
                "match": match,
                "chain_hash": ev["event_hash"],
                "recomputed_hash": recomputed_hash,
                "block": ev["block"],
                "block_hash": ev["block_hash"],
            }

    def assess_recurrence(self, fingerprint: str, source: str | None, event_type: str, now: float) -> dict[str, Any]:
        """Attack memory: has this fingerprint / source+type been seen before?"""
        window = self.policy["recurrence_window_s"]
        with self._lock:
            prior = 0
            fp = self.fingerprints.get(fingerprint)
            if fp and now - fp["last_ts"] <= window:
                prior = fp["count"]
            elif source:
                s = self.sources.get(source)
                if s and event_type in s["types"] and now - s["last_ts"] <= window:
                    prior = max(prior, 1)
        levels = 0
        if prior >= self.policy["repeat_escalate_2"]:
            levels = 2
        elif prior >= self.policy["repeat_escalate_1"]:
            levels = 1
        return {"repeat_count": prior, "escalate_levels": levels}

    # ---- state-changing functions (each commits a block) ------------------------------------
    def registerDevice(self, device_id: str, name: str, kind: str, pubkey: str, firmware_hash: str | None = None) -> Block:
        with self._lock:
            if device_id in self.devices and not self.devices[device_id].get("unregistered"):
                raise ContractError(f"{device_id} already registered")
        return self.network.submit(
            "REGISTER_DEVICE",
            {"device_id": device_id, "name": name, "kind": kind, "pubkey": pubkey, "firmware_hash": firmware_hash},
        )

    def recordAttack(self, record: dict[str, Any]) -> Block:
        required = {"event_id", "device_id", "event_type", "severity", "risk_score", "event_hash", "fingerprint", "ts"}
        missing = required - set(record)
        if missing:
            raise ContractError(f"missing fields: {sorted(missing)}")
        return self.network.submit("ATTACK_EVENT", record)

    def updateTrustScore(self, device_id: str, new_score: float, reason: str) -> dict[str, Any]:
        """Commit a trust change. Returns whether the policy rule requires quarantine."""
        new_score = max(0.0, min(100.0, round(float(new_score), 1)))
        with self._lock:
            d = self.devices.get(device_id)
            if d is None:
                raise ContractError(f"unknown device {device_id}")
            previous = d["trust"]
        block = self.network.submit(
            "TRUST_UPDATE", {"device_id": device_id, "trust": new_score, "previous": previous, "reason": reason}
        )
        # Illustrative rule from the design: IF trust_score < 20 THEN mark for quarantine.
        return {"block": block, "quarantine_required": new_score < self.policy["quarantine_below"]}

    def quarantineDevice(self, device_id: str, reason: str) -> Block:
        with self._lock:
            d = self.devices.get(device_id)
            if d is None:
                raise ContractError(f"unknown device {device_id}")
            if d["status"] == QUARANTINED:
                raise ContractError("already quarantined")
            trust = d["trust"]
        return self.network.submit("QUARANTINE", {"device_id": device_id, "reason": reason, "trust": trust})

    def recordRecoveryVerified(self, device_id: str, checks: dict[str, Any]) -> Block:
        with self._lock:
            d = self.devices.get(device_id)
            if d is None or d["status"] != QUARANTINED:
                raise ContractError("device is not quarantined")
        return self.network.submit("RECOVERY_VERIFIED", {"device_id": device_id, "checks": checks})

    def restoreDevice(self, device_id: str, admin: str, notes: str = "") -> Block:
        with self._lock:
            d = self.devices.get(device_id)
            if d is None:
                raise ContractError(f"unknown device {device_id}")
            if d["status"] != RECOVERY_PENDING:
                raise ContractError("restore requires a completed recovery verification")
        return self.network.submit(
            "RESTORE",
            {"device_id": device_id, "admin": admin, "notes": notes, "trust": self.policy["restore_trust"]},
        )

    def recordIntegrityAlert(self, event_id: str, device_id: str | None, kind: str, expected: str | None, found: str | None) -> Block:
        return self.network.submit(
            "INTEGRITY_ALERT",
            {"event_id": event_id, "device_id": device_id, "kind": kind, "expected_hash": expected, "found_hash": found},
        )

    # ---- convenience ---------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "height": self.height,
                "tx_counts": dict(self.tx_counts),
                "events": len(self.events),
                "fingerprints": len(self.fingerprints),
                "integrity_alerts": len(self.integrity_alerts),
                "policy": dict(self.policy),
            }
