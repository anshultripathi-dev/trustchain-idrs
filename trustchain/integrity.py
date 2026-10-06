"""Ledger-integrity checker (Module E): recompute local record hashes, compare with the
chain, and audit the validator nodes. Its result is a direct *input to device trust*
(see Engine._on_tamper) rather than a passive report."""
from __future__ import annotations

from typing import Any

from .ledger.chain import LedgerNetwork
from .ledger.contract import SecurityContract
from .store import LocalStore, event_hash


class IntegrityChecker:
    def __init__(self, contract: SecurityContract, network: LedgerNetwork, store: LocalStore, clock):
        self.contract, self.network, self.store, self.clock = contract, network, store, clock
        self.last_report: dict[str, Any] = {"ran_at": None, "status": "NOT_RUN"}
        self._node_alerted: set[tuple[str, int | None]] = set()

    def scan_records(self) -> list[dict[str, Any]]:
        """Return mismatches between local records and their on-chain hashes."""
        out = []
        for event_id in list(self.contract.event_order):
            ev = self.contract.events[event_id]
            local = self.store.get_event(event_id)
            if local is None:
                out.append({"event_id": event_id, "device_id": ev["device_id"], "kind": "MISSING_RECORD",
                            "expected_hash": ev["event_hash"], "found_hash": None, "already_flagged": bool(ev.get("integrity_flagged"))})
                continue
            found = event_hash(local)
            if found != ev["event_hash"]:
                out.append({"event_id": event_id, "device_id": ev["device_id"], "kind": "HASH_MISMATCH",
                            "expected_hash": ev["event_hash"], "found_hash": found, "already_flagged": bool(ev.get("integrity_flagged"))})
        return out

    def run(self) -> dict[str, Any]:
        audit = self.network.audit()
        mism = self.scan_records()
        new_nodes = []
        for r in audit["nodes"]:
            if r["online"] and not (r["valid"] and r["matches_majority"]):
                key = (r["node"], r["first_bad_index"] if r["first_bad_index"] is not None else r.get("diverges_at"))
                if key not in self._node_alerted:
                    self._node_alerted.add(key)
                    new_nodes.append({"node": r["node"], "first_bad_index": key[1], "errors": r["errors"]})
        report = {
            "ran_at": self.clock.now(),
            "status": "OK" if audit["consistent"] and not mism else "TAMPERING_DETECTED",
            "ledger": audit,
            "records_checked": len(self.contract.event_order),
            "mismatches": mism,
            "new_mismatches": [m for m in mism if not m["already_flagged"]],
            "new_node_faults": new_nodes,
        }
        self.last_report = report
        return report

    def forget_node_alerts(self, node_id: str) -> None:
        self._node_alerted = {k for k in self._node_alerted if k[0] != node_id}

