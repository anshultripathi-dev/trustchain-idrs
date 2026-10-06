"""Permissioned hash-chain ledger replicated across several validator nodes.

Each block carries one transaction, is linked to its predecessor by SHA-256, is signed by
its proposer (round-robin proof-of-authority) and co-signed by a quorum of validators.
Every node keeps its own SQLite copy, so tampering with one copy is detected by hash
linkage, signature checks, and cross-node comparison.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..crypto import KeyPair, canonical, sha256_hex, verify

ZERO_HASH = "0" * 64


class LedgerError(Exception):
    pass


@dataclass
class Block:
    index: int
    timestamp: float
    tx_type: str
    payload: dict[str, Any]
    prev_hash: str
    proposer: str
    hash: str = ""
    signatures: dict[str, str] = field(default_factory=dict)

    def header(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "tx_type": self.tx_type,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "proposer": self.proposer,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical(self.header()))

    def to_dict(self) -> dict[str, Any]:
        return {**self.header(), "hash": self.hash, "signatures": dict(self.signatures)}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Block":
        return cls(
            index=d["index"],
            timestamp=d["timestamp"],
            tx_type=d["tx_type"],
            payload=d["payload"],
            prev_hash=d["prev_hash"],
            proposer=d["proposer"],
            hash=d.get("hash", ""),
            signatures=dict(d.get("signatures", {})),
        )


class LedgerNode:
    """One validator holding a full copy of the chain."""

    def __init__(self, node_id: str, keypair: KeyPair, db_path: str = ":memory:"):
        self.node_id = node_id
        self.keypair = keypair
        self.online = True
        self.db_path = db_path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS blocks (idx INTEGER PRIMARY KEY, hash TEXT, data TEXT)"
        )
        self._db.commit()
        self._sig_cache: set[str] = set()

    # ---- storage -------------------------------------------------------------------
    def height(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM blocks").fetchone()
            return int(row[0])

    def head(self) -> Block | None:
        with self._lock:
            row = self._db.execute(
                "SELECT data FROM blocks ORDER BY idx DESC LIMIT 1"
            ).fetchone()
        return Block.from_dict(json.loads(row[0])) if row else None

    def get(self, index: int) -> Block | None:
        with self._lock:
            row = self._db.execute("SELECT data FROM blocks WHERE idx=?", (index,)).fetchone()
        return Block.from_dict(json.loads(row[0])) if row else None

    def blocks(self, start: int = 0, limit: int | None = None) -> list[Block]:
        sql = "SELECT data FROM blocks WHERE idx>=? ORDER BY idx"
        params: tuple = (start,)
        if limit is not None:
            sql += " LIMIT ?"
            params = (start, limit)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [Block.from_dict(json.loads(r[0])) for r in rows]

    def append_raw(self, block: Block) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO blocks (idx, hash, data) VALUES (?,?,?)",
                (block.index, block.hash, json.dumps(block.to_dict(), sort_keys=True)),
            )
            self._db.commit()

    def truncate_from(self, index: int) -> None:
        with self._lock:
            self._db.execute("DELETE FROM blocks WHERE idx>=?", (index,))
            self._db.commit()
        self._sig_cache.clear()

    def overwrite_raw(self, index: int, data: dict[str, Any]) -> None:
        """Direct DB write that bypasses validation -- used only to simulate an attacker."""
        with self._lock:
            self._db.execute(
                "UPDATE blocks SET data=? WHERE idx=?", (json.dumps(data, sort_keys=True), index)
            )
            self._db.commit()

    # ---- validation ------------------------------------------------------------------
    def validators(self) -> dict[str, str]:
        genesis = self.get(0)
        if not genesis:
            return {}
        return dict(genesis.payload.get("validators", {}))

    def quorum(self) -> int:
        genesis = self.get(0)
        return int(genesis.payload.get("quorum", 1)) if genesis else 1

    def _sig_ok(self, block: Block, validators: dict[str, str]) -> tuple[bool, str]:
        key = sha256_hex(canonical(block.header()) + canonical(block.signatures))
        if key in self._sig_cache:
            return True, ""
        data = block.hash.encode()
        pub = validators.get(block.proposer)
        if block.index > 0:
            if pub is None:
                return False, f"proposer {block.proposer} is not a validator"
            if not verify(pub, data, block.signatures.get(block.proposer, "")):
                return False, "invalid proposer signature"
        good = {n for n, s in block.signatures.items() if n in validators and verify(validators[n], data, s)}
        need = int(self._quorum_for(block))
        if block.index > 0 and len(good) < need:
            return False, f"only {len(good)} valid signatures, quorum is {need}"
        self._sig_cache.add(key)
        return True, ""

    def _quorum_for(self, block: Block) -> int:
        return self.quorum()

    def verify_chain(self) -> dict[str, Any]:
        """Full local audit: hash recomputation, linkage, signatures."""
        blocks = self.blocks()
        errors: list[dict[str, Any]] = []
        validators = dict(blocks[0].payload.get("validators", {})) if blocks else {}
        prev: Block | None = None
        for b in blocks:
            problem = None
            if b.compute_hash() != b.hash:
                problem = "block hash does not match contents"
            elif prev is None and (b.index != 0 or b.prev_hash != ZERO_HASH):
                problem = "invalid genesis"
            elif prev is not None and b.prev_hash != prev.hash:
                problem = "broken link to previous block"
            elif prev is not None and b.index != prev.index + 1:
                problem = "non-sequential index"
            else:
                ok, why = self._sig_ok(b, validators)
                if not ok:
                    problem = why
            if problem:
                errors.append({"index": b.index, "error": problem})
            prev = b
        head = blocks[-1] if blocks else None
        return {
            "node": self.node_id,
            "valid": not errors,
            "height": len(blocks),
            "head_hash": head.hash if head else None,
            "first_bad_index": errors[0]["index"] if errors else None,
            "errors": errors[:5],
        }

    def validate_proposal(self, block: Block) -> tuple[bool, str]:
        """Pre-commit check used before endorsing a proposed block."""
        head = self.head()
        if head is None:
            return False, "empty chain"
        validators = self.validators()
        if block.index != head.index + 1:
            return False, "index mismatch"
        if block.prev_hash != head.hash:
            return False, "prev_hash mismatch"
        if block.compute_hash() != block.hash:
            return False, "hash mismatch"
        pub = validators.get(block.proposer)
        if pub is None or not verify(pub, block.hash.encode(), block.signatures.get(block.proposer, "")):
            return False, "bad proposer signature"
        return True, ""

    def endorse(self, block: Block) -> str | None:
        ok, _ = self.validate_proposal(block)
        return self.keypair.sign(block.hash.encode()) if ok else None


class LedgerNetwork:
    """Coordinates proposal, endorsement and commit across validator nodes."""

    def __init__(self, nodes: list[LedgerNode], clock=None):
        if len(nodes) < 1:
            raise ValueError("need at least one node")
        self.nodes = nodes
        self.clock = clock
        self._lock = threading.RLock()
        self.on_commit: list = []
        self.flagged: set[str] = set()  # nodes whose last audit failed

    def _now(self) -> float:
        return self.clock.now() if self.clock else time.time()

    @property
    def quorum(self) -> int:
        return len(self.nodes) // 2 + 1

    def node(self, node_id: str) -> LedgerNode:
        for n in self.nodes:
            if n.node_id == node_id:
                return n
        raise KeyError(node_id)

    def init_genesis(self, policy: dict[str, Any] | None = None) -> None:
        with self._lock:
            if all(n.height() > 0 for n in self.nodes):
                return
            genesis = Block(
                index=0,
                timestamp=self._now(),
                tx_type="GENESIS",
                payload={
                    "validators": {n.node_id: n.keypair.public_hex for n in self.nodes},
                    "quorum": self.quorum,
                    "policy": policy or {},
                    "network": "trustchain-idrs-permissioned",
                },
                prev_hash=ZERO_HASH,
                proposer="genesis",
            )
            genesis.hash = genesis.compute_hash()
            for n in self.nodes:
                if n.height() == 0:
                    n.append_raw(genesis)
            self._notify(genesis)

    # ---- health -----------------------------------------------------------------------
    def _majority_head(self) -> tuple[str | None, int]:
        tally: dict[tuple[str, int], int] = {}
        for n in self.nodes:
            if not n.online:
                continue
            h = n.head()
            if h:
                key = (h.hash, n.height())
                tally[key] = tally.get(key, 0) + 1
        if not tally:
            return None, 0
        (head_hash, height), _ = max(tally.items(), key=lambda kv: (kv[1], kv[0][1]))
        return head_hash, height

    def _healthy_nodes(self) -> list[LedgerNode]:
        """Online nodes whose chain verifies and whose head matches the majority head."""
        head_hash, _ = self._majority_head()
        out = []
        for n in self.nodes:
            if not n.online or n.node_id in self.flagged:
                continue
            h = n.head()
            # Cheap per-submit check; the full chain walk happens in audit().
            if h and h.hash == head_hash and h.compute_hash() == h.hash:
                out.append(n)
        return out

    # ---- consensus --------------------------------------------------------------------
    def submit(self, tx_type: str, payload: dict[str, Any]) -> Block:
        with self._lock:
            healthy = self._healthy_nodes()
            if len(healthy) < self.quorum:
                raise LedgerError(
                    f"no quorum: {len(healthy)} healthy validators, need {self.quorum}"
                )
            reference = healthy[0]
            head = reference.head()
            index = head.index + 1
            proposer = healthy[index % len(healthy)]
            block = Block(
                index=index,
                timestamp=self._now(),
                tx_type=tx_type,
                payload=payload,
                prev_hash=head.hash,
                proposer=proposer.node_id,
            )
            block.hash = block.compute_hash()
            block.signatures[proposer.node_id] = proposer.keypair.sign(block.hash.encode())
            for n in healthy:
                if n is proposer:
                    continue
                sig = n.endorse(block)
                if sig:
                    block.signatures[n.node_id] = sig
            if len(block.signatures) < self.quorum:
                raise LedgerError("block failed to reach quorum")
            for n in healthy:
                n.append_raw(block)
            # Lagging-but-honest nodes (e.g. back online) catch up lazily.
            for n in self.nodes:
                if n not in healthy and n.online:
                    self._try_sync(n, reference)
            self._notify(block)
            return block

    def _notify(self, block: Block) -> None:
        for cb in self.on_commit:
            cb(block)

    # ---- sync / heal ------------------------------------------------------------------
    def _try_sync(self, node: LedgerNode, source: LedgerNode) -> bool:
        """Copy missing blocks from source if node's own prefix is consistent."""
        h = node.height()
        if h > source.height():
            return False
        if h > 0:
            mine = node.get(h - 1)
            theirs = source.get(h - 1)
            if not mine or not theirs or mine.hash != theirs.hash or mine.compute_hash() != mine.hash:
                return False
        for b in source.blocks(h):
            node.append_raw(b)
        return True

    def heal(self, node_id: str) -> dict[str, Any]:
        """Repair a tampered/diverged node from the healthy majority."""
        with self._lock:
            node = self.node(node_id)
            healthy = [n for n in self._healthy_nodes() if n is not node]
            if len(healthy) < max(1, self.quorum - 1):
                raise LedgerError("not enough healthy peers to heal from")
            source = healthy[0]
            report = node.verify_chain()
            first_bad = report["first_bad_index"]
            h = node.height()
            if first_bad is None and h <= source.height():
                keep = h
            else:
                keep = first_bad if first_bad is not None else 0
                # also re-check against the peer to catch forks that are internally valid
                keep = min(keep, h)
            # walk back to common prefix with the peer
            while keep > 0:
                mine, theirs = node.get(keep - 1), source.get(keep - 1)
                if mine and theirs and mine.hash == theirs.hash and mine.compute_hash() == mine.hash:
                    break
                keep -= 1
            node.truncate_from(keep)
            for b in source.blocks(keep):
                node.append_raw(b)
            node.online = True
            self.flagged.discard(node_id)
            return {"node": node_id, "restored_from_index": keep, "height": node.height()}

    # ---- audit ------------------------------------------------------------------------
    def audit(self) -> dict[str, Any]:
        reports = []
        head_hash, height = self._majority_head()
        for n in self.nodes:
            r = n.verify_chain()
            h = n.head()
            r["online"] = n.online
            r["matches_majority"] = bool(h and h.hash == head_hash and n.height() == height)
            # An internally valid chain that disagrees with the majority at an older block
            # is still a fork: locate the first differing block.
            r["diverges_at"] = None
            if n.online and not r["matches_majority"] and r["valid"]:
                ref = next((m for m in self.nodes if m is not n and m.online and m.head() and m.head().hash == head_hash), None)
                if ref:
                    for i in range(min(n.height(), ref.height())):
                        a, b = n.get(i), ref.get(i)
                        if a.hash != b.hash:
                            r["diverges_at"] = i
                            break
            reports.append(r)
        consistent = all(r["valid"] and r["matches_majority"] for r in reports if r["online"])
        self.flagged = {r["node"] for r in reports if r["online"] and not (r["valid"] and r["matches_majority"])}
        return {
            "timestamp": self._now(),
            "consistent": consistent,
            "majority_head": head_hash,
            "height": height,
            "quorum": self.quorum,
            "nodes": reports,
        }

    def primary(self) -> LedgerNode:
        """A healthy node to read from."""
        healthy = self._healthy_nodes()
        if not healthy:
            raise LedgerError("no healthy node available")
        return healthy[0]

    def iter_blocks(self, start: int = 0) -> Iterable[Block]:
        return self.primary().blocks(start)
