"""Time one engine tick of the full smart home (run on an otherwise idle machine).

    python scripts/bench_home.py

Wall-clock timings are only meaningful when nothing else is competing for the CPU, so this is deliberately
separate from the evaluation (whose result files must not depend on machine load).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("TRUSTCHAIN_MODE", "sim")

from trustchain.config import Settings  # noqa: E402
from trustchain.detection.train import ensure_model  # noqa: E402
from trustchain.engine import Engine  # noqa: E402

if __name__ == "__main__":
    s = Settings(in_memory=True, virtual_clock=True, home="full", mode="sim")
    model = ensure_model(s.model_dir)
    t0 = time.time()
    e = Engine(s, model=model, seed=5, start_hour=14.0)
    print(f"bootstrap: {len(e.runtimes)} devices registered on the ledger in {time.time() - t0:.2f}s (chain height {e.contract.height})")
    for _ in range(20):          # warm-up
        e.step()
    n = 200
    t0 = time.time()
    for _ in range(n):
        e.step()
    per = (time.time() - t0) / n * 1000
    t0 = time.time()
    e.overview()
    print(f"tick: {per:.1f} ms for {len(e.runtimes)} devices  ({per / len(e.runtimes):.2f} ms per device)")
    print(f"overview payload build: {(time.time() - t0) * 1000:.1f} ms")
    print("budget: the engine ticks once per second, so this leaves ~%d%% headroom" % round(100 - per / 10))
