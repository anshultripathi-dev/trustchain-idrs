"""Train the Isolation Forest + attack classifier and print the evaluation summary."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustchain.config import Settings  # noqa: E402
from trustchain.detection.train import ensure_model  # noqa: E402

if __name__ == "__main__":
    b = ensure_model(Settings().model_dir, retrain=True)
    m = b.metrics
    print(f"trained in {m['seconds']}s on {m['samples']}")
    for name, r in m["comparison"].items():
        rec = {k: v["episode_recall"] for k, v in r["per_attack"].items()}
        print(f"\n{name}: FPR(tick)={r['false_positive_rate_tick']:.4f} FPR(confirmed)={r['false_positive_rate_confirmed']:.4f} macro-recall={r['episode_recall_macro']:.3f}")
        print("  episode recall:", json.dumps(rec))
    print("\nclassifier accuracy:", m["classifier"]["accuracy"])
