"""Run the full attack-scenario evaluation and print a summary table."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trustchain.config import Settings  # noqa: E402
from trustchain.detection.train import ensure_model  # noqa: E402
from trustchain.evaluation import evaluate  # noqa: E402

if __name__ == "__main__":
    s = Settings()
    model = ensure_model(s.model_dir)
    res = evaluate(model, trials=int(sys.argv[1]) if len(sys.argv) > 1 else 5, progress=lambda x: print("..", x, flush=True))
    print(f"\nclean traffic: {res['clean']}")
    print(f"\n{'scenario':<22}{'detect':>8}{'classify':>10}{'latency':>9}{'quarantine':>12}")
    for k, v in res["scenarios"].items():
        print(f"{k:<22}{v['detection_rate']:>8}{v['classification_rate']:>10}{str(v['mean_latency_ticks']):>9}{v['quarantine_rate']:>12}")
    print("\ntamper:", json.dumps(res["tamper"]))
    os.makedirs(s.data_dir, exist_ok=True)
    with open(os.path.join(s.data_dir, "evaluation.json"), "w") as fh:
        json.dump(res, fh, indent=2)
