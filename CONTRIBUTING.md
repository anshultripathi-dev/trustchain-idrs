# Contributing

## Setup

```bash
make setup
make test
```

The suite is hermetic: `tests/conftest.py` forces simulation mode and clears any board IPs, so a local `.env`
for real hardware never affects it.

## Guidelines

- **Never commit secrets.** `.env`, `data/` (ledger, keys, local log) and `firmware/.local/` are git-ignored.
  Firmware sketches must keep the `YOUR_WIFI_SSID` / `YOUR_WIFI_PASSWORD` placeholders — CI fails otherwise.
- Keep security policy values (trust penalties, risk weights, bands) in `trustchain/trust.py` and the contract policy;
  they are calibration values, not constants of nature. Document changes in `docs/ARCHITECTURE.md`.
- New detection logic needs a test in `tests/test_engine.py`; new ledger behaviour needs one in `tests/test_ledger.py`.
  Cover the failure case (tamper, replay, unreachable board), not only the happy path.
- Results in docs must come from `make evaluate` / `make train`. Do not hand-edit numbers.
- Dashboard code is plain ES modules (no build step). Run `make check-js` before pushing.

## Commit style

Short imperative subject with a scope, e.g. `feat(ledger): …`, `fix(hardware): …`, `docs: …`.
