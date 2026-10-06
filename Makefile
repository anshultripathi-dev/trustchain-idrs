PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

.PHONY: help setup run test train evaluate check-js clean

help:
	@echo "make setup      create .venv and install dependencies"
	@echo "make run        start the engine and dashboard on http://127.0.0.1:8000"
	@echo "make test       run the test suite (hermetic, simulation mode)"
	@echo "make train      (re)train the ML models and rewrite models/metrics.json"
	@echo "make evaluate   run the attack-scenario evaluation (~5 min)"
	@echo "make check-js   syntax-check the dashboard modules"
	@echo "make clean      remove caches (keeps data/ and keys)"

setup:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

run:
	$(PY) run.py

test:
	$(PY) -m pytest -q

train:
	$(PY) scripts/train_models.py

evaluate:
	$(PY) scripts/evaluate.py 3

check-js:
	@set -e; for f in web/js/*.js web/pages/*.js; do \
	  cp $$f /tmp/_chk.mjs; node --check /tmp/_chk.mjs && echo "ok  $$f"; \
	done; rm -f /tmp/_chk.mjs

clean:
	find . -name __pycache__ -not -path "./.venv/*" -prune -exec rm -rf {} +
	rm -rf .pytest_cache
