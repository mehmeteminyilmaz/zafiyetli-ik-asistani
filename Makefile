PYTHON ?= python

.PHONY: install install-scan install-dev run test test-live lint scan scan-secure validate-judge benchmark adaptive

install:
	$(PYTHON) -m pip install -r requirements.txt

install-scan:
	$(PYTHON) -m pip install -r requirements-scan.txt

install-dev:
	$(PYTHON) -m pip install -r requirements-dev.txt

run:
	$(PYTHON) main.py

test:
	$(PYTHON) -m pytest -q

test-live:
	$(PYTHON) -m pytest -q --run-live

lint:
	$(PYTHON) -m ruff check .

scan:
	$(PYTHON) giskard_scan.py --target vulnerable

scan-secure:
	$(PYTHON) giskard_scan.py --target secure --num-requirements 6 --num-samples 4 --injection-samples 8

validate-judge:
	$(PYTHON) validate_judge.py

benchmark:
	$(PYTHON) redteam_benchmark.py --runs 2

adaptive:
	$(PYTHON) adaptive_redteam.py --turns 3
