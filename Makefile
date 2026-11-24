PYTHON ?= python

.PHONY: install install-scan install-dev run test test-live lint scan benchmark

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

benchmark:
	$(PYTHON) redteam_benchmark.py --runs 2
