PY ?= python
AUDIT ?= data/audit_export.json

.PHONY: test test-py test-web demo intake calibrate audit-verify

test: test-py test-web

test-py: ; $(PY) -m pytest tests -q

test-web: ; npm --prefix web run lint && npm --prefix web test && npm --prefix web run build

demo: ; docker compose up --build

intake: ; $(PY) -m deconflicted.eval.intake --input data/organizer

calibrate: ; $(PY) -m deconflicted.eval.calibrate --input data/organizer --report data/eval/report.json

audit-verify: ; $(PY) -m deconflicted.ledger.verify_cli $(AUDIT)