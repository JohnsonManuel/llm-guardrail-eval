.PHONY: install test corpus baseline ablation report eval

install:
	pip install ollama pydantic pytest matplotlib

corpus:
	python -m attacks.build

test:
	python -m pytest tests/ -q --ignore=tests/smoke.py

gate:
	python -m tests.smoke qwen3.5:4b

baseline:
	python -m runner.run --layer L0

ablation:
	for L in L0 L1 L2 L3 L4 L5; do python -m runner.run --layer $$L; done

report:
	python -m runner.report

eval: corpus test ablation report
