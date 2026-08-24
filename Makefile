.PHONY: install test corpus baseline ablation report promptfoo trace-check eval

install:
	pip install -r requirements.txt

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

trace-check:
	python -m runner.trace

promptfoo:
	python -m promptfoo_int.build_config --layer L5 --limit 24
	npx promptfoo eval -c promptfooconfig.yaml --output results/promptfoo.json --no-cache
	python -m runner.run --layer L5 --limit 24
	cp results/L5_qwen35-4b.json results/parity_L5_qwen35-4b.json
	python -m pytest tests/test_promptfoo_parity.py -q

eval: corpus test ablation report
