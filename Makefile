.PHONY: help install dev demo test lint serve users site benchmark clean

help:
	@echo "install    install runtime dependencies"
	@echo "dev        install dev dependencies"
	@echo "demo       generate synthetic data and run the pipeline"
	@echo "test       run the test suite"
	@echo "lint       run ruff"
	@echo "users      create an analyst and a lead account (prompts for passwords)"
	@echo "serve      start the API and dashboard on http://127.0.0.1:8000"
	@echo "site       build the static dashboard demo into site/"
	@echo "benchmark  run the synthetic benchmark on 10 datasets"
	@echo "clean      remove generated data and caches"

install:
	pip install -r requirements.txt

dev:
	pip install -r requirements-dev.txt

demo:
	python -m itds generate --users 60 --days 60
	python -m itds run

test:
	python -m pytest tests -q

lint:
	ruff check itds tests scripts

users:
	python -m itds user add analyst1 --role analyst
	python -m itds user add lead1 --role lead

serve:
	python -m itds serve --port 8000

site:
	python scripts/build_demo.py --out site

benchmark:
	python scripts/benchmark.py --seeds 10 --out results/benchmark.json

clean:
	rm -rf data/*.jsonl data/*.json data/*.db results site .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
