.PHONY: help install dev demo test lint serve clean

help:
	@echo "install   install runtime dependencies"
	@echo "dev       install dev dependencies"
	@echo "demo      generate data and run the pipeline"
	@echo "test      run the test suite"
	@echo "lint      run ruff"
	@echo "serve     start the API and dashboard on :8000"
	@echo "clean     remove generated data and caches"

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
	ruff check itds tests

serve:
	uvicorn itds.api.main:app --reload --port 8000

clean:
	rm -rf data/*.jsonl data/*.json data/*.db .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
