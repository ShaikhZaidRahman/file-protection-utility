.PHONY: install test lint demo clean
install:
	python -m pip install -e ".[dev]"
test:
	python -m pytest
lint:
	ruff check .
demo:
	bash scripts/demo.sh
clean:
	rm -rf build dist .pytest_cache .ruff_cache src/*.egg-info
