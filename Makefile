.DEFAULT_GOAL := help

SHELL := /bin/bash
PYTHON := python3
VENV_DIR := .venv

.PHONY: help
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: venv
venv: ## Create a local virtual environment and install dev dependencies
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install --upgrade pip
	$(VENV_DIR)/bin/pip install -r requirements.txt
	$(VENV_DIR)/bin/pip install -e '.[dev]'

.PHONY: test
test: ## Run the DK test suite with coverage
	$(VENV_DIR)/bin/pytest --cov --cov-report=term-missing -q

.PHONY: lint
lint: ## Run ruff linting
	$(VENV_DIR)/bin/ruff check .

.PHONY: format
format: ## Run ruff formatting
	$(VENV_DIR)/bin/ruff format .

.PHONY: audit
audit: ## Run a Python dependency vulnerability scan
	$(VENV_DIR)/bin/pip-audit --requirement requirements.txt

.PHONY: clean
clean: ## Remove build artifacts and the local virtual environment
	rm -rf $(VENV_DIR) .pytest_cache .coverage htmlcov __pycache__ ./**/*.pyc
