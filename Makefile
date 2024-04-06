.PHONY: help
help:             ## Show the help.
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@fgrep "##" Makefile | fgrep -v fgrep


.PHONY: show
show:             ## Show the current environment.
	@echo "Current environment:"
	@echo "Running using $(VIRTUAL_ENV)"
	@$(VIRTUAL_ENV)/bin/python -V
	@$(VIRTUAL_ENV)/bin/python -m site

.PHONY: fmt
fmt:              ## Format code using black & isort.
	isort sqlelf/ benchmarks/ tests/ tools/
	black sqlelf/ benchmarks/ tests/ tools/

.PHONY: lint
lint:             ## Run pep8, black, mypy linters.
	flake8 sqlelf/ benchmarks/ tests/ tools/
	isort --check sqlelf/ benchmarks/ tests/ tools/
	black --check sqlelf/ benchmarks/ tests/ tools/
	pyright
	mypy --strict --install-types --non-interactive sqlelf tests tools

.PHONY: test
test:             ## Run pytest primarily.
	pytest
	pytest -m "slow"

.PHONY: coverage
coverage:
	coverage run -m pytest

.PHONY: vendor
vendor:             ## Update third-party dependencies.
	copybara copy.bara.sky vendor_pyelftools --folder-dir ./sqlelf/_vendor