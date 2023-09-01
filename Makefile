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
	isort sqlelf/
	black sqlelf/
	nixpkgs-fmt .

.PHONY: lint
lint:             ## Run pep8, black, mypy linters.
	flake8 sqlelf/
	black --check sqlelf/
# TODO(fzakaria): without pythonpath it picks up the wrong python
# and then does not find the venv for the imports
	pyright --pythonpath $(shell which python)
	nixpkgs-fmt --check .