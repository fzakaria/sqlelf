ENV_PREFIX=$(shell python -c "if __import__('pathlib').Path('.venv/bin/pip').exists(): print('.venv/bin/')")

.PHONY: help
help:             ## Show the help.
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@fgrep "##" Makefile | fgrep -v fgrep


.PHONY: show
show:             ## Show the current environment.
	@echo "Current environment:"
	@echo "Running using $(ENV_PREFIX)"
	@$(ENV_PREFIX)python -V
	@$(ENV_PREFIX)python -m site

.PHONY: fmt
fmt:              ## Format code using black & isort.
	$(ENV_PREFIX)isort sqlelf/
	$(ENV_PREFIX)black sqlelf/
	nixpkgs-fmt .

.PHONY: lint
lint:             ## Run pep8, black, mypy linters.
	$(ENV_PREFIX)flake8 sqlelf/
	$(ENV_PREFIX)black --check sqlelf/
	$(ENV_PREFIX)pyright
	nixpkgs-fmt --check .