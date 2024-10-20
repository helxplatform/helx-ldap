# Variables
PYTHON := python3
SCRIPT := scripts/generate_helx_ldap_config.py
CONFIG_FILE := helx_ldap_config.yaml

# Default target
all: $(CONFIG_FILE)

# Target to generate helx_ldap_config.yaml
$(CONFIG_FILE): $(SCRIPT)
	@echo "Generating $(CONFIG_FILE)..."
	$(PYTHON) $(SCRIPT)
	@echo "$(CONFIG_FILE) has been generated."

# Generate openldap_values.yaml using Python script
openldap_values.yaml: helx_ldap_config.yaml scripts/generate_openldap_values.py
	@echo "Generating openldap_values.yaml..."
	scripts/generate_openldap_values.py

# Check if Python is installed
check-python:
	@if ! command -v $(PYTHON) &> /dev/null; then \
		echo "Python3 could not be found. Please install it to proceed."; \
		exit 1; \
	fi

# Install dependencies (if any)
install-deps:
	@echo "Installing dependencies..."
	@pip3 install pyyaml

# Clean target to remove the generated YAML file
clean:
	@echo "Cleaning up..."
	@rm -f $(CONFIG_FILE)

# Phony targets
.PHONY: all clean check-python install-deps
