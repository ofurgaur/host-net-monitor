SHELL := /bin/sh

CARGO ?= cargo
PYTHON ?= python3
VENV ?= .venv-reputation
REPUTATION_PY := $(VENV)/bin/python
REPUTATION_REQUIREMENTS := tools/reputation/requirements.txt
REPUTATION_CONFIG ?= threat-reputation.config.json

.PHONY: help build release test lint check fmt reputation reputation-install reputation-lookup \
	reputation-test check-config list-interfaces map-server package-macos package-windows clean

help:
	@printf '%s\n' \
		'make build              Build the debug binary' \
		'make release            Build the optimized release binary' \
		'make test               Run Rust and reputation updater tests' \
		'make lint               Run rustfmt and Clippy' \
		'make check              Compile-check without building binaries' \
		'make reputation         Refresh mmdb/threat-reputation.mmdb' \
		'make reputation-install Create the Python updater virtual environment' \
		'make reputation-lookup IP=8.8.8.8  Query the reputation database' \
		'make check-config CONFIG=config.yaml  Validate configuration' \
		'make list-interfaces    List capture interfaces' \
		'make map-server         Serve the live network activity map' \
		'make package-macos      Build and archive a macOS package' \
		'make package-windows    Build and archive a Windows package' \
		'make clean              Remove generated build and updater files'

build:
	$(CARGO) build --locked

release:
	$(CARGO) build --release --locked

test:
	$(CARGO) test --locked
	$(MAKE) reputation-test

reputation-test: reputation-install
	$(REPUTATION_PY) -m unittest discover -s tools/reputation -p 'test_*.py'

lint:
	$(CARGO) fmt --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

check:
	$(CARGO) check --locked

fmt:
	$(CARGO) fmt

reputation-install:
	$(PYTHON) -m venv $(VENV)
	$(REPUTATION_PY) -m pip install -r $(REPUTATION_REQUIREMENTS)

reputation: reputation-install
	$(REPUTATION_PY) tools/reputation/update.py --config $(REPUTATION_CONFIG)

reputation-lookup: reputation-install
	@test -n "$(IP)" || (printf '%s\n' 'Usage: make reputation-lookup IP=8.8.8.8' >&2; exit 2)
	$(REPUTATION_PY) tools/reputation/update.py --config $(REPUTATION_CONFIG) --lookup $(IP)

check-config: CONFIG ?= config.example.yaml
check-config:
	$(CARGO) run --locked -- check-config $(CONFIG)

list-interfaces:
	$(CARGO) run --locked -- list-interfaces

map-server:
	$(PYTHON) map-server/AttackMapServer.py --flow-log network-flows.jsonl --ip-log network-ips.jsonl

package-macos:
	@test "$$(uname -s)" = Darwin || (printf '%s\n' 'package-macos must run on macOS' >&2; exit 2)
	$(CARGO) build --release --locked
	@rm -rf target/macos-package
	@mkdir -p target/macos-package/packaging
	@cp target/release/host-net-monitor target/macos-package/
	@cp config.macos.example.yaml MACOS.md README.md target/macos-package/
	@cp packaging/org.host-net-monitor.plist packaging/install-macos.sh target/macos-package/packaging/
	tar -czf target/host-net-monitor-macos-$$(uname -m).tar.gz -C target/macos-package .

package-windows:
	$(CARGO) build --release --locked
	@if command -v pwsh >/dev/null 2>&1; then \
		pwsh -NoProfile -Command '$$p="target/windows-package"; New-Item -ItemType Directory -Force "$$p/packaging" | Out-Null; Copy-Item target/release/host-net-monitor.exe "$$p/"; Copy-Item config.windows.example.yaml,WINDOWS.md,README.md "$$p/"; Copy-Item packaging/host-net-monitor.winsw.xml,packaging/install-windows.ps1 "$$p/packaging/"; Compress-Archive -Path "$$p/*" -DestinationPath target/host-net-monitor-windows.zip -Force'; \
	else \
		printf '%s\n' 'package-windows requires PowerShell (pwsh) on this host' >&2; exit 2; \
	fi

clean:
	$(CARGO) clean
	$(PYTHON) -c 'from pathlib import Path; [p.unlink() for p in Path(".").glob("*.pyc")]'
