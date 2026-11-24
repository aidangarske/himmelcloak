.PHONY: build test demo clean help image unit lint shell test-live test-live-verbose \
	oracle-up oracle-down pam-smoke linux-test linux-shell linux-no-distro native local-build local-all-features \
	local-test local-lint fmt test-distros nss-module nss-smoke
.DEFAULT_GOAL := build

DISTROS = debian-12 ubuntu-24.04 opensuse-leap-16.0 opensuse-tumbleweed \
	sle-bci-16.0 rockylinux-9 fedora
export DISTRO
ifneq ($(DISTRO),)
ifeq ($(filter $(DISTRO),$(DISTROS)),)
$(error DISTRO must be one of: $(DISTROS))
endif
export TESTER_IMAGE := himmelcloak-tester:$(DISTRO)
endif

CONTAINER ?= docker
override CONTAINER := $(strip $(CONTAINER))
ifneq ($(CONTAINER),docker)
ifneq ($(CONTAINER),podman)
$(error CONTAINER must be docker or podman)
endif
endif
export CONTAINER

COMPOSE = $(CONTAINER) compose -f tests/keycloak/docker-compose.yml
IN_DOCKER = $(COMPOSE) run --rm --no-deps --entrypoint /usr/bin/env tester

##@ Everything runs in containers; the host needs Docker or Podman, Compose v2, and openssl.

build: image ## Build every crate (the default)
	$(IN_DOCKER) cargo build --locked --workspace

test: ## Run every check: unit tests, lint, then the live Keycloak suite
	$(MAKE) unit lint
	tests/keycloak/run.sh; status=$$?; $(COMPOSE) down; exit $$status

demo: ## Log a fixture user in with the CLI (METHOD=password|totp|totp-devices|list) and show Keycloak's events
	METHOD="$(METHOD)" QR="$(QR)" tests/keycloak/demo.sh

test-distros: ## Run make test on every supported distro, one after another
	@for distro in $(DISTROS); do \
		echo "==> $$distro"; $(MAKE) --no-print-directory test DISTRO=$$distro || exit 1; \
	done

clean: ## Stop Keycloak and remove the test containers and build cache
	$(COMPOSE) down -v

help: ## Show every target
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} \
		/^[a-z-]+:.*## / {printf "  \033[36mmake %-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
	@echo "DISTRO values: $(DISTROS)"
	@echo "Example: make test DISTRO=opensuse-leap-16.0"
	@echo "CONTAINER values: docker (default) podman"
	@echo "Example: make test CONTAINER=podman"

##@ Individual steps

image: ## Build the tester image for the default or DISTRO distribution
	tests/keycloak/tester-image.sh

unit: image ## Unit and integration tests only
	$(IN_DOCKER) cargo test --locked --workspace --tests

lint: image ## rustfmt and clippy, as CI runs them
	$(IN_DOCKER) cargo fmt --all --check
	$(IN_DOCKER) cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test-live: ## Live Keycloak suite only, leaving Keycloak running
	tests/keycloak/run.sh

test-live-verbose: ## Live suite with each step and Keycloak's event log
	tests/keycloak/run.sh --verbose

shell: image ## Shell in the build container with the repo at /work
	$(IN_DOCKER) bash -i

oracle-up: ## Start Keycloak in the background
	tests/keycloak/bootstrap-cert.sh
	$(COMPOSE) up -d --pull always --force-recreate keycloak

oracle-down: clean

pam-smoke: ## Load the PAM module in a container
	bash crates/pam_himmelcloak/tests/pam-load-smoke.sh "$(CURDIR)"

# The test system is always Debian 12 (built with the default tester image), so
# refuse DISTRO before spending minutes building another distribution's image.
LINUX_PREREQ := $(if $(DISTRO),linux-no-distro,image)

linux-test: $(LINUX_PREREQ) ## Boot a disposable Linux test system, check its recovery account and SSH, then remove it
	tests/linux/run.sh test

linux-shell: $(LINUX_PREREQ) ## Open a shell in a disposable Linux test system (removed when you exit)
	tests/linux/run.sh shell

linux-no-distro:
	@echo "The disposable test system is always Debian 12; run make linux-test without DISTRO." >&2
	@exit 2

##@ Native Linux builds without Docker (needs autotools, libtool, pkg-config, clang, rustup)

native: ## Build pinned wolfSSL and curl into .native
	scripts/build-native.sh

local-build: native ## Build on the host
	scripts/with-native.sh cargo build --locked --workspace

local-all-features: native ## Build with all features on the host
	scripts/with-native.sh cargo build --locked --workspace --all-features

local-test: native ## Unit tests on the host
	scripts/with-native.sh cargo test --locked --workspace --tests

local-lint: native ## clippy and rustfmt on the host
	scripts/with-native.sh cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo fmt --all --check

fmt: ## Format the code on the host
	cargo fmt --all

##@ NSS module (native GNU/Linux)

NSS_TARGET_DIR = $(or $(CARGO_TARGET_DIR),target)

nss-module: ## Build the NSS shared library with its glibc ABI filename
	cargo build --locked --release -p nss_himmelcloak --target-dir "$(NSS_TARGET_DIR)"
	install -m 0755 "$(NSS_TARGET_DIR)/release/libnss_himmelcloak.so" "$(NSS_TARGET_DIR)/release/libnss_himmelcloak.so.2"

nss-smoke: nss-module ## Trace the unit tests and load the module with a test nsswitch.conf
	bash crates/nss_himmelcloak/tests/load-smoke.sh "$(NSS_TARGET_DIR)/release/libnss_himmelcloak.so.2"
