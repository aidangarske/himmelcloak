.PHONY: build test demo clean help image unit lint shell test-live test-live-verbose \
	oracle-up oracle-down pam-smoke native local-build local-all-features \
	local-test local-lint fmt
.DEFAULT_GOAL := build

COMPOSE = docker compose -f tests/keycloak/docker-compose.yml
IN_DOCKER = $(COMPOSE) run --rm --no-deps --entrypoint /usr/bin/env tester

##@ Everything runs in Docker; the host needs only Docker, Compose v2, and openssl

build: image ## Build every crate (the default)
	$(IN_DOCKER) cargo build --locked --workspace

test: ## Run every check: unit tests, lint, then the live Keycloak suite
	$(MAKE) unit lint
	tests/keycloak/run.sh; status=$$?; $(COMPOSE) down -v; exit $$status

demo: ## Log alice in to a real Keycloak with the CLI and show the server's events
	tests/keycloak/demo.sh

clean: ## Stop Keycloak and remove the test containers and volumes
	$(COMPOSE) down -v

help: ## Show every target
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n\033[1m%s\033[0m\n", substr($$0, 5)} \
		/^[a-z-]+:.*## / {printf "  \033[36mmake %-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

##@ Individual steps

image: ## Build the tester image (Rust, pinned wolfSSL, wolfSSL-backed curl)
	$(COMPOSE) build tester

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
	$(COMPOSE) run --rm --no-deps --entrypoint bash tester

oracle-up: ## Start Keycloak in the background
	tests/keycloak/bootstrap-cert.sh
	$(COMPOSE) up -d --pull always --force-recreate keycloak

oracle-down: clean

pam-smoke: ## Load the PAM module in a container
	bash crates/pam_himmelcloak/tests/pam-load-smoke.sh "$(CURDIR)"

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
