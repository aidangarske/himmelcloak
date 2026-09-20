.PHONY: native build all-features test lint fmt oracle-up oracle-down test-live test-live-verbose docker-lint

COMPOSE = docker compose -f testing/keycloak/docker-compose.yml

native:
	scripts/build-native.sh

build: native
	scripts/with-native.sh cargo build --locked

all-features: native
	scripts/with-native.sh cargo build --locked --all-features

test: native
	scripts/with-native.sh cargo test --locked --lib

lint: native
	scripts/with-native.sh cargo clippy --locked --all-targets --all-features -- -D warnings
	cargo fmt --all --check

fmt:
	cargo fmt --all

oracle-up:
	testing/keycloak/bootstrap-cert.sh
	$(COMPOSE) up -d keycloak

oracle-down:
	$(COMPOSE) down -v

test-live:
	testing/keycloak/run.sh

test-live-verbose:
	testing/keycloak/run.sh --verbose

docker-lint:
	$(COMPOSE) build tester
	docker run --rm -v "$(CURDIR):/work" -e CARGO_TARGET_DIR=/tmp/himmelcloak-target -w /work himmelcloak-tester:ci cargo fmt --all --check
	docker run --rm -v "$(CURDIR):/work" -v himmelcloak-cargo-target:/tmp/himmelcloak-target -e CARGO_TARGET_DIR=/tmp/himmelcloak-target -w /work himmelcloak-tester:ci cargo clippy --locked --all-targets --all-features -- -D warnings
