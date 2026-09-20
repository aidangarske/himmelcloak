.PHONY: native build all-features test lint fmt oracle-up oracle-down test-live docker-lint

COMPOSE = docker compose -f testing/keycloak/docker-compose.yml

native:
	scripts/build-native.sh

build: native
	scripts/with-native.sh cargo build --locked --workspace

all-features: native
	scripts/with-native.sh cargo build --locked --workspace --all-features

test: native
	scripts/with-native.sh cargo test --locked --workspace --lib

lint: native
	scripts/with-native.sh cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
	cargo fmt --all --check

fmt:
	cargo fmt --all

oracle-up:
	testing/keycloak/bootstrap-cert.sh
	$(COMPOSE) up -d keycloak

oracle-down:
	$(COMPOSE) down -v

test-live: oracle-up
	$(COMPOSE) build tester
	$(COMPOSE) run --rm --no-build tester

docker-lint:
	$(COMPOSE) build tester
	docker run --rm -v "$(CURDIR):/work" -w /work himmelcloak-tester:ci cargo fmt --all --check
	docker run --rm -v "$(CURDIR):/work" -w /work himmelcloak-tester:ci cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
