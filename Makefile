.PHONY: build all-features test lint fmt oracle-up oracle-down

build:
	cargo build --workspace

all-features:
	cargo build --workspace --all-features

test:
	cargo test --workspace

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all --check

fmt:
	cargo fmt --all

oracle-up:
	docker compose -f testing/keycloak/docker-compose.yml up -d

oracle-down:
	docker compose -f testing/keycloak/docker-compose.yml down -v
