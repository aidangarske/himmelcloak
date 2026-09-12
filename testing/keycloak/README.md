# Keycloak test oracle

A real Keycloak in Docker is our authentication oracle and CI target. himmelcloak ships zero
Java. We drive this Keycloak exactly like a browser would, over HTTP, to capture and reproduce
the real per method contract.

## Run locally

```
make oracle-up      # starts Keycloak on http://localhost:8080 (admin / admin)
make oracle-down    # stops it and wipes state
```

## Setup tasks

- Pin the Keycloak version in `docker-compose.yml`.
- Build `realm-export.json` with one test user per auth method and a client configured for the
  flows himmelcloak drives (password, TOTP, WebAuthn, X.509, recovery).
- Wire the CI version matrix (`.github/workflows/keycloak-matrix.yml`) so every PR runs the flow
  suite across supported Keycloak versions.
- Provide a virtual (software) authenticator so WebAuthn flows run headlessly in CI.
