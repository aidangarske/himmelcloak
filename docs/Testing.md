# Keycloak test oracle

The integration suite authenticates against an unmodified Keycloak container. Compose imports
`testing/keycloak/realm-export.json`, which has a public OIDC client and the disposable `alice`
user. A generated test CA signs the HTTPS certificate for the `keycloak.test`
Docker network alias.

Run `make test-live` for the moving `latest` Keycloak image or set `KEYCLOAK_IMAGE` to another tag.
Run `make oracle-down` afterward to remove the test server and its state.

The live test requires `KEYCLOAK_URL` and `KEYCLOAK_CA`; the Compose tester sets both. CI runs
the same test against the latest stable release tag and the `nightly` development image on every
push and PR. CI resolves both image digests before starting the matrix, so a run records exactly
which server builds it tested. The separate native dependency matrix resolves current stable and
development refs for wolfSSL and curl; the standard build remains pinned to wolfSSL 5.9.2. Each
new login factor must add a live scenario before its feature is treated as complete.

The exact Cargo versions remain in `Cargo.lock` for reproducible builds.
Dependabot opens weekly Cargo and GitHub Actions update PRs into `core`, while
the resolver workflows expose new native and Keycloak releases immediately.
