# NSS group sync: N1 S2

HC-49 ([GitHub #67](https://github.com/aidangarske/himmelcloak/issues/67)) adds the
read-only group-fetch stage of `himmelcloak-cli sync-users`. It authenticates a
confidential Keycloak service account using client credentials and reads only
`GET /admin/realms/{realm}/groups/{group-id}/members`. It never discovers groups
or lists the realm-wide `/users` endpoint. The configured group is an exact ID,
not a name or search string. The Keycloak base URL may include a deployment path
such as `/auth`; do not include `/realms/<realm>` in `--server-url`.

This sprint outputs the complete membership as JSON on stdout. It does not yet
write passwd/group files, allocate UIDs, change NSS configuration, install a
systemd timer, or enable user login. Those belong to later integration slices.
Disabled members retain `enabled: false` so downstream mapping can handle them
explicitly rather than accidentally treating them as enabled.

## Service account and command

Create a confidential client with service accounts enabled and browser/password
login disabled. Grant read-only group-member access. The compatibility fixture
uses only `realm-management`'s `view-users` role, without `manage-users` or
`realm-admin`. That role can view users across the realm; the application limits
its requests to the configured group. This is not a claim of server-enforced
per-group isolation. Deployments requiring that isolation should configure
Keycloak fine-grained group permissions separately.

Store the real client secret in a root-owned regular file with mode 0600 or 0400.
The CLI refuses symlinks, non-root-owned files, other permission modes, empty
secrets and files larger than 16 KiB. The secret is never a command-line argument.
A final CR/LF is removed from the secret file; other whitespace is preserved.

```sh
sudo target/debug/himmelcloak-cli sync-users \
  --server-url https://keycloak.example.org \
  --realm example --client-id linux-sync \
  --group-id 11111111-1111-4111-8111-111111111111 \
  --client-secret-file /etc/himmelcloak/admin-client.secret
```

Use `--ca-bundle /path/to/ca.pem` for a private CA; otherwise the transport uses
its default trust store. HTTPS and certificate verification are required, using
the existing wolfSSL/libcurl transport. No insecure HTTP or skip-verification
option is added. Run the job as root. `--help` works without root.

On success, stdout is a JSON array of `{id, username, enabled}` objects. On any
API, credential or response failure, the command exits nonzero and produces no
partial JSON. Errors omit the client secret, bearer token and response body.
There is no fallback to reading all users after a 401, 403, 404 or other failure.

## Pagination and failure limits

Requests use `first`, `max=100` and `briefRepresentation=true`. Offset advances
by the number of returned members and fetching ends only on an empty page,
including when the server caps pages below 100. Responses over 100 members,
more than 100,000 accumulated members, missing required identity fields, and
repeated IDs fail closed. The existing transport bounds individual responses
and applies request timeouts. Group membership can change while pages are
being read; this operation does not claim a transactional snapshot. A repeated
ID is rejected rather than silently accepting a potentially inconsistent result.

## Unit and live tests

With the project's pinned Rust/native build environment:

```sh
scripts/with-native.sh cargo test --locked --workspace --all-targets
scripts/with-native.sh cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
```

`src/admin.rs` uses an injected transport to assert the exact token endpoint,
client-credentials form, group-only GET paths, pagination offsets, and bearer
header. It covers empty/short/full pages, oversized pages, authorization/server
failures, malformed/repeated responses, path/query injection and invalid inputs.
The CLI tests check option validation and secret-file handling.

`tests/keycloak/hc49-test-realm.json` is a separate disposable realm imported by
the existing Docker Compose Keycloak service. It contains an allowed member, an
unrelated member, a read-only service account and a no-permission service account.
Its secrets are public test values, never deployment credentials. `make test-live`
includes the ignored `admin::tests::read_only_service_account_live` test alongside
the existing live suite. The test verifies only the allowed member is returned,
user creation by the read-only account gets HTTP 403, and group reads by the
unprivileged account get HTTP 403.

For a dedicated local Keycloak installation instead of Docker, install Java 21
and unpack a Keycloak distribution, then run:

```sh
HC49_KEYCLOAK_HOME=/path/to/disposable/keycloak bash tests/keycloak/start-hc49-local.sh
```

This imports only the test realm, generates a short-lived localhost certificate,
and starts the disposable server on loopback port 18443. Use a fresh dedicated
installation when changing the fixture: startup import does not overwrite an
existing realm. In another terminal, after the server is ready:

```sh
HC49_KEYCLOAK_URL=https://localhost:18443 \
HC49_KEYCLOAK_CA=/tmp/himmelcloak-hc49-live/server.crt \
scripts/with-native.sh cargo test --locked -p himmelcloak --lib \
  admin::tests::read_only_service_account_live -- --ignored --exact
```

The live test also accepts the existing `KEYCLOAK_URL` / `KEYCLOAK_CA` variables
used by the Docker suite. Stop the local fixture with Ctrl+C in its terminal.

## Protocol references

- [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- [Keycloak service accounts and admin roles](https://www.keycloak.org/docs/latest/server_admin/index.html)
