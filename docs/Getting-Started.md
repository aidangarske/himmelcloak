# Getting Started

The working core currently covers OIDC discovery, password direct grant, ID-token verification,
refresh, revocation, and userinfo. The native flow driver and additional factors are in progress.

## CLI administration

The `himmelcloak-cli` workspace crate provides the administrator command-line
interface. Build it from the workspace root:

```sh
cargo build --locked -p himmelcloak-cli
```

The CLI reads `himmelcloak.toml` from the directory where you run the command.
For example, create this minimal file:

```toml
realm = "himmelcloak-test"
```

Check that the file contains valid TOML:

```sh
cargo run --locked -p himmelcloak-cli -- config check
```

The following command names are available now:

```sh
cargo run --locked -p himmelcloak-cli -- test-login
cargo run --locked -p himmelcloak-cli -- sync-users
cargo run --locked -p himmelcloak-cli -- clear-state
```

`config check` validates TOML syntax only. `test-login` and `clear-state` remain
placeholders. `sync-users` now reads the configured group as described below.

### Group sync

Build using the project's native dependencies, then run the CLI as root from a
trusted configuration directory. The command reads `himmelcloak.toml` in that
directory, following the existing CLI configuration-file behavior. Add:

```toml
[sync]
server_url = "https://keycloak.example.org"
realm = "example"
client_id = "linux-sync"
allowed_group_id = "11111111-1111-4111-8111-111111111111"
client_secret_file = "/etc/himmelcloak/admin-client.secret"
# ca_bundle = "/etc/ssl/certs/private-keycloak-ca.pem"
# state_directory = "/var/lib/himmelcloak"
```

The server URL is the base URL before `/realms/<realm>` and may include a deployment
prefix such as `/auth`. The group is an exact ID, not a group-name search.
Provision a confidential client with service accounts enabled and read-only
member access; disable its browser and password grants. Do not grant `manage-users`
or `realm-admin`. On Keycloak 26.8.2 and later, also assign the built-in
`kc-admin-api` client scope as a default scope; without it the Admin REST API
rejects the service account's token with 401. The [architecture](Architecture.md#nss-group-synchronization)
explains the fixture's read-only role and its limitations.

The config must be a root-owned regular file without group/other write access
and no larger than 64 KiB. The secret must be a separate root-owned regular file
with mode 0600 or 0400 and no larger than 16 KiB. Both reject symlinks. File paths
inside `[sync]` must be absolute; a trailing CR/LF is trimmed from the secret.
Only the `[sync]` table receives typed validation here; `config check` retains
its existing syntax-only behavior. Use your secret-provisioning process to create
the real secret file, and never put the secret in command arguments or source control.

```sh
# Build at the repository root with the native build environment configured.
scripts/with-native.sh cargo build --locked -p himmelcloak-cli

# From the trusted directory containing himmelcloak.toml:
sudo /absolute/path/to/target/debug/himmelcloak-cli sync-users
```

Provision `state_directory` (default `/var/lib/himmelcloak`) as a root-owned
directory with mode 0755 under a trusted parent. The command does not create it.
The directory must not be a symlink or writable by group/others.

Success saves a version-1 JSON object containing `users` and `groups` in
`users.json` with mode 0644, then prints the enabled-user count. Each user has
`id`, `username`, `uid`, `gid`, `home`, and `shell`; the single `himmelcloak` group
has `name`, `gid`, and `members`. Keeping both lists in one snapshot avoids
publishing mismatched user and group generations. The command writes and syncs a
temporary file in the same directory before replacing the old snapshot with a
single rename. Fetch and pre-rename write failures preserve the previous file.
A directory-sync failure after rename reports an error, but the complete new
snapshot is already visible; its durability across power loss is uncertain.
System-login integration is not implemented by this stage.

The proposed mapping uses FNV-1a over the server/realm namespace, a zero byte,
and the Keycloak user ID to select a UID in a reserved range. This is an ID
selector, not cryptography. A rename or membership ordering change does not
change the UID. Collisions fail the entire sync instead of probing another UID.
The default UID range is 200000 through 2000199999, and the shared primary GID
is 200000. Administrators must reserve these IDs across their identity sources.
Optional overrides go in a `[sync.mapping]` table: `uid_min`, `uid_max`, and `gid`.
Values below 1000 and above 2147483647 are rejected. Changing the range or
server/realm namespace changes mappings and requires an account-data migration.

Disabled members are omitted. Names must start with a lowercase ASCII letter,
contain at most 64 bytes, and use lowercase letters, digits, `_`, `-`, `.`, or `@`.
`root`, duplicate names/IDs, and UID collisions are rejected. Existing local
usernames/UIDs and group names/GIDs are checked directly in `/etc/passwd` and
`/etc/group`; other NSS sources are not queried. Homes are `/home/<username>`
and the shell is `/bin/bash`; no home directories or system accounts are created.
The snapshot also stores the namespace, mapping settings, and `reservations`
(`id`, `uid`, and every username used by that ID). Removing or disabling a
member removes the active account but keeps these reservations. A returning
member retains its UID; another ID cannot reuse its UID or old usernames.
Do not delete the snapshot to resolve collisions: that would discard its history.
Changed mapping settings, unsupported versions, malformed state, or invalid
reservations fail the sync and require an explicit administrator migration.
History and active accounts are replaced together. A directory lock excludes
overlapping syncs, and snapshots are limited to 64 MiB. Reservation history is
not pruned automatically; reaching the limit fails without replacing the file.

## Run the real Keycloak suite

Docker with the Compose v2 plugin and the OpenSSL command-line tool is the
simplest supported development environment:

```sh
make test-live
make oracle-down
```

This builds a test image with the pinned Rust toolchain, the pinned wolfSSL stable release, and the
`curl` crate linked to a wolfSSL-backed libcurl. It generates a local test CA, starts stock
Keycloak with the seeded realm, and runs real HTTPS login tests.
`KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:nightly make test-live` selects the nightly server. CI
resolves the latest stable Keycloak release and the nightly image to exact image digests at run
time. Stable login is required for merging; nightly failures remain visible in an optional
check without cancelling stable. See [CI gates and runtime baseline](CI.md) for triggers
and branch-rule settings.

On Linux, `make native` builds the same native libraries into `.native`. `make build`, `make test`,
and `make lint` use them. The local build requires Autotools, libtool, pkg-config, clang, and a
Rust toolchain from `rust-toolchain.toml`. Plain `cargo test` skips the ignored live tests;
`make test` runs unit tests plus the local integration and contract tests. Use `make test-live` for Keycloak.
The Linux native build links wolfSSL and libcurl statically so locally built
applications can run without setting a library search path. The static objects
are position independent (`--with-pic`) so they can also be linked into the PAM
shared module. The cache stamp records this build setting. If an existing
prefix predates it, choose a fresh prefix rather than reusing non-PIC objects:

```bash
export NATIVE_PREFIX="$PWD/target/native-pic"
make test
make lint
```

The previous native prefix is left intact. See the [PAM module notes](../crates/pam_himmelcloak/README.md)
for HC-40's message translation and configuration-parsing boundary.

The test realm's user is `alice` with password `correct-horse-battery-staple`. These credentials
are for the disposable Docker realm only.

See [Testing](Testing.md) for the fixture and CI contract.
