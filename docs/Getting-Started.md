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

`config check` validates TOML syntax only. `clear-state` remains a placeholder.
`test-login` runs an interactive native password and one-time-code login. `sync-users` reads the
configured group as described below.

### Test login

Add a `[login]` table to `himmelcloak.toml` in the directory where you run
the CLI. Existing tables, including `[sync]`, can remain in the file.

```toml
[login]
server_url = "https://keycloak.example.org"
realm = "example"
client_id = "linux-login"
# ca_bundle = "/absolute/path/to/private-keycloak-ca.pem"
```

Use a public client with the standard authorization-code flow enabled and
this allowed redirect URI:

```text
http://127.0.0.1:8845/himmelcloak/callback
```

Direct access grants are not required. The server URL must use HTTPS.
Set `ca_bundle` when the certificate requires a private CA; otherwise omit it.

From the repository root, build using the native environment:

```sh
scripts/with-native.sh cargo build --locked -p himmelcloak-cli
```

From the directory containing `himmelcloak.toml`, run:

```sh
/absolute/path/to/target/debug/himmelcloak-cli test-login
```

Enter the username and password when prompted. Password input requires an
interactive Unix terminal and is not echoed. Do not put the password in
configuration files or command arguments.

Success prints `himmelcloak-cli: login succeeded` and exits with status 0.
Errors exit nonzero with a fixed message. Tokens and server-provided error
details are not printed, and resulting tokens are not persisted.

The command handles username, password, and one-time-code (TOTP and HOTP)
challenges. The code is not echoed, and spaces typed inside it are dropped.
When Keycloak offers several code devices, the command lists them by number.
WebAuthn and required-action challenges are not supported by this command.

The interrupt handler attempts to restore terminal settings before exiting
with status 130 on Ctrl+C, SIGTERM, or SIGHUP.

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
`users.json` with mode 0644, then prints the number of saved local accounts. Each user has
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

Disabled members are omitted. Sync applies the same top-level `[identity]`
rules as PAM. The default uses the Keycloak username as the local account name.
Explicit rules can map usernames or Keycloak user IDs (`claim = "sub"`) and
omit identities without a rule. Sync rejects `claim = "email"` because the
group member lookup does not supply that claim.

Invalid same-name mappings, duplicate names/IDs, and UID collisions fail the
sync. Local names follow the shared validation rules and cannot be `root`.
Sync checks local usernames, UIDs, primary GIDs, group names and GIDs, and
supplementary group memberships directly in `/etc/passwd` and `/etc/group`.
Homes are `/home/<username>`
and the shell is `/bin/bash`; no home directories or system accounts are created.
The snapshot also stores the namespace, mapping settings, and `reservations`
(`id`, `uid`, and every username used by that ID). Removing or disabling a
member removes the active account but keeps these reservations. A returning
member retains its UID; another ID cannot reuse its UID or old usernames.
Do not delete the snapshot to resolve collisions: that would discard its history.
Changed mapping settings, unsupported versions, malformed state, or invalid
reservations fail the sync and require an explicit administrator migration.
History and active accounts are replaced together. A root-owned `.sync.lock`
file with mode 0600 excludes
overlapping syncs, and snapshots are limited to 64 MiB. Reservation history is
not pruned automatically; reaching the limit fails without replacing the file.

## Build and test

Everything runs in containers. The host needs Docker with the Compose v2 plugin
(or Podman, below), `make`, and the OpenSSL command-line tool:

```sh
make         # build every crate in the tester image
make test    # unit tests, lint, then the live Keycloak suite; removes containers after
make demo    # interactive test-login against Keycloak, then Keycloak's event log
make clean   # stop Keycloak and remove the test containers and volumes
```

To use Podman instead of Docker, pass `CONTAINER=podman` to any target:

```sh
make test CONTAINER=podman
make demo CONTAINER=podman METHOD=totp
```

The scripts then call `podman` and `podman compose`. Podman needs a compose
provider (the `docker-compose` binary or plugin is what CI uses) and its API
socket running, for example with `systemctl --user enable --now podman.socket`.
Hosts that run Podman through the `podman-docker` shim can keep the default.

On SELinux hosts, the Compose bind mounts use `:z` to give the checkout and
Keycloak fixtures a shared container label. This lets the tester read
`/work/Cargo.toml` and keeps the overlapping Keycloak mounts accessible when
both containers run.

`make help` lists the individual steps:

| Target | Runs |
| --- | --- |
| `make unit` | `cargo test --workspace --tests` in the tester image |
| `make lint` | `cargo fmt --check` and clippy with `-D warnings`, as CI does |
| `make test-live` | The live Keycloak suite only, leaving Keycloak running |
| `make test-live-verbose` | The live suite plus client steps and Keycloak's event lines |
| `make shell` | A shell in the tester image with the checkout at `/work` |
| `make oracle-up` | Keycloak in the background, for manual testing |

The tester image (`tests/build/Dockerfile`) contains the pinned Rust toolchain,
the pinned wolfSSL stable release, and the `curl` crate linked to a wolfSSL-backed
libcurl. Docker or Podman caches it after the first build. Cargo output goes to a
named volume, so the host `target/` directory is untouched. The live suite and the demo
generate a local test CA, start stock Keycloak with the seeded realm, and log in
over real HTTPS through the `keycloak.test` Compose network alias.

`make demo` first prints the distribution and the `curl --version` line, which
names the wolfSSL backend. It then logs in through the `himmelcloak-browser-only`
client, which has the password grant disabled, so the CLI walks Keycloak's login
pages. Enter `alice` and `correct-horse-battery-staple`; run it again with a
wrong password to see the rejection.

`METHOD=` picks the login. `password` (the default) signs in `alice`; `totp` signs
in `bob` with a code from a phone authenticator app; `totp-devices` has `carol`
choose between two code devices first; `list` prints the methods. See
[Phone one-time-code demo](#phone-one-time-code-demo) for the phone setup.

`KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:nightly make test` selects the nightly
server. Keycloak gets a random free host port, so an existing service on 8443
does not block the tests; set `KEYCLOAK_HOST_PORT=8443` to pin it. CI resolves
the latest stable Keycloak release and the nightly image to exact image digests
at run time. Stable login is required for merging; nightly failures remain
visible in an optional check without cancelling stable.
See [CI gates and runtime baseline](CI.md) for triggers and branch-rule settings.

### Phone one-time-code demo

`make demo METHOD=totp` signs `bob` in with his password and a code from your
phone, the same way a site that uses Google Authenticator works. No browser
opens and no code is sent to the phone: the phone and Keycloak share a secret
once, through the QR code, and each computes the same 6-digit code from that
secret and the current time.

1. Run `make demo METHOD=totp`. It prints a QR code before the login prompts.
   Make the terminal at least 50 columns wide so the code is not cut off.
2. Add the account to your phone once:
   - **iPhone (Apple Passwords):** point the Camera at the QR code and tap the
     link it shows. Passwords opens and offers to add a verification code.
     Create a new entry, name it something like `Himmelcloak bob`, and save it.
     The website field is only a label; `keycloak.test` works.
   - **Google Authenticator, Aegis, 2FAS, or FreeOTP:** open the app, tap
     **+**, choose **Scan a QR code**, and scan it from inside the app.
3. At the prompts, enter `bob` and `correct-horse-battery-staple`.
4. At `One-time code:`, open the entry on your phone (in Apple Passwords, the
   **Verification Code** field) and type the 6 digits it shows. The input is
   hidden like a password, and a space typed in the middle, as in `546 708`, is
   ignored. The code changes every 30 seconds; if it is about to change, wait for
   the next one.
5. The demo prints `himmelcloak-cli: login succeeded`, then Keycloak's `LOGIN`
   event for `bob`.

From then on, run `make demo METHOD=totp QR=0` to skip the QR code and use the
same phone entry each time. `make clean` removes Keycloak, but the next run loads
`bob` with the same fixed secret, so the phone entry keeps working. Scan again
only if `tests/keycloak/realm-export.json` changes his secret.

Type a wrong code to see the rejection: the demo prints
`himmelcloak-cli: login failed` and exits with status 1. Keycloak also refuses a
code that was already used, so a second login inside the same 30 seconds needs
the next code.

`make demo METHOD=totp-devices` does the same for `carol`, who has two code
devices. Pick `1` (Authenticator app) from the menu, then enter her code. Her
code is SHA-256 with 8 digits. Aegis, 2FAS, and FreeOTP handle it; other apps,
including Google Authenticator, may ignore SHA-256 and show codes Keycloak rejects.

If the image has no `qrencode`, as some `DISTRO` images do not, the demo prints
the `otpauth://` link instead; enter it in the app by hand. Codes also fail when
the host clock is more than about 30 seconds off; check with `timedatectl`.

These secrets are public test fixtures. Real users enroll through Keycloak's own
"Configure OTP" page, which creates a private secret and shows the QR code.

### Other Linux distributions

Every target accepts `DISTRO=<name>`, for example
`make test DISTRO=opensuse-leap-16.0` or `make demo DISTRO=rockylinux-9`.
`make test-distros` runs `make test` on each distribution in turn.

| `DISTRO` | Base image |
| --- | --- |
| `debian-12` | `debian:12` |
| `ubuntu-24.04` | `ubuntu:24.04` |
| `opensuse-leap-16.0` | `opensuse/leap:16.0` |
| `opensuse-tumbleweed` | `opensuse/tumbleweed` |
| `sle-bci-16.0` | SUSE Linux Enterprise BCI 16.0 |
| `rockylinux-9` | `rockylinux:9` |
| `fedora` | `fedora` |

With `DISTRO` set, the tester is built locally from the matching
`.github/docker/himmelcloak-ci/` Dockerfile, the same files the cross-distro CI
uses, and tagged `himmelcloak-tester:<name>`. Each image compiles the branch's
pinned wolfSSL and libcurl, so the first build of a distribution takes several
minutes and later runs reuse the container engine's cache. These images are x86-64 only, so
Apple silicon runs them under emulation. Each distribution keeps its own Cargo
build directory, so switching does not mix build output.

### Native Linux build

On Linux, `make native` builds the same native libraries into `.native`. `make local-build`,
`make local-test`, and `make local-lint` use them. The local build requires Autotools, libtool, pkg-config, clang, and a
Rust toolchain from `rust-toolchain.toml`. Plain `cargo test` skips the ignored live tests;
`make local-test` runs unit tests plus the local integration and contract tests. Use `make test-live` for Keycloak.
The Linux native build links wolfSSL and libcurl statically so locally built
applications can run without setting a library search path. The static objects
are position independent (`--with-pic`) so they can also be linked into the PAM
shared module. The cache stamp records this build setting. If an existing
prefix predates it, choose a fresh prefix rather than reusing non-PIC objects:

```bash
export NATIVE_PREFIX="$PWD/target/native-pic"
make local-test
make local-lint
```

The previous native prefix is left intact. See the [PAM module notes](../crates/pam_himmelcloak/README.md)
for the PAM conversation, the `[pam]` and `[identity]` configuration, and the
PAM stack tests.

The test realm's user is `alice` with password `correct-horse-battery-staple`. These credentials
are for the disposable Docker realm only.

See [Testing](Testing.md) for the fixture and CI contract.
