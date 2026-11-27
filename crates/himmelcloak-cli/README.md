## Test login

`himmelcloak-cli test-login` runs a native login through the
authentication engine. It prompts for a username and a hidden password,
then for a device and a hidden one-time code when Keycloak asks for one.
It requires an interactive Unix terminal.

Create or extend `himmelcloak.toml` in the current working directory:

```toml
[login]
server_url = "https://keycloak.test:8443"
realm = "himmelcloak-test"
client_id = "himmelcloak-test-client"
ca_bundle = "/absolute/path/to/tests/keycloak/.generated/ca.pem"
```

Use the server, realm, and public client configured for your deployment.
The server must use HTTPS. Omit `ca_bundle` when the server certificate
is trusted by the system. Never put the user's password in this file.

Run:

```bash
scripts/with-native.sh cargo run --locked -p himmelcloak-cli -- test-login
```

A successful login prints `himmelcloak-cli: login succeeded` and exits
with status 0. Failed logins and configuration errors exit with a
nonzero status and a fixed error message.

The command does not print or persist resulting tokens. Password input
is not echoed. Server-provided failure details are not printed.

This command supports username, password, and one-time-code (TOTP and
HOTP) challenges. The code is not echoed. When Keycloak offers several
code devices, the command lists them by number and posts the chosen one;
device labels are printed with control characters removed. Other
challenges, including WebAuthn and required actions, end the login with
an unsupported-challenge message.

### Validation

Configuration tests cover missing settings, HTTPS enforcement, optional
CA configuration, unrelated configuration tables, and error messages
that do not echo sensitive configuration values.

A live terminal test against the latest Keycloak image must also confirm
successful fixture-user login and that neither the password nor tokens
appear in command output.

## Clear session state

`himmelcloak-cli clear-state` removes one user's existing encrypted
TokenCache entry. It reads `himmelcloak.toml` from the current working
directory.

Add the following settings, using the username and absolute paths for
your existing cache:

```toml
[session]
username = "alice"
cache_directory = "/var/lib/himmelcloak/tokens"
key_file = "/etc/himmelcloak/token.key"
```

The configuration must be a root-owned regular file, must not be a
symlink, and must not be writable by group or others. Its maximum size
is 64 KiB. Running with `sudo` does not change the file's ownership.

On the target Linux system, review the configuration and ensure it is
in a trusted directory before setting its ownership and permissions:

```bash
sudo chown root:root himmelcloak.toml
sudo chmod 0600 himmelcloak.toml
```

Then run the built binary from that directory:

```bash
sudo /absolute/path/to/target/debug/himmelcloak-cli clear-state
```

Build the binary first if needed:

```bash
scripts/with-native.sh cargo build --locked -p himmelcloak-cli
```

The command removes only the configured user's cache entry. It does not
delete the encryption key or other users' entries. Missing cache or key
paths cause an error rather than creating new state.

This clears local cached state; it does not revoke sessions in Keycloak.
The `test-login` command remains stateless: it neither saves nor restores
tokens, and each invocation starts a new authentication flow.