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

`test-login --verbose` (or `HIMMELCLOAK_TRACE=1`) prints a `himmelcloak:`
line to stderr for each step: every HTTPS request with its wolfSSL TLS
version and cipher, the PKCE challenge, the Keycloak page found, the form
field names posted, the code exchange, and the ID-token checks, followed by
the token's issuer, audience, username, and subject once it is verified. On a
failure it adds the libcurl or wolfSSL error, that Keycloak rejected the answer,
or the token check that failed. It never prints passwords, codes, cookie
values, raw tokens, or query strings, and escapes control characters in
text from the server. Names, paths, and verified claims are printed as the
configured Keycloak serves them, so the trace trusts that server.

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
