# pam_himmelcloak

The PAM module that will sign Linux users in with Keycloak. The exported entry
points still deny every login: connecting them to the login engine is HC-42.
What exists so far:

- `conversation::plan(&Challenge)` turns a login challenge into ordered PAM
  messages (HC-40).
- `pam_conv::converse` sends those messages through the login program's real
  Linux-PAM conversation function and returns the answers (HC-41).
- `config::ConfigDocument` reads `/etc/himmelcloak/himmelcloak.toml`, and
  `pam_settings()` validates the `[pam]` connection and `[identity]` mapping
  rules (HC-40 syntax, HC-41 settings).

## Message styles

| Challenge or event | PAM message style |
| --- | --- |
| Username or sign-in method selection | `PAM_PROMPT_ECHO_ON` (2) |
| Password, one-time code, recovery code | `PAM_PROMPT_ECHO_OFF` (1) |
| Choosing among multiple OTP devices | Visible device selection, then hidden code |
| Required-action fields | Each field's `secret` flag selects hidden or visible input |
| Information or a required-action message | `PAM_TEXT_INFO` (4) |
| WebAuthn | Information plus a marker requiring the caller's adapter; no signing here |
| Failed authentication message | `PAM_ERROR_MSG` (3), via `failure_plan` |

Information and fieldless required actions require the caller to acknowledge;
they do not automatically approve the login. Unsupported future challenges,
empty method lists, and messages containing an interior NUL are rejected.

## Conversation

`pam_conv::converse` looks up the application's `struct pam_conv` with
`pam_get_item(PAM_CONV)`, sends up to 32 messages in one call, and copies each
answer into a zeroizing buffer. Every response string the application returns
is wiped and then freed with `free`, as Linux-PAM requires.

Any of these fail with `PAM_CONV_ERR` and never count as an answer:

- no conversation function, or the function reports an error
- no response array, or no answer to a prompt
- an answer over 512 bytes (`PAM_MAX_RESP_SIZE`) or not valid UTF-8
- more than 32 messages, or a message containing NUL (checked before the call)

Information and error messages return no answer, even if the application sends
one back. An empty answer (the user just pressed Enter) is kept as an empty string.

`pam_get_item` is resolved from the libpam that loads the module, so building
the crate needs no PAM development headers.

## Configuration

The module reads one root-owned file, `/etc/himmelcloak/himmelcloak.toml`
(mode 0644, no secrets). `ConfigDocument::load_trusted` refuses symlinks,
non-regular files, files owned by another user, and files group or others can
write. Reads are capped at 64 KiB, and error messages never repeat the file's
contents. Other tables in the same file, such as the CLI's `[sync]` and
`[login]`, are ignored here.

```toml
[pam]
server_url = "https://keycloak.example.org"
realm = "example"
client_id = "linux-login"
# ca_bundle = "/etc/himmelcloak/keycloak-ca.pem"

[identity]
claim = "preferred_username"   # or "email", or "sub" (explicit mode only)
mode = "same-name"             # or "explicit"

# Optional rules. In explicit mode, only listed identities may sign in.
[[identity.map]]
keycloak = "alice@example.org"
local = "alice"
```

`[pam]` uses the same server, realm, and client checks as the core library
(HTTPS only, no credentials or query in the URL). `ca_bundle` must be absolute.

### Identity mapping rules

The verified token claim named by `claim` identifies the user:

- **same-name:** the local account has the same name as the claim value,
  unless a `[[identity.map]]` rule says otherwise.
- **explicit:** only identities listed in `[[identity.map]]` may sign in;
  everyone else is denied.

Local names must start with a lowercase letter and use only lowercase letters,
digits, `_`, `-`, `.`, or `@` (up to 64 characters), the same names the sync job
writes for the NSS module. Nothing ever maps to `root`.

The configuration is rejected if:

- `claim` or `mode` is unknown, or a table has an unknown key
- `claim = "sub"` is used with same-name (a subject ID is not an account name)
- explicit mode has no rules
- a rule targets `root` or an invalid local name, or has an empty or
  control-character Keycloak identity
- two rules share a Keycloak identity, or two identities map to the same account
- in same-name mode, a rule renames an identity to an account that a Keycloak
  user of that name would also reach, unless that name has its own rule

This proposed format needs confirmation from the NSS (HC-50) and core owners.
The rules only choose an account name. Checking that the account exists and
is served by the Himmelcloak NSS source, so a Keycloak name can never take over
an unrelated local account, belongs to the account checks in HC-42.

## Validation

Use the prerequisites in [Getting Started](../../docs/Getting-Started.md).
From the repository root:

```bash
make test
make lint
make pam-smoke
```

`make pam-smoke` is separate from default unit tests and requires Docker and
network access. In a disposable Linux container it runs the load smoke test and
the conversation round trip through the real Linux-PAM stack. See
[the PAM stack test instructions](tests/README.md).

The `conversation-selftest` feature exists only for that round trip. With it,
a debug build's `pam_sm_authenticate` asks for a username and password, reports
what arrived, and still denies. Release builds ignore the feature.

## Design reference

David recommended forking [Tozny's Rust PAM project](https://github.com/tozny/toznyauth-pam).
The current-Rust scaffold in [Josh's fork](https://github.com/synod1c/toznyauth-pam)
follows its separation of PAM entry points, conversation handling, and config
parsing. The helpers here are adapted from that scaffold; the original Tozny
2015 authentication and build code is not installed or used by this crate.

Tasks: [HC-40 / issue #54](https://github.com/aidangarske/himmelcloak/issues/54),
[HC-41 / issue #55](https://github.com/aidangarske/himmelcloak/issues/55).
