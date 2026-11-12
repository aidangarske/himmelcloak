# PAM stack tests

These checks load `pam_himmelcloak.so` through a real Linux-PAM stack inside a
disposable Debian Bookworm container built from `tests/build/Dockerfile`.

Requirements: Bash, Make, and a working Docker CLI with a Linux-container engine.
Network access is needed for image, package, native-library, and Rust dependency
downloads. The Rust module and C applications are built inside the same container;
no host C compiler or Linux-PAM development headers are required.

From the repository root, run:

```bash
make pam-smoke
```

`pam-load-smoke.sh` builds the image and runs `run-pam-stack-tests.sh` in the
container. The repository is mounted read only, and each test uses a private PAM
service directory through `pam_start_confdir`, so no system PAM configuration is
touched. Docker removes the container and its temporary files when it exits.
This target is separate from the default unit tests.

## 1. Load smoke test (`pam-load-smoke.c`)

Builds the default module and checks that every entry point loads and denies.
The test application's conversation returns `PAM_CONV_ERR` if it is ever
called; the default build never prompts.

```text
pam_start_confdir: 0 (expected 0)
pam_authenticate: 7 (expected 7)
pam_acct_mgmt: 6 (expected 6)
pam_setcred: 17 (expected 17)
pam_end: 0 (expected 0)
PAM load smoke test: PASS
```

## 2. Conversation round trip (`pam-conversation-roundtrip.c`, HC-41)

Builds the module with the test-only `conversation-selftest` feature in a
separate target directory. The C program plays the login program: it answers
the module's prompts and records every message.

| Scenario | Expected |
| --- | --- |
| Answers `alice` and a 28-byte password | Visible `Username: `, hidden `Password: `, then an information line reporting the username and password length; `pam_authenticate` still returns 7 |
| The program's conversation fails | `pam_authenticate` returns 19 (`PAM_CONV_ERR`) |
| The program returns no password | `pam_authenticate` returns 19 |

The password itself is never shown back to the program. Expected ending:

```text
messages shown: 2 (expected 2)
PAM conversation round trip: PASS
```

The nonzero authentication results are intentional until the module is
connected to the login engine (HC-42). Any unexpected result makes the test
exit unsuccessfully.

PAM API references: [pam_start_confdir](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam_start.3.xml),
[pam_conv](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam_conv.3.xml).
