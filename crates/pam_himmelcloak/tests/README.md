# PAM skeleton load test

This check verifies the Sprint 1 denying stubs through a real Linux-PAM stack
inside a disposable Debian Bookworm container using `tests/build/Dockerfile`.

Requirements: Bash, Make, and a working Docker CLI with a Linux-container engine.
Network access is needed for image, package, native-library, and Rust dependency
downloads. The Rust module and C application are built inside the same container;
no host C compiler or Linux-PAM development headers are required.

Place `pam-load-smoke.sh` and `pam-load-smoke.c` together in
`crates/pam_himmelcloak/tests`. From the repository root, run:

```bash
make pam-smoke
```

The script builds the Rust library and a small C application inside the
container, copies the library into a temporary directory as `pam_himmelcloak.so`,
and supplies a private PAM service configuration to `pam_start_confdir`.
The repository is mounted read only; build output and temporary test files stay
inside the container. This target is separate from the default unit tests.
The test application supplies a conversation callback that returns
`PAM_CONV_ERR` if called; real prompting remains unimplemented in the skeleton.

Expected results:

```text
pam_start_confdir: 0 (expected 0)
pam_authenticate: 7 (expected 7)
pam_acct_mgmt: 6 (expected 6)
pam_setcred: 17 (expected 17)
pam_end: 0 (expected 0)
PAM load smoke test: PASS
```

The nonzero authentication, account, and credential codes are intentional for
the Sprint 1 skeleton. These expectations must be revisited when working login
flows are implemented. Any unexpected result makes the test exit unsuccessfully.
Docker removes the test container and its temporary files when it exits.

PAM API reference: [pam_start_confdir](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam_start.3.xml).
