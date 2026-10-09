# PAM skeleton load test

This check verifies the Sprint 1 denying stubs through a real Linux-PAM stack
inside a disposable Ubuntu 26.04 container.

Requirements: a Linux development environment, a C compiler, Linux-PAM
development headers (the `libpam0g-dev` package on Ubuntu), and a working Docker
CLI. The container needs network access to install its PAM runtime packages.

Place `pam-load-smoke.sh` and `pam-load-smoke.c` together in
`pam_himmelcloak/tests`. From the repository root, run:

```bash
make build
bash pam_himmelcloak/tests/pam-load-smoke.sh "$PWD"
```

The script compiles a small C application, copies the built Rust library into a
temporary directory as `pam_himmelcloak.so`, and supplies a private PAM service
configuration to `pam_start_confdir`. The container mounts these test files read
only. The test application supplies a conversation callback that returns
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
The script cleans up its temporary files, and Docker removes the test container.

PAM API reference: [pam_start_confdir](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam_start.3.xml).
