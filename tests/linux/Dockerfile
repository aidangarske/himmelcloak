# Himmelcloak disposable Linux test system (HC-45).
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A throwaway Debian 12 system with OpenSSH, the Himmelcloak PAM module in the
# sshd stack, and a separate local recovery account. Login changes are only
# ever tested here, never on a member's own computer. Build it with
# tests/linux/run.sh (make linux-test or make linux-shell).

# The default (Debian 12) tester image has the pinned Rust toolchain and native
# libraries. run.sh always uses it, on the same platform as the final image, so
# the module matches this image's glibc and architecture.
ARG TESTER_IMAGE=himmelcloak-tester:ci
FROM ${TESTER_IMAGE} AS build
COPY . /src
WORKDIR /src
RUN cargo build --locked --release -p pam_himmelcloak \
    && install -m 0644 target/release/libpam_himmelcloak.so /pam_himmelcloak.so

# Same Debian release as the tester image, so the module's glibc matches.
FROM docker.io/library/debian:12-slim
# The slim image has no CA certificates, so install them first (packages are
# still signature-checked), then switch apt to HTTPS like the tester image.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       jq openssh-client openssh-server pamtester sshpass \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /pam_himmelcloak.so /tmp/pam_himmelcloak.so
RUN install -m 0644 /tmp/pam_himmelcloak.so "/usr/lib/$(uname -m)-linux-gnu/security/pam_himmelcloak.so" \
    && rm /tmp/pam_himmelcloak.so

# The documented local recovery account: an ordinary local user whose UID is
# far below the synced Keycloak range (200000 and up) and whose password is
# checked by pam_unix, so it still signs in when Keycloak or Himmelcloak is
# broken. The password exists only inside this disposable image.
ARG RECOVERY_UID=1001
RUN useradd --uid "$RECOVERY_UID" --user-group --create-home --shell /bin/bash recovery \
    && echo 'recovery:local-recovery-test-only' | chpasswd

COPY tests/linux/rootfs/ /
RUN chmod 0644 /etc/pam.d/sshd /etc/pam.d/himmelcloak-load \
       /etc/ssh/sshd_config.d/himmelcloak.conf \
       /var/lib/himmelcloak/users.json \
    && chmod 0755 /usr/local/libexec/himmelcloak/check-system.sh \
    && ssh-keygen -A \
    && mkdir -p /run/sshd \
    && /usr/sbin/sshd -t

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
