FROM debian:bookworm-slim

ARG SSHMGR_AUDIT_UID=1000
ARG SSHMGR_DEVICE_UID=1001

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -u "$SSHMGR_AUDIT_UID" -s /bin/sh audit \
    && useradd -m -u "$SSHMGR_DEVICE_UID" -s /bin/sh device \
    && passwd -d audit \
    && passwd -d device \
    && printf 'audit ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/sshmgr-access \
    && chmod 0440 /etc/sudoers.d/sshmgr-access

COPY network-cli /usr/local/bin/network-cli
COPY sshd_config /etc/ssh/sshd_config

RUN chmod 0755 /usr/local/bin/network-cli

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
