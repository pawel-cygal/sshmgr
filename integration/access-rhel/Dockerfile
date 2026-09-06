FROM rockylinux:9-minimal

RUN microdnf install -y openssh-server sudo shadow-utils \
    && microdnf clean all \
    && mkdir -p /run/sshd /etc/ssh/keys /etc/ssh/principals \
    && ssh-keygen -A \
    && useradd -m -u 1000 -s /bin/sh audit \
    && useradd -m -u 1001 -s /bin/sh denied \
    && usermod -p '' audit \
    && usermod -p '' denied \
    && printf 'audit ALL=(ALL) NOPASSWD: ALL\n' >/etc/sudoers.d/sshmgr-access \
    && chmod 0440 /etc/sudoers.d/sshmgr-access

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
