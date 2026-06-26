FROM docker.io/library/alpine:3.20

# OpenSSH 9.7p1 — patched (CVE-2023-48795)
# Alpine 3.20 ships 9.7p1 which automatically advertises kex-strict-s-v00@openssh.com

RUN apk add --no-cache openssh && \
    ssh-keygen -A && \
    mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
