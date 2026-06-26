FROM docker.io/library/alpine:3.19

# OpenSSH 9.5p1 — vulnerable to CVE-2023-48795 (Terrapin)
# Alpine 3.19 ships 9.5p1 which does NOT advertise kex-strict-s-v00@openssh.com

RUN apk add --no-cache openssh && \
    ssh-keygen -A && \
    mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
