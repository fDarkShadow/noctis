FROM ubuntu:22.04

# OpenSSH 9.6 — patched CVE-2023-48795
# Advertises kex-strict-s-v00@openssh.com in KEXINIT

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends openssh-server wget build-essential \
      libssl-dev zlib1g-dev libpam0g-dev && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.6p1.tar.gz && \
    tar xf openssh-9.6p1.tar.gz && \
    cd openssh-9.6p1 && \
    ./configure --prefix=/usr/local --with-pam && \
    make -j$(nproc) && make install && \
    cd / && rm -rf openssh-9.6p1*

RUN mkdir -p /var/run/sshd
COPY sshd_config /usr/local/etc/sshd_config
RUN /usr/local/bin/ssh-keygen -A 2>/dev/null || true

EXPOSE 22
CMD ["/usr/local/sbin/sshd", "-D", "-e"]
