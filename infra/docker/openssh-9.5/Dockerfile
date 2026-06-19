FROM ubuntu:22.04

# OpenSSH 9.5 — vulnerable to CVE-2023-48795
# Offers chacha20-poly1305 and ETM MACs without kex-strict-s-v00 extension

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends openssh-server wget build-essential \
      libssl-dev zlib1g-dev libpam0g-dev && \
    rm -rf /var/lib/apt/lists/*

# Download and compile OpenSSH 9.5p1
RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.5p1.tar.gz && \
    tar xf openssh-9.5p1.tar.gz && \
    cd openssh-9.5p1 && \
    ./configure --prefix=/usr/local --with-pam && \
    make -j$(nproc) && make install && \
    cd / && rm -rf openssh-9.5p1*

RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A -f /usr/local/etc 2>/dev/null || \
    /usr/local/sbin/sshd -t 2>/dev/null; \
    /usr/local/bin/ssh-keygen -A 2>/dev/null || true

COPY sshd_config /usr/local/etc/sshd_config

EXPOSE 22
CMD ["/usr/local/sbin/sshd", "-D", "-e"]
