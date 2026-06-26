FROM mcr.microsoft.com/devcontainers/rust:1-bookworm

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    # Rust native deps
    libssh2-1-dev \
    pkg-config \
    libssl-dev \
    openssl \
    # Infra / scripting
    python3 \
    python3-pip \
    python3-venv \
    jq \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# ── GitHub CLI ────────────────────────────────────────────────────────────────
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
      | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update -qq \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# ── Task runner (go-task) ─────────────────────────────────────────────────────
RUN TASK_VERSION="v3.37.2" \
    && curl -fsSL "https://github.com/go-task/task/releases/download/${TASK_VERSION}/task_linux_amd64.tar.gz" \
       | tar -xz -C /usr/local/bin task

# ── Ansible ───────────────────────────────────────────────────────────────────
RUN pip3 install --quiet --break-system-packages \
    ansible-core \
    ansible \
    jmespath \
    && ansible-galaxy collection install community.docker --quiet

# ── Rust toolchain extras ─────────────────────────────────────────────────────
RUN rustup component add clippy rustfmt

# ── Podman → Docker shim ──────────────────────────────────────────────────────
# The Ansible infra and Taskfile call 'podman'; Docker-in-Docker provides the
# actual daemon. The symlink makes task build / task test-all work as-is.
RUN ln -s /usr/bin/docker /usr/local/bin/podman

ENV RUST_LOG=info
