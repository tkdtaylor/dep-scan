# dep-scan dev image
# Extends the shared Claude Code base with the Rust toolchain.
# Go is also installed since the language decision is pending (ADR 001).
FROM claude-project-dev:latest

# Align container uid/gid to host so bind-mounted host files are accessible.
RUN usermod -u 1000 developer \
 && groupmod -g 1000 developer \
 && chown -R developer:developer /app /home/developer

# Install Rust toolchain
USER developer
ENV PATH="/home/developer/.cargo/bin:$PATH"
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable --no-modify-path
USER root

# Install Go toolchain
RUN GO_VERSION=1.22.0 \
 && curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:$PATH"
