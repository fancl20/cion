FROM debian:unstable-slim

RUN groupadd --gid 1000 coder && \
    useradd --uid 1000 --gid 1000 -m coder

RUN apt-get update && apt-get install -y \
    curl git vim jq fish \
    nodejs npm

RUN apt-get install -y \
    build-essential pkg-config \
    python3 golang

RUN curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b /usr/bin/

# Clean up
RUN rm -rf /tmp/* /var/tmp/* /var/lib/apt/lists/*

SHELL ["/usr/bin/fish"]
USER coder
