FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG OPENCODE_VERSION=latest

# Common dev tools: git for SCM, curl/unzip for the opencode installer,
# ca-certificates so TLS to AI providers works inside the container.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        git \
        ca-certificates \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Install opencode via the official script.
# The binary lands in /root/.local/bin when running as root.
RUN curl -fsSL https://opencode.ai/install | bash

ENV PATH="/root/.local/bin:$PATH"

# opencode serve listens on this port inside the container.
# opencode-sandbox publishes it to a random host port automatically.
EXPOSE 4096

WORKDIR /workspace
