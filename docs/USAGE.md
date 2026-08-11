# Usage Guide

agent-sandbox is a CLI-agnostic Docker sandbox for AI coding agents. It builds isolated containers with network firewalls, so agents can't reach the host or external services unless you explicitly allow it.

This guide covers **opencode** (first priority) and **Claude Code** (at minimum). The same config structure works for any agent CLI — just change the `run.entrypoint`, `run.command`, and related fields.

For architecture details, see [DESIGN.md](DESIGN.md).

---

## 1. Build — Version Specification

Agent CLIs are installed inside the Docker image at build time. Pin versions via `build.args` with env var expansion (`os.ExpandEnv` — the host shell resolves `${VAR}` at build time).

### opencode

**Dockerfile:**

```dockerfile
FROM ubuntu:24.04

ARG OPENCODE_VERSION=latest

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# Pin version via build arg
RUN curl -fsSL https://opencode.ai/install | bash

ENV PATH="/root/.local/bin:$PATH"
EXPOSE 4096
WORKDIR /workspace
```

**Config — pin from host shell:**

```yaml
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
      context: .
      args:
        OPENCODE_VERSION: "${OPENCODE_VERSION}"  # from host shell
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
```

**Pin a specific version:**

```bash
# Shell env var
OPENCODE_VERSION=0.21.0 agent-sandbox run

# Or inline
agent-sandbox run --env OPENCODE_VERSION=0.21.0
```

**Use latest (default):**

```bash
agent-sandbox run  # OPENCODE_VERSION defaults to "latest" in Dockerfile ARG
```

### Claude Code

**Dockerfile:**

```dockerfile
FROM node:22-slim

ARG CLAUDE_VERSION=latest

RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_VERSION}

EXPOSE 4096
WORKDIR /workspace
```

**Config:**

```yaml
profiles:
  default:
    build:
      dockerfile: ./Dockerfile.claude
      context: .
      args:
        CLAUDE_VERSION: "${CLAUDE_VERSION}"
    run:
      entrypoint: ["claude"]
      command: ["--port", "4096"]
```

**Pin:**

```bash
CLAUDE_VERSION=1.0.50 agent-sandbox run
```

### Build secrets

For private registries or API keys needed during build:

```yaml
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
      context: .
      args:
        OPENCODE_VERSION: "${OPENCODE_VERSION}"
      secrets:
        - id: npm-token
          env: NPM_TOKEN       # from host env var
        - id: pip-creds
          src: ~/.pip/pip.conf # from file
```

In Dockerfile:

```dockerfile
RUN --mount=type=secret,id=npm-token \
    NPM_TOKEN=$(cat /run/secrets/npm-token) npm install
```

---

## 2. Configure — Config Overrides

Host-side config flows into the sandbox via mounts and env vars. Override anything inside the container with `run.env` and `run.mounts`.

### opencode

**Host config mounted RO at `/root/.config/opencode`:**

```yaml
profiles:
  default:
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      data_dir: /root/.local/share/opencode
      attach_cmd: "opencode attach %s"

      mounts:
        # Project directory (RW — agent edits files here)
        - source: ~/workspace/myapp
          target: /workspace

        # Host opencode config (RO — inherits settings)
        - source: ~/.config/opencode
          target: /root/.config/opencode
          readonly: true

        # Git identity (RO)
        - source: ~/.gitconfig
          target: /root/.gitconfig
          readonly: true

        # SSH keys (RO — for git-over-SSH)
        - source: ~/.ssh
          target: /root/.ssh
          readonly: true

      env:
        OPENCODE_TELEMETRY: "0"
        # Override host config inside sandbox:
        # OPENCODE_CONFIG_CONTENT: '{"permission":"allow"}'

      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1
```

**Override permissions at runtime (without changing config):**

```bash
agent-sandbox run -e OPENCODE_CONFIG_CONTENT='{"permission":"allow"}'
```

### Claude Code

**Host config mounted RO at `/root/.claude`:**

```yaml
profiles:
  default:
    run:
      entrypoint: ["claude"]
      command: ["--port", "4096"]

      mounts:
        - source: ~/workspace/myapp
          target: /workspace

        # Claude Code config (RO)
        - source: ~/.claude
          target: /root/.claude
          readonly: true

        # Git identity (RO)
        - source: ~/.gitconfig
          target: /root/.gitconfig
          readonly: true

        # SSH keys (RO)
        - source: ~/.ssh
          target: /root/.ssh
          readonly: true

      env:
        ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"

      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1
```

### Profile selection

1. `-p <profile>` flag (highest priority)
2. `default_profile` in config
3. Auto-select if only one profile is defined

```bash
agent-sandbox -p go-dev run        # explicit profile
agent-sandbox run                  # uses default_profile or sole profile
```

### Session persistence

Every sandbox gets a Docker named volume mounted at `run.data_dir` (opencode default: `/root/.local/share/opencode`). Sessions survive container removal.

```bash
agent-sandbox sessions ps          # list session volumes
agent-sandbox sessions rm --all    # clean up all sessions
```

---

## 3. Network Rules

The firewall container enforces network isolation. All agent traffic flows through it.

### CIDR rules

Allow or deny IP ranges. Deny wins — if a CIDR appears in both lists, deny takes precedence.

```yaml
firewall:
  network:
    default: deny          # block everything not explicitly allowed
    cidr:
      allow:
        - 10.0.0.0/8       # private network
        - 172.16.0.0/12    # private network
        - 192.168.0.0/16   # private network
      deny:
        - 10.0.0.0/24      # block specific subnet (overrides allow)
    auto_pin_resolved: true  # auto-allow DNS-resolved IPs
```

### DNS rules

Allow or deny domains. Supports wildcards. Deny wins.

```yaml
firewall:
  network:
    dns:
      default: deny
      allow:
        - "*.anthropic.com"    # all Anthropic subdomains
        - "api.openai.com"     # OpenAI API only
        - "registry.npmjs.org" # npm registry
      deny:
        - "evil.anthropic.com" # block specific subdomain
      upstream:
        - 1.1.1.1              # Cloudflare DNS
        - 8.8.8.8              # Google DNS
```

### Default policy

- `default: deny` — block everything not in allow list (recommended for untrusted agents)
- `default: allow` — allow everything not in deny list (convenient for trusted agents)

### Conflict detection

If the same CIDR or domain appears in both allow and deny lists, the config loader logs a warning at startup. Deny always wins at enforcement time.

### Examples

**API-only lockdown (Anthropic + OpenAI only):**

```yaml
firewall:
  network:
    default: deny
    cidr:
      allow: []
      deny: []
    dns:
      default: deny
      allow:
        - "*.anthropic.com"
        - "api.openai.com"
      upstream: [1.1.1.1]
```

**Private subnet access (dev environment):**

```yaml
firewall:
  network:
    default: deny
    cidr:
      allow:
        - 10.0.0.0/8
        - 172.16.0.0/12
    dns:
      default: allow
      upstream: [1.1.1.1, 8.8.8.8]
```

---

## 4. Reverse Forwarding (Host → Container)

Forward host services into the sandbox. The firewall runs socat forwarders and auto-generates nftables OUTPUT rules (scoped to exact host ports — rest of host unreachable).

### Port forwarding

Forward a host port to a container port:

```yaml
run:
  reverse_forward:
    ports:
      - host: 3000          # host port
        container: 3000     # port inside firewall (agent reaches via firewall IP)
      - host: 8080
        container: 8080
```

**Use case:** Forward a host dev server into the sandbox so the agent can access it.

### Socket forwarding

Forward a host Unix socket to a container TCP port:

```yaml
run:
  reverse_forward:
    sockets:
      - socket: /var/run/docker.sock
        container: 2375     # Docker API inside container
```

**Use case:** Let the agent use Docker inside the sandbox (Docker-in-Docker via socket).

### How it works

1. The firewall container runs socat listeners on its isolated network IP
2. Each socat forwards traffic from `<firewall-ip>:<container-port>` → `host.docker.internal:<host-port>`
3. nftables OUTPUT rules are auto-generated to allow the firewall container to reach `host.docker.internal` on the exact specified ports
4. The agent connects to `<firewall-ip>:<container-port>` — traffic flows through the firewall to the host

### Security note

Reverse-forwarded ports bypass the agent-facing CIDR/DNS rules by design. The firewall's OUTPUT chain allows traffic to `host.docker.internal` on the exact ports you specify. The rest of the host is unreachable.

---

## 5. SSH / Git Credential Forwarding

No special flags — use existing `run.mounts` + `run.env` mechanisms.

### SSH agent forwarding

```yaml
run:
  mounts:
    # Linux: direct socket mount
    - source: ${SSH_AUTH_SOCK}
      target: /ssh-agent
      readonly: true

    # macOS Docker Desktop: use the Docker-provided socket
    # - source: /run/host-services/ssh-auth.sock
    #   target: /ssh-agent
    #   readonly: true

  env:
    SSH_AUTH_SOCK: /ssh-agent
```

**Security note:** This authorizes the container to use your SSH identity for the session. Only use with trusted agents.

### Git config

```yaml
run:
  mounts:
    - source: ~/.gitconfig
      target: /root/.gitconfig
      readonly: true
```

### Git HTTPS with token

```yaml
run:
  env:
    GH_TOKEN: "${GH_TOKEN}"
```

Then inside the container:

```bash
gh auth setup-git
```

---

## 6. Common Recipes

### API-only lockdown

Allow only Anthropic and OpenAI API access, block everything else:

```yaml
profiles:
  secure:
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1

    firewall:
      network:
        default: deny
        dns:
          default: deny
          allow:
            - "*.anthropic.com"
            - "api.openai.com"
          upstream: [1.1.1.1]
```

### Private subnet access

Agent can reach internal services (devpi, private npm, internal APIs):

```yaml
profiles:
  dev:
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1

    firewall:
      network:
        default: deny
        cidr:
          allow:
            - 10.0.0.0/8
            - 172.16.0.0/12
        dns:
          default: allow
          upstream: [1.1.1.1, 8.8.8.8]
```

### Development server (live reload)

Forward a host dev server into the sandbox:

```yaml
profiles:
  dev:
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1
      reverse_forward:
        ports:
          - host: 5173      # Vite dev server on host
            container: 5173  # accessible inside sandbox

    firewall:
      network:
        default: deny
        dns:
          default: allow
          upstream: [1.1.1.1]
```

### Multi-profile setup

Separate profiles for different projects:

```yaml
default_profile: go-dev

profiles:
  go-dev:
    build:
      dockerfile: ./Dockerfile-go
      context: .
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      data_dir: /root/.local/share/opencode
      attach_cmd: "opencode attach %s"
      env:
        GOFLAGS: "-mod=mod"
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1

  node-dev:
    build:
      dockerfile: ./Dockerfile-node
      context: .
    run:
      entrypoint: ["opencode"]
      command: ["serve", "--hostname=0.0.0.0", "--port=4096"]
      data_dir: /root/.local/share/opencode
      attach_cmd: "opencode attach %s"
      env:
        NODE_ENV: development
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        container: 4096/tcp
        bind: 127.0.0.1
```

```bash
agent-sandbox -p go-dev run     # Go project
agent-sandbox -p node-dev run   # Node.js project
```

---

## 7. CLI Reference

### Commands

| Command | Description |
|---------|-------------|
| `run` | Create (if needed), start, and attach to a sandbox. Idempotent — safe to re-run. |
| `create` | Create sandbox resources without starting or attaching |
| `start` | Start a stopped sandbox |
| `stop` | Stop a running sandbox |
| `build` | Build the sandbox image without creating a container |
| `ps` | List sandbox containers (`-a` to include stopped/failed) |
| `rm` | Remove sandbox containers (`--all` for all) |
| `logs` | Stream container logs (`-f` to follow, `--tail N` for last N lines) |
| `sessions ps` | List sandbox session volumes |
| `sessions rm` | Remove session volumes (`--all` for all, `--force` to skip confirmation) |
| `config` | Print resolved config as YAML |

### Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | `-c` | Config file path (default: `./agent-sandbox.yaml`) |
| `--profile` | `-p` | Profile to use |

### Run flags

| Flag | Short | Description |
|------|-------|-------------|
| `--env KEY=VALUE` | `-e` | Set or override an env var; repeatable |
| `--mount source:target[:ro]` | `-v` | Append a mount; repeatable |
| `--bind IP` | | Override `run.port.bind` (e.g. `0.0.0.0` for LAN) |
| `--cmd` | | Override the attach command (default: `run.attach_cmd` from config) |
| `--no-build` | | Skip the build step |
| `--pull` | | Pass `--pull` to `docker build` |

### Config file resolution

1. Path given by `-c`
2. `./agent-sandbox.yaml` (current directory)
3. `$XDG_CONFIG_HOME/agent-sandbox/config.yaml` (default: `~/.config/agent-sandbox/config.yaml`)

Config is profiles-based. Deep-merge: project config overrides global config.

### Examples

```bash
# Basic usage
agent-sandbox run -e ANTHROPIC_API_KEY=sk-ant-...

# Specific profile
agent-sandbox -p go-dev run

# Expose to LAN
agent-sandbox run --bind 0.0.0.0

# Skip build (image already built)
agent-sandbox run --no-build

# Custom attach command
agent-sandbox run --cmd "ssh root@localhost -p %s"

# List running sandboxes
agent-sandbox ps

# Stop a sandbox
agent-sandbox stop <name-or-id>

# View logs
agent-sandbox logs -f <name-or-id>

# Clean up everything
agent-sandbox rm --all
agent-sandbox sessions rm --all
```

---

## Further Reading

- [DESIGN.md](DESIGN.md) — Architecture, threat model, design decisions
- [examples/](../examples/) — Ready-to-use config examples
