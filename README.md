# agent-sandbox

Docker-based sandbox for [opencode](https://opencode.ai) agents. Each sandbox runs in an isolated container with its own network firewall, so agents can't reach the host or external services unless you explicitly allow it.

```
opencode attach http://127.0.0.1:49312
```

## Installation

```bash
go install github.com/preved911/agent-sandbox/cmd/agent-sandbox@latest
```

## Quick start

Create `agent-sandbox.yaml` in your project:

```yaml
profiles:
  default:
    build:
      dockerfile: ./Dockerfile
      context: .
    run:
      mounts:
        - source: $PWD
          target: /workspace
      workdir: /workspace
      port:
        bind: 127.0.0.1
```

Then run:

```bash
agent-sandbox run -e ANTHROPIC_API_KEY=sk-ant-...
```

The command builds the image, creates the sandbox (agent container + firewall + network), and prints the attach URL.

## Architecture

Each sandbox consists of 3 Docker resources:

| Resource | Purpose |
|----------|---------|
| **Agent container** | Runs opencode CLI with your project mounted |
| **Firewall container** | Runs nftables + CoreDNS; all network flows through it |
| **Sessions volume** | Durable opencode session data (survives container removal) |

The agent container's DNS is pointed at the firewall, which enforces network rules (CIDR allow/deny, domain allow/deny) and forwards allowed traffic.

## Commands

| Command | Description |
|---------|-------------|
| `run` | Create (if needed), start, and attach to a sandbox |
| `create` | Create sandbox resources without starting or attaching |
| `start` | Start a stopped sandbox |
| `stop` | Stop a running sandbox |
| `build` | Build the sandbox image without creating a container |
| `ps` | List sandbox containers (`-a` to include stopped/failed) |
| `rm` | Remove sandbox containers by name/ID, or `--all` |
| `logs` | Stream container logs (`-f` to follow) |
| `sessions ps` | List sandbox session volumes |
| `sessions rm` | Remove session volumes (`--all` for all) |
| `config` | Print resolved config as YAML |

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | `-c` | Config file path |
| `--profile` | `-p` | Profile to use |

## Run flags

| Flag | Short | Description |
|------|-------|-------------|
| `--env KEY=VALUE` | `-e` | Set or override an env var; repeatable |
| `--mount source:target[:ro]` | `-v` | Append a mount; repeatable |
| `--bind IP` | | Override `run.port.bind` |
| `--no-build` | | Skip the build step |

## Config file

The tool looks for config in order:

1. Path given by `-c`
2. `./agent-sandbox.yaml`
3. `$XDG_CONFIG_HOME/agent-sandbox/config.yaml`

```yaml
docker:
  macos:
    shared_paths_check: true   # validate Docker Desktop shared paths (macOS)

default_profile: go-dev

profiles:
  go-dev:
    build:
      dockerfile: ./Dockerfile
      context: .

    run:
      env:
        OPENCODE_TELEMETRY: "0"
      mounts:
        - source: $PWD
          target: /workspace
        - source: ~/.gitconfig
          target: /root/.gitconfig
          readonly: true
      workdir: /workspace
      port:
        bind: 127.0.0.1

    firewall:
      network:
        default: deny
        cidr:
          allow: [10.0.0.0/8]
          deny: [10.0.0.0/24]
        dns:
          default: allow
          allow: [anthropic.com, "*.anthropic.com"]
          deny: [evil.anthropic.com]
          upstream: [1.1.1.1, 8.8.8.8]
        auto_pin_resolved: true

    reverse_forward:
      ports:
        - host: 3000
          container: 3000
```

### Network rules

Firewall rules use deny-wins semantics: if an address appears in both allow and deny lists, deny wins. Conflict detection logs warnings at config load.

### Reverse forwarding

Forward host services into the sandbox:

```yaml
reverse_forward:
  ports:
    - host: 3000        # host port
      container: 3000   # port inside firewall (agent reaches via firewall IP)
  sockets:
    - socket: /var/run/docker.sock
      container: 2375
```

### Credential forwarding (recipes)

Use existing mount + env mechanisms — no special flags:

```yaml
# SSH agent forwarding
run:
  mounts:
    - source: ${SSH_AUTH_SOCK}
      target: /ssh-agent
      readonly: true
  env:
    SSH_AUTH_SOCK: /ssh-agent

# Git config
run:
  mounts:
    - source: ~/.gitconfig
      target: /root/.gitconfig
      readonly: true
```

### Profile selection

`-p` flag → `default_profile` in config → auto-select if only one profile is defined

### Session persistence

Every sandbox automatically gets a Docker named volume mounted at opencode's default data path. Sessions survive container removal — use `sessions rm` to clean up.

## Examples

Ready-to-use configs are in [`examples/`](examples/):

- [`examples/basic/`](examples/basic/) — single profile with a project-local Dockerfile
- [`examples/profiles/`](examples/profiles/) — multi-profile config for Go and Node.js dev environments

## Requirements

- Go 1.25+
- Docker with BuildKit enabled (Docker 20.10+)
