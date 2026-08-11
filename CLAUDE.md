# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when writing code in this repository.

## Commands

```bash
# Build the binary
go build ./cmd/opencode-sandbox/

# Build and verify all packages compile
go build ./...

# Run a specific test
go test ./internal/config/...

# Run all tests
go test ./...
```

There is no Makefile. The binary entry point is `cmd/opencode-sandbox/main.go`.

## Architecture

The tool creates isolated Docker sandboxes for opencode agents. Each sandbox has 3 resources: an agent container, a firewall container (nftables + CoreDNS), and a sessions volume.

### Package layout

- `cmd/opencode-sandbox/main.go` — Entry point, signal handling
- `internal/cli/` — Cobra commands: root, run, build, create, start, stop, logs, ps, rm, sessions (ps/rm), config
- `internal/config/` — Config loading, types, validation
  - `config.go` — Profile-based config loader (explicit path → ./opencode-sandbox.yaml → $XDG_CONFIG_HOME)
  - `firewall.go` — NetworkConfig, CIDRRules, DNSRules types
  - `forward.go` — ReverseForwardConfig (ports + sockets)
  - `validation.go` — CIDR parsing, conflict detection, port validation
- `internal/sandbox/` — Naming (hash-based), labels, constants
  - `HashPath(absPath) → 8 hex chars` — deterministic sandbox identity
  - `ResourceName(hash, suffix) → opencode-sandbox-<hash>-<suffix>`
- `internal/docker/` — Docker SDK client wrapper (`NewClient`)
- `internal/run/` — Agent container creation + start on isolated network
- `internal/build/` — Docker image build (shells out to `docker build`)
- `internal/network/` — Isolated bridge network create/remove/exists
- `internal/stack/` — Stack orchestration (create/start/stop/remove all resources)
- `internal/preflight/` — macOS shared-paths validation (Docker Desktop settings)
- `firewall/` — Firewall Docker image (Dockerfile, entrypoint.sh, Go generators)
  - `nftables.go` — deny-before-allow nftables rule generation
  - `coredns.go` — CoreDNS config generation
  - `forward.go` — socat reverse forwarders + implicit OUTPUT rules
  - `firewall.go` — FirewallEnv() generates container env vars from config

### Key design decisions

- **Naming:** hash-only (`opencode-sandbox-<hash>-<suffix>`), SHA-256[:8] of absolute cwd path
- **3 resources per sandbox:** agent container + firewall container + sessions volume
- **Network isolation:** agent DNS → firewall; nftables enforces CIDR/DNS rules; deny wins
- **Reverse forwarding:** socat in firewall, implicit nftables OUTPUT rules auto-generated
- **Config loading:** profiles-based, deep-merge (project overrides global)

### Config schema (YAML)

```yaml
docker:
  macos:
    shared_paths_check: true

profiles:
  <name>:
    build:
      dockerfile: string
      context: string
      args: {KEY: "${ENV_VAR}"}  # env vars expanded from host shell
    run:
      env: map[string]string
      mounts: [{source, target, readonly?}]
      workdir: string
      port: {bind: string}
      reverse_forward:
        ports: [{host: int, container: int}]
        sockets: [{socket: string, container: int}]
    firewall:
      network:
        default: "deny" | "allow"
        cidr: {allow: [string], deny: [string]}
        dns:
          default: "deny" | "allow"
          allow: [string]
          deny: [string]
          upstream: [string]
        auto_pin_resolved: bool
    reverse_forward:
      ports: [{host: int, container: int}]
      sockets: [{socket: string, container: int}]
```

### Docker SDK v27.3.1 gotchas

- `ContainerInspect` returns `types.ContainerJSON` (from `github.com/docker/docker/api/types`), NOT `container.InspectResponse`
- `ContainerStop` takes `container.StopOptions{Timeout: *int}` — must convert `time.Duration` to `int` seconds
- `container.StartOptions` is `{}` (no fields needed for basic start)
- Network filter: `filters.NewArgs(filters.Arg("name", name))`
- DNS goes in `container.HostConfig.DNS []string`, NOT in `network.EndpointSettings.DNS`
- Port map keys are `nat.Port` type (e.g. `nat.Port("4096/tcp")`)

### Issue closure policy

Issues should ONLY be closed when the PR is merged to main. Do NOT close issues when pushing to a PR branch.
