# opencode-sandbox

Builds and runs isolated Docker containers that expose an [opencode](https://opencode.ai) `serve` endpoint, so you can attach a local opencode client to a sandboxed run.

```
opencode attach http://127.0.0.1:49312
```

## Installation

```bash
go install github.com/preved911/opencode-sandbox/cmd/opencode-sandbox@latest
```

## Quick start

Create `opencode-sandbox.yaml` in your project:

```yaml
default_profile: default

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
opencode-sandbox run -e ANTHROPIC_API_KEY=sk-ant-...
```

The command builds the image, starts the container, and prints the attach URL.

## Commands

| Command | Description |
|---------|-------------|
| `run` | Build (unless `--no-build`) and start a sandbox, print the attach URL |
| `build` | Build the sandbox image without starting a container |
| `ps` | List sandbox containers (`-a` to include stopped/failed) |
| `rm` | Remove sandbox containers by name/ID, or `--all` |

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | `-c` | Config file path |
| `--profile` | `-p` | Profile to use |
| `--docker-host` | `-H` | Docker daemon to connect to |

## Run flags

| Flag | Short | Description |
|------|-------|-------------|
| `--env KEY=VALUE` | `-e` | Set or override an env var; repeatable |
| `--mount source:target[:ro]` | `-v` | Append a mount; repeatable |
| `--bind IP` | | Override `run.port.bind` |
| `--name` | | Override the container name |
| `--no-build` | | Skip the build step |
| `--pull` | | Pass `--pull` to `docker build` |

## Config file

Config files are always profiles-based. The tool looks for the config file in order:

1. Path given by `-c`
2. `./opencode-sandbox.yaml`
3. `$XDG_CONFIG_HOME/opencode-sandbox/config.yaml` (default: `~/.config/opencode-sandbox/config.yaml`)

```yaml
docker:
  host: tcp://build-box:2375   # global docker host; applies to all profiles

default_profile: go-dev        # used when -p is omitted

profiles:
  go-dev:
    docker:
      host: tcp://other-box:2375   # overrides global docker.host for this profile
      attach_host: build-box       # hostname used in the printed attach URL

    build:
      dockerfile: ./Dockerfile
      context: .
      target: dev              # optional BuildKit target
      args:
        VERSION: latest
      pull: false
      secrets:
        - id: api-key
          env: ANTHROPIC_API_KEY   # or src: /path/to/file

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
      user: "1000"
      port:
        bind: 127.0.0.1
```

### Docker host precedence

`--docker-host` flag → profile `docker.host` → global `docker.host` → `DOCKER_HOST` env var → active Docker CLI context → SDK default

### Bind mount sources and remote hosts

When `docker.host` is a TCP or SSH endpoint, bind mount sources are passed to the daemon **as-is** — no local `~` or `$VAR` expansion is performed. Use absolute paths that exist on the remote machine:

```yaml
run:
  mounts:
    - source: /Users/remote-user/workspace   # absolute path on the remote host
      target: /workspace
```

For local daemons (Unix socket or no explicit host) paths are expanded locally: `~`, `$VAR`, and relative paths resolve against the config file's directory.

### Profile selection

`-p` flag → `default_profile` in config → auto-select if only one profile is defined

### Session persistence

Every sandbox automatically gets a Docker named volume (e.g. `go-dev-sessions`) mounted at `/data/opencode` inside the container. The `OPENCODE_DATA_DIRECTORY` environment variable is set automatically so opencode writes its SQLite database and conversation history there.

- The volume is created automatically on the first run.
- It is reused when you recreate the sandbox.
- It is **not** deleted by `opencode-sandbox rm` — sessions survive container removal.

## Examples

Ready-to-use configs are in [`examples/`](examples/):

- [`examples/basic/`](examples/basic/) — single profile with a project-local Dockerfile
- [`examples/profiles/`](examples/profiles/) — multi-profile config for Go and Node.js dev environments, suitable for `~/.config/opencode-sandbox/config.yaml`

## Requirements

- Go 1.25+
- Docker with BuildKit enabled (Docker 20.10+)
