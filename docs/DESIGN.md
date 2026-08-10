# opencode-sandbox — Design Document

**Status:** Draft
**Date:** 2026-08-10
**Scope:** Target architecture for the sandbox evolution. Aligned to the founding requirements (see §1).

---

## 1. Problem Statement & Requirements

We run [opencode](https://opencode.ai) and its agents inside an isolated environment where:

- **Filesystem access** is contained to the project directory plus explicitly shared paths.
- **Network access** is restricted to an allowlist of **CIDR ranges** and **DNS names**.
- **Spawning a sandbox is trivial** — one command, zero per-sandbox ceremony, bound to the directory you're in.
- **Security is enforced at the OS/container level**, not via in-app permission dialogs that interrupt flow.

The existing tool already builds and runs a Docker container exposing an opencode `serve` endpoint, with profile-based config and durable session volumes. This document specifies the evolution to a **multi-container sandbox with a network firewall, path-bound identity, and host-config inheritance**.

### Founding requirements (verbatim intent)

1. **Wrapper manages the sandbox environment.** Users call it as a command to create a new sandbox.
2. **Config describes sandbox defaults:** allowed/denied network rules (subnet CIDRs + DNS records), sandbox env vars, sandbox mount points (Docker-native, with read-only or read-write permissions), and container-specific things (Dockerfile, configs).
3. **A mount of the current directory with full permissions is always present**, so opencode keeps its directory-scoped behavior (shared sessions, etc.). Inside the container, opencode runs in this directory and **the container `./` path matches the host `./` path**.
4. **Sandboxes are bound to the path from which they were created** — deterministic logic converts the sandbox's directory path to its name.
5. **The tool provides a full list of subcommands** to manage sandboxes on the host.
6. **Remote Docker host support is removed.** The only host-side networking concern that remains is the **published port bind address** — default `127.0.0.1:<random> -> 0.0.0.0:4096`, configurable to `0.0.0.0:<random>` or any listed address.
7. **Each sandbox is three resources:** one Docker **volume** with opencode sessions (durable, survives container recreation, cleanup via a dedicated subcommand), one Docker **container with the agents** (opencode CLI or alternatives), and one Docker **container with the firewall** (all network communication flows through it, per the network rules).
8. **opencode config and auth are taken from the host** and merged with overrides (the `permission` block at minimum). The same applies to skills and other user-side settings.
9. **A `run` command creates (if absent) and attaches** to the sandbox. The attach step runs the equivalent of `opencode attach http://127.0.0.1:<port>` by default.

---

## 2. Goals

- **One-command sandboxing:** `opencode-sandbox run` from any project directory creates-or-attaches the sandbox bound to that path.
- **Egress firewall:** all outbound traffic routes through a dedicated firewall container enforcing CIDR + DNS allowlists.
- **Host inheritance:** opencode config, auth, agents, and skills flow from the host into the sandbox, merged with sandbox-specific overrides.
- **Durable, per-path sessions:** conversation history survives container recreation via a named volume scoped to the sandbox.
- **Cross-platform:** identical behavior on macOS and Linux via Docker.
- **Secure by default, zero-config capable:** a default profile exists so a sandbox runs with no `opencode-sandbox.yaml`; a fresh sandbox has **no egress** until you allow it.

## 3. Non-Goals

- **Remote Docker hosts** — dropped. The wrapper assumes a local daemon (Docker Desktop, Colima, OrbStack, or native Linux `dockerd`).
- **Per-agent isolation** — all agents within one project share one sandbox. (opencode subagents are in-process; per-agent OS isolation is out of scope and not needed for host containment.)
- **In-app permission approval** — explicitly avoided; isolation is container-level.
- **Nested sandboxes** — not supported.
- **Windows** — out of scope (macOS + Linux only).

---

## 4. Architecture Overview

Each sandbox is a **stack of three Docker resources** managed as a unit:

```
┌─ Docker Volume ──────────────────────────────────────────────┐
│  opencode-sandbox-<slug>-sessions                            │
│  mounted at the opencode data directory inside the container │
│  DURABLE: survives container recreation & `rm`               │
│  CLEANED only via the `clean-sessions` subcommand            │
└──────────────────────────────────────────────────────────────┘
        ▲ mounted by
┌───────┴────────────────────┐      ┌──────────────────────────────┐
│   AGENT CONTAINER           │      │   FIREWALL CONTAINER          │
│  ─────────────────────────  │      │  ──────────────────────────   │
│  • opencode serve :4096     │      │  • CoreDNS resolver           │
│  • <cwd> mounted RW at the  │      │    (domain allowlist)         │
│    SAME absolute host path  │      │  • nftables egress policy     │
│  • host ~/.config/opencode  │      │    (CIDR allowlist)           │
│    mounted RO               │      │  • SOLE egress gateway        │
│  • port fwd to host:        │      │                               │
│    127.0.0.1:<random>       │─────►│   agent ──► firewall ──► net  │
│                             │      │                               │
│  network: opencode-sandbox- │      │  network: opencode-sandbox-   │
│    <slug>-net (isolated,    │      │    <slug>-net (isolated)      │
│    NO direct internet)      │      │   + default bridge (internet) │
└─────────────────────────────┘      └──────────────────────────────┘
        │ host publishes 127.0.0.1:<random> ──► container 0.0.0.0:4096
        ▼
   HOST: opencode attach http://127.0.0.1:<random>
```

**Key principle:** the agent container has **no direct internet access**. Its only network interface is the isolated sandbox bridge, whose gateway is the firewall container. The firewall holds the only bridge to the outside, and it filters.

### Why three resources (not one container)?

| Approach | Problem |
|---|---|
| Single container, iptables inside | Agent needs `NET_ADMIN` (privilege); rules live with the workload; one compromised process disables its own firewall |
| Single container, proxy env vars | Only catches HTTP(S)-aware clients; raw-TCP exfil bypasses; fragile |
| **Agent + firewall containers** | **Separation of concerns; firewall independent of agent; least privilege; agent has no `NET_ADMIN`** |

### Network topology

1. **Isolated bridge network** `opencode-sandbox-<slug>-net` — internal-only; no default gateway to the host bridge.
2. **Firewall container** joins **both** the isolated network **and** Docker's default bridge (which has internet). It enables IP forwarding + SNAT between the two. It runs:
   - **nftables** egress policy: default-deny; allow only configured CIDRs (plus DNS upstream).
   - **CoreDNS** on `<firewall-ip>:53`: allowlisted domains → forward to upstream; everything else → `NXDOMAIN`.
3. **Agent container** joins **only** the isolated network. Its `/etc/resolv.conf` points to the firewall's IP; its default route points to the firewall. It cannot reach the host bridge or internet directly.

### Lifecycle ordering

- The firewall container starts **before** the agent container.
- The agent only starts once the resolver answers a health query.
- `start`/`stop`/`rm` operate on the whole stack (firewall + agent) as a unit; the volume is handled separately (see §10).

---

## 5. CIDR + DNS Enforcement Model

The two rule types are **complementary**, not redundant:

- **DNS allowlist (domain names):** controls *what can be resolved*. A domain not on the list never gets an IP — the connection fails at the DNS step.
- **CIDR allowlist (IP ranges):** controls *what can be reached*. Even a known/hardcoded IP is blocked by nftables unless its range is allowed.

For a domain to be fully reachable, **both** its name must be DNS-allowed **and** its resolved IP must fall within an allowed CIDR. To keep this ergonomic, an **`auto_pin_resolved`** mode (default on) has the resolver dynamically write time-limited nftables allow rules for the IPs of allowlisted domains — so adding a domain to the DNS list "just works" without also whitelisting its CIDR range. CIDR rules remain the escape hatch for static/known ranges (private subnets, package registries, etc.).

| Threat | Caught by |
|---|---|
| Agent calls a non-allowlisted domain | DNS → NXDOMAIN |
| Agent calls an allowlisted domain | DNS resolves → nftables allows (CIDR or auto-pinned IP) |
| Agent calls a hardcoded/raw IP not in a CIDR | nftables blocks |
| Agent exfils over raw TCP to a blocked host | nftables blocks (no proxy-env bypass possible) |

---

## 6. Sandbox Identity & Naming

A sandbox is **bound to a directory**. The same absolute directory always maps to the same sandbox.

### Path → name algorithm

```
input:  host absolute cwd, e.g. /Users/bob/projects/myapp
output: opencode-sandbox-<slug>

slug:   lowercase, replace '/' with '-', strip leading '-'
        /Users/bob/projects/myapp  →  users-bob-projects-myapp
        →  opencode-sandbox-users-bob-projects-myapp
```

- **Collision safety:** if the slug exceeds Docker's 63-char name limit, truncate the middle and append a 12-char SHA-256 suffix of the full path.
- **Labels (not just names):** every resource carries:
  - `opencode-sandbox=true` (existing invariant)
  - `opencode-sandbox-path=<absolute-host-cwd>`
  - `opencode-sandbox-role=agent|firewall`
- This is how `ps`/`rm`/`logs` discover the stack.

### Create-or-attach (`run`) logic

```
on `run` in <cwd>:
  name = slug(<cwd>)
  if sandbox exists and is running  → attach
  if sandbox exists but stopped     → start, then attach
  if absent                          → create (volume + firewall + agent), then attach
```

---

## 7. Filesystem & Mounts

### Mandatory mounts (always present)

| Host path | Container path | Mode | Purpose |
|---|---|---|---|
| `<cwd>` (project dir) | `<cwd>` (identical absolute path) | RW | Project files; opencode runs here so paths match the host 1:1 |
| `~/.config/opencode/` | `~/.config/opencode/` (same) | RO | opencode config, auth, agents, skills |

The **cwd is mounted at its own absolute path** inside the container — not at `/workspace`. This is deliberate: opencode's file operations, session metadata, and user-facing path output then correspond exactly to the host. The container workdir is set to `<cwd>`.

### opencode sessions (durable volume)

opencode stores sessions under its data directory. To keep sessions durable but **scoped per-sandbox-path** (different projects don't share sessions), the data dir is a **named volume** rather than a bind mount:

- Volume name: `opencode-sandbox-<slug>-sessions`
- Mounted at the opencode data path inside the container
- Survives `rm`; cleaned only via `clean-sessions`

### Configurable mounts (from profile)

User-defined mounts in the profile's `run.mounts` are applied on top, with Docker-native semantics (`source`, `target`, `readonly`). SSH agent forwarding and `.gitconfig` mounts are documented as recipes (§11), not hard-coded.

---

## 8. Host Config Inheritance & Overrides

The sandboxed opencode should behave like the host opencode, minus whatever the sandbox restricts.

### Inheritance (read-only from host)

- `~/.config/opencode/opencode.json` → global config (models, providers, defaults)
- `~/.config/opencode/auth.json` → API keys / auth tokens
- `~/.config/opencode/agent(s)/` → agent definitions
- `~/.config/opencode/skill(s)/` → user skills
- Project `<cwd>/.opencode/` and `<cwd>/opencode.json` → project-level config, agents, skills, commands

All mounted **read-only** so the sandbox cannot mutate host settings.

### Overrides (injected, not mounted)

Sandbox-specific overrides are injected via opencode's `OPENCODE_CONFIG_CONTENT` environment variable — opencode deep-merges this inline JSON as the **final local-scope layer**. Typical overrides:

- `permission`: deny rules that tighten the host policy inside the sandbox (required minimum per the spec)
- `experimental`: sandbox-specific experiments

**Merge order:** host global → host project → `OPENCODE_CONFIG_CONTENT` (sandbox overrides win). No files are generated or mutated on the host.

---

## 9. Port Forwarding

opencode runs as a `serve` process inside the agent container, listening on `0.0.0.0:4096` (configurable).

- The wrapper publishes the port to the host: `<bind>:<random>` → `0.0.0.0:4096`.
- **Default bind:** `127.0.0.1` (loopback only — safest; only the local user can attach).
- **Configurable bind:** `0.0.0.0`, a specific interface IP, or any address (for LAN/remote-attach scenarios). Set via `run.port.bind` or the `--bind` flag.
- **Host port:** randomly allocated by Docker from the ephemeral range (avoids collisions across multiple sandboxes).
- The wrapper records the allocated host port in container labels and uses it to print/run the attach command.

**Remote Docker host support is removed** — there is no `docker.host` config and no `--docker-host` flag. The wrapper talks to the local daemon only.

---

## 10. CLI Interface

| Command | Description |
|---|---|
| `run` | **Create-or-attach** (§6). Ensures the sandbox for the cwd exists and is running, then attaches (`opencode attach http://<bind>:<port>`). The primary command. |
| `create` | Create the sandbox stack (volume + firewall + agent) without attaching. |
| `start` | Start a stopped sandbox's containers (keeps volume). |
| `stop` | Stop a sandbox's containers (keeps volume). |
| `attach` | Attach to a running sandbox (run the attach command). |
| `ps` | List sandboxes on this host (filter by `opencode-sandbox=true` label). |
| `logs` | Stream logs from the agent and/or firewall container (`--firewall` to target the firewall). |
| `rm` | Remove a sandbox's containers. Volume retained unless `--purge`. |
| `clean-sessions` | Remove the sessions volume for a sandbox (or all, with `--all`). |
| `config` | Show the resolved config for the cwd's sandbox. |

### Global flags

`-c` (config path), `-p` (profile), `-v` (verbose). **Removed:** `--docker-host`/`-H` (no remote daemon).

### `run` flags

`--env`/`-e`, `--mount`/`-v`, `--bind`, `--name`, `--no-build`, `--pull` — as today. **Added:** `--attach-cmd` to override the default attach command.

---

## 11. Profile & Config Model

Config remains **profiles-based** (`opencode-sandbox.yaml`), resolved in order: `-c` path → `./opencode-sandbox.yaml` → `$XDG_CONFIG_HOME/opencode-sandbox/config.yaml`.

### Changes from current

| Area | Change |
|---|---|
| `docker.host` (global + per-profile) | **Removed** — local daemon only |
| `--docker-host`/`-H` flag | **Removed** |
| Remote bind-mount path passthrough | **Removed** |
| `firewall` section (per profile) | **Added** — network rules (§12) |
| Default profile (zero-config) | **Added** — works with no config file |
| `build`, `run.env`, `run.mounts`, `run.workdir`, `run.port.bind` | Kept |
| Session volume behavior | Kept |
| `opencode-sandbox=true` label invariant | Kept, extended with path + role labels |

### Example full config

```yaml
default_profile: default

profiles:
  default:
    build:
      dockerfile: ./Dockerfile
      context: .

    run:
      env:
        OPENCODE_TELEMETRY: "0"
      mounts:
        - source: ~/.gitconfig
          target: /root/.gitconfig
          readonly: true
      workdir: <cwd>            # set automatically to the host cwd
      port:
        bind: 127.0.0.1         # default; use 0.0.0.0 for LAN access

    firewall:
      network:
        allow_cidr:
          - 10.0.0.0/8
          - 151.101.0.0/16      # fastly CDN
        auto_pin_resolved: true
        dns:
          allow:
            - anthropic.com
            - "*.anthropic.com"
            - github.com
            - proxy.golang.org
          upstream:
            - 1.1.1.1
            - 8.8.8.8
```

### Default profile (zero-config, secure by default)

When no config file is found, the built-in default profile applies:

- Mount cwd RW at its own absolute path
- Mount `~/.config/opencode/` RO
- opencode `serve` on `0.0.0.0:4096`, host bind `127.0.0.1`
- Firewall: **deny all egress** (user must allow domains/CIDRs to enable network)
- Sessions volume at the opencode data path

A fresh sandbox has **no internet until you allow it**.

### Recipes (documented, not hard-coded flags)

- **Git access:** mount `~/.gitconfig` RO + forward `SSH_AUTH_SOCK`.
- **Package registries:** add the registry domain to `firewall.network.dns.allow`.
- **Private registries/subnets:** add CIDRs to `firewall.network.allow_cidr`.

---

## 12. Firewall Configuration Reference

```yaml
firewall:
  network:
    # CIDR egress allowlist. Default DENY; only these ranges are reachable.
    allow_cidr:
      - 10.0.0.0/8
    # When true, DNS-allowed domains have their resolved IPs auto-allowed in
    # nftables (ergonomic). When false, BOTH DNS name + CIDR must match.
    auto_pin_resolved: true
    dns:
      # Domains allowed to resolve. Everything else → NXDOMAIN.
      allow:
        - anthropic.com
        - "*.anthropic.com"
      upstream:        # resolvers the firewall forwards allowlisted queries to
        - 1.1.1.1
        - 8.8.8.8
```

**Enforcement layers (inside the firewall container):**

1. **CoreDNS** with a generated zone config: allowlisted domains → forward to `upstream`; all else → `NXDOMAIN`.
2. **nftables** with a default-deny FORWARD policy:
   - allow established/related (return traffic)
   - allow DNS (UDP/53) to the upstream resolvers
   - allow egress to each `allow_cidr` entry
   - if `auto_pin_resolved`: time-limited allow rules for IPs resolved for allowlisted domains
3. **Agent container** `/etc/resolv.conf` = firewall IP; default route = firewall IP.

---

## 13. Alternatives Considered

| Alternative | Why rejected |
|---|---|
| **macOS Seatbelt** (`sandbox-exec`) | macOS-only; **cannot filter network by CIDR or DNS** (IP filter limited to `*`/`localhost`); requires a proxy overlay anyway; no nested sandboxes; in-process subagents can't be individually jailed |
| **ACP federation** (delegate subagents to jailed `opencode acp` processes) | opencode has no native ACP *client* for subagent delegation; needs a custom plugin; per-agent config registration = friction; complex |
| **Per-call bash wrapping** (`@anthropic-ai/sandbox-runtime` around bash only) | File tools (read/edit/write/patch) bypass bash and hit host FS directly; weakest isolation |
| **Firecracker / microVM** | Needs Linux + KVM; not native on macOS |
| **opencode `experimental.sandbox`** (PR #21538) | macOS-only, experimental, covers bash/PTY only, file tools bypass, not cross-platform |

**Docker wins** because: cross-platform (macOS + Linux); mature network-namespace isolation; CIDR + DNS filtering is straightforward with a gateway container; file isolation is total (the whole process is jailed); and the per-OS complexity is delegated to Docker rather than reimplemented.

---

## 14. Open Questions

1. **opencode data path inside the container** — confirm the exact path opencode uses for its SQLite/session store on the chosen base image, so the sessions volume mounts correctly. (Current code uses `/root/.local/share/opencode`; verify against current opencode.)
2. **`auto_pin_resolved` implementation** — concrete mechanism for the DNS resolver to inject time-limited nftables rules (CoreDNS plugin vs. a sidecar watching resolver logs). Deferred to implementation planning.
3. **SSH / git-credentials forwarding** — offer documented recipes vs. special-cased flags. Leaning toward recipes (mount `SSH_AUTH_SOCK`, `.gitconfig`).
4. **opencode version pinning in the agent image** — how the image selects/pins the opencode binary (build arg? latest? pinned in Dockerfile?). Needs a recommendation.
5. **macOS bind-mount path sharing** — Docker Desktop / Colima require the host path to be in the shared-paths list. The existing `docker.macos` validation flag should be retained/extended.

---

## 15. Migration Notes (from current codebase)

The current codebase already provides: profiles-based config, `run`/`build`/`ps`/`rm`, session volumes, the `opencode-sandbox=true` label invariant, macOS path validation, and `serve`+`attach` flow. The evolution is additive + subtractive:

**Add:**
- Firewall container + isolated network + nftables/CoreDNS enforcement (§4, §5, §12).
- Path-bound sandbox naming + create-or-attach `run` semantics (§6).
- Host config/auth/skills inheritance + `OPENCODE_CONFIG_CONTENT` overrides (§8).
- New subcommands: `create`, `start`, `stop`, `attach`, `logs`, `clean-sessions`, `config` (§10).
- Default profile for zero-config operation (§11).
- Stack-level lifecycle management (firewall + agent as a unit).

**Remove:**
- `docker.host` (global + per-profile), `--docker-host`/`-H` flag, remote bind-mount passthrough.
- Random/profile-based container naming → replaced by path-bound naming.

**Keep:**
- `build` section, `run.env`/`run.mounts`/`run.workdir`/`run.port.bind`.
- Session volume behavior (made per-path via `<slug>-sessions`).
- Label invariant (extended with path + role labels).
- Go + Cobra CLI structure, `internal/{config,cli,sandbox,paths}` package layout.
