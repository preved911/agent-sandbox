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
10. **Reverse forwarding from host to container.** The config may declare port-to-port and socket-to-port maps that make host-side services (a local dev server, the Docker API, a database) reachable from inside the container network. The firewall container bridges these connections from the isolated network to the host.

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

## 5. Network Enforcement Model — Allow + Deny, Deny Wins

### Two rule types, both with allow AND deny lists

Both CIDR and DNS rules support **independent allow and deny lists**. This models real-world intent:

- **Allow-only mode** (secure default): start empty, allow specific destinations.
- **Deny-only mode** (permissive): start with broad allow, deny specific destinations.
- **Mixed mode** (common): allow a broad range, deny a subset.

**Deny always wins.** If a destination matches both an allow and a deny rule, the deny rule takes precedence — regardless of specificity or order. This is enforced by rule evaluation ordering (deny rules checked first).

### CIDR enforcement (nftables, IP layer)

```
nftables FORWARD chain (deny-first ordering):

  1. established/related  → accept     (return traffic for allowed connections)
  2. DENY CIDR rules      → drop       (checked BEFORE allow — deny wins)
  3. ALLOW CIDR rules     → accept
  4. auto_pin IPs         → accept     (resolved IPs of allowlisted domains)
  5. default policy       → drop/accept (per config: default deny or allow)
```

A packet hitting a deny CIDR is dropped at step 2, before any allow rule at step 3 can match. This gives unconditional deny-wins semantics.

### DNS enforcement (CoreDNS, resolution layer)

```
CoreDNS query resolution:

  1. DENY domains    → immediate NXDOMAIN     (deny wins)
  2. ALLOW domains   → forward to upstream resolvers
  3. default policy  → NXDOMAIN (deny mode) or pass-through (allow mode)
```

Same deny-first logic. A domain on the deny list never resolves, even if it also matches an allow wildcard (e.g., `*.anthropic.com` allowed, `evil.anthropic.com` denied → evil gets NXDOMAIN).

### Conflict detection

At **config load time**, the wrapper validates rules and logs warnings:

| Scenario | Action |
|---|---|
| Same CIDR in both allow and deny | **Warning:** `"Conflict: <cidr> appears in both allow and deny — deny takes precedence"` |
| Overlapping CIDRs (allow ⊃ deny) | **Warning:** `"Conflict: deny <deny-cidr> is a subset of allow <allow-cidr> — deny wins for the overlap"` |
| Same domain in both allow and deny | **Warning:** `"Conflict: <domain> in both allow and deny — deny takes precedence"` |
| Allow wildcard + specific deny (e.g. `*.anthropic.com` allowed, `evil.anthropic.com` denied) | **Info** (not a conflict — intentional narrowing) |

### auto_pin_resolved

When `auto_pin_resolved: true` (default on), DNS-allowed domains have their resolved IPs automatically allowed in nftables — so adding a domain to the DNS allow list "just works" without also whitelisting its CIDR range. Resolved IPs are checked against the deny CIDR list first; if they fall in a deny range, the connection is blocked and a warning is logged.

For a domain to be fully reachable: its name must be DNS-allowed (or default=allow) **AND** its resolved IP must not be in any deny CIDR **AND** (its IP is in an allow CIDR, OR auto_pin is on, OR default=allow).

| Threat | Caught by |
|---|---|
| Agent calls a denied domain | DNS → NXDOMAIN |
| Agent calls a domain not in allow list (default=deny) | DNS → NXDOMAIN |
| Agent calls an allowed domain | DNS resolves → nftables allows (CIDR/auto-pin/default) |
| Agent calls a denied IP | nftables drops (deny rule checked first) |
| Agent calls a hardcoded IP not in any allow CIDR (default=deny) | nftables drops |
| Agent exfils over raw TCP to a blocked host | nftables drops (no proxy-env bypass possible) |

---

## 6. Sandbox Identity & Naming

A sandbox is **bound to a directory**. The same absolute directory always maps to the same sandbox.

### Path → name algorithm

Docker enforces a **63-character limit** on container and volume names (DNS label spec). The prefix `opencode-sandbox-` alone consumes 18 characters, leaving only 45 for the path-derived part. Long filesystem paths (common on macOS: `/Users/bob/Documents/Developer/...`) would blow this budget immediately if converted naively.

The naming scheme uses **basename + short hash** — readable, collision-safe, and guaranteed within limits:

```
input:   host absolute cwd, e.g. /Users/bob/projects/myapp

step 1:  basename = last path component → "myapp"
         (fallback: "root" if cwd is "/")
step 2:  hash      = SHA-256(abspath)[:8] → "a1b2c3d4"
step 3:  name      = "opencode-sandbox-" + basename + "-" + hash

output:  opencode-sandbox-myapp-a1b2c3d4   (36 chars — well within 63)
```

**Budget enforcement:** `18 (prefix) + len(basename) + 1 (dash) + 8 (hash) = 27 + len(basename)`. If `basename` exceeds 36 chars, truncate from the left to fit (preserving the hash for uniqueness). Worst case: `opencode-sandbox-<36chars>-<8hash>` = exactly 63 chars.

**Why basename, not full path?** The last directory component is what the user recognizes in `ps` output ("myapp", "client-portal-v2"). The full absolute path is stored in **labels** for lookup and display — the name is just a human handle. Two different paths with the same basename are differentiated by the hash.

- **Labels (the real identity):** every resource carries:
  - `opencode-sandbox=true` (existing invariant)
  - `opencode-sandbox-path=<absolute-host-cwd>` (full path for `ps` display + discovery)
  - `opencode-sandbox-role=agent|firewall`
- `ps`/`rm`/`logs` discover resources by these labels, not by parsing names.

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

opencode stores sessions under its default data directory. To keep sessions durable but **scoped per-sandbox-path** (different projects don't share sessions), the data dir is a **named volume** rather than a bind mount:

- Volume name: `opencode-sandbox-<name>-sessions`
- Mounted at **opencode's default data path** inside the container — not configurable. The wrapper uses whatever path opencode uses by default (currently `/root/.local/share/opencode` for root in the container). Less configuration burden, no surprises.
- Survives `rm`; cleaned only via `clean-sessions`

### Configurable mounts (from profile)

User-defined mounts in the profile's `run.mounts` are applied on top, with Docker-native semantics (`source`, `target`, `readonly`). SSH agent forwarding and `.gitconfig` mounts are documented as recipes (§11), not hard-coded.

---

## 8. Host Config Inheritance & Permission Override

The sandboxed opencode should behave like the host opencode, with the container providing isolation instead of permission dialogs.

### Inheritance (read-only from host)

- `~/.config/opencode/opencode.json` → global config (models, providers, defaults)
- `~/.config/opencode/auth.json` → API keys / auth tokens
- `~/.config/opencode/agent(s)/` → agent definitions
- `~/.config/opencode/skill(s)/` → user skills
- Project `<cwd>/.opencode/` and `<cwd>/opencode.json` → project-level config, agents, skills, commands

All mounted **read-only** so the sandbox cannot mutate host settings.

### Permission override — the key design decision

**The entire point of the sandbox is to eliminate approve dialogs.** Inside the container, the user wants frictionless operation — `"*": "allow"` for all tools — because the container itself is the security boundary. The host's carefully-tuned permission rules (which exist to protect the *host*) are irrelevant inside the sandbox and should not produce dialogs.

**Problem:** opencode's `OPENCODE_CONFIG_CONTENT` uses **deep-merge**. If the host has `permission: {"bash": {"git *": "allow", "rm *": "deny", "*": "ask"}}` and the sandbox injects `permission: {"bash": {"*": "allow"}}`, the merge combines them — the host's `"rm *": "deny"` survives and could still trigger behavior the user doesn't want inside the sandbox.

**Solution:** When the merge type changes (object → string), opencode replaces the value entirely. Injecting `{"permission": "allow"}` (a string) replaces the host's permission **object** with the string shorthand `"allow"` — which is opencode's built-in "allow everything" sentinel. The host's detailed rules disappear completely inside the sandbox.

The sandbox profile controls this behavior:

```yaml
permissions:
  mode: override              # default — REPLACES host permission block entirely
  rules:
    default: allow            # base: allow everything (no dialogs inside sandbox)
    overrides:
      bash:
        "rm -rf /": deny      # optional: add specific denials even inside sandbox
```

**Two modes:**

| Mode | Behavior | Use case |
|---|---|---|
| `override` (default) | Sandbox generates a **complete** permission block from the profile. Host's permission rules are invisible inside the container. | Normal use — container is the boundary, allow everything, no dialogs |
| `merge` | Host's permission rules survive; sandbox adds/restricts on top via deep-merge | You want host restrictions (e.g., `edit: deny`) to also apply inside the sandbox |

**Default profile behavior:** `mode: override`, `rules.default: allow` → injects `{"permission": "allow"}` → zero dialogs inside the sandbox.

### Other overrides (injected, not mounted)

Beyond permissions, sandbox-specific overrides are injected via `OPENCODE_CONFIG_CONTENT`:

- `experimental`: sandbox-specific experiments
- Model/provider overrides if the sandbox should use a different model than the host

**Merge order:** host global → host project → `OPENCODE_CONFIG_CONTENT` (sandbox overrides win). No files are generated or mutated on the host.

---

## 9. Port Forwarding & Host Service Forwarding

### 9.1 Outbound: container → host (publishing the agent port)

opencode runs as a `serve` process inside the agent container, listening on `0.0.0.0:4096` (configurable).

- The wrapper publishes the port to the host: `<bind>:<random>` → `0.0.0.0:4096`.
- **Default bind:** `127.0.0.1` (loopback only — safest; only the local user can attach).
- **Configurable bind:** `0.0.0.0`, a specific interface IP, or any address (for LAN/remote-attach scenarios). Set via `run.port.bind` or the `--bind` flag.
- **Host port:** randomly allocated by Docker from the ephemeral range (avoids collisions across multiple sandboxes).
- The wrapper records the allocated host port in container labels and uses it to print/run the attach command.

**Remote Docker host support is removed** — there is no `docker.host` config and no `--docker-host` flag. The wrapper talks to the local daemon only.

### 9.2 Reverse forwarding: host → container (making host services reachable inside)

The agent inside the container often needs to reach services running on the host — a local dev server, a database, the Docker API, or any host-bound process. Because the agent container is on an **isolated network with no direct host access**, these services are made reachable through the **firewall container**, which is the sole bridge between the isolated network and the outside.

**Config schema:**

```yaml
run:
  reverse_forward:
    ports:
      - host: 3000            # TCP port on the host
        container: 3000       # reachable at <firewall-ip>:3000 from the agent
      - host: 5432
        container: 15432      # can map to a different container-side port
    sockets:
      - socket: /var/run/docker.sock   # host Unix socket
        container: 2375                # reachable at <firewall-ip>:2375 (TCP)
```

**Port-to-port mechanism:**

The firewall container runs a forwarder process (e.g. `socat`) for each entry:

- Listens on `<firewall-isolated-ip>:<container_port>` (the isolated-network interface only)
- Connects to `host.docker.internal:<host_port>` (Docker Desktop) or `<host-gateway-ip>:<host_port>` (Linux)
- The agent reaches the host service by connecting to `<firewall-ip>:<container_port>`

The firewall's isolated-network IP is deterministic (it's the gateway of the isolated bridge). The wrapper injects it into the agent container's `/etc/hosts` or environment so the agent can reference it by a stable name.

**Socket-to-port mechanism (platform-dependent):**

| Host OS | Approach |
|---|---|
| **Linux** | Bind-mount the host Unix socket into the firewall container. Run `socat TCP-LISTEN:<container_port>,bind=<isolated-ip> UNIX-CONNECT:<socket_path>` inside the firewall container. |
| **macOS — Docker socket** (`/var/run/docker.sock`) | Docker Desktop auto-proxies this socket across the VM boundary. Bind-mount + socat works identically to Linux. |
| **macOS — other host Unix sockets** | The socket lives on the Mac host, **outside** the Linux VM — it cannot be bind-mounted directly. The wrapper starts a **host-side** forwarder (e.g. `socat UNIX-CONNECT:<socket> TCP-LISTEN:<port>`) on the Mac, bridging the socket to a TCP port on `localhost`. The firewall container then forwards from the isolated network to `host.docker.internal:<that_port>`. The wrapper manages the host-side process lifecycle (start on `create`, stop on `rm`). |

**Implicit firewall rules:** When reverse_forward entries are configured, the wrapper **automatically generates nftables OUTPUT rules** in the firewall container allowing outbound connections to the host gateway (`host.docker.internal` on Docker Desktop, `host-gateway` IP on Linux) **on exactly the specified host ports** — no manual CIDR/DNS config needed. Each `host: <port>` entry produces one rule: `allow output to <host-gateway-ip>:<port>`. Socket entries that require a host-side bridge (macOS non-Docker sockets) similarly auto-allow the bridge port. The user should never have to also add `host.docker.internal` to a firewall allow list — declaring a reverse forward is sufficient.

**Security note:** Reverse-forwarded ports **bypass the agent-facing CIDR/DNS firewall rules** (§5) by design — the user explicitly configured these tunnels. Traffic to forwarded ports is destined to the firewall container itself (local INPUT chain), not forwarded through nftables (FORWARD chain). The auto-allowed OUTPUT rules are scoped to the **exact host ports** in the config — the rest of the host remains unreachable. The general internet filtering still applies to all other traffic from the agent container.

**Lifecycle:** reverse-forward processes start when the firewall container starts and stop when it stops. The host-side helper (macOS socket case only) is managed by the wrapper and tied to the sandbox lifecycle.

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
      reverse_forward:
        ports:
          - host: 3000          # local dev server on host
            container: 3000
          - host: 5432          # local postgres
            container: 15432
        sockets:
          - socket: /var/run/docker.sock  # Docker API
            container: 2375

    firewall:
      network:
        default: deny            # default policy: deny (secure) or allow (permissive)
        cidr:
          allow:
            - 10.0.0.0/8
            - 151.101.0.0/16      # fastly CDN
          deny:
            - 10.0.0.0/24         # a sensitive subnet inside the allowed /8
        auto_pin_resolved: true
        dns:
          default: deny           # default DNS policy: deny (NXDOMAIN) or allow (pass-through)
          allow:
            - anthropic.com
            - "*.anthropic.com"
            - github.com
            - proxy.golang.org
          deny:
            - evil.anthropic.com  # narrow exception under the wildcard allow
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
    # Default IP-layer policy when no allow/deny rule matches.
    #   deny  (default, secure) — drop everything not explicitly allowed
    #   allow (permissive)      — allow everything not explicitly denied
    default: deny
    cidr:
      allow:                  # CIDRs reachable at the IP layer
        - 10.0.0.0/8
        - 151.101.0.0/16      # fastly CDN
      deny:                   # always drops, wins over allow regardless of specificity
        - 10.0.0.0/24         # sensitive subnet inside the allowed /8
    auto_pin_resolved: true   # DNS-allowed domain → auto-allow its resolved IPs in nftables
    dns:
      # Default DNS policy when no allow/deny rule matches.
      #   deny  (default) — NXDOMAIN for everything not explicitly allowed
      #   allow           — pass-through to upstream for everything not explicitly denied
      default: deny
      allow:                  # domains that resolve (forwarded to upstream)
        - anthropic.com
        - "*.anthropic.com"
      deny:                   # always NXDOMAIN, wins over allow (even wildcard matches)
        - evil.anthropic.com
      upstream:               # resolvers the firewall forwards allowlisted queries to
        - 1.1.1.1
        - 8.8.8.8
```

**Enforcement layers (inside the firewall container):**

1. **CoreDNS** with a generated zone config:
   - deny domains → immediate `NXDOMAIN` (**checked first — deny wins**)
   - allow domains → forward to `upstream`
   - default policy: `NXDOMAIN` (deny mode) or pass-through to `upstream` (allow mode)
2. **nftables** with deny-first FORWARD chain ordering (see §5):
   - allow established/related (return traffic for permitted connections)
   - **deny CIDR rules → drop** (checked **before** allow — deny wins)
   - allow CIDR rules → accept
   - auto_pin resolved IPs → accept (checked against deny list first; overlap → drop + warn)
   - default policy → drop (deny mode) or accept (allow mode)
   - DNS (UDP/53) to upstream resolvers always allowed so allowlisted domains can resolve
3. **Agent container** `/etc/resolv.conf` = firewall IP; default route = firewall IP. The agent has no direct path to the host bridge or internet.

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

1. **SSH / git-credentials forwarding** — offer documented recipes vs. special-cased flags. Leaning toward recipes (mount `SSH_AUTH_SOCK`, `.gitconfig`).
2. **opencode version pinning in the agent image** — how the image selects/pins the opencode binary (build arg? latest? pinned in Dockerfile?). Needs a recommendation.
3. **macOS bind-mount path sharing** — Docker Desktop / Colima require the host path to be in the shared-paths list. The existing `docker.macos` validation flag should be retained/extended.

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
