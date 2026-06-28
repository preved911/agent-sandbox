// Package run creates and starts a sandbox container, then reports the host
// port that Docker assigned to the published container port.
package run

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	"github.com/preved911/opencode-sandbox/internal/config"
	"github.com/preved911/opencode-sandbox/internal/docker"
	"github.com/preved911/opencode-sandbox/internal/paths"
	"github.com/preved911/opencode-sandbox/internal/sandbox"
)

// containerPort is the port opencode serves on inside the container.
const containerPort nat.Port = "4096/tcp"

// opencodeContainerDataDir is the in-container path where opencode stores its
// SQLite database and session data. A Docker named volume is mounted here so
// sessions survive container removal.
const opencodeContainerDataDir = "/data/opencode"

var entrypoint = []string{"opencode"}
var cmd = []string{"serve", "--hostname=0.0.0.0", "--port=4096"}

// Result describes a successfully started sandbox.
type Result struct {
	ContainerID string
	Name        string
	HostPort    int
	Binds       []string // resolved bind specs (source:target[:ro]) passed to the daemon
	Volume      string   // named Docker volume used for session persistence
}

// Start creates and starts a container named name running image.
func Start(ctx context.Context, cli *client.Client, cfg *config.Config, image, name string) (*Result, error) {
	envSlice := make([]string, 0, len(cfg.Run.Env))
	for k, v := range cfg.Run.Env {
		envSlice = append(envSlice, k+"="+v)
	}
	// Force opencode to write its SQLite database and sessions to the
	// persistent Docker volume regardless of its default path.
	envSlice = append(envSlice, "OPENCODE_DATA_DIRECTORY="+opencodeContainerDataDir)

	// Bind mounts use HostConfig.Binds (the "source:target[:ro]" string form
	// used by `docker run -v`) so that Docker Desktop's VirtioFS / gRPC-FUSE
	// path-translation layer is triggered. The structured Mounts field bypasses
	// that layer and causes "path does not exist" on macOS.
	// Non-bind mounts (volume, tmpfs) continue to use HostConfig.Mounts.
	binds, otherMounts, err := buildMounts(cfg)
	if err != nil {
		return nil, err
	}

	// Every sandbox gets a named volume for opencode session data.
	// Docker creates the volume automatically if it does not exist, and
	// reuses it on subsequent runs. The volume is NOT removed when the
	// container is removed.
	volumeName := cfg.Name + "-sessions"
	otherMounts = append(otherMounts, mount.Mount{
		Type:   mount.TypeVolume,
		Source: volumeName,
		Target: opencodeContainerDataDir,
	})

	bindIP := cfg.Run.Port.Bind
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}

	cConf := &container.Config{
		Image:      image,
		Entrypoint: entrypoint,
		Cmd:        cmd,
		Env:        envSlice,
		WorkingDir:   cfg.Run.Workdir,
		User:         cfg.Run.User,
		ExposedPorts: nat.PortSet{containerPort: struct{}{}},
		Labels: map[string]string{
			sandbox.Label:     "true",
			sandbox.LabelName: cfg.Name,
		},
	}
	hConf := &container.HostConfig{
		Binds:  binds,
		Mounts: otherMounts,
		PortBindings: nat.PortMap{
			containerPort: []nat.PortBinding{{HostIP: bindIP, HostPort: "0"}},
		},
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
	}

	created, err := cli.ContainerCreate(ctx, cConf, hConf, nil, nil, name)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	if err := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		_ = cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("start container: %w", err)
	}

	inspect, err := cli.ContainerInspect(ctx, created.ID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	if inspect.NetworkSettings == nil {
		return nil, fmt.Errorf("container has no network settings yet")
	}
	bindings := inspect.NetworkSettings.Ports[containerPort]
	if len(bindings) == 0 || bindings[0].HostPort == "" {
		return nil, fmt.Errorf("container did not publish %s", containerPort)
	}
	port, err := strconv.Atoi(bindings[0].HostPort)
	if err != nil {
		return nil, fmt.Errorf("parse host port %q: %w", bindings[0].HostPort, err)
	}

	// Use the actual name assigned by Docker (strips the leading "/").
	actualName := strings.TrimPrefix(inspect.Name, "/")

	return &Result{
		ContainerID: created.ID,
		Name:        actualName,
		HostPort:    port,
		Binds:       binds,
		Volume:      volumeName,
	}, nil
}

// buildMounts splits config mounts into bind strings (HostConfig.Binds) and
// structured mounts (HostConfig.Mounts for volume/tmpfs).
func buildMounts(cfg *config.Config) (binds []string, mounts []mount.Mount, err error) {
	remote := docker.IsRemoteHost(cfg.DockerHost)

	for i, m := range cfg.Run.Mounts {
		if m.Target == "" {
			return nil, nil, fmt.Errorf("mount %d: target is required", i)
		}

		switch m.Type {
		case "", "bind":
			if m.Source == "" {
				return nil, nil, fmt.Errorf("mount %d: bind source is required", i)
			}

			var src string
			if remote {
				// Remote daemon: expand env vars but require an absolute path — relative
				// paths and ~ have no meaning on a remote host.
				src = os.ExpandEnv(m.Source)
				if src == "" {
					return nil, nil, fmt.Errorf("mount %d: source expanded to empty string (unset variable?)", i)
				}
				if !strings.HasPrefix(src, "/") {
					return nil, nil, fmt.Errorf("mount %d: remote bind source %q must be an absolute path", i, m.Source)
				}
			} else {
				src, err = paths.Expand(m.Source, cfg.BaseDir())
				if err != nil {
					return nil, nil, fmt.Errorf("mount %d source: %w", i, err)
				}
				if cfg.DockerMacOS && runtime.GOOS == "darwin" {
					if _, err := os.Stat(src); err != nil {
						return nil, nil, fmt.Errorf("mount %d: source path %s does not exist on the macOS host", i, src)
					}
				}
			}

			spec := src + ":" + m.Target
			if m.ReadOnly {
				spec += ":ro"
			}
			binds = append(binds, spec)

		case "volume":
			mm := mount.Mount{
				Type:     mount.TypeVolume,
				Source:   m.Source,
				Target:   m.Target,
				ReadOnly: m.ReadOnly,
			}
			mounts = append(mounts, mm)

		case "tmpfs":
			mounts = append(mounts, mount.Mount{
				Type:   mount.TypeTmpfs,
				Target: m.Target,
			})

		default:
			return nil, nil, fmt.Errorf("mount %d: unknown type %q", i, m.Type)
		}
	}
	return binds, mounts, nil
}
