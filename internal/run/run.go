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
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/paths"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// Result describes a successfully started sandbox.
type Result struct {
	ContainerID string
	Name        string
	HostPort    int
	Binds       []string // resolved bind specs (source:target[:ro]) passed to the daemon
	Volume      string   // named Docker volume used for session persistence
}

// Create creates a container named name running image without starting it.
// The container is created on the specified network (if any) and can be started later.
func Create(ctx context.Context, cli *client.Client, cfg *config.Config, image, hash string) error {
	containerPort := nat.Port(cfg.Run.Port.Container)

	envSlice := make([]string, 0, len(cfg.Run.Env))
	for k, v := range cfg.Run.Env {
		envSlice = append(envSlice, k+"="+v)
	}

	binds, otherMounts, err := buildMounts(cfg)
	if err != nil {
		return err
	}

	// Mount sessions volume only if data_dir is configured.
	if cfg.Run.DataDir != "" {
		volumeName := sandbox.ResourceName(hash, sandbox.SuffixSessions)
		otherMounts = append(otherMounts, mount.Mount{
			Type:   mount.TypeVolume,
			Source: volumeName,
			Target: cfg.Run.DataDir,
		})
	}

	bindIP := cfg.Run.Port.Bind
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}

	name := sandbox.ResourceName(hash, sandbox.SuffixAgent)
	labels := sandbox.DefaultLabels(hash, "", "")

	cConf := &container.Config{
		Image:        image,
		Entrypoint:   cfg.Run.Entrypoint,
		Cmd:          cfg.Run.Command,
		Env:          envSlice,
		WorkingDir:   cfg.Run.Workdir,
		User:         cfg.Run.User,
		ExposedPorts: nat.PortSet{containerPort: struct{}{}},
		Labels:       labels,
	}
	hConf := &container.HostConfig{
		Binds:  binds,
		Mounts: otherMounts,
		PortBindings: nat.PortMap{
			containerPort: []nat.PortBinding{{HostIP: bindIP, HostPort: "0"}},
		},
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		// DNS points to the firewall container so all DNS queries are filtered by CoreDNS.
		DNS: []string{"172.20.0.1"},
	}

	// Network config — join isolated network if specified
	nConf := &network.NetworkingConfig{}
	networkName := sandbox.ResourceName(hash, sandbox.SuffixNet)
	nConf.EndpointsConfig = map[string]*network.EndpointSettings{
		networkName: {},
	}

	_, err = cli.ContainerCreate(ctx, cConf, hConf, nConf, nil, name)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	return nil
}

// Start creates and starts a container named name running image.
func Start(ctx context.Context, cli *client.Client, cfg *config.Config, image, name string) (*Result, error) {
	containerPort := nat.Port(cfg.Run.Port.Container)

	envSlice := make([]string, 0, len(cfg.Run.Env))
	for k, v := range cfg.Run.Env {
		envSlice = append(envSlice, k+"="+v)
	}

	// Bind mounts use HostConfig.Binds (the "source:target[:ro]" string form
	// used by `docker run -v`) so that Docker Desktop's VirtioFS / gRPC-FUSE
	// path-translation layer is triggered. The structured Mounts field bypasses
	// that layer and causes "path does not exist" on macOS.
	// Non-bind mounts (volume, tmpfs) continue to use HostConfig.Mounts.
	binds, otherMounts, err := buildMounts(cfg)
	if err != nil {
		return nil, err
	}

	// Mount sessions volume only if data_dir is configured.
	if cfg.Run.DataDir != "" {
		volumeName := strings.TrimSuffix(name, sandbox.SuffixAgent) + sandbox.SuffixSessions
		otherMounts = append(otherMounts, mount.Mount{
			Type:   mount.TypeVolume,
			Source: volumeName,
			Target: cfg.Run.DataDir,
		})
	}

	bindIP := cfg.Run.Port.Bind
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}

	cConf := &container.Config{
		Image:        image,
		Entrypoint:   cfg.Run.Entrypoint,
		Cmd:          cfg.Run.Command,
		Env:          envSlice,
		WorkingDir:   cfg.Run.Workdir,
		User:         cfg.Run.User,
		ExposedPorts: nat.PortSet{containerPort: struct{}{}},
		Labels: map[string]string{
			sandbox.Label:     "true",
			sandbox.LabelName: name,
		},
	}
	hConf := &container.HostConfig{
		Binds:  binds,
		Mounts: otherMounts,
		PortBindings: nat.PortMap{
			containerPort: []nat.PortBinding{{HostIP: bindIP, HostPort: "0"}},
		},
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped},
		// DNS points to the firewall container so all DNS queries are filtered by CoreDNS.
		DNS: []string{"172.20.0.1"},
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
		Volume:      strings.TrimSuffix(name, sandbox.SuffixAgent) + sandbox.SuffixSessions,
	}, nil
}

// buildMounts splits config mounts into bind strings (HostConfig.Binds) and
// structured mounts (HostConfig.Mounts for volume/tmpfs).
func buildMounts(cfg *config.Config) (binds []string, mounts []mount.Mount, err error) {
	for i, m := range cfg.Run.Mounts {
		if m.Target == "" {
			return nil, nil, fmt.Errorf("mount %d: target is required", i)
		}

		switch m.Type {
		case "", "bind":
			if m.Source == "" {
				return nil, nil, fmt.Errorf("mount %d: bind source is required", i)
			}

			src, err := paths.Expand(m.Source, cfg.BaseDir())
			if err != nil {
				return nil, nil, fmt.Errorf("mount %d source: %w", i, err)
			}
			if cfg.SharedPathsCheck && runtime.GOOS == "darwin" {
				if _, err := os.Stat(src); err != nil {
					return nil, nil, fmt.Errorf("mount %d: source path %s does not exist on the macOS host", i, src)
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
