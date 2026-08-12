// Package run creates and starts a sandbox container, then reports the host
// port that Docker assigned to the published container port.
package run

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	dockernet "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/paths"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// AgentIP is the fixed IP for the agent container on the isolated network.
// The firewall DNAT rule forwards published port traffic to this IP.
const AgentIP = "172.20.0.10"

// Create creates a container named name running image without starting it.
// The container is created on the isolated network with a fixed IP.
func Create(ctx context.Context, cli *client.Client, cfg *config.Config, image, hash string) error {
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

	name := sandbox.ResourceName(hash, sandbox.SuffixAgent)
	labels := sandbox.DefaultLabels(hash, "", "")

	cConf := &container.Config{
		Image:      image,
		Entrypoint: cfg.Run.Entrypoint,
		Cmd:        cfg.Run.Command,
		Env:        envSlice,
		WorkingDir: cfg.Run.Workdir,
		User:       cfg.Run.User,
		Labels:     labels,
	}

	hConf := &container.HostConfig{
		Binds:  binds,
		Mounts: otherMounts,
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
		// DNS points to the firewall container so all DNS queries are filtered by CoreDNS.
		DNS: []string{"172.20.0.2"},
	}

	// Create on the isolated network with a fixed IP.
	// No port publishing — traffic reaches the agent via firewall DNAT.
	networkName := sandbox.ResourceName(hash, sandbox.SuffixNet)
	nConf := &dockernet.NetworkingConfig{
		EndpointsConfig: map[string]*dockernet.EndpointSettings{
			networkName: {
				IPAMConfig: &dockernet.EndpointIPAMConfig{
					IPv4Address: AgentIP,
				},
			},
		},
	}

	_, err = cli.ContainerCreate(ctx, cConf, hConf, nConf, nil, name)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}

	return nil
}

// Start creates and starts a container named name running image.
// This function is retained for direct use; the stack orchestrator calls
// ContainerStart directly instead.
func Start(ctx context.Context, cli *client.Client, cfg *config.Config, image, name, hash string) (*Result, error) {
	envSlice := make([]string, 0, len(cfg.Run.Env))
	for k, v := range cfg.Run.Env {
		envSlice = append(envSlice, k+"="+v)
	}

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

	cConf := &container.Config{
		Image:      image,
		Entrypoint: cfg.Run.Entrypoint,
		Cmd:        cfg.Run.Command,
		Env:        envSlice,
		WorkingDir: cfg.Run.Workdir,
		User:       cfg.Run.User,
		Labels: map[string]string{
			sandbox.Label:     "true",
			sandbox.LabelName: name,
		},
	}

	hConf := &container.HostConfig{
		Binds:  binds,
		Mounts: otherMounts,
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
		DNS: []string{"172.20.0.2"},
	}

	// Create on the isolated network with a fixed IP.
	networkName := sandbox.ResourceName(hash, sandbox.SuffixNet)
	nConf := &dockernet.NetworkingConfig{
		EndpointsConfig: map[string]*dockernet.EndpointSettings{
			networkName: {
				IPAMConfig: &dockernet.EndpointIPAMConfig{
					IPv4Address: AgentIP,
				},
			},
		},
	}

	created, err := cli.ContainerCreate(ctx, cConf, hConf, nConf, nil, name)
	if err != nil {
		return nil, fmt.Errorf("create container: %w", err)
	}
	if err := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		_ = cli.ContainerRemove(ctx, created.ID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("start container: %w", err)
	}

	// Use the actual name assigned by Docker (strips the leading "/").
	inspect, err := cli.ContainerInspect(ctx, created.ID)
	if err != nil {
		return nil, fmt.Errorf("inspect container: %w", err)
	}
	actualName := strings.TrimPrefix(inspect.Name, "/")

	return &Result{
		ContainerID: created.ID,
		Name:        actualName,
		Binds:       binds,
		Volume:      strings.TrimSuffix(name, sandbox.SuffixAgent) + sandbox.SuffixSessions,
	}, nil
}

// Result describes a successfully started sandbox.
type Result struct {
	ContainerID string
	Name        string
	Binds       []string // resolved bind specs (source:target[:ro]) passed to the daemon
	Volume      string   // named Docker volume used for session persistence
}

// buildMounts splits config mounts into bind strings (HostConfig.Binds) and
// structured mounts (HostConfig.Mounts for volume/tmpfs).
//
// The current working directory is always mounted at run.workdir (RW) unless
// a user-defined mount already targets that path.
func buildMounts(cfg *config.Config) (binds []string, mounts []mount.Mount, err error) {
	// Auto-mount cwd → workdir. Skip if user already mounts the workdir target.
	workdir := cfg.Run.Workdir
	if workdir == "" {
		workdir = "/workspace"
	}
	workdirMounted := false
	for _, m := range cfg.Run.Mounts {
		if m.Target == workdir {
			workdirMounted = true
			break
		}
	}
	if !workdirMounted {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, nil, fmt.Errorf("get working directory: %w", err)
		}
		binds = append(binds, cwd+":"+workdir)
	}

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
