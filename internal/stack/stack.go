package stack

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/docker/docker/api/types/container"
	dockernet "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"

	"github.com/preved911/agent-sandbox/internal/config"
	"github.com/preved911/agent-sandbox/internal/firewall"
	sandboxnet "github.com/preved911/agent-sandbox/internal/network"
	"github.com/preved911/agent-sandbox/internal/run"
	"github.com/preved911/agent-sandbox/internal/sandbox"
)

// Stack manages the 3-resource sandbox stack:
// - Sessions volume (durable)
// - Firewall container (network enforcement)
// - Agent container (opencode)
type Stack struct {
	cli    *client.Client
	hash   string
	path   string // absolute working directory path
	config *config.Config
}

// New creates a new stack manager.
func New(cli *client.Client, hash, path string, cfg *config.Config) *Stack {
	return &Stack{
		cli:    cli,
		hash:   hash,
		path:   path,
		config: cfg,
	}
}

// Create creates the full stack without starting containers.
// Lifecycle:
// 1. Create sessions volume (if not exists)
// 2. Create isolated network
// 3. Create firewall container (with published port for host access)
// 4. Create agent container (on isolated network only)
func (s *Stack) Create(ctx context.Context, image string) error {
	// 1. Sessions volume — created automatically by Docker on first use
	volumeName := sandbox.ResourceName(s.hash, sandbox.SuffixSessions)
	log.Printf("Sessions volume: %s", volumeName)

	// 2. Create isolated network
	log.Printf("Creating isolated network...")
	if _, err := sandboxnet.Create(ctx, s.cli, s.hash); err != nil {
		return fmt.Errorf("create network: %w", err)
	}

	// 3. Create firewall container (with published port for host→agent access)
	log.Printf("Creating firewall container...")
	if err := s.createFirewall(ctx); err != nil {
		return fmt.Errorf("create firewall: %w", err)
	}

	// 4. Create agent container on the isolated network with a fixed IP.
	// No port publishing — traffic reaches the agent via firewall DNAT.
	log.Printf("Creating agent container...")
	if err := run.Create(ctx, s.cli, s.config, image, s.hash, s.path); err != nil {
		return fmt.Errorf("create agent: %w", err)
	}

	return nil
}

// Start starts the full stack with health checks.
// Lifecycle:
// 1. Start firewall container
// 2. Wait for firewall health check
// 3. Start agent container
func (s *Stack) Start(ctx context.Context) error {
	// 1. Start firewall
	log.Printf("Starting firewall container...")
	if err := s.startFirewall(ctx); err != nil {
		return fmt.Errorf("start firewall: %w", err)
	}

	// 2. Wait for firewall health
	log.Printf("Waiting for firewall health check...")
	fw := firewall.NewFirewallContainer(s.cli, s.hash)
	if err := WaitForHealthy(ctx, fw, 30*time.Second); err != nil {
		return fmt.Errorf("firewall health check: %w", err)
	}
	log.Printf("Firewall is healthy")

	// 3. Start agent
	log.Printf("Starting agent container...")
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	if err := s.cli.ContainerStart(ctx, agentName, container.StartOptions{}); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	return nil
}

// Stop stops both containers, keeps volume.
func (s *Stack) Stop(ctx context.Context, timeout int) error {
	// Stop agent first
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	log.Printf("Stopping agent container...")
	secs := timeout
	if err := s.cli.ContainerStop(ctx, agentName, container.StopOptions{Timeout: &secs}); err != nil {
		log.Printf("Warning: stop agent: %v", err)
	}

	// Stop firewall
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	log.Printf("Stopping firewall container...")
	if err := s.cli.ContainerStop(ctx, fwName, container.StopOptions{Timeout: &secs}); err != nil {
		log.Printf("Warning: stop firewall: %v", err)
	}

	return nil
}

// Remove removes containers + network, keeps volume unless purge=true.
func (s *Stack) Remove(ctx context.Context, force bool, purge bool) error {
	// Remove agent container
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	log.Printf("Removing agent container...")
	if err := s.cli.ContainerRemove(ctx, agentName, container.RemoveOptions{Force: force}); err != nil {
		log.Printf("Warning: remove agent: %v", err)
	}

	// Remove firewall container
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	log.Printf("Removing firewall container...")
	if err := s.cli.ContainerRemove(ctx, fwName, container.RemoveOptions{Force: force}); err != nil {
		log.Printf("Warning: remove firewall: %v", err)
	}

	// Remove network
	log.Printf("Removing network...")
	if err := sandboxnet.Remove(ctx, s.cli, s.hash); err != nil {
		log.Printf("Warning: remove network: %v", err)
	}

	// Remove volume only if purge
	if purge {
		volumeName := sandbox.ResourceName(s.hash, sandbox.SuffixSessions)
		log.Printf("Purging sessions volume...")
		if err := s.cli.VolumeRemove(ctx, volumeName, true); err != nil {
			log.Printf("Warning: remove volume: %v", err)
		}
	}

	return nil
}

// GetPort returns the published port for the firewall container.
// The firewall's published port is used for host→agent access via nftables DNAT.
func (s *Stack) GetPort(ctx context.Context) (string, error) {
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	resp, err := s.cli.ContainerInspect(ctx, fwName)
	if err != nil {
		return "", fmt.Errorf("inspect firewall: %w", err)
	}

	// The firewall publishes the agent's container port (e.g., 4096/tcp).
	portKey := nat.Port(s.config.Run.Port.Container)
	if ports, ok := resp.NetworkSettings.Ports[portKey]; ok && len(ports) > 0 {
		return ports[0].HostPort, nil
	}

	return "", fmt.Errorf("no published port found for %s", portKey)
}

// Exists checks if the stack exists.
func (s *Stack) Exists(ctx context.Context) (bool, error) {
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	_, err := s.cli.ContainerInspect(ctx, agentName)
	if err != nil {
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("inspect agent: %w", err)
	}
	return true, nil
}

// Status returns the status of all stack resources.
func (s *Stack) Status(ctx context.Context) (*StackStatus, error) {
	status := &StackStatus{}

	// Agent container
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	resp, err := s.cli.ContainerInspect(ctx, agentName)
	if err != nil {
		if client.IsErrNotFound(err) {
			status.Agent = "not found"
		} else {
			return nil, fmt.Errorf("inspect agent: %w", err)
		}
	} else {
		status.Agent = resp.State.Status
	}

	// Firewall container
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	resp, err = s.cli.ContainerInspect(ctx, fwName)
	if err != nil {
		if client.IsErrNotFound(err) {
			status.Firewall = "not found"
		} else {
			return nil, fmt.Errorf("inspect firewall: %w", err)
		}
	} else {
		status.Firewall = resp.State.Status
	}

	// Network
	exists, err := sandboxnet.Exists(ctx, s.cli, s.hash)
	if err != nil {
		return nil, fmt.Errorf("check network: %w", err)
	}
	if exists {
		status.Network = "exists"
	} else {
		status.Network = "not found"
	}

	return status, nil
}

// StackStatus holds the status of all stack resources.
type StackStatus struct {
	Agent    string
	Firewall string
	Network  string
}

// agentIP is derived from the hash — see sandboxnet.AgentIPFromHash.

func (s *Stack) createFirewall(ctx context.Context) error {
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	networkName := sandbox.ResourceName(s.hash, sandbox.SuffixNet)

	// Derive unique IPs from hash.
	_, _, firewallIP, agentIP := sandboxnet.SubnetFromHash(s.hash)

	// Ensure firewall image exists (auto-build from embedded files if missing)
	imageTag, err := firewall.EnsureFirewallImage(ctx, s.cli, s.config.Run.Firewall.Image)
	if err != nil {
		return fmt.Errorf("ensure firewall image: %w", err)
	}

	// Build firewall env vars from config
	fw := firewall.NewFirewallContainer(s.cli, s.hash)
	envSlice := fw.FirewallEnv(&s.config.Run.Firewall)

	// Add DNAT target IP so firewall entrypoint can generate the rule.
	envSlice = append(envSlice, "AGENT_IP="+agentIP)

	// Add the agent's container port so firewall knows which port to DNAT.
	envSlice = append(envSlice, "AGENT_PORT="+s.config.Run.Port.Container)

	// Add subnet for SNAT rule.
	_, subnet, _, _ := sandboxnet.SubnetFromHash(s.hash)
	envSlice = append(envSlice, "SUBNET="+subnet)

	labels := sandbox.DefaultLabels(s.hash, s.path, "")
	labels[sandbox.SandboxRole] = "firewall"

	cConf := &container.Config{
		Image:  imageTag,
		Labels: labels,
		Env:    envSlice,
	}

	// Step 1: Create firewall on default bridge only (port publishing works on bridge).
	capAdd := []string{"NET_ADMIN", "NET_RAW"}

	containerPort := nat.Port(s.config.Run.Port.Container)
	bindIP := s.config.Run.Port.Bind
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}

	hConf := &container.HostConfig{
		CapAdd: capAdd,
		PortBindings: nat.PortMap{
			containerPort: []nat.PortBinding{{HostIP: bindIP, HostPort: "0"}},
		},
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
	}

	_, err = s.cli.ContainerCreate(ctx, cConf, hConf, nil, nil, fwName)
	if err != nil {
		return fmt.Errorf("create firewall on bridge: %w", err)
	}

	// Step 2: Connect firewall to isolated network with fixed IP.
	// Port publishing is already bound via HostConfig; adding the second
	// network via NetworkConnect keeps the bindings intact.
	networkEndpoint := &dockernet.EndpointSettings{
		IPAMConfig: &dockernet.EndpointIPAMConfig{
			IPv4Address: firewallIP,
		},
	}
	if err := s.cli.NetworkConnect(ctx, networkName, fwName, networkEndpoint); err != nil {
		return fmt.Errorf("connect firewall to isolated network: %w", err)
	}

	return nil
}

func (s *Stack) startFirewall(ctx context.Context) error {
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	return s.cli.ContainerStart(ctx, fwName, container.StartOptions{})
}
