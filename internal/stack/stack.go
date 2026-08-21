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

// Stack manages the 4-resource sandbox stack:
// - Sessions volume (durable)
// - Firewall container (nftables + CoreDNS — traffic filtering)
// - Proxy container (nginx — host→agent port forwarding)
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
func (s *Stack) Create(ctx context.Context, image string) error {
	// 1. Sessions volume
	volumeName := sandbox.ResourceName(s.hash, sandbox.SuffixSessions)
	log.Printf("Sessions volume: %s", volumeName)

	// 2. Create isolated network
	log.Printf("Creating isolated network...")
	if _, err := sandboxnet.Create(ctx, s.cli, s.hash); err != nil {
		return fmt.Errorf("create network: %w", err)
	}

	// 3. Create firewall container (no published port — traffic filtering only)
	log.Printf("Creating firewall container...")
	if err := s.createFirewall(ctx); err != nil {
		return fmt.Errorf("create firewall: %w", err)
	}

	// 4. Create proxy container (published port — nginx reverse proxy)
	log.Printf("Creating proxy container...")
	if err := s.createProxy(ctx); err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}

	// 5. Create agent container on the isolated network with a fixed IP.
	log.Printf("Creating agent container...")
	if err := run.Create(ctx, s.cli, s.config, image, s.hash, s.path); err != nil {
		return fmt.Errorf("create agent: %w", err)
	}

	return nil
}

// Start starts the full stack with health checks.
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

	// 3. Start proxy
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	log.Printf("Starting proxy container...")
	if err := s.cli.ContainerStart(ctx, proxyName, container.StartOptions{}); err != nil {
		return fmt.Errorf("start proxy: %w", err)
	}

	// 4. Start agent
	log.Printf("Starting agent container...")
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	if err := s.cli.ContainerStart(ctx, agentName, container.StartOptions{}); err != nil {
		return fmt.Errorf("start agent: %w", err)
	}

	return nil
}

// Stop stops all containers, keeps volume.
func (s *Stack) Stop(ctx context.Context, timeout int) error {
	secs := timeout

	// Stop agent first
	agentName := sandbox.ResourceName(s.hash, sandbox.SuffixAgent)
	log.Printf("Stopping agent container...")
	if err := s.cli.ContainerStop(ctx, agentName, container.StopOptions{Timeout: &secs}); err != nil {
		log.Printf("Warning: stop agent: %v", err)
	}

	// Stop proxy
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	log.Printf("Stopping proxy container...")
	if err := s.cli.ContainerStop(ctx, proxyName, container.StopOptions{Timeout: &secs}); err != nil {
		log.Printf("Warning: stop proxy: %v", err)
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

	// Remove proxy container
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	log.Printf("Removing proxy container...")
	if err := s.cli.ContainerRemove(ctx, proxyName, container.RemoveOptions{Force: force}); err != nil {
		log.Printf("Warning: remove proxy: %v", err)
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

// GetPort returns the published port for the proxy container.
func (s *Stack) GetPort(ctx context.Context) (string, error) {
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	resp, err := s.cli.ContainerInspect(ctx, proxyName)
	if err != nil {
		return "", fmt.Errorf("inspect proxy: %w", err)
	}

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

	// Proxy container
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	resp, err = s.cli.ContainerInspect(ctx, proxyName)
	if err != nil {
		if client.IsErrNotFound(err) {
			status.Proxy = "not found"
		} else {
			return nil, fmt.Errorf("inspect proxy: %w", err)
		}
	} else {
		status.Proxy = resp.State.Status
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
	Proxy    string
	Network  string
}

// createFirewall creates the firewall container (nftables + CoreDNS only, no published port).
func (s *Stack) createFirewall(ctx context.Context) error {
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	networkName := sandbox.ResourceName(s.hash, sandbox.SuffixNet)

	_, _, firewallIP, agentIP, _, _, _ := sandboxnet.SubnetFromHash(s.hash)

	imageTag, err := firewall.EnsureFirewallImage(ctx, s.cli, s.config.Run.Firewall.Image)
	if err != nil {
		return fmt.Errorf("ensure firewall image: %w", err)
	}

	fw := firewall.NewFirewallContainer(s.cli, s.hash)
	envSlice := fw.FirewallEnv(&s.config.Run.Firewall)
	envSlice = append(envSlice, "AGENT_IP="+agentIP)
	envSlice = append(envSlice, "AGENT_PORT="+s.config.Run.Port.Container)

	subnet, gateway, _, _, subnet6, _, _ := sandboxnet.SubnetFromHash(s.hash)
	envSlice = append(envSlice, "SUBNET="+subnet)
	envSlice = append(envSlice, "GATEWAY="+gateway)
	// Derive the IPv6 gateway from the /64 subnet (::1 host).
	// The firewall claims this address as a secondary IP so agent IPv6
	// traffic routed to the network gateway lands on the firewall.
	if subnet6 != "" {
		// subnet6 is "fd<xx>:<yy>00::/64" → gateway6 is "fd<xx>:<yy>00::1"
		gw6 := subnet6[:len(subnet6)-len("::/64")] + "::1"
		envSlice = append(envSlice, "SUBNET6="+subnet6)
		envSlice = append(envSlice, "GATEWAY6="+gw6)
	}

	labels := sandbox.DefaultLabels(s.hash, s.path, "")
	labels[sandbox.SandboxRole] = "firewall"

	cConf := &container.Config{
		Image:  imageTag,
		Labels: labels,
		Env:    envSlice,
	}

	hConf := &container.HostConfig{
		CapAdd: []string{"NET_ADMIN", "NET_RAW"},
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
		// Enable IPv6 forwarding inside the firewall container so it can route
		// IPv6 traffic from the agent to the outside world. Done via sysctl
		// rather than entrypoint because /proc/sys is read-only without it.
		Sysctls: map[string]string{
			"net.ipv6.conf.all.forwarding": "1",
		},
	}

	_, _, _, _, _, firewallIP6, _ := sandboxnet.SubnetFromHash(s.hash)

	// Create on isolated network only (no port publishing needed).
	networkSettings := &dockernet.NetworkingConfig{
		EndpointsConfig: map[string]*dockernet.EndpointSettings{
			networkName: {
				IPAMConfig: &dockernet.EndpointIPAMConfig{
					IPv4Address: firewallIP,
					IPv6Address: firewallIP6,
				},
			},
		},
	}

	_, err = s.cli.ContainerCreate(ctx, cConf, hConf, networkSettings, nil, fwName)
	if err != nil {
		return fmt.Errorf("create firewall: %w", err)
	}

	return nil
}

// createProxy creates the proxy container (nginx reverse proxy with published port).
func (s *Stack) createProxy(ctx context.Context) error {
	proxyName := sandbox.ResourceName(s.hash, sandbox.SuffixProxy)
	networkName := sandbox.ResourceName(s.hash, sandbox.SuffixNet)

	_, _, _, agentIP, _, _, _ := sandboxnet.SubnetFromHash(s.hash)

	imageTag, err := firewall.EnsureProxyImage(ctx, s.cli, "")
	if err != nil {
		return fmt.Errorf("ensure proxy image: %w", err)
	}

	labels := sandbox.DefaultLabels(s.hash, s.path, "")
	labels[sandbox.SandboxRole] = "proxy"

	cConf := &container.Config{
		Image: imageTag,
		Labels: labels,
		Env: []string{
			"AGENT_IP=" + agentIP,
			"AGENT_PORT=" + s.config.Run.Port.Container,
		},
	}

	// Port publishing — proxy listens on bridge, forwards to agent via nginx.
	containerPort := nat.Port(s.config.Run.Port.Container)
	bindIP := s.config.Run.Port.Bind
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}

	hConf := &container.HostConfig{
		PortBindings: nat.PortMap{
			containerPort: []nat.PortBinding{{HostIP: bindIP, HostPort: "0"}},
		},
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
	}

	// Step 1: Create on default bridge (port publishing works on bridge).
	_, err = s.cli.ContainerCreate(ctx, cConf, hConf, nil, nil, proxyName)
	if err != nil {
		return fmt.Errorf("create proxy on bridge: %w", err)
	}

	// Step 2: Connect to isolated network (to reach agent IP).
	networkEndpoint := &dockernet.EndpointSettings{}
	if err := s.cli.NetworkConnect(ctx, networkName, proxyName, networkEndpoint); err != nil {
		return fmt.Errorf("connect proxy to isolated network: %w", err)
	}

	return nil
}

func (s *Stack) startFirewall(ctx context.Context) error {
	fwName := sandbox.ResourceName(s.hash, sandbox.SuffixFirewall)
	return s.cli.ContainerStart(ctx, fwName, container.StartOptions{})
}
