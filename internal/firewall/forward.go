package firewall

import (
	"fmt"
	"strings"

	"github.com/preved911/agent-sandbox/internal/config"
)

// GenerateReverseForwardNftables generates nftables OUTPUT rules for reverse forwarding.
// These rules allow the firewall container to reach host services on exact specified ports.
// Rules are appended to the main nftables config.
func GenerateReverseForwardNftables(reverseForward *config.ReverseForwardConfig) string {
	if reverseForward == nil || len(reverseForward.Ports) == 0 {
		return ""
	}

	var b strings.Builder
	b.WriteString("\n# Reverse forwarding — implicit OUTPUT rules (auto-generated)\n")
	b.WriteString("# Allow firewall -> host-gateway on exact specified ports\n")

	for _, port := range reverseForward.Ports {
		b.WriteString(fmt.Sprintf("# host:%d -> container:%d\n", port.Host, port.Container))
	}

	return b.String()
}

// GenerateSocatCommands generates socat commands for reverse port forwarding.
// Each command listens on the inside interface and forwards to host.docker.internal.
func GenerateSocatCommands(reverseForward *config.ReverseForwardConfig, insideIP string) []string {
	if reverseForward == nil || len(reverseForward.Ports) == 0 {
		return nil
	}

	var cmds []string
	for _, port := range reverseForward.Ports {
		cmd := fmt.Sprintf(
			"socat TCP-LISTEN:%d,bind=%s,fork,reuseaddr TCP:host.docker.internal:%d",
			port.Container, insideIP, port.Host)
		cmds = append(cmds, cmd)
	}

	return cmds
}

// GenerateSocketForwardSocat generates socat commands for socket-to-port forwarding.
// Socket forwarding requires the socket to be accessible from the firewall container.
func GenerateSocketForwardSocat(reverseForward *config.ReverseForwardConfig, insideIP string) []string {
	if reverseForward == nil || len(reverseForward.Sockets) == 0 {
		return nil
	}

	var cmds []string
	for _, sock := range reverseForward.Sockets {
		// Socket-to-port: socat listens on TCP port and forwards to Unix socket
		cmd := fmt.Sprintf(
			"socat TCP-LISTEN:%d,bind=%s,fork,reuseaddr UNIX-CONNECT:%s",
			sock.Container, insideIP, sock.Socket)
		cmds = append(cmds, cmd)
	}

	return cmds
}

// GenerateSocatEnv generates environment variables for the firewall container
// that the entrypoint script uses to start socat forwarders.
func GenerateSocatEnv(reverseForward *config.ReverseForwardConfig) []string {
	var env []string

	if reverseForward != nil && len(reverseForward.Ports) > 0 {
		var portPairs []string
		for _, p := range reverseForward.Ports {
			portPairs = append(portPairs, fmt.Sprintf("%d:%d", p.Host, p.Container))
		}
		env = append(env, fmt.Sprintf("REVERSE_FORWARD_PORTS=%s", joinStrings(portPairs)))
	}

	if reverseForward != nil && len(reverseForward.Sockets) > 0 {
		var sockPairs []string
		for _, s := range reverseForward.Sockets {
			sockPairs = append(sockPairs, fmt.Sprintf("%s:%d", s.Socket, s.Container))
		}
		env = append(env, fmt.Sprintf("REVERSE_FORWARD_SOCKETS=%s", joinStrings(sockPairs)))
	}

	return env
}
