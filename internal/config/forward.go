package config

// ReverseForwardConfig defines host-to-container forwarding rules.
// The firewall container acts as the bridge: it listens on the isolated
// network and forwards traffic to host services via host.docker.internal.
type ReverseForwardConfig struct {
	// Ports maps host TCP ports to container-side ports.
	// The firewall runs socat for each entry:
	//   listen on <firewall-ip>:<container_port> → connect to host.docker.internal:<host_port>
	Ports []PortForward `yaml:"ports,omitempty"`

	// Sockets maps host Unix sockets to container-side TCP ports.
	// The firewall runs socat for each entry:
	//   listen on <firewall-ip>:<container_port> → connect to <socket>
	Sockets []SocketForward `yaml:"sockets,omitempty"`
}

// PortForward maps a host TCP port to a container-side port.
type PortForward struct {
	Host      int `yaml:"host"`
	Container int `yaml:"container"`
}

// SocketForward maps a host Unix socket to a container-side TCP port.
type SocketForward struct {
	Socket    string `yaml:"socket"`
	Container int    `yaml:"container"`
}
