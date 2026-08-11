// Package proxy runs host-side TCP proxy goroutines for reverse forwarding.
// Each proxy listens on the Docker bridge gateway IP (reachable from containers
// on that bridge) and forwards connections to the actual host service.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/preved911/agent-sandbox/internal/config"
)

const (
	// TargetTypeTCP forwards to a TCP address (e.g. "127.0.0.1:3000").
	TargetTypeTCP = "tcp"
	// TargetTypeUnix forwards to a Unix socket (e.g. "/var/run/docker.sock").
	TargetTypeUnix = "unix"
)

// Proxy forwards connections from a listener on the bridge gateway to a target.
type Proxy struct {
	listenAddr string       // address to listen on (e.g. "172.20.0.1:5173")
	target     string       // target address (e.g. "127.0.0.1:5173" or "/var/run/docker.sock")
	targetType string       // "tcp" or "unix"
	listener   net.Listener
	wg         sync.WaitGroup
}

// New creates a new proxy that forwards gateway:port to the target.
func New(gateway string, port int, targetType, target string) *Proxy {
	return &Proxy{
		listenAddr: fmt.Sprintf("%s:%d", gateway, port),
		target:     target,
		targetType: targetType,
	}
}

// Start opens the listener and begins accepting connections.
// It runs until the context is cancelled or Stop is called.
func (p *Proxy) Start(ctx context.Context) error {
	var err error
	p.listener, err = net.Listen("tcp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.listenAddr, err)
	}

	log.Printf("Reverse proxy: listening on %s -> %s (%s)", p.listenAddr, p.target, p.targetType)

	p.wg.Add(1)
	go p.acceptLoop(ctx)

	return nil
}

func (p *Proxy) acceptLoop(ctx context.Context) {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			// Check if context was cancelled (graceful shutdown).
			select {
			case <-ctx.Done():
				return
			default:
			}
			log.Printf("Reverse proxy: accept error on %s: %v", p.listenAddr, err)
			return
		}

		p.wg.Add(1)
		go p.handleConn(ctx, conn)
	}
}

func (p *Proxy) handleConn(ctx context.Context, clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	// Connect to target.
	var targetConn net.Conn
	var err error

	switch p.targetType {
	case "unix":
		targetConn, err = net.DialTimeout("unix", p.target, 5*time.Second)
	case "tcp":
		// For TCP targets, connect to localhost on the host.
		targetConn, err = net.DialTimeout("tcp", p.target, 5*time.Second)
	default:
		log.Printf("Reverse proxy: unknown target type %q", p.targetType)
		return
	}

	if err != nil {
		log.Printf("Reverse proxy: connect to %s (%s) failed: %v", p.target, p.targetType, err)
		return
	}
	defer targetConn.Close()

	// Bidirectional copy with context cancellation.
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(targetConn, clientConn) // client -> target
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn) // target -> client
		done <- struct{}{}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

// Stop closes the listener and waits for in-flight connections to finish.
func (p *Proxy) Stop() {
	if p.listener != nil {
		p.listener.Close()
	}
	// Wait with timeout for in-flight connections.
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("Reverse proxy: timed out waiting for in-flight connections on %s", p.listenAddr)
	}
}

// Manager manages all proxy goroutines for a sandbox.
type Manager struct {
	proxies []*Proxy
}

// NewManager creates a new proxy manager.
func NewManager() *Manager {
	return &Manager{}
}

// StartProxies starts proxy goroutines for all configured reverse forwards.
// gateway is the Docker bridge gateway IP (e.g. "172.20.0.1").
func (m *Manager) StartProxies(ctx context.Context, gateway string, rf *config.ReverseForwardConfig) error {
	if rf == nil {
		return nil
	}

	// Port forwards.
	for _, port := range rf.Ports {
		target := fmt.Sprintf("127.0.0.1:%d", port.Host)
		p := New(gateway, port.Container, "tcp", target)
		if err := p.Start(ctx); err != nil {
			// Stop any already-started proxies.
			m.StopAll()
			return err
		}
		m.proxies = append(m.proxies, p)
	}

	// Socket forwards.
	for _, sock := range rf.Sockets {
		p := New(gateway, sock.Container, "unix", sock.Socket)
		if err := p.Start(ctx); err != nil {
			m.StopAll()
			return err
		}
		m.proxies = append(m.proxies, p)
	}

	return nil
}

// StopAll stops all proxy goroutines gracefully.
func (m *Manager) StopAll() {
	for _, p := range m.proxies {
		p.Stop()
	}
	m.proxies = nil
}
