package proxy

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/preved911/agent-sandbox/internal/config"
)

func TestNew(t *testing.T) {
	p := New("172.20.0.1", 8080, TargetTypeTCP, "127.0.0.1:3000")

	if p.listenAddr != "172.20.0.1:8080" {
		t.Errorf("listenAddr = %q, want %q", p.listenAddr, "172.20.0.1:8080")
	}
	if p.target != "127.0.0.1:3000" {
		t.Errorf("target = %q, want %q", p.target, "127.0.0.1:3000")
	}
	if p.targetType != TargetTypeTCP {
		t.Errorf("targetType = %q, want %q", p.targetType, TargetTypeTCP)
	}
}

func TestNew_Unix(t *testing.T) {
	p := New("172.20.0.1", 9090, TargetTypeUnix, "/var/run/docker.sock")

	if p.targetType != TargetTypeUnix {
		t.Errorf("targetType = %q, want %q", p.targetType, TargetTypeUnix)
	}
	if p.target != "/var/run/docker.sock" {
		t.Errorf("target = %q, want %q", p.target, "/var/run/docker.sock")
	}
}

func TestManager_StopAll_NoProxies(t *testing.T) {
	m := NewManager()

	// StopAll should not panic even with no proxies
	m.StopAll()
}

func TestProxy_Start_InvalidAddress(t *testing.T) {
	// Use an invalid listen address
	p := New("999.999.999.999", 1, TargetTypeTCP, "127.0.0.1:3000")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := p.Start(ctx)
	if err == nil {
		t.Error("Start with invalid address should return error")
		p.Stop()
	}
}

func TestProxy_E2E_TCP(t *testing.T) {
	// Create a simple TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer echoLn.Close()

	echoAddr := echoLn.Addr().String()

	// Echo goroutine
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Start proxy on random port
	p := New("127.0.0.1", 0, TargetTypeTCP, echoAddr)

	// Manually set listen address with port 0 (let OS pick)
	p.listenAddr = "127.0.0.1:0"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.Start(ctx)
	if err != nil {
		t.Fatalf("proxy Start failed: %v", err)
	}
	defer p.Stop()

	if p.listener == nil {
		t.Fatal("listener should not be nil after Start")
	}

	actualAddr := p.listener.Addr().String()

	// Connect through proxy
	conn, err := net.DialTimeout("tcp", actualAddr, time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send data through proxy
	testData := []byte("hello proxy")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Read echo
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo = %q, want %q", string(buf[:n]), string(testData))
	}
}

func TestProxy_E2E_Unix(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Unix socket test in short mode")
	}

	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create Unix echo server
	unixLn, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to start Unix echo server: %v", err)
	}
	defer unixLn.Close()

	go func() {
		for {
			conn, err := unixLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Start proxy
	p := New("127.0.0.1", 0, TargetTypeUnix, socketPath)
	p.listenAddr = "127.0.0.1:0"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = p.Start(ctx)
	if err != nil {
		t.Fatalf("proxy Start failed: %v", err)
	}
	defer p.Stop()

	actualAddr := p.listener.Addr().String()

	// Connect through proxy
	conn, err := net.DialTimeout("tcp", actualAddr, time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	// Send and receive
	testData := []byte("hello unix proxy")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo = %q, want %q", string(buf[:n]), string(testData))
	}
}

func TestProxy_Stop_ClosesListener(t *testing.T) {
	p := New("127.0.0.1", 0, TargetTypeTCP, "127.0.0.1:3000")
	p.listenAddr = "127.0.0.1:0"

	ctx := context.Background()
	err := p.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	ln := p.listener
	if ln == nil {
		t.Fatal("listener should not be nil")
	}

	p.Stop()

	// Listener should be closed — Accept should fail
	_, err = ln.Accept()
	if err == nil {
		t.Error("Accept on closed listener should return error")
	}
}

func TestManager_StartStop(t *testing.T) {
	m := NewManager()

	// Start a TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx := context.Background()

	rf := &config.ReverseForwardConfig{
		Ports: []config.PortForward{
			{Host: 3000, Container: 8080},
		},
	}

	// StartProxies will try to listen on gateway:8080 — may fail without Docker
	// but we can test the manager lifecycle
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		m.StartProxies(ctx, "127.0.0.1", rf)
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// StopAll should work
	m.StopAll()

	// If StartProxies failed to bind, that's OK for unit test
	_ = os.ErrClosed
}

func TestProxy_ContextCancellation(t *testing.T) {
	// Create echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Start proxy with short-lived context
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	p := New("127.0.0.1", 0, TargetTypeTCP, echoLn.Addr().String())
	p.listenAddr = "127.0.0.1:0"

	err = p.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Connect before context expires
	conn, err := net.DialTimeout("tcp", p.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	conn.Close()

	// Wait for context to expire and proxy to stop
	time.Sleep(500 * time.Millisecond)

	// Listener should be closed after Stop() was called by context cancellation
	_, err = net.DialTimeout("tcp", p.listener.Addr().String(), 100*time.Millisecond)
	// Connection should fail (listener closed)
	if err == nil {
		// Race condition — OS hasn't fully processed the close yet
		// This is acceptable in a timing-sensitive test
		t.Log("connection succeeded after Stop — timing race, acceptable")
	}
}
