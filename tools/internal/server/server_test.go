package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/policy"
	"sshgate/internal/testutil"
)

// shortTempDir returns a directory with a short path, because unix socket
// paths are limited to about 104 bytes on macOS.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sshgate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func startServer(t *testing.T) (sock string, granted ssh.PublicKey, cancel context.CancelFunc, done chan error) {
	t.Helper()
	privA, a := testutil.NewKey(t)
	privB, _ := testutil.NewKey(t)
	keyring := agent.NewKeyring()
	for _, k := range []any{privA, privB} {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	dial := func() (net.Conn, error) {
		c, s := net.Pipe()
		go agent.ServeAgent(keyring, s)
		return c, nil
	}

	sock = filepath.Join(shortTempDir(t), "g.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	g := policy.Grant{Name: "t", Expires: time.Now().Add(time.Hour), Keys: []ssh.PublicKey{a.PublicKey()}}
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { done <- Serve(ctx, l, dial, g, time.Now, log) }()
	t.Cleanup(cancel)
	return sock, a.PublicKey(), cancel, done
}

func TestServeFiltersAndStops(t *testing.T) {
	sock, granted, cancel, done := startServer(t)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || string(keys[0].Blob) != string(granted.Marshal()) {
		t.Fatalf("List = %v", keys)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
	if _, err := agent.NewClient(conn).List(); err == nil {
		t.Error("open connection still works after stop")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket not removed: %v", err)
	}
}

func TestListenPermissions(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "socks")
	sock := filepath.Join(dir, "g.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for path, want := range map[string]os.FileMode{dir: 0o700, sock: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestListenRefusesLiveSocket(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "g.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := Listen(sock); err == nil {
		t.Fatal("second Listen on a live socket should fail")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "g.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l2, err := Listen(sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	l2.Close()
}

func TestListenRefusesRegularFile(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path); err == nil {
		t.Fatal("Listen must not replace a regular file")
	}
}

func TestPeerPID(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "g.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := PeerPID(c); got != os.Getpid() {
		t.Errorf("PeerPID = %d, want %d", got, os.Getpid())
	}
}

// serveWith runs Serve with the given dial, clock and expiry.
func serveWith(t *testing.T, dial func() (net.Conn, error), expires time.Time, now func() time.Time) (string, context.CancelFunc, chan error) {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "g.sock")
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	g := policy.Grant{Name: "t", Expires: expires, Keys: []ssh.PublicKey{testutil.NewPublicKey(t)}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() { done <- Serve(ctx, l, dial, g, now, log) }()
	return sock, cancel, done
}

func waitDone(t *testing.T, done chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestServeStopsAtWallClockExpiry(t *testing.T) {
	old := expiryCheckInterval
	expiryCheckInterval = 10 * time.Millisecond
	t.Cleanup(func() { expiryCheckInterval = old })

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	dial := func() (net.Conn, error) { return nil, errors.New("unused") }
	_, _, done := serveWith(t, dial, now.Add(time.Hour), clock)

	mu.Lock()
	now = now.Add(2 * time.Hour) // e.g. the laptop slept
	mu.Unlock()
	waitDone(t, done)
}

func TestServeStopsWithBlockedUpstream(t *testing.T) {
	// The upstream never answers, like an agent that waits for a touch.
	dial := func() (net.Conn, error) {
		c, s := net.Pipe()
		t.Cleanup(func() { s.Close() })
		return c, nil
	}
	sock, cancel, done := serveWith(t, dial, time.Now().Add(time.Hour), time.Now)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go agent.NewClient(conn).List()
	time.Sleep(100 * time.Millisecond)
	cancel()
	waitDone(t, done)
}

func TestListenRejectsLongPath(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), strings.Repeat("x", 120)+".sock")
	_, err := Listen(sock)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("err = %v, want a 'too long' error", err)
	}
}
