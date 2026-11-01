// Package server serves one grant on one unix socket.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/policy"
	"sshgate/internal/proxy"
)

// expiryCheckInterval is how often Serve compares the wall clock with the
// grant expiry. Timers use the monotonic clock, which stops while the
// machine sleeps, so a timer alone would extend a grant over a sleep.
var expiryCheckInterval = 10 * time.Second

// maxSocketPath is the size of sun_path on macOS, minus the final NUL.
const maxSocketPath = 103

// Listen creates a unix socket at path. The parent directory is created with
// mode 0700 and must not be accessible by others. A stale socket is replaced;
// a live socket or any other file is an error.
func Listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("socket path %s is too long (max %d bytes)", path, maxSocketPath)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%s must be a directory with mode 0700 that you own", dir)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != os.ModeSocket {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s is in use", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve accepts connections on l until ctx is done or the grant expires by
// the wall clock. Each connection gets its own upstream connection from dial
// and its own proxy.Agent. At the end, Serve closes the listener (which
// removes the socket) and all client and upstream connections.
func Serve(ctx context.Context, l net.Listener, dial func() (net.Conn, error), g policy.Grant, now func() time.Time, log *slog.Logger) error {
	log = log.With("grant", g.Name)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(expiryCheckInterval)
		defer t.Stop()
		for ctx.Err() == nil && now().Before(g.Expires) {
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
		l.Close()
	}()

	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		conns = map[net.Conn]struct{}{}
	)
	track := func(c net.Conn) {
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
	}
	untrack := func(c net.Conn) {
		mu.Lock()
		delete(conns, c)
		mu.Unlock()
		c.Close()
	}

	var err error
	for {
		var c net.Conn
		if c, err = l.Accept(); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				err = nil
			}
			break
		}
		track(c)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer untrack(c)
			log := log.With("pid", PeerPID(c))
			up, err := dial()
			if err != nil {
				log.Error("upstream agent unreachable", "err", err)
				return
			}
			track(up)
			defer untrack(up)
			agent.ServeAgent(proxy.New(agent.NewClient(up), g, now, log), c)
		}()
	}

	l.Close()
	mu.Lock()
	for c := range conns {
		c.Close()
	}
	mu.Unlock()
	wg.Wait()
	return err
}
