// Package proxy implements a filtering ssh-agent in front of an upstream agent.
//
// One Agent serves one client connection. It handles session-bind itself and
// asks the policy package about every sign request.
package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/policy"
	"sshgate/internal/sigdata"
)

const sessionBindExt = "session-bind@openssh.com"

var errNotPermitted = errors.New("sshgate: operation not permitted")

// Agent is an agent.ExtendedAgent for one client connection.
type Agent struct {
	upstream agent.ExtendedAgent
	grant    policy.Grant
	now      func() time.Time
	log      *slog.Logger

	mu   sync.Mutex
	conn policy.Conn
}

// New returns a proxy agent for one client connection.
func New(upstream agent.ExtendedAgent, g policy.Grant, now func() time.Time, log *slog.Logger) *Agent {
	return &Agent{upstream: upstream, grant: g, now: now, log: log}
}

// List returns the upstream keys that are part of the grant.
func (a *Agent) List() ([]*agent.Key, error) {
	if !a.now().Before(a.grant.Expires) || a.state().Poisoned != "" {
		return nil, nil
	}
	keys, err := a.upstream.List()
	if err != nil {
		return nil, err
	}
	var out []*agent.Key
	for _, k := range keys {
		if pk, err := ssh.ParsePublicKey(k.Blob); err == nil && a.grant.HasKey(pk) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *Agent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	conn := a.state()
	log := a.log.With("key", ssh.FingerprintSHA256(key), "request", describe(data, conn))
	if err := policy.Decide(a.grant, a.now(), conn, key, data); err != nil {
		log.Warn("sign denied", "reason", err)
		return nil, err
	}
	sig, err := a.upstream.SignWithFlags(key, data, flags)
	if err != nil {
		log.Error("upstream sign failed", "err", err)
		return nil, err
	}
	log.Info("sign allowed")
	return sig, nil
}

func (a *Agent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExt {
		return nil, agent.ErrExtensionUnsupported
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn.Poisoned != "" {
		return nil, errors.New(a.conn.Poisoned)
	}

	bind, err := sigdata.ParseSessionBind(contents)
	switch {
	case err != nil:
		a.conn.Poisoned = "invalid session-bind: " + err.Error()
	case bind.Forwarding:
		a.conn.Poisoned = "forwarded agent connection"
	case a.conn.Bind != nil && !(bytes.Equal(a.conn.Bind.SessionID, bind.SessionID) && policy.KeyEqual(a.conn.Bind.HostKey, bind.HostKey)):
		a.conn.Poisoned = "more than one session-bind"
	default:
		a.conn.Bind = &bind
		a.log.Info("session bound", "host_key", ssh.FingerprintSHA256(bind.HostKey), "session", shortHex(bind.SessionID))
		return nil, nil
	}
	a.log.Warn("session-bind refused", "reason", a.conn.Poisoned)
	return nil, errors.New(a.conn.Poisoned)
}

func (a *Agent) state() policy.Conn {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.conn
}

func (a *Agent) Add(agent.AddedKey) error       { return errNotPermitted }
func (a *Agent) Remove(ssh.PublicKey) error     { return errNotPermitted }
func (a *Agent) RemoveAll() error               { return errNotPermitted }
func (a *Agent) Lock([]byte) error              { return errNotPermitted }
func (a *Agent) Unlock([]byte) error            { return errNotPermitted }
func (a *Agent) Signers() ([]ssh.Signer, error) { return nil, errNotPermitted }

// describe returns a short log description of a sign request.
func describe(data []byte, c policy.Conn) string {
	switch r, _ := sigdata.Parse(data); r := r.(type) {
	case sigdata.SSHSig:
		return "sshsig namespace=" + r.Namespace
	case sigdata.UserAuth:
		host := "unbound"
		if c.Bind != nil {
			host = ssh.FingerprintSHA256(c.Bind.HostKey)
		}
		return fmt.Sprintf("login user=%s host_key=%s session=%s", r.User, host, shortHex(r.SessionID))
	}
	return "unknown"
}

func shortHex(b []byte) string {
	return hex.EncodeToString(b[:min(len(b), 8)])
}
