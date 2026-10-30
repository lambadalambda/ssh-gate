// Package policy decides whether a grant allows a single sign request.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"sshgate/internal/sigdata"
)

// Grant is what one agent socket may do, until Expires.
type Grant struct {
	Name     string
	Expires  time.Time
	Keys     []ssh.PublicKey
	HostKeys []ssh.PublicKey
	// Users limits the remote user name for logins. Empty means any user.
	Users []string
	// Namespaces lists the allowed SSHSIG namespaces, e.g. "git".
	Namespaces []string
}

// Conn is the state of one client connection to the agent socket.
type Conn struct {
	// Bind is the last verified session-bind on this connection.
	Bind *sigdata.SessionBind
	// Poisoned, if set, is the reason why this connection may not sign.
	Poisoned string
}

// HasKey reports whether key is part of the grant.
func (g Grant) HasKey(key ssh.PublicKey) bool {
	return containsKey(g.Keys, key)
}

// Decide returns nil if the grant allows signing data with key, or an error
// that explains the denial.
func Decide(g Grant, now time.Time, c Conn, key ssh.PublicKey, data []byte) error {
	if !now.Before(g.Expires) {
		return errors.New("grant expired")
	}
	if !g.HasKey(key) {
		return errors.New("key not in grant")
	}
	if c.Poisoned != "" {
		return fmt.Errorf("connection refused: %s", c.Poisoned)
	}
	if c.Bind != nil && c.Bind.Forwarding {
		return errors.New("connection refused: forwarded agent connection")
	}
	req, err := sigdata.Parse(data)
	if err != nil {
		return err
	}
	switch r := req.(type) {
	case sigdata.SSHSig:
		if !slices.Contains(g.Namespaces, r.Namespace) {
			return fmt.Errorf("namespace %q not allowed", r.Namespace)
		}
		return nil
	case sigdata.UserAuth:
		return decideLogin(g, c, key, r)
	default:
		return errors.New("unrecognised sign request")
	}
}

func decideLogin(g Grant, c Conn, key ssh.PublicKey, r sigdata.UserAuth) error {
	if c.Bind == nil {
		return errors.New("login without session-bind (needs OpenSSH 8.9 or newer)")
	}
	if !bytes.Equal(r.SessionID, c.Bind.SessionID) {
		return errors.New("session ID does not match session-bind")
	}
	if !containsKey(g.HostKeys, c.Bind.HostKey) {
		return fmt.Errorf("host key %s not allowed", ssh.FingerprintSHA256(c.Bind.HostKey))
	}
	if r.HostKey != nil && !keyEqual(r.HostKey, c.Bind.HostKey) {
		return errors.New("hostbound host key does not match session-bind")
	}
	if !keyEqual(r.Key, key) {
		return errors.New("userauth key differs from signing key")
	}
	if len(g.Users) > 0 && !slices.Contains(g.Users, r.User) {
		return fmt.Errorf("user %q not allowed", r.User)
	}
	return nil
}

func keyEqual(a, b ssh.PublicKey) bool {
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func containsKey(keys []ssh.PublicKey, key ssh.PublicKey) bool {
	return slices.ContainsFunc(keys, func(k ssh.PublicKey) bool { return keyEqual(k, key) })
}
