// Package sigdata classifies the data that an ssh-agent client asks to sign.
//
// Only two formats are recognised:
//   - SSH user authentication requests (RFC 4252 section 7, plus the OpenSSH
//     "publickey-hostbound-v00@openssh.com" variant), as sent by ssh(1).
//   - SSHSIG blobs (OpenSSH PROTOCOL.sshsig), as sent by ssh-keygen -Y sign,
//     which git uses for commit signing.
//
// Everything else is an error, so callers can deny by default.
package sigdata

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	msgUserAuthRequest = 50
	serviceConnection  = "ssh-connection"
	methodPublicKey    = "publickey"
	methodHostbound    = "publickey-hostbound-v00@openssh.com"
	sshsigMagic        = "SSHSIG"
	// maxSessionIDLen is SSH_DIGEST_MAX_LENGTH in OpenSSH.
	maxSessionIDLen = 64
)

// sshsigHashLen lists the hash algorithms that PROTOCOL.sshsig allows.
var sshsigHashLen = map[string]int{"sha256": 32, "sha512": 64}

// Request is either UserAuth or SSHSig.
type Request interface{ isRequest() }

// UserAuth is a signature request for SSH public key user authentication.
type UserAuth struct {
	SessionID []byte
	User      string
	Service   string
	Key       ssh.PublicKey
	// HostKey is set only for the hostbound method.
	HostKey ssh.PublicKey
}

// SSHSig is a signature request for an SSHSIG blob (e.g. git commit signing).
type SSHSig struct {
	Namespace string
	HashAlg   string
}

func (UserAuth) isRequest() {}
func (SSHSig) isRequest()   {}

// Parse classifies data. It returns an error for anything it does not
// recognise completely.
func Parse(data []byte) (Request, error) {
	if bytes.HasPrefix(data, []byte(sshsigMagic)) {
		return parseSSHSig(data[len(sshsigMagic):])
	}
	return parseUserAuth(data)
}

func parseSSHSig(data []byte) (Request, error) {
	var m struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}
	if err := ssh.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("sshsig: %w", err)
	}
	if n, ok := sshsigHashLen[m.HashAlg]; !ok || len(m.Hash) != n {
		return nil, fmt.Errorf("sshsig: bad hash %q of %d bytes", m.HashAlg, len(m.Hash))
	}
	return SSHSig{Namespace: m.Namespace, HashAlg: m.HashAlg}, nil
}

func parseUserAuth(data []byte) (Request, error) {
	var m struct {
		SessionID  []byte
		Msg        byte
		User       string
		Service    string
		Method     string
		SigFollows byte
		Algo       string
		Key        []byte
		Rest       []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unrecognised sign request: %w", err)
	}
	if m.Msg != msgUserAuthRequest || m.SigFollows != 1 || len(m.SessionID) > maxSessionIDLen {
		return nil, errors.New("unrecognised sign request")
	}
	if m.Service != serviceConnection {
		return nil, fmt.Errorf("userauth: unexpected service %q", m.Service)
	}
	key, err := ssh.ParsePublicKey(m.Key)
	if err != nil {
		return nil, fmt.Errorf("userauth key: %w", err)
	}
	if !algoMatchesKeyType(m.Algo, key.Type()) {
		return nil, fmt.Errorf("userauth: algorithm %q does not match key type %q", m.Algo, key.Type())
	}
	ua := UserAuth{SessionID: m.SessionID, User: m.User, Service: m.Service, Key: key}
	switch m.Method {
	case methodPublicKey:
		if len(m.Rest) != 0 {
			return nil, errors.New("userauth: trailing data")
		}
	case methodHostbound:
		var h struct{ HostKey []byte }
		if err := ssh.Unmarshal(m.Rest, &h); err != nil {
			return nil, fmt.Errorf("userauth host key: %w", err)
		}
		if ua.HostKey, err = ssh.ParsePublicKey(h.HostKey); err != nil {
			return nil, fmt.Errorf("userauth host key: %w", err)
		}
	default:
		return nil, fmt.Errorf("userauth: unsupported method %q", m.Method)
	}
	return ua, nil
}

// algoMatchesKeyType reports whether a userauth signature algorithm belongs
// to the key type. RSA keys sign with rsa-sha2-256 and rsa-sha2-512.
func algoMatchesKeyType(algo, keyType string) bool {
	for _, p := range []string{"rsa-sha2-256", "rsa-sha2-512"} {
		if rest, ok := strings.CutPrefix(algo, p); ok {
			algo = "ssh-rsa" + rest
		}
	}
	return algo == keyType
}

// SessionBind is a verified session-bind@openssh.com extension message.
type SessionBind struct {
	HostKey    ssh.PublicKey
	SessionID  []byte
	Forwarding bool
}

// ParseSessionBind parses the contents of a session-bind@openssh.com
// extension and verifies the host key's signature over the session ID.
func ParseSessionBind(contents []byte) (SessionBind, error) {
	var m struct {
		HostKey, SessionID, Sig []byte
		Forwarding              bool
	}
	if err := ssh.Unmarshal(contents, &m); err != nil {
		return SessionBind{}, fmt.Errorf("session-bind: %w", err)
	}
	if len(m.SessionID) > maxSessionIDLen {
		return SessionBind{}, errors.New("session-bind: session ID too long")
	}
	hostKey, err := ssh.ParsePublicKey(m.HostKey)
	if err != nil {
		return SessionBind{}, fmt.Errorf("session-bind host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(m.Sig, &sig); err != nil {
		return SessionBind{}, fmt.Errorf("session-bind signature: %w", err)
	}
	if err := hostKey.Verify(m.SessionID, &sig); err != nil {
		return SessionBind{}, fmt.Errorf("session-bind signature: %w", err)
	}
	return SessionBind{HostKey: hostKey, SessionID: m.SessionID, Forwarding: m.Forwarding}, nil
}
