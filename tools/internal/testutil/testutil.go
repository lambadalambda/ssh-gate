// Package testutil builds keys and agent protocol payloads for tests.
package testutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	methodPublicKey = "publickey"
	methodHostbound = "publickey-hostbound-v00@openssh.com"
)

// NewKey returns a fresh ed25519 private key and its signer.
func NewKey(t testing.TB) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, s
}

// NewPublicKey returns a fresh ed25519 public key.
func NewPublicKey(t testing.TB) ssh.PublicKey {
	_, s := NewKey(t)
	return s.PublicKey()
}

// UserAuthMsg is the data that ssh(1) signs for public key authentication.
// Tests can change single fields to build invalid requests.
type UserAuthMsg struct {
	SessionID             []byte
	Msg                   byte
	User, Service, Method string
	SigFollows            byte
	Algo                  string
	Key                   []byte
	Rest                  []byte `ssh:"rest"`
}

// NewUserAuthMsg returns a valid request. A non-nil hostKey selects the
// publickey-hostbound-v00@openssh.com method.
func NewUserAuthMsg(sessionID []byte, user string, key, hostKey ssh.PublicKey) UserAuthMsg {
	m := UserAuthMsg{sessionID, 50, user, "ssh-connection", methodPublicKey, 1, key.Type(), key.Marshal(), nil}
	if hostKey != nil {
		m.Method = methodHostbound
		m.Rest = ssh.Marshal(struct{ H []byte }{hostKey.Marshal()})
	}
	return m
}

// UserAuth builds a valid userauth request, see NewUserAuthMsg.
func UserAuth(sessionID []byte, user string, key, hostKey ssh.PublicKey) []byte {
	return ssh.Marshal(NewUserAuthMsg(sessionID, user, key, hostKey))
}

// SSHSig builds the data that ssh-keygen -Y sign signs.
func SSHSig(namespace string) []byte {
	return SSHSigRaw(namespace, "sha512", 64)
}

// SSHSigRaw builds an SSHSIG blob with any hash algorithm name and length.
func SSHSigRaw(namespace, hashAlg string, hashLen int) []byte {
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", hashAlg, bytes.Repeat([]byte{1}, hashLen)})...)
}

// SessionBind builds the contents of a session-bind@openssh.com extension,
// with host's signature over signed (normally equal to sessionID).
func SessionBind(t testing.TB, host ssh.Signer, sessionID, signed []byte, forwarding bool) []byte {
	t.Helper()
	sig, err := host.Sign(rand.Reader, signed)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(struct {
		HostKey, SessionID, Sig []byte
		Forwarding              bool
	}{host.PublicKey().Marshal(), sessionID, ssh.Marshal(sig), forwarding})
}
