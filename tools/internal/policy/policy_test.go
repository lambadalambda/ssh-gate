package policy

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"sshgate/internal/sigdata"
	"sshgate/internal/testutil"
)

var (
	newKey   = testutil.NewPublicKey
	userAuth = testutil.UserAuth
	sshsig   = testutil.SSHSig
)

type fixture struct {
	grant   Grant
	key     ssh.PublicKey
	host    ssh.PublicKey
	now     time.Time
	boundTo Conn
}

func setup(t *testing.T) fixture {
	key, host := newKey(t), newKey(t)
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	g := Grant{
		Name:       "test",
		Expires:    now.Add(time.Hour),
		Keys:       []ssh.PublicKey{key},
		HostKeys:   []ssh.PublicKey{host},
		Users:      []string{"git"},
		Namespaces: []string{"git"},
	}
	conn := Conn{Bind: &sigdata.SessionBind{HostKey: host, SessionID: []byte("sid")}}
	return fixture{g, key, host, now, conn}
}

func wantDeny(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("allowed, want deny containing %q", reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("err = %q, want it to contain %q", err, reason)
	}
}

func TestLoginAllowed(t *testing.T) {
	f := setup(t)
	if err := Decide(f.grant, f.now, f.boundTo, f.key, userAuth([]byte("sid"), "git", f.key, nil)); err != nil {
		t.Fatal(err)
	}
	if err := Decide(f.grant, f.now, f.boundTo, f.key, userAuth([]byte("sid"), "git", f.key, f.host)); err != nil {
		t.Fatalf("hostbound: %v", err)
	}
}

func TestLoginAnyUserWhenUsersEmpty(t *testing.T) {
	f := setup(t)
	f.grant.Users = nil
	if err := Decide(f.grant, f.now, f.boundTo, f.key, userAuth([]byte("sid"), "root", f.key, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestLoginDenied(t *testing.T) {
	other := newKey(t)
	cases := []struct {
		name   string
		mutate func(*fixture) []byte
		reason string
	}{
		{"expired", func(f *fixture) []byte {
			f.now = f.grant.Expires
			return userAuth([]byte("sid"), "git", f.key, nil)
		}, "expired"},
		{"key not in grant", func(f *fixture) []byte {
			f.key = other
			return userAuth([]byte("sid"), "git", other, nil)
		}, "key not in grant"},
		{"no bind", func(f *fixture) []byte {
			f.boundTo = Conn{}
			return userAuth([]byte("sid"), "git", f.key, nil)
		}, "session-bind"},
		{"poisoned", func(f *fixture) []byte {
			f.boundTo.Poisoned = "forwarded"
			return userAuth([]byte("sid"), "git", f.key, nil)
		}, "forwarded"},
		{"session mismatch", func(f *fixture) []byte {
			return userAuth([]byte("other"), "git", f.key, nil)
		}, "session"},
		{"host not allowed", func(f *fixture) []byte {
			f.boundTo.Bind.HostKey = other
			return userAuth([]byte("sid"), "git", f.key, nil)
		}, "host key"},
		{"hostbound mismatch", func(f *fixture) []byte {
			return userAuth([]byte("sid"), "git", f.key, other)
		}, "host key"},
		{"user", func(f *fixture) []byte {
			return userAuth([]byte("sid"), "root", f.key, nil)
		}, "user"},
		{"signed key differs from userauth key", func(f *fixture) []byte {
			return userAuth([]byte("sid"), "git", other, nil)
		}, "key"},
		{"forwarding bind", func(f *fixture) []byte {
			f.boundTo.Bind.Forwarding = true
			return userAuth([]byte("sid"), "git", f.key, nil)
		}, "forwarded"},
		{"garbage", func(f *fixture) []byte { return []byte("hello") }, "unrecognised"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setup(t)
			data := c.mutate(&f)
			wantDeny(t, Decide(f.grant, f.now, f.boundTo, f.key, data), c.reason)
		})
	}
}

func TestGitSigning(t *testing.T) {
	f := setup(t)
	if err := Decide(f.grant, f.now, Conn{}, f.key, sshsig("git")); err != nil {
		t.Fatal(err)
	}
	wantDeny(t, Decide(f.grant, f.now, Conn{}, f.key, sshsig("file")), "namespace")
	wantDeny(t, Decide(f.grant, f.now, Conn{Poisoned: "forwarded"}, f.key, sshsig("git")), "forwarded")
	fwd := Conn{Bind: &sigdata.SessionBind{HostKey: f.host, SessionID: []byte("sid"), Forwarding: true}}
	wantDeny(t, Decide(f.grant, f.now, fwd, f.key, sshsig("git")), "forwarded")
	f.grant.Namespaces = nil
	wantDeny(t, Decide(f.grant, f.now, Conn{}, f.key, sshsig("git")), "namespace")
}

func TestVisible(t *testing.T) {
	f := setup(t)
	if !f.grant.HasKey(f.key) || f.grant.HasKey(newKey(t)) {
		t.Fatal("HasKey wrong")
	}
}
