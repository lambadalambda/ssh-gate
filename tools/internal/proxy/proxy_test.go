package proxy

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/policy"
	"sshgate/internal/testutil"
)

// spy wraps the upstream keyring and records what reaches it.
type spy struct {
	agent.ExtendedAgent
	extensions []string
	signErr    error
}

func (s *spy) Extension(t string, c []byte) ([]byte, error) {
	s.extensions = append(s.extensions, t)
	return s.ExtendedAgent.Extension(t, c)
}

func (s *spy) SignWithFlags(k ssh.PublicKey, d []byte, f agent.SignatureFlags) (*ssh.Signature, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return s.ExtendedAgent.SignWithFlags(k, d, f)
}

type env struct {
	client   agent.ExtendedAgent
	upstream *spy
	logs     *bytes.Buffer
	granted  ssh.Signer
	other    ssh.Signer
	host     ssh.Signer
	now      *time.Time
}

// start serves a proxy for one connection, with an in-memory upstream
// keyring that holds a granted and a non-granted key.
func start(t *testing.T) env {
	t.Helper()
	grantedPriv, granted := testutil.NewKey(t)
	otherPriv, other := testutil.NewKey(t)
	_, host := testutil.NewKey(t)

	keyring := agent.NewKeyring()
	for _, k := range []any{grantedPriv, otherPriv} {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	g := policy.Grant{
		Name:       "test",
		Expires:    now.Add(time.Hour),
		Keys:       []ssh.PublicKey{granted.PublicKey()},
		HostKeys:   []ssh.PublicKey{host.PublicKey()},
		Namespaces: []string{"git"},
	}
	upstream := &spy{ExtendedAgent: keyring.(agent.ExtendedAgent)}
	e := env{upstream: upstream, logs: &bytes.Buffer{}, granted: granted, other: other, host: host, now: &now}

	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close() })
	log := slog.New(slog.NewTextHandler(e.logs, nil))
	p := New(upstream, g, func() time.Time { return *e.now }, log)
	go agent.ServeAgent(p, serverSide)
	e.client = agent.NewClient(clientSide)
	return e
}

func TestListShowsOnlyGrantedKeys(t *testing.T) {
	e := start(t)
	keys, err := e.client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || string(keys[0].Blob) != string(e.granted.PublicKey().Marshal()) {
		t.Fatalf("List = %v, want only the granted key", keys)
	}
}

func TestListEmptyAfterExpiry(t *testing.T) {
	e := start(t)
	*e.now = e.now.Add(2 * time.Hour)
	keys, err := e.client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("List = %v, want empty", keys)
	}
}

func TestGitSignature(t *testing.T) {
	e := start(t)
	data := testutil.SSHSig("git")
	sig, err := e.client.Sign(e.granted.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.granted.PublicKey().Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Sign(e.granted.PublicKey(), testutil.SSHSig("file")); err == nil {
		t.Fatal("namespace file should be denied")
	}
	if _, err := e.client.Sign(e.other.PublicKey(), data); err == nil {
		t.Fatal("non-granted key should be denied")
	}
}

func TestLoginNeedsBind(t *testing.T) {
	e := start(t)
	sid := []byte("session-1")
	data := testutil.UserAuth(sid, "git", e.granted.PublicKey(), nil)
	if _, err := e.client.Sign(e.granted.PublicKey(), data); err == nil {
		t.Fatal("login without session-bind should be denied")
	}
	if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, sid, sid, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Sign(e.granted.PublicKey(), data); err != nil {
		t.Fatalf("login after bind: %v", err)
	}
}

func TestBadBindPoisonsConnection(t *testing.T) {
	cases := map[string]func(e env, sid []byte) []byte{
		"forwarded": func(e env, sid []byte) []byte {
			return testutil.SessionBind(t, e.host, sid, sid, true)
		},
		"bad signature": func(e env, sid []byte) []byte {
			return testutil.SessionBind(t, e.host, sid, []byte("other"), false)
		},
		"garbage": func(env, []byte) []byte { return []byte("garbage") },
		"same session, other host": func(e env, sid []byte) []byte {
			_, other := testutil.NewKey(t)
			if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, sid, sid, false)); err != nil {
				t.Fatal(err)
			}
			return testutil.SessionBind(t, other, sid, sid, false)
		},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			e := start(t)
			sid := []byte("session-1")
			if _, err := e.client.Extension(sessionBindExt, payload(e, sid)); err == nil {
				t.Fatal("bind should fail")
			}
			if _, err := e.client.Sign(e.granted.PublicKey(), testutil.SSHSig("git")); err == nil {
				t.Fatal("poisoned connection should not sign")
			}
			if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, sid, sid, false)); err == nil {
				t.Fatal("valid bind must not clear the poison")
			}
			if keys, _ := e.client.List(); len(keys) != 0 {
				t.Fatal("poisoned connection should list no keys")
			}
		})
	}
}

func TestSecondBindPoisons(t *testing.T) {
	e := start(t)
	a, b := []byte("session-a"), []byte("session-b")
	if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, a, a, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, b, b, false)); err == nil {
		t.Fatal("second bind should fail")
	}
	if _, err := e.client.Sign(e.granted.PublicKey(), testutil.UserAuth(a, "git", e.granted.PublicKey(), nil)); err == nil {
		t.Fatal("poisoned connection should not sign")
	}
}

func TestRepeatedBindAllowed(t *testing.T) {
	e := start(t)
	sid := []byte("session-1")
	for range 2 {
		if _, err := e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, sid, sid, false)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.client.Sign(e.granted.PublicKey(), testutil.UserAuth(sid, "git", e.granted.PublicKey(), nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.logs.String(), ssh.FingerprintSHA256(e.host.PublicKey())) {
		t.Errorf("allowed login does not log the host key:\n%s", e.logs)
	}
}

func TestDeniedRequestIsDescribed(t *testing.T) {
	e := start(t)
	e.client.Sign(e.granted.PublicKey(), testutil.SSHSig("file"))
	if !strings.Contains(e.logs.String(), "namespace=file") {
		t.Errorf("denied request not described in log:\n%s", e.logs)
	}
}

func TestUpstreamFailureLogged(t *testing.T) {
	e := start(t)
	e.upstream.signErr = errors.New("touch id cancelled")
	if _, err := e.client.Sign(e.granted.PublicKey(), testutil.SSHSig("git")); err == nil {
		t.Fatal("expected upstream error")
	}
	if !strings.Contains(e.logs.String(), "touch id cancelled") {
		t.Errorf("upstream error not logged:\n%s", e.logs)
	}
}

func TestExtensionsNotForwarded(t *testing.T) {
	e := start(t)
	if _, err := e.client.Extension("query", nil); err == nil {
		t.Fatal("unknown extension should fail")
	}
	sid := []byte("s")
	e.client.Extension(sessionBindExt, testutil.SessionBind(t, e.host, sid, sid, false))
	if len(e.upstream.extensions) != 0 {
		t.Fatalf("extensions reached upstream: %v", e.upstream.extensions)
	}
}

func TestMutationsDenied(t *testing.T) {
	e := start(t)
	_, extra := testutil.NewKey(t)
	if err := e.client.Add(agent.AddedKey{PrivateKey: extra}); err == nil {
		t.Error("Add should be denied")
	}
	if err := e.client.Remove(e.granted.PublicKey()); err == nil {
		t.Error("Remove should be denied")
	}
	if err := e.client.RemoveAll(); err == nil {
		t.Error("RemoveAll should be denied")
	}
	if err := e.client.Lock([]byte("x")); err == nil {
		t.Error("Lock should be denied")
	}
	if keys, _ := e.upstream.List(); len(keys) != 2 {
		t.Errorf("upstream changed: %d keys", len(keys))
	}
}
