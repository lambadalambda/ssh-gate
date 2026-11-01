package sigdata

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/ssh"

	"sshgate/internal/testutil"
)

func TestParseUserAuth(t *testing.T) {
	key := testutil.NewPublicKey(t)
	got, err := Parse(testutil.UserAuth([]byte("sid"), "git", key, nil))
	if err != nil {
		t.Fatal(err)
	}
	ua, ok := got.(UserAuth)
	if !ok {
		t.Fatalf("got %T, want UserAuth", got)
	}
	if string(ua.SessionID) != "sid" || ua.User != "git" || ua.HostKey != nil {
		t.Errorf("unexpected %+v", ua)
	}
	if !bytes.Equal(ua.Key.Marshal(), key.Marshal()) {
		t.Error("key mismatch")
	}
}

func TestParseUserAuthHostbound(t *testing.T) {
	key, host := testutil.NewPublicKey(t), testutil.NewPublicKey(t)
	got, err := Parse(testutil.UserAuth([]byte("sid"), "root", key, host))
	if err != nil {
		t.Fatal(err)
	}
	ua := got.(UserAuth)
	if ua.HostKey == nil || !bytes.Equal(ua.HostKey.Marshal(), host.Marshal()) {
		t.Error("host key not parsed")
	}
}

func TestParseUserAuthInvalid(t *testing.T) {
	key, host := testutil.NewPublicKey(t), testutil.NewPublicKey(t)
	cases := map[string]func(m *testutil.UserAuthMsg){
		"trailing data":      func(m *testutil.UserAuthMsg) { m.Rest = []byte{0, 0, 0, 0} },
		"wrong message type": func(m *testutil.UserAuthMsg) { m.Msg = 51 },
		"wrong service":      func(m *testutil.UserAuthMsg) { m.Service = "ssh-userauth" },
		"password method":    func(m *testutil.UserAuthMsg) { m.Method = "password" },
		"no signature":       func(m *testutil.UserAuthMsg) { m.SigFollows = 0 },
		"sig-follows not 1":  func(m *testutil.UserAuthMsg) { m.SigFollows = 2 },
		"algo mismatch":      func(m *testutil.UserAuthMsg) { m.Algo = "ssh-rsa" },
		"long session ID":    func(m *testutil.UserAuthMsg) { m.SessionID = make([]byte, 65) },
		"hostbound without host key": func(m *testutil.UserAuthMsg) {
			m.Method = methodHostbound
		},
		"hostbound trailing data": func(m *testutil.UserAuthMsg) {
			m.Method = methodHostbound
			m.Rest = append(ssh.Marshal(struct{ H []byte }{host.Marshal()}), 0)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testutil.NewUserAuthMsg([]byte("sid"), "git", key, nil)
			mutate(&m)
			if _, err := Parse(ssh.Marshal(m)); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestAlgoMatchesKeyType(t *testing.T) {
	cases := []struct {
		algo, keyType string
		want          bool
	}{
		{"ssh-ed25519", "ssh-ed25519", true},
		{"rsa-sha2-256", "ssh-rsa", true},
		{"rsa-sha2-512", "ssh-rsa", true},
		{"ssh-rsa", "ssh-rsa", true},
		{"rsa-sha2-256-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com", true},
		{"rsa-sha2-256", "ssh-ed25519", false},
		{"ssh-ed25519", "ssh-rsa", false},
	}
	for _, c := range cases {
		if got := algoMatchesKeyType(c.algo, c.keyType); got != c.want {
			t.Errorf("algoMatchesKeyType(%q, %q) = %v", c.algo, c.keyType, got)
		}
	}
}

func TestParseSSHSig(t *testing.T) {
	for _, alg := range []struct {
		name string
		len  int
	}{{"sha512", 64}, {"sha256", 32}} {
		got, err := Parse(testutil.SSHSigRaw("git", alg.name, alg.len))
		if err != nil {
			t.Fatalf("%s: %v", alg.name, err)
		}
		if sig, ok := got.(SSHSig); !ok || sig.Namespace != "git" {
			t.Fatalf("%s: got %+v", alg.name, got)
		}
	}
}

func TestParseSSHSigInvalid(t *testing.T) {
	cases := map[string][]byte{
		"magic only":       []byte("SSHSIG"),
		"trailing data":    append(testutil.SSHSig("git"), 0),
		"unknown hash alg": testutil.SSHSigRaw("git", "md5", 16),
		"wrong hash len":   testutil.SSHSigRaw("git", "sha512", 32),
	}
	for name, blob := range cases {
		if _, err := Parse(blob); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseUnknown(t *testing.T) {
	for _, blob := range [][]byte{nil, []byte("hello"), {0, 0, 0, 3, 'a', 'b', 'c', 1}} {
		if _, err := Parse(blob); err == nil {
			t.Errorf("Parse(%q) should fail", blob)
		}
	}
}

func TestParseSessionBind(t *testing.T) {
	_, host := testutil.NewKey(t)
	for _, fwd := range []bool{false, true} {
		b, err := ParseSessionBind(testutil.SessionBind(t, host, []byte("sid"), []byte("sid"), fwd))
		if err != nil {
			t.Fatal(err)
		}
		if string(b.SessionID) != "sid" || b.Forwarding != fwd {
			t.Errorf("unexpected %+v", b)
		}
		if !bytes.Equal(b.HostKey.Marshal(), host.PublicKey().Marshal()) {
			t.Error("host key mismatch")
		}
	}
}

func TestParseSessionBindInvalid(t *testing.T) {
	_, host := testutil.NewKey(t)
	_, other := testutil.NewKey(t)
	cases := map[string][]byte{
		"signature over other data": testutil.SessionBind(t, host, []byte("sid"), []byte("other"), false),
		"long session ID":           testutil.SessionBind(t, host, make([]byte, 65), make([]byte, 65), false),
		"garbage":                   []byte("garbage"),
	}
	// Signed by another key than the host key in the message.
	m := testutil.SessionBind(t, other, []byte("sid"), []byte("sid"), false)
	var parsed struct {
		HostKey, SessionID, Sig []byte
		Forwarding              bool
	}
	if err := ssh.Unmarshal(m, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.HostKey = host.PublicKey().Marshal()
	cases["signed by other key"] = ssh.Marshal(parsed)

	for name, payload := range cases {
		if _, err := ParseSessionBind(payload); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
