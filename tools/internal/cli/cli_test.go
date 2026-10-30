package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"sshgate/internal/policy"
	"sshgate/internal/testutil"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

var home = env(map[string]string{"HOME": "/h", "SSH_AUTH_SOCK": "/up.sock"})

func TestParseArgsDefaults(t *testing.T) {
	o, err := ParseArgs([]string{"--name", "claude", "--key", "SHA256:x", "--host", "example.com"}, home)
	if err != nil {
		t.Fatal(err)
	}
	want := Options{
		Name: "claude", Upstream: "/up.sock", Socket: "/h/.sshgate/claude.sock",
		KnownHosts: "/h/.ssh/known_hosts", TTL: time.Hour,
		Keys: []string{"SHA256:x"}, Hosts: []string{"example.com"},
	}
	if o.Name != want.Name || o.Upstream != want.Upstream || o.Socket != want.Socket ||
		o.KnownHosts != want.KnownHosts || o.TTL != want.TTL ||
		strings.Join(o.Keys, ",") != "SHA256:x" || strings.Join(o.Hosts, ",") != "example.com" {
		t.Errorf("got %+v", o)
	}
}

func TestParseArgsRepeatable(t *testing.T) {
	o, err := ParseArgs([]string{"--name", "a", "--key", "k1", "--key", "k2", "--namespace", "git",
		"--user", "git", "--user", "deploy", "--ttl", "4h", "--upstream", "/s", "--socket", "/t/a.sock"}, home)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Keys) != 2 || len(o.Users) != 2 || o.Namespaces[0] != "git" || o.TTL != 4*time.Hour ||
		o.Upstream != "/s" || o.Socket != "/t/a.sock" {
		t.Errorf("got %+v", o)
	}
}

func TestParseArgsErrors(t *testing.T) {
	cases := map[string][]string{
		"no name":             {"--key", "k", "--host", "h"},
		"bad name":            {"--name", "../x", "--key", "k", "--host", "h"},
		"no key":              {"--name", "a", "--host", "h"},
		"no host or ns":       {"--name", "a", "--key", "k"},
		"bad ttl":             {"--name", "a", "--key", "k", "--host", "h", "--ttl", "0s"},
		"unknown flag":        {"--name", "a", "--key", "k", "--host", "h", "--nope"},
		"positional argument": {"--name", "a", "--key", "k", "--host", "h", "extra"},
	}
	for name, args := range cases {
		if _, err := ParseArgs(args, home); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := ParseArgs([]string{"--name", "a", "--key", "k", "--host", "h"}, env(nil)); err == nil {
		t.Error("missing upstream: expected error")
	}
}

func TestResolveKeys(t *testing.T) {
	a, b := testutil.NewPublicKey(t), testutil.NewPublicKey(t)
	upstream := []*agent.Key{{Format: a.Type(), Blob: a.Marshal()}, {Format: b.Type(), Blob: b.Marshal()}}
	files := map[string][]byte{"/b.pub": ssh.MarshalAuthorizedKey(b)}
	read := func(p string) ([]byte, error) {
		if d, ok := files[p]; ok {
			return d, nil
		}
		return nil, errors.New("no such file")
	}

	keys, err := ResolveKeys([]string{ssh.FingerprintSHA256(a), "/b.pub"}, upstream, read)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !policy.KeyEqual(keys[0], a) || !policy.KeyEqual(keys[1], b) {
		t.Fatalf("got %v", keys)
	}

	c := testutil.NewPublicKey(t)
	files["/c.pub"] = ssh.MarshalAuthorizedKey(c)
	for _, spec := range []string{ssh.FingerprintSHA256(c), "/c.pub", "/missing.pub"} {
		if _, err := ResolveKeys([]string{spec}, upstream, read); err == nil {
			t.Errorf("%s: expected error", spec)
		}
	}
}

func TestHostKeys(t *testing.T) {
	plain, hashed, ported, revoked, other, ca := testutil.NewPublicKey(t), testutil.NewPublicKey(t),
		testutil.NewPublicKey(t), testutil.NewPublicKey(t), testutil.NewPublicKey(t), testutil.NewPublicKey(t)
	lines := []string{
		knownhosts.Line([]string{"example.com"}, plain),
		knownhosts.Line([]string{knownhosts.HashHostname("example.com")}, hashed),
		knownhosts.Line([]string{"example.com"}, revoked),
		"@revoked * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(revoked))),
		knownhosts.Line([]string{"[example.com]:2222"}, ported),
		knownhosts.Line([]string{"other.org"}, other),
		"@cert-authority example.com,ca.only " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca))),
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := HostKeys(path, []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !policy.KeyEqual(keys[0], plain) || !policy.KeyEqual(keys[1], hashed) {
		t.Fatalf("example.com: got %d keys", len(keys))
	}

	keys, err = HostKeys(path, []string{"example.com:2222", "other.org"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !policy.KeyEqual(keys[0], ported) || !policy.KeyEqual(keys[1], other) {
		t.Fatalf("port and second host: got %d keys", len(keys))
	}

	for _, host := range []string{"unknown.net", "ca.only"} {
		if _, err := HostKeys(path, []string{host}); err == nil {
			t.Errorf("%s: expected error", host)
		}
	}
}
