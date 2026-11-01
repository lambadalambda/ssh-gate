// Package cli turns command line arguments into the parts of a grant.
package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"sshgate/internal/policy"
)

// Options are the flags of "sshgate grant".
type Options struct {
	Name       string
	Upstream   string
	Socket     string
	KnownHosts string
	TTL        time.Duration
	Keys       []string
	Hosts      []string
	Users      []string
	Namespaces []string
}

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func flagSet(o *Options) *flag.FlagSet {
	fs := flag.NewFlagSet("sshgate grant", flag.ContinueOnError)
	fs.StringVar(&o.Name, "name", "", "grant name (letters, digits, . _ -)")
	fs.StringVar(&o.Upstream, "upstream", "", "upstream agent socket (default $SSH_AUTH_SOCK)")
	fs.StringVar(&o.Socket, "socket", "", "grant socket path (default ~/.sshgate/NAME.sock)")
	fs.StringVar(&o.KnownHosts, "known-hosts", "", "known_hosts file for --host (default ~/.ssh/known_hosts)")
	fs.DurationVar(&o.TTL, "ttl", time.Hour, "grant lifetime")
	fs.Var((*listFlag)(&o.Keys), "key", "key as SHA256 fingerprint or .pub file (repeatable)")
	fs.Var((*listFlag)(&o.Hosts), "host", "allowed host[:port], keys from known_hosts (repeatable)")
	fs.Var((*listFlag)(&o.Users), "user", "allowed remote user (repeatable, default any)")
	fs.Var((*listFlag)(&o.Namespaces), "namespace", "allowed SSHSIG namespace, e.g. git (repeatable)")
	return fs
}

// Usage returns the flag help text.
func Usage() string {
	var b strings.Builder
	fs := flagSet(&Options{})
	fs.SetOutput(&b)
	fs.PrintDefaults()
	return "usage: sshgate grant [flags]\n" + b.String()
}

// ParseArgs parses and validates the flags of "sshgate grant".
func ParseArgs(args []string, getenv func(string) string) (Options, error) {
	var o Options
	fs := flagSet(&o)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() > 0 {
		return o, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if !validName.MatchString(o.Name) {
		return o, errors.New("--name is required and may contain only letters, digits, '.', '_' and '-'")
	}
	if len(o.Keys) == 0 {
		return o, errors.New("at least one --key is required")
	}
	if len(o.Hosts) == 0 && len(o.Namespaces) == 0 {
		return o, errors.New("at least one --host or --namespace is required")
	}
	if o.TTL <= 0 {
		return o, errors.New("--ttl must be positive")
	}
	home := getenv("HOME")
	o.Upstream = firstNonEmpty(o.Upstream, getenv("SSH_AUTH_SOCK"))
	o.Socket = firstNonEmpty(o.Socket, filepath.Join(home, ".sshgate", o.Name+".sock"))
	o.KnownHosts = firstNonEmpty(o.KnownHosts, filepath.Join(home, ".ssh", "known_hosts"))
	if o.Upstream == "" {
		return o, errors.New("no --upstream and no $SSH_AUTH_SOCK")
	}
	return o, nil
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ResolveKeys turns each spec (a SHA256 fingerprint or the path of a public
// key file) into a key. Every key must be present in the upstream agent.
func ResolveKeys(specs []string, upstream []*agent.Key, readFile func(string) ([]byte, error)) ([]ssh.PublicKey, error) {
	var avail []ssh.PublicKey
	for _, k := range upstream {
		if pk, err := ssh.ParsePublicKey(k.Blob); err == nil {
			avail = append(avail, pk)
		}
	}
	var out []ssh.PublicKey
	for _, spec := range specs {
		key, err := resolveKey(spec, avail, readFile)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, nil
}

func resolveKey(spec string, avail []ssh.PublicKey, readFile func(string) ([]byte, error)) (ssh.PublicKey, error) {
	var want ssh.PublicKey
	if !strings.HasPrefix(spec, "SHA256:") {
		data, err := readFile(spec)
		if err != nil {
			return nil, err
		}
		if want, _, _, _, err = ssh.ParseAuthorizedKey(data); err != nil {
			return nil, fmt.Errorf("%s: %w", spec, err)
		}
	}
	for _, k := range avail {
		if (want == nil && ssh.FingerprintSHA256(k) == spec) || (want != nil && policy.KeyEqual(k, want)) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("key %s is not in the upstream agent", spec)
}

// HostKeys returns the keys that knownHostsPath lists for each host, without
// revoked keys. Each host must have at least one key.
func HostKeys(knownHostsPath string, hosts []string) ([]ssh.PublicKey, error) {
	check, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return nil, err
	}
	cas, err := certAuthorities(knownHostsPath)
	if err != nil {
		return nil, err
	}
	probe, err := probeKey()
	if err != nil {
		return nil, err
	}
	placeholder := &net.TCPAddr{IP: net.IPv4zero, Port: 22}
	var out []ssh.PublicKey
	for _, host := range hosts {
		addr := host
		if _, _, err := net.SplitHostPort(host); err != nil {
			addr = net.JoinHostPort(host, "22")
		}
		// No line matches the random probe key, so the KeyError lists all
		// keys for the host.
		var keyErr *knownhosts.KeyError
		if !errors.As(check(addr, placeholder, probe), &keyErr) {
			return nil, fmt.Errorf("%s: unexpected known_hosts result", host)
		}
		n := len(out)
		for _, k := range keyErr.Want {
			isCA := slices.ContainsFunc(cas, func(ca ssh.PublicKey) bool { return policy.KeyEqual(ca, k.Key) })
			if !isCA && check(addr, placeholder, k.Key) == nil {
				out = append(out, k.Key)
			}
		}
		if len(out) == n {
			return nil, fmt.Errorf("%s: no keys in %s", host, knownHostsPath)
		}
	}
	return out, nil
}

// certAuthorities returns the keys of all @cert-authority lines. knownhosts
// reports them like host keys, but sshgate pins plain host keys only.
func certAuthorities(path string) ([]ssh.PublicKey, error) {
	rest, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cas []ssh.PublicKey
	for len(rest) > 0 {
		var marker string
		var key ssh.PublicKey
		marker, _, key, _, rest, err = ssh.ParseKnownHosts(rest)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if marker == "cert-authority" {
			cas = append(cas, key)
		}
	}
	return cas, nil
}

func probeKey() (ssh.PublicKey, error) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(pub)
}
