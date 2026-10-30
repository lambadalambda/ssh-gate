// Package grantreq builds request-grant@heldscal.la agent extension requests.
package grantreq

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// ExtensionName is the agent extension that the Secretive fork handles.
const ExtensionName = "request-grant@heldscal.la"

// Request is a grant request. Fields that do not belong to Kind are empty.
type Request struct {
	KeyBlob   []byte
	Kind      string // "login" or "sign"
	Host      string
	Port      uint32
	User      string
	Namespace string
	Seconds   uint32
	Reason    string
}

// Encode returns the extension contents (without the extension name).
func (r Request) Encode() []byte {
	return ssh.Marshal(struct {
		KeyBlob    []byte
		Kind, Host string
		Port       uint32
		User, NS   string
		Seconds    uint32
		Reason     string
	}{r.KeyBlob, r.Kind, r.Host, r.Port, r.User, r.Namespace, r.Seconds, r.Reason})
}

// Usage is the command line help.
const Usage = `usage:
  ssh-grant login [user@]host[:port] [--for 1h] [--reason "..."] [--key key.pub]
  ssh-grant sign [--namespace git] [--for 1h] [--reason "..."] [--key key.pub]
  ssh-grant ssh [--for 1h] [--reason "..."] [--] <ssh arguments>

Asks the SSH agent (SSH_AUTH_SOCK) for a grant before the key is used. The
user approves in a window. Exit status 0 if granted, 1 if not, 2 on usage
errors. "ssh-grant ssh" asks for the destination that ssh would use (ssh -G)
and then runs ssh with the arguments, also if not granted.
`

// ParseArgs parses the command line (without the program name). Flags may
// come before or after the positional arguments.
func ParseArgs(args []string, getenv func(string) string, readFile func(string) ([]byte, error)) (Request, error) {
	if len(args) == 0 {
		return Request{}, errors.New("missing command")
	}
	r := Request{Kind: args[0]}
	if r.Kind != "login" && r.Kind != "sign" {
		return r, fmt.Errorf("unknown command %q", r.Kind)
	}
	fs := flag.NewFlagSet("ssh-grant "+r.Kind, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	duration := fs.Duration("for", time.Hour, "how long the grant should last")
	fs.StringVar(&r.Reason, "reason", "", "why the grant is needed (shown to the user)")
	keyFile := fs.String("key", "", "public key file (default: the agent's first key)")
	namespace := fs.String("namespace", "git", "SSHSIG namespace (sign only)")

	var positional []string
	rest := args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			return r, err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	if *duration <= 0 || duration.Seconds() > math.MaxUint32 {
		return r, errors.New("--for must be positive")
	}
	r.Seconds = uint32(duration.Seconds())
	if *keyFile != "" {
		data, err := readFile(*keyFile)
		if err != nil {
			return r, err
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return r, fmt.Errorf("%s: %w", *keyFile, err)
		}
		r.KeyBlob = key.Marshal()
	}

	switch r.Kind {
	case "login":
		if len(positional) != 1 {
			return r, errors.New("login needs exactly one [user@]host[:port]")
		}
		return parseDestination(r, positional[0], getenv("USER"))
	default:
		if len(positional) != 0 {
			return r, fmt.Errorf("unexpected argument %q", positional[0])
		}
		if *namespace == "" {
			return r, errors.New("--namespace must not be empty")
		}
		r.Namespace = *namespace
		return r, nil
	}
}

func parseDestination(r Request, dest, defaultUser string) (Request, error) {
	r.User = defaultUser
	if at := strings.LastIndex(dest, "@"); at >= 0 {
		r.User, dest = dest[:at], dest[at+1:]
	}
	r.Host, r.Port = dest, 22
	if host, port, err := net.SplitHostPort(dest); err == nil {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return r, fmt.Errorf("invalid port %q", port)
		}
		r.Host, r.Port = host, uint32(n)
	}
	if r.User == "" || r.Host == "" {
		return r, errors.New("missing user or host")
	}
	return r, nil
}
