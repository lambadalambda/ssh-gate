// Package e2e tests sshgate against the real OpenSSH client, sshd and
// ssh-keygen. It runs two sshd processes with different host keys in a
// podman container and grants access to only one of them.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/cli"
	"sshgate/internal/policy"
	"sshgate/internal/server"
)

// sshdScript runs two sshd processes with different host keys in an Alpine
// container. Keys come in through the environment, because the podman VM
// cannot see /tmp on macOS.
const sshdScript = `set -e
apk add -q openssh-server >/dev/null
sed -i 's/^root:[^:]*:/root:*:/' /etc/shadow
mkdir -p /root/.ssh
printf '%s\n' "$AUTH" > /root/.ssh/authorized_keys
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
for h in A B; do
  eval "printf '%s\n' \"\$HOST$h\"" > /etc/ssh/host$h; chmod 600 /etc/ssh/host$h
done
/usr/sbin/sshd -e -p 2201 -h /etc/ssh/hostA
exec /usr/sbin/sshd -D -e -p 2202 -h /etc/ssh/hostB
`

type fixture struct {
	dir, sock, userPub string
	logs               *syncBuffer
}

// syncBuffer is a bytes.Buffer that is safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startSSHD starts the container and returns the local ports of the sshd
// with host key hostA and the one with hostB.
func startSSHD(t *testing.T, dir string) (portA, portB int) {
	t.Helper()
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("no podman")
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	portA, portB = freePort(t), freePort(t)
	name := filepath.Base(dir)
	cmd := exec.Command("podman", "run", "--rm", "--name", name,
		"-p", fmt.Sprintf("127.0.0.1:%d:2201", portA), "-p", fmt.Sprintf("127.0.0.1:%d:2202", portB),
		"-e", "AUTH="+read("user.pub"), "-e", "HOSTA="+read("hostA"), "-e", "HOSTB="+read("hostB"),
		"docker.io/library/alpine:3", "sh", "-c", sshdScript)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stderr, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		exec.Command("podman", "rm", "-f", name).Run()
		cmd.Wait()
		if t.Failed() {
			t.Logf("sshd log:\n%s", stderr.String())
		}
	})
	for _, port := range []int{portA, portB} {
		waitForBanner(t, port, &stderr)
	}
	return portA, portB
}

// waitForBanner waits until an SSH server answers on port. The podman port
// forwarder accepts TCP connections before sshd runs, so a connect alone
// is not enough.
func waitForBanner(t *testing.T, port int, log *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
			c.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 4)
			_, err := io.ReadFull(c, buf)
			c.Close()
			if err == nil && string(buf) == "SSH-" {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sshd on port %d did not start:\n%s", port, log)
}

func setup(t *testing.T) fixture {
	if testing.Short() {
		t.Skip("e2e test skipped in -short mode")
	}
	dir, err := os.MkdirTemp("/tmp", "sshgate-e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	for _, name := range []string{"user", "hostA", "hostB"} {
		run(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, name))
	}
	userKey := filepath.Join(dir, "user")
	f := fixture{dir: dir, userPub: userKey + ".pub", logs: &syncBuffer{}}

	// Upstream: an in-memory agent with the user key.
	pemBytes, err := os.ReadFile(userKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	dial := func() (net.Conn, error) {
		c, s := net.Pipe()
		go agent.ServeAgent(keyring, s)
		return c, nil
	}

	upstreamKeys, _ := keyring.List()
	keys, err := cli.ResolveKeys([]string{f.userPub}, upstreamKeys, os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	g := policy.Grant{
		Name:       "e2e",
		Expires:    time.Now().Add(time.Hour),
		Keys:       keys,
		HostKeys:   []ssh.PublicKey{readPub(t, dir, "hostA")},
		Namespaces: []string{"git"},
	}

	f.sock = filepath.Join(dir, "grant.sock")
	l, err := server.Listen(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	log := slog.New(slog.NewTextHandler(f.logs, nil))
	go func() { server.Serve(ctx, l, dial, g, time.Now, log); close(done) }()
	t.Cleanup(func() {
		cancel()
		<-done
		if t.Failed() {
			t.Logf("sshgate log:\n%s", f.logs)
		}
	})
	return f
}

func readPub(t *testing.T, dir, name string) ssh.PublicKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func (f fixture) ssh(t *testing.T, knownHosts string, port int) error {
	t.Helper()
	cmd := exec.Command("ssh", "-F", "/dev/null",
		"-o", "IdentityAgent="+f.sock,
		"-o", "UserKnownHostsFile="+knownHosts,
		"-o", "StrictHostKeyChecking=yes",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=publickey",
		"-p", fmt.Sprint(port), "root@127.0.0.1", "true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func (f fixture) sign(namespace string) error {
	msg := filepath.Join(f.dir, "msg-"+namespace)
	if err := os.WriteFile(msg, []byte("hello"), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-f", f.userPub, "-n", namespace, msg)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+f.sock)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func TestSSHLogin(t *testing.T) {
	f := setup(t)
	portA, portB := startSSHD(t, f.dir)

	// ssh itself trusts both hosts; only sshgate tells them apart.
	knownHosts := filepath.Join(f.dir, "known_hosts")
	var kh strings.Builder
	for name, port := range map[string]int{"hostA": portA, "hostB": portB} {
		fmt.Fprintf(&kh, "[127.0.0.1]:%d %s", port, ssh.MarshalAuthorizedKey(readPub(t, f.dir, name)))
	}
	if err := os.WriteFile(knownHosts, []byte(kh.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := f.ssh(t, knownHosts, portA); err != nil {
		t.Fatalf("login to granted host failed: %v", err)
	}
	if err := f.ssh(t, knownHosts, portB); err == nil {
		t.Fatal("login to other host succeeded")
	}
	logs := f.logs.String()
	host := ssh.FingerprintSHA256(readPub(t, f.dir, "hostB"))
	if !strings.Contains(logs, "login user=root") || !strings.Contains(logs, "host key "+host+" not allowed") {
		t.Errorf("allowed login or host denial not logged:\n%s", logs)
	}
}

func TestGitSigning(t *testing.T) {
	f := setup(t)
	if err := f.sign("git"); err != nil {
		t.Fatalf("git signing failed: %v", err)
	}
	if err := f.sign("file"); err == nil {
		t.Fatal("signing in namespace file succeeded")
	}
}
