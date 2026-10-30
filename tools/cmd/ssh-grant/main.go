// Command ssh-grant asks the SSH agent for a grant before the key is used.
// See internal/grantreq for the request format.
//
// "ssh-grant ssh [--for D] [--reason R] [--] <ssh args>" requests a login
// grant for the destination that ssh would use, then runs ssh.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/grantreq"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "ssh" {
		os.Exit(sshCommand(os.Args[2:]))
	}
	req, err := grantreq.ParseArgs(os.Args[1:], os.Getenv, os.ReadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant: %v\n\n%s", err, grantreq.Usage)
		os.Exit(2)
	}
	if err := send(req, os.Getenv("SSH_AUTH_SOCK")); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("granted")
}

// send asks the agent at sock for the grant.
func send(req grantreq.Request, sock string) error {
	if sock == "" {
		return fmt.Errorf("SSH_AUTH_SOCK is not set")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	defer conn.Close()
	if _, err := agent.NewClient(conn).Extension(grantreq.ExtensionName, req.Encode()); err != nil {
		// The agent answers every refusal the same way: denied, timed out,
		// unknown host, or no support for grant requests.
		return fmt.Errorf("not granted (denied, timed out, host not in known_hosts, or the agent does not support grant requests)")
	}
	return nil
}

// sshCommand requests a login grant for ssh's destination and then replaces
// itself with ssh. ssh runs also without a grant, for password logins and
// first connections to unknown hosts.
func sshCommand(args []string) int {
	duration, reason, sshArgs, err := grantreq.SplitSSHArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant ssh: %v\n\n%s", err, grantreq.Usage)
		return 2
	}
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ssh-grant ssh: ssh not found")
		return 1
	}
	if out, err := exec.Command(sshPath, append([]string{"-G"}, sshArgs...)...).Output(); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant ssh: ssh -G: %v; continuing without grant\n", err)
	} else if d, err := grantreq.ParseSSHConfig(string(out), os.Getenv("HOME")); err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant ssh: %v; continuing without grant\n", err)
	} else {
		if reason == "" {
			reason = fmt.Sprintf("ssh %s@%s", d.User, d.Host)
		}
		// Ask the agent that ssh will use.
		sock := d.Agent
		if sock == "" {
			sock = os.Getenv("SSH_AUTH_SOCK")
		}
		req := grantreq.Request{Kind: "login", Host: d.Host, Port: d.Port, User: d.User, Seconds: uint32(duration.Seconds()), Reason: reason}
		if err := send(req, sock); err != nil {
			fmt.Fprintf(os.Stderr, "ssh-grant ssh: %v; continuing without grant\n", err)
		}
	}
	return execSSH(sshPath, sshArgs)
}

func execSSH(path string, args []string) int {
	err := syscall.Exec(path, append([]string{"ssh"}, args...), os.Environ())
	fmt.Fprintf(os.Stderr, "ssh-grant ssh: %v\n", err)
	return 1
}
