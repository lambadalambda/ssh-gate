// Command ssh-grant asks the SSH agent for a grant before the key is used.
// See internal/grantreq for the request format.
package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/grantreq"
)

func main() {
	req, err := grantreq.ParseArgs(os.Args[1:], os.Getenv, os.ReadFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant: %v\n\n%s", err, grantreq.Usage)
		os.Exit(2)
	}
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		fmt.Fprintln(os.Stderr, "ssh-grant: SSH_AUTH_SOCK is not set")
		os.Exit(2)
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh-grant: agent: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	if _, err := agent.NewClient(conn).Extension(grantreq.ExtensionName, req.Encode()); err != nil {
		// The agent answers every refusal the same way: denied, timed out,
		// unknown host, or no support for grant requests.
		fmt.Fprintln(os.Stderr, "ssh-grant: not granted (denied, timed out, host not in known_hosts, or the agent does not support grant requests)")
		os.Exit(1)
	}
	fmt.Println("granted")
}
