// Command sshgate serves a restricted ssh-agent socket for one grant.
//
//	sshgate grant --name claude --key ~/.ssh/id_ed25519.pub \
//	    --host git.example.com --user git --namespace git --ttl 4h
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"sshgate/internal/cli"
	"sshgate/internal/policy"
	"sshgate/internal/server"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "grant" {
		fmt.Fprint(os.Stderr, cli.Usage())
		os.Exit(2)
	}
	if err := grant(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "sshgate:", err)
		os.Exit(1)
	}
}

func grant(args []string) error {
	o, err := cli.ParseArgs(args, os.Getenv)
	if err != nil {
		return fmt.Errorf("%w\n\n%s", err, cli.Usage())
	}
	dial := func() (net.Conn, error) { return net.Dial("unix", o.Upstream) }

	up, err := dial()
	if err != nil {
		return fmt.Errorf("upstream agent: %w", err)
	}
	upstreamKeys, err := agent.NewClient(up).List()
	up.Close()
	if err != nil {
		return fmt.Errorf("upstream agent: %w", err)
	}
	keys, err := cli.ResolveKeys(o.Keys, upstreamKeys, os.ReadFile)
	if err != nil {
		return err
	}
	g := policy.Grant{
		Name: o.Name,
		// Round(0) drops the monotonic reading, so expiry checks use the
		// wall clock and a sleeping machine does not extend the grant.
		Expires:    time.Now().Add(o.TTL).Round(0),
		Keys:       keys,
		Users:      o.Users,
		Namespaces: o.Namespaces,
	}
	if len(o.Hosts) > 0 {
		if g.HostKeys, err = cli.HostKeys(o.KnownHosts, o.Hosts); err != nil {
			return err
		}
	}

	l, err := server.Listen(o.Socket)
	if err != nil {
		return err
	}
	// x/crypto/ssh/agent logs every refused request with the standard
	// logger. The proxy already logs them with more context.
	log.SetOutput(io.Discard)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	logger.Info("grant active", "grant", g.Name, "socket", o.Socket, "expires", g.Expires.Format(time.RFC3339),
		"keys", len(g.Keys), "host_keys", len(g.HostKeys), "users", o.Users, "namespaces", o.Namespaces)
	fmt.Printf("export SSH_AUTH_SOCK=%s\n", o.Socket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	err = server.Serve(ctx, l, dial, g, time.Now, logger)
	reason := "expired"
	if ctx.Err() != nil {
		reason = "signal"
	}
	logger.Info("grant ended", "grant", g.Name, "reason", reason)
	return err
}
