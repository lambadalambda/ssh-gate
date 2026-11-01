package grantreq

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SplitSSHArgs splits the arguments of "ssh-grant ssh": grant options
// (--for, --reason) come first and end at "--" or at the first other
// argument; everything after goes to ssh unchanged.
func SplitSSHArgs(args []string) (duration time.Duration, reason string, ssh []string, err error) {
	duration = time.Hour
	i := 0
loop:
	for i < len(args) {
		switch args[i] {
		case "--":
			i++
			break loop
		case "--for", "--reason":
			if i+1 >= len(args) {
				return 0, "", nil, fmt.Errorf("%s needs a value", args[i])
			}
			if args[i] == "--reason" {
				reason = args[i+1]
			} else if duration, err = time.ParseDuration(args[i+1]); err != nil || duration <= 0 {
				return 0, "", nil, fmt.Errorf("invalid --for %q", args[i+1])
			}
			i += 2
		default:
			break loop
		}
	}
	if i >= len(args) {
		return 0, "", nil, errors.New("missing ssh arguments")
	}
	return duration, reason, args[i:], nil
}

// Destination is where ssh would connect, from `ssh -G`.
type Destination struct {
	User, Host string
	Port       uint32
	// Agent is the IdentityAgent socket, or "" if ssh uses SSH_AUTH_SOCK.
	Agent string
}

// ParseSSHConfig reads the destination from `ssh -G` output. The host is the
// HostKeyAlias if one is set, as ssh uses it to look up known_hosts.
func ParseSSHConfig(output, home string) (Destination, error) {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, " "); ok {
			values[key] = value
		}
	}
	d := Destination{User: values["user"], Host: values["hostname"]}
	if alias := values["hostkeyalias"]; alias != "" && alias != "none" {
		d.Host = alias
	}
	switch agent := values["identityagent"]; {
	case agent == "" || agent == "none" || agent == "SSH_AUTH_SOCK":
	case strings.HasPrefix(agent, "~/"):
		d.Agent = home + agent[1:]
	default:
		d.Agent = agent
	}
	p, err := strconv.ParseUint(values["port"], 10, 16)
	if d.User == "" || d.Host == "" || err != nil || p == 0 {
		return Destination{}, errors.New("could not read user, host and port from ssh -G")
	}
	d.Port = uint32(p)
	return d, nil
}
