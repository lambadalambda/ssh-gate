package grantreq

import (
	"reflect"
	"testing"
	"time"
)

func TestSplitSSHArgs(t *testing.T) {
	cases := []struct {
		args          []string
		duration      time.Duration
		reason        string
		ssh           []string
		expectedError bool
	}{
		{[]string{"root@backup.example.com"}, time.Hour, "", []string{"root@backup.example.com"}, false},
		{[]string{"--for", "4h", "--reason", "deploy", "-p", "2222", "host", "uptime"}, 4 * time.Hour, "deploy", []string{"-p", "2222", "host", "uptime"}, false},
		{[]string{"--for", "15m", "--", "--for", "x"}, 15 * time.Minute, "", []string{"--for", "x"}, false},
		{[]string{"-v", "host", "--for", "4h"}, time.Hour, "", []string{"-v", "host", "--for", "4h"}, false},
		{[]string{"--for"}, 0, "", nil, true},
		{[]string{"--for", "soon", "host"}, 0, "", nil, true},
		{nil, 0, "", nil, true},
	}
	for _, c := range cases {
		d, reason, ssh, err := SplitSSHArgs(c.args)
		if (err != nil) != c.expectedError {
			t.Fatalf("%v: err = %v", c.args, err)
		}
		if err == nil && (d != c.duration || reason != c.reason || !reflect.DeepEqual(ssh, c.ssh)) {
			t.Errorf("%v: got %v %q %v", c.args, d, reason, ssh)
		}
	}
}

func TestParseSSHConfig(t *testing.T) {
	home := "/Users/me"
	d, err := ParseSSHConfig("user root\nhostname nas.local\nport 2222\nhostkeyalias none\nidentityagent ~/agent.sock\n", home)
	want := Destination{User: "root", Host: "nas.local", Port: 2222, Agent: "/Users/me/agent.sock"}
	if err != nil || d != want {
		t.Fatalf("got %+v %v", d, err)
	}
	d, _ = ParseSSHConfig("user root\nhostname 10.0.0.5\nport 22\nhostkeyalias nas\n", home)
	if d.Host != "nas" || d.Agent != "" {
		t.Errorf("hostkeyalias / no agent: got %+v", d)
	}
	for _, agent := range []string{"none", "SSH_AUTH_SOCK"} {
		if d, _ := ParseSSHConfig("user u\nhostname h\nport 22\nidentityagent "+agent+"\n", home); d.Agent != "" {
			t.Errorf("identityagent %s: got %q", agent, d.Agent)
		}
	}
	for _, bad := range []string{"", "user root\nport 22\n", "user root\nhostname h\nport x\n"} {
		if _, err := ParseSSHConfig(bad, home); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}
