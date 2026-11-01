package grantreq

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"sshgate/internal/testutil"
)

func str(s string) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(s)))
	return append(b, s...)
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func TestEncodeMatchesWireFormat(t *testing.T) {
	r := Request{KeyBlob: []byte{1, 2}, Kind: "login", Host: "git.example", Port: 2222, User: "git", Seconds: 3600, Reason: "push"}
	want := bytes.Join([][]byte{str("\x01\x02"), str("login"), str("git.example"), u32(2222), str("git"), str(""), u32(3600), str("push")}, nil)
	if got := r.Encode(); !bytes.Equal(got, want) {
		t.Fatalf("Encode = %x\nwant     %x", got, want)
	}
}

var env = func(k string) string { return map[string]string{"USER": "me"}[k] }

func noFile(string) ([]byte, error) { return nil, errors.New("no file") }

func TestParseLogin(t *testing.T) {
	cases := []struct {
		args []string
		want Request
	}{
		{[]string{"login", "git@git.example"}, Request{Kind: "login", Host: "git.example", Port: 22, User: "git", Seconds: 3600}},
		{[]string{"login", "host.example:2222", "--for", "4h", "--reason", "deploy"}, Request{Kind: "login", Host: "host.example", Port: 2222, User: "me", Seconds: 4 * 3600, Reason: "deploy"}},
		{[]string{"login", "--for", "15m", "root@[::1]:2200"}, Request{Kind: "login", Host: "::1", Port: 2200, User: "root", Seconds: 900}},
		{[]string{"login", "root@::1"}, Request{Kind: "login", Host: "::1", Port: 22, User: "root", Seconds: 3600}},
	}
	for _, c := range cases {
		got, err := ParseArgs(c.args, env, noFile)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got.Kind != c.want.Kind || got.Host != c.want.Host || got.Port != c.want.Port || got.User != c.want.User ||
			got.Seconds != c.want.Seconds || got.Reason != c.want.Reason || got.KeyBlob != nil {
			t.Errorf("%v: got %+v, want %+v", c.args, got, c.want)
		}
	}
}

func TestParseSign(t *testing.T) {
	got, err := ParseArgs([]string{"sign", "--for", "30m"}, env, noFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "sign" || got.Namespace != "git" || got.Seconds != 1800 {
		t.Errorf("got %+v", got)
	}
	got, err = ParseArgs([]string{"sign", "--namespace", "file"}, env, noFile)
	if err != nil || got.Namespace != "file" {
		t.Errorf("namespace: %+v %v", got, err)
	}
}

func TestParseKey(t *testing.T) {
	key := testutil.NewPublicKey(t)
	read := func(p string) ([]byte, error) {
		if p == "/k.pub" {
			return ssh.MarshalAuthorizedKey(key), nil
		}
		return nil, errors.New("no file")
	}
	got, err := ParseArgs([]string{"sign", "--key", "/k.pub"}, env, read)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.KeyBlob, key.Marshal()) {
		t.Error("key blob mismatch")
	}
	if _, err := ParseArgs([]string{"sign", "--key", "/missing.pub"}, env, read); err == nil {
		t.Error("missing key file: expected error")
	}
}

func TestParseErrors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"exec"},
		{"login"},
		{"login", "a", "b"},
		{"login", "host:0"},
		{"login", "host:99999"},
		{"login", "@host"},
		{"login", "host", "--for", "0s"},
		{"login", "host", "--for", "-1h"},
		{"login", "host", "--for", "2000000h"},
		{"sign", "extra"},
		{"sign", "--namespace", ""},
	} {
		if _, err := ParseArgs(args, env, noFile); err == nil {
			t.Errorf("%v: expected error", args)
		}
	}
	if _, err := ParseArgs([]string{"login", "host"}, func(string) string { return "" }, noFile); err == nil {
		t.Error("no user and no $USER: expected error")
	}
}
