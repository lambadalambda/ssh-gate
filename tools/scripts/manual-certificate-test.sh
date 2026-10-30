#!/bin/sh
# Manual test of grant certificates with the Secretive fork. Needs:
# - the fork's agent running, with a key marked as grant CA in the host app,
# - ssh-grant (go build -o ssh-grant ./cmd/ssh-grant),
# - a person to approve the window.
#
#   scripts/manual-certificate-test.sh [CA public key file] [agent socket]
#
# Starts an sshd on 127.0.0.1:2245 that trusts only the CA (no authorized_keys).
# Adds that test host to ~/.ssh/known_hosts with the marker below, because the
# agent and ssh read that file; removes exactly those lines again at the end.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
container=$HOME/Library/Containers/com.example.sshgate.SecretAgent/Data
sock=${2:-$container/socket.ssh}
marker="sshgate-certificate-test"
port=2245
grant=${SSH_GRANT:-$here/ssh-grant}

ca=${1:-$(grep -l "grant-ca@" "$container"/PublicKeys/*.pub 2>/dev/null | head -1)}
[ -n "$ca" ] && [ -f "$ca" ] || { echo "CA public key not found; pass it as first argument"; exit 1; }
[ -x "$grant" ] || { echo "ssh-grant not found at $grant; build it or set SSH_GRANT"; exit 1; }

dir=$(mktemp -d /tmp/cert-test.XXXX)
cleanup() {
	kill "$(cat "$dir/pid" 2>/dev/null)" 2>/dev/null
	sed -i '' "/$marker/d" "$HOME/.ssh/known_hosts"
	rm -rf "$dir"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N "" -f "$dir/host"
cp "$ca" "$dir/ca.pub"
printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s\nTrustedUserCAKeys %s\nAuthorizedKeysFile none\nPidFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
	$port "$dir/host" "$dir/ca.pub" "$dir/pid" > "$dir/sshd.conf"
/usr/sbin/sshd -f "$dir/sshd.conf" -E "$dir/sshd.log" || { echo "sshd did not start"; exit 1; }
echo "[127.0.0.1]:$port $(cut -d' ' -f1,2 "$dir/host.pub") $marker" >> "$HOME/.ssh/known_hosts"
sleep 1

login() {
	SSH_AUTH_SOCK=$sock ssh -o IdentityAgent="$sock" -o StrictHostKeyChecking=yes -o BatchMode=yes \
		-p $port "$USER@127.0.0.1" true 2>/dev/null && echo ok || echo refused
}

printf '\n1. login without grant\n  expect: no window (the server does not accept the plain key) -> refused\n  result: '
login
printf '\n2. ssh-grant login %s@127.0.0.1:%s --for 15m\n  expect: window with reason; approve -> granted\n  result: ' "$USER" $port
SSH_AUTH_SOCK=$sock "$grant" login "$USER@127.0.0.1:$port" --for 15m --reason "certificate test"
printf '\n3. certificate listed by the agent\n'
SSH_AUTH_SOCK=$sock ssh-add -L | grep -- "-cert-v01@openssh.com" > "$dir/cert.pub" && ssh-keygen -L -f "$dir/cert.pub" | sed -n '1,12p' || echo "  no certificate listed"
printf '\n4. login with the certificate\n  expect: no window -> ok\n  result: '
login
