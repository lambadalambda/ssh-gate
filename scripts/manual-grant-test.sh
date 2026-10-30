#!/bin/sh
# Manual test of scoped grants with a running agent. Needs a key that the agent
# lists, and a person to answer the approval window.
#
#   scripts/manual-grant-test.sh [socket]
#
# Starts two local sshd (ed25519 and ECDSA host keys, ports 2241/2242), then:
#   1. git signature        -> window; approve "1 hour" for the default requester
#   2. git signature again  -> no window
#   3. login to host A      -> window (other purpose); approve "1 hour"
#   4. login to host A      -> no window
#   5. login to host B      -> window (other host); deny
set -u
sock=${1:-$HOME/Library/Containers/com.example.sshgate.SecretAgent/Data/socket-debug.ssh}
dir=$(mktemp -d /tmp/grant-test.XXXX)
trap 'kill $(cat "$dir"/*.pid 2>/dev/null) 2>/dev/null; rm -rf "$dir"' EXIT

SSH_AUTH_SOCK=$sock ssh-add -L | head -1 > "$dir/key.pub" || { echo "agent has no key at $sock"; exit 1; }
cp "$dir/key.pub" "$dir/authorized_keys"
: > "$dir/known_hosts"
port=2241
for type in ed25519 ecdsa; do
	ssh-keygen -q -t $type -N "" -f "$dir/host_$type"
	printf 'Port %s\nListenAddress 127.0.0.1\nHostKey %s\nAuthorizedKeysFile %s\nPidFile %s\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n' \
		$port "$dir/host_$type" "$dir/authorized_keys" "$dir/$type.pid" > "$dir/$type.conf"
	/usr/sbin/sshd -f "$dir/$type.conf" -E "$dir/$type.log"
	echo "[127.0.0.1]:$port $(cat "$dir/host_$type.pub")" >> "$dir/known_hosts"
	port=$((port + 1))
done
sleep 1

sign() {
	echo "test" > "$dir/msg"; rm -f "$dir/msg.sig"
	SSH_AUTH_SOCK=$sock ssh-keygen -Y sign -f "$dir/key.pub" -n git "$dir/msg" >/dev/null 2>&1 && echo ok || echo refused
}
login() {
	ssh -F /dev/null -o IdentityAgent="$sock" -o UserKnownHostsFile="$dir/known_hosts" -o StrictHostKeyChecking=yes \
		-o BatchMode=yes -p "$1" "$USER@127.0.0.1" true 2>/dev/null && echo ok || echo refused
}
step() {
	printf '\n%s\n  expect: %s\n  result: ' "$1" "$2"
}

step "1. git signature" "window; approve 1 hour -> ok";       sign
step "2. git signature again" "no window -> ok";                sign
step "3. login to host A (ed25519)" "window; approve 1 hour -> ok"; login 2241
step "4. login to host A again" "no window -> ok";              login 2241
step "5. login to host B (ECDSA)" "window; deny -> refused";    login 2242
