#!/bin/sh
# Installs dist/SSH Gate.app into /Applications and restarts the agent.
#
# The agent is a login item: launchd restarts it as soon as it stops. So the
# new app is put in place completely first, and only then is the agent
# stopped; launchd starts it again from the new files. (Stopping it first lets
# launchd start it from half-copied files, and its XPC services then reject it.)
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
app=${1:-$root/dist/SSH Gate.app}
target="/Applications/SSH Gate.app"
new="/Applications/SSH Gate.new.app"
[ -d "$app" ] || { echo "no app at $app; run scripts/release.sh first"; exit 1; }
plist() { /usr/libexec/PlistBuddy -c "Print :$2" "$1/Contents/Info.plist" 2>/dev/null; }
bundle=$(plist "$app/Contents/Library/LoginItems/SSH Gate Agent.app" CFBundleIdentifier)

rm -rf "$new"
ditto "$app" "$new"
pkill -x "SSH Gate" || true
pkill -x Secretive || true
rm -rf "$target"
mv "$new" "$target"
# Earlier builds of this fork were called Secretive.app, with the same bundle IDs.
if [ -d /Applications/Secretive.app ] && [ "$(plist /Applications/Secretive.app CFBundleIdentifier)" = "$(plist "$target" CFBundleIdentifier)" ]; then
	rm -rf /Applications/Secretive.app
fi

# Remove the agent's launchd job, which may still point to an old app path,
# and stop agents that were started by hand. The app registers the login item
# again when it starts, and launchd then starts the agent from the new files.
launchctl bootout "gui/$(id -u)/$bundle" 2>/dev/null || true
pkill -f "LoginItems/(SSH Gate Agent|SecretAgent).app/Contents/MacOS/" || true
open -g "$target"
sock="$HOME/Library/Containers/$bundle/Data/socket.ssh"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	sleep 2
	SSH_AUTH_SOCK=$sock ssh-add -l >/dev/null 2>&1 && break
	[ $? -eq 1 ] && break # running, but no keys
done
if ! launchctl print "gui/$(id -u)/$bundle" 2>/dev/null | grep -q "state = running"; then
	echo "warning: the login item did not start; open SSH Gate and use Setup Agent. Starting the agent by hand for now."
	open "$target/Contents/Library/LoginItems/SSH Gate Agent.app"
fi
echo "installed $(plist "$target" CFBundleShortVersionString)"
