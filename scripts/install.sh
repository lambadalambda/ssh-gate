#!/bin/sh
# Installs dist/Secretive.app into /Applications and restarts the agent.
#
# The agent is a login item: launchd restarts it as soon as it stops. So the
# new app is put in place completely first, and only then is the agent
# stopped; launchd starts it again from the new files. (Stopping it first lets
# launchd start it from half-copied files, and its XPC services then reject it.)
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
app=${1:-$root/dist/Secretive.app}
[ -d "$app" ] || { echo "no app at $app; run scripts/release.sh first"; exit 1; }
bundle=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$app/Contents/Library/LoginItems/SecretAgent.app/Contents/Info.plist")

rm -rf /Applications/Secretive.new.app
ditto "$app" /Applications/Secretive.new.app
pkill -x Secretive || true
rm -rf /Applications/Secretive.app
mv /Applications/Secretive.new.app /Applications/Secretive.app

# launchd starts the agent under its bundle ID, not its path.
pkill -f "^$bundle\$" || true
pkill -f "LoginItems/SecretAgent.app/Contents/MacOS/SecretAgent" || true
sleep 3
pgrep -f "^$bundle\$|LoginItems/SecretAgent.app/Contents/MacOS/SecretAgent" >/dev/null ||
	open /Applications/Secretive.app/Contents/Library/LoginItems/SecretAgent.app
echo "installed $(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" /Applications/Secretive.app/Contents/Info.plist)"
