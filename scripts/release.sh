#!/bin/sh
# Builds a Developer ID signed Secretive.app with the team from
# Sources/Config/OpenSource.xcconfig. Notarizes it if NOTARY_PROFILE names a
# `xcrun notarytool store-credentials` profile; without notarization the app
# runs on the Mac that built it, but Gatekeeper blocks it on other Macs.
#
#   scripts/release.sh            -> dist/Secretive.app, dist/Secretive.zip
set -e
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root/Sources"
team=$(sed -n 's/^SECRETIVE_DEVELOPMENT_TEAM_OSS *= *//p' Config/OpenSource.xcconfig)
[ -n "$team" ] || { echo "set SECRETIVE_DEVELOPMENT_TEAM_OSS in Sources/Config/OpenSource.xcconfig"; exit 1; }
version=${VERSION:-$(git describe --tags --abbrev=0 | sed 's/^v//')_grants-$(date +%Y%m%d)}
out=${OUT:-$root/dist}
rm -rf "$out" && mkdir -p "$out"

IDEEnableNewPackagePIFBuilder=NO xcodebuild -project Secretive.xcodeproj -scheme Secretive -configuration Release \
	-archivePath "$out/Secretive.xcarchive" -allowProvisioningUpdates \
	CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development" DEVELOPMENT_TEAM="$team" PROVISIONING_PROFILE_SPECIFIER= \
	CI_VERSION="$version" archive

cat > "$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key><string>developer-id</string>
	<key>signingStyle</key><string>automatic</string>
	<key>teamID</key><string>$team</string>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath "$out/Secretive.xcarchive" -exportPath "$out" \
	-exportOptionsPlist "$out/ExportOptions.plist" -allowProvisioningUpdates

if [ -n "${NOTARY_PROFILE:-}" ]; then
	ditto -c -k --keepParent "$out/Secretive.app" "$out/notarize.zip"
	xcrun notarytool submit "$out/notarize.zip" --keychain-profile "$NOTARY_PROFILE" --wait
	xcrun stapler staple "$out/Secretive.app"
	rm "$out/notarize.zip"
fi
ditto -c -k --keepParent "$out/Secretive.app" "$out/Secretive.zip"
codesign -dv "$out/Secretive.app" 2>&1 | grep -E "Authority=Developer ID|TeamIdentifier"
echo "Version $version: $out/Secretive.app"
