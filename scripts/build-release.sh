#!/bin/sh
# Builds a Release app signed with the team from Config/OpenSource.xcconfig
# (SECRETIVE_DEVELOPMENT_TEAM_OSS), using automatic "Apple Development"
# signing instead of upstream's manual Developer ID profiles.
set -e
cd "$(dirname "$0")/../Sources"
team=$(sed -n 's/^SECRETIVE_DEVELOPMENT_TEAM_OSS *= *//p' Config/OpenSource.xcconfig)
[ -n "$team" ] || { echo "set SECRETIVE_DEVELOPMENT_TEAM_OSS in Sources/Config/OpenSource.xcconfig"; exit 1; }
IDEEnableNewPackagePIFBuilder=NO xcodebuild -project Secretive.xcodeproj -scheme Secretive -configuration Release \
	-derivedDataPath "${DERIVED_DATA:-/tmp/secretive-release}" -allowProvisioningUpdates \
	CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development" DEVELOPMENT_TEAM="$team" PROVISIONING_PROFILE_SPECIFIER= \
	build "$@"
echo "App: ${DERIVED_DATA:-/tmp/secretive-release}/Build/Products/Release/Secretive.app"
