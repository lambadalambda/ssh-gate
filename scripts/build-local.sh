#!/bin/sh
# Builds the app without code signing where Xcode cannot sandbox package
# manifests and macro plugins (e.g. inside an already sandboxed session).
set -e
cd "$(dirname "$0")/../Sources"
xcodebuild -project Secretive.xcodeproj -scheme Secretive -configuration Debug \
	-derivedDataPath "${DERIVED_DATA:-/tmp/secretive-dd}" \
	CODE_SIGNING_ALLOWED=NO \
	-IDEPackageSupportDisableManifestSandbox=YES \
	-IDEPackageSupportDisablePluginExecutionSandbox=YES \
	'OTHER_SWIFT_FLAGS=$(inherited) -disable-sandbox' \
	build "$@"
