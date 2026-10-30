#!/bin/sh
# Runs the package tests where SwiftPM cannot sandbox itself (e.g. inside an
# already sandboxed session). The bundles run under xctest, which the parser
# assertions in SSHProtocolKit expect.
set -e
cd "$(dirname "$0")/../Sources/Packages"
swift build --build-tests --disable-sandbox "$@"
status=0
for bundle in .build/out/Products/Debug/*Tests.xctest; do
	echo "== $(basename "$bundle")"
	out=$(xcrun xctest "$bundle" 2>&1) || status=1
	echo "$out" | grep -E "✘|Test run with|error:" || true
done
exit $status
