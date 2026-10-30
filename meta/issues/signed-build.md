# Signed build with team entitlements

## Summary

Build the fork with the user's Apple Developer team, so Secure Enclave keys in the keychain work.

## Acceptance Criteria

- The user can install the built app, create a key and use it through the agent socket.

## Notes

- Create `Sources/Config/OpenSource.xcconfig` (git-ignored) with `SECRETIVE_DEVELOPMENT_TEAM_OSS = <team ID>` and `SECRETIVE_BASE_BUNDLE_ID_OSS = <own bundle ID>`. The own bundle ID gives the fork its own container and socket, so it runs next to an installed Secretive.
