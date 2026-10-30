# Signed build with team entitlements

## Summary

Build the fork with the user's Apple Developer team, so Secure Enclave keys in the keychain work.

## Acceptance Criteria

- The user can install the built app, create a key and use it through the agent socket.

## Notes

- Create `Sources/Config/OpenSource.xcconfig` (git-ignored) with `SECRETIVE_DEVELOPMENT_TEAM_OSS = <team ID>` and `SECRETIVE_BASE_BUNDLE_ID_OSS = <own bundle ID>`. The own bundle ID gives the fork its own container and socket, so it runs next to an installed Secretive.
- Done 2026-10-30: Debug build signed with team ABCDE12345, bundle ID com.example.sshgate, automatic provisioning. Agent runs, a Secure Enclave key was created through the host app, and the agent lists it.
- Needed fix: XPC service names were fixed to com.maxgoedjen.Secretive.*, and a missing service hung every request.
