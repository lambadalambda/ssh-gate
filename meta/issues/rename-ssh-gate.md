# Rename the app to SSH Gate

## Summary

The fork differs a lot from Secretive; it gets its own name. Decided with the user: name "SSH Gate", bundle IDs and keychain group stay (socket path and keys unchanged).

## Requirements

- App file and display names: "SSH Gate.app" with the agent "SSH Gate Agent".
- English UI strings say "SSH Gate" where they name the app; credit to Secretive (MIT) stays in README and LICENSE.
- Scripts (release, install, tests) use the new names; install removes the old Secretive.app.
- Package and module names stay, for upstream merges.

## Acceptance Criteria

- Release build installs as /Applications/SSH Gate.app, the agent runs and answers, grants work.
