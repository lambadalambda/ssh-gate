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

## Notes

- Done. Installed as /Applications/SSH Gate.app; the agent runs as login item; signing and login grants through it worked for these commits and pushes.
- After a path change, the old launchd job keeps the stale path (EX_CONFIG, "Could not find program"); `scripts/install.sh` boots it out so the app registers it again.
- Gitea repo still called `secretive` (rename pending the user's decision).
