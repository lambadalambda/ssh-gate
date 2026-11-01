# XPC code signing requirement in release builds

## Summary

`XPCTypedSession` sets `connection.setCodeSigningRequirement(... certificate leaf[subject.OU] = "Z72PRUAWF6")` in non-DEBUG builds. Release builds signed with another team can therefore not talk to their own XPC services.

## Requirements

- Derive the team ID from the app's own code signature (SecCodeCopySelf + SecCodeCopySigningInformation) or from a build setting.

## Acceptance Criteria

- A Release build signed with team ABCDE12345 lists keys through its socket.

## Notes

- Done: requirement from the app's own team ID in all configurations; unsigned Debug builds skip it, unsigned Release builds fail closed ("never"). Two XPC targets had the upstream team fixed for Release in the project.
- Release builds need `IDEEnableNewPackagePIFBuilder=NO` (as upstream CI); `scripts/build-release.sh` in the fork. Tested: the Release agent lists the key and reaches the approval window.
