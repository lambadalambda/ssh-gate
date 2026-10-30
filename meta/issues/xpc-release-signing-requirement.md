# XPC code signing requirement in release builds

## Summary

`XPCTypedSession` sets `connection.setCodeSigningRequirement(... certificate leaf[subject.OU] = "Z72PRUAWF6")` in non-DEBUG builds. Release builds signed with another team can therefore not talk to their own XPC services.

## Requirements

- Derive the team ID from the app's own code signature (SecCodeCopySelf + SecCodeCopySigningInformation) or from a build setting.

## Acceptance Criteria

- A Release build signed with team ABCDE12345 lists keys through its socket.
