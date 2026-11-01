# Stable requester identity

## Summary

A PID alone can be reused. Identify a process by PID plus start time (proc_pidinfo PROC_PIDTBSDINFO), and keep the executable path and code signature info for display.

## Requirements

- Add start time to Secretive's traced processes.
- Choose the default "agent" process in a chain (the first process below the terminal or launchd that is not a shell); the user can choose another one in the pop-up.

## Acceptance Criteria

- Unit tests for the default choice with example chains.
- A process with the same PID but another start time does not match a grant.
