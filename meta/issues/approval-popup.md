# Approval pop-up with duration and Touch ID

## Summary

A window that shows the requester chain (with code signature status and working directory), the key, the purpose (host name and host key fingerprint, or namespace) and a duration choice (this request, 1h, 4h, 8h). Approve needs Touch ID.

## Acceptance Criteria

- Manual test by the user: approve, deny, durations.

## Notes

- Say clearly that a grant covers the requester and everything it starts.
- Show the executable path of each process, not only the name: process names are chosen by the process itself.
- With no safe default requester (`RequesterSelection.defaultIndex` is nil), offer only "this request".
- After approval, keys with "require authentication" still ask for Touch ID in the existing flow, so the user may be asked twice. Decide: reuse the approval's LAContext, or recommend keys without per-use authentication for agents.
- Remove or hide the key-wide "remember for N minutes" option once grants work.
