# ssh-grant command

## Summary

A small CLI that sends the grant request extension through `SSH_AUTH_SOCK` and waits for the decision.

## Requirements

- `ssh-grant login user@host[:port] --for 4h --reason "..." [--key FILE.pub]`
- `ssh-grant sign --namespace git --for 4h --reason "..." [--key FILE.pub]`
- Exit 0 if granted, 1 if denied, 2 on usage errors. Clear message on stderr.

## Acceptance Criteria

- Unit tests for argument parsing and message encoding; manual run against the app.
