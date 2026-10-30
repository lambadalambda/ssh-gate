# ssh wrapper that requests a grant first

## Summary

`ssh-grant ssh [--for D] [--reason R] [--] <ssh args>` finds user, host and port like ssh (`ssh -G`), requests a login grant, then execs ssh with the original arguments.

## Requirements

- Destination from `ssh -G`: user, hostname (or hostkeyalias if set), port.
- Default reason "ssh <user>@<host>"; default duration 1h.
- Always exec ssh, also when not granted (password logins, unknown hosts); print a warning.
- Agent: a request in advance that existing grants of the same requester already cover is answered without a window.

## Acceptance Criteria

- Go unit tests for argument splitting and `ssh -G` parsing; Swift test for the covered-request case.
- Manual: `ssh-grant ssh root@backup.example.com` logs in with a certificate; a second call opens no window.
