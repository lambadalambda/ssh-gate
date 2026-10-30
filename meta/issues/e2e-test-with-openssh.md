# End-to-end test with real OpenSSH

## Summary

Prove the format assumptions against real binaries: a local unprivileged sshd, the system ssh client and ssh-keygen -Y sign.

## Acceptance Criteria

- ssh to the pinned local sshd works through the grant socket.
- ssh to a second sshd with a different host key is denied.
- `ssh-keygen -Y sign -n git` works. `-n file` is denied.
- The test is skipped when sshd is not available.
