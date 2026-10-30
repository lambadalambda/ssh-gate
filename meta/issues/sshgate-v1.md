# sshgate v1 (meta)

## Summary

A filtering ssh-agent proxy. Each grant gets its own socket. Through that socket, an AI agent can log in only to pinned hosts and sign only git (SSHSIG namespace "git"), until the grant expires.

## Sub-issues

- [Parse sign requests](parse-sign-requests.md)
- [Grant policy](grant-policy.md)
- [Filtering proxy agent](filtering-proxy-agent.md)
- [Grant CLI and socket server](grant-cli-and-socket-server.md)
- [End-to-end test with real OpenSSH](e2e-test-with-openssh.md)

## Acceptance Criteria

- All sub-issues are complete.
- `ssh` to a pinned host and `git commit -S` work through a grant socket. `ssh` to any other host fails.

## Notes

- Identity is the socket path, not the peer PID. The PID is for logs only.
- The sandbox (e.g. Agent Safehouse) must keep the AI agent away from the upstream socket and from private key files.
