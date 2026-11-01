# Parse sign requests

## Summary

Classify the data in an agent sign request as SSH userauth (publickey and publickey-hostbound-v00@openssh.com) or SSHSIG. Parse and verify session-bind@openssh.com.

## Requirements

- Strict parsing that matches OpenSSH ssh-agent.c: service "ssh-connection", sig-follows exactly 1, algorithm matches key type, session ID at most 64 bytes, no trailing data.
- SSHSIG: hash algorithm sha256 or sha512 with the correct hash length.
- session-bind: the host key signature over the session ID must verify.
- Anything else is an error.

## Acceptance Criteria

- Unit tests cover valid and invalid blobs for each format.
