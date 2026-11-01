# Harden session-bind handling in Secretive

## Summary

Port the sshgate rules: a forwarded bind or a second bind with another session ID or host key on one connection poisons the connection; a login signature needs a bind and a matching session ID.

## Acceptance Criteria

- Unit tests in SecretAgentKit for each case.

## Findings in upstream SSHProtocolKit (2026-10-30)

- session-bind handling in `Agent` is disabled, and its state is per agent, not per connection.
- `sshConnectionPayload` drops the session ID and stores only the second chunk of the host key blob. For ECDSA that is the curve name, so all P-256 hosts look the same. Grants must use the full host key blob.
- session-bind verification: ECDSA reads the curve name as the key and treats the `mpint r, s` signature as raw bytes (always fails); RSA is refused; `ssh-mldsa-87` verifies with MLDSA65. All fail closed.

## Requirements (added)

- Strict userauth parser: session ID, user, service, method (publickey or hostbound), sig-follows == 1, algorithm matches key type, full host key blob, no trailing data.
- session-bind verification for ed25519, ECDSA P-256/P-384/P-521 and RSA (rsa-sha2-256/512), keeping the full host key blob.
- Fixtures captured from real OpenSSH traffic for each host key type.
