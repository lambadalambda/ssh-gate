# Harden session-bind handling in Secretive

## Summary

Port the sshgate rules: a forwarded bind or a second bind with another session ID or host key on one connection poisons the connection; a login signature needs a bind and a matching session ID.

## Acceptance Criteria

- Unit tests in SecretAgentKit for each case.
