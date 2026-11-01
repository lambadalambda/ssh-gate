# Filtering proxy agent

## Summary

An `agent.ExtendedAgent` for one client connection that forwards allowed requests to an upstream agent.

## Requirements

- List shows only granted keys, and nothing after expiry.
- Sign goes through policy.Decide and is logged.
- session-bind is handled locally. An invalid, forwarded or second bind poisons the connection.
- Add, Remove, RemoveAll, Lock, Unlock and Signers are denied.

## Acceptance Criteria

- Tests over an in-memory upstream keyring, through the real agent protocol.
