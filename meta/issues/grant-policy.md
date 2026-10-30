# Grant policy

## Summary

A pure function `Decide(grant, now, conn, key, data)` that allows or denies one sign request.

## Requirements

- Deny after expiry, for keys not in the grant, and on poisoned connections.
- Login: needs a session-bind on the same connection, a matching session ID, an allowed host key, a matching hostbound host key, the same key, and an allowed user (empty list = any user).
- SSHSIG: the namespace must be in the grant.
- Defence in depth: deny when the bind is a forwarding bind.

## Acceptance Criteria

- Table tests for each allow and deny reason.
