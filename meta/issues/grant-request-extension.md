# Grant request extension in the agent

## Summary

An agent protocol extension (`request-grant@heldscal.la`) lets a client ask for a grant before it uses the key. The window shows the request with the client's reason. The requester is taken from the socket's process chain, as for sign requests; the request command itself is an intermediary.

## Requirements

- Fields: key (public key blob, optional: first key if empty), purpose (login with host, port and user, or signature with namespace), duration, reason.
- Login: the agent resolves the host keys itself from known_hosts (its own reading, never from the client). No known host key → refuse.
- One approval creates one grant per resolved host key.
- The reason is shown as the client's claim, not as a fact.
- Forwarded connections cannot request grants.

## Acceptance Criteria

- Unit tests: login and signature requests, unknown host refused, duration capped at the window's maximum, reason passed to the approver, forwarded refused.

## Notes

- Done. After review: requests in advance are accepted only from `ssh-grant` as connecting process, are never merged, pause 30 s after a denial, host names must be ASCII (≤ 253), wildcard known_hosts matches are named in the window, all host key fingerprints are listed, the reason is in its own box.
- Live test found that the app sandbox blocks Security.framework from reading client binaries; peers are now checked with csops/csops_audittoken.
- Hashed known_hosts entries are not resolved (refused).
