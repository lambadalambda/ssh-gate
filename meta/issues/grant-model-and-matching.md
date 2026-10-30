# Grant model and matching

## Summary

Pure Swift types: a grant is (requester, secret, purpose, expiry). Purpose is a login (host key + user) or a signature (SSHSIG namespace). A store answers "does a grant match this request?".

## Requirements

- Match only if: same secret, requester process is in the request's process chain, purpose matches exactly, now < expiry (wall clock).
- Requests without a known target never match.
- Expired grants are removed.

## Acceptance Criteria

- Unit tests for each match and non-match case.
