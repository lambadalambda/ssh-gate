# Identify the peer by audit token

## Summary

The tracer gets the peer pid with LOCAL_PEERPID at accept. If the client exits between connect and accept, its pid can be reused. LOCAL_PEERTOKEN returns the audit token with the pid version, which identifies the process exactly.

## Requirements

- Use LOCAL_PEERTOKEN and check that the pid version still matches when the chain is built.

## Notes

- Found in review of the grant model. The current checks (start time not after accept, parents not younger than children) fail closed for most cases.
- Done (fork, "fix(tracer): identify the peer by audit token"): LOCAL_PEERTOKEN at accept; after the lookup, `SecCodeCopyGuestWithAttributes` with the token must still succeed, which Security.framework refuses when the pid version differs. Tested with a changed pid version and live in the Release app.
