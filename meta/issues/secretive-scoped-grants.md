# Secretive fork with scoped grants (meta)

## Summary

Replace sshgate's proxy design with a fork of Secretive (MIT). The app owns the keys (Secure Enclave). When a process asks for a signature, the app checks for a grant (requester, key, purpose, expiry). With no grant, it shows a pop-up: who asks, for what, for how long. The user approves with Touch ID.

## Sub-issues

- [Set up Secretive fork](secretive-fork-setup.md)
- [Grant model and matching](grant-model-and-matching.md)
- [Stable requester identity](stable-requester-identity.md)
- [Harden session-bind handling in Secretive](harden-session-bind.md)
- [Enforce grants in the agent](enforce-grants-in-agent.md)
- [Approval pop-up with duration and Touch ID](approval-popup.md)
- [Signed build with team entitlements](signed-build.md)

## Acceptance Criteria

- An agent process can log in to a granted host and sign with a granted namespace during the grant, without new prompts.
- Any other host, namespace, key or process gets a new pop-up or is denied.
- After expiry (wall clock), the next request asks again.

## Notes

- Fork: https://github.com/lambadalambda/ssh-gate
- Secretive already has: process chain tracing with code signature check, session-bind verification, `SigningRequestTarget` (login with host key, SSHSIG namespace), host names from known_hosts, key-wide "remember for N minutes".
- Later: explicit request command with a reason; upstream PR.
