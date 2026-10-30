# sshgate v2: short-lived certificates from an SSH CA

## Summary

For hosts that trust an SSH user CA: a login grant also gets a certificate for the agent key, valid for the grant duration and only for the approved user. The server then enforces the expiry, even if the agent's grant logic fails. The agent key does not need to be in any authorized_keys.

## Design for the Secretive fork (2026-10-30)

- One Secretive key is marked as the user CA (setting). It requires authentication. The approval's LAContext unlocks it, so there is no second prompt.
- On a login grant: certificate type user, key = agent key, principals = [approved user], valid from now - 60 s until grant expiry, key ID names the requester (path, pid), default extensions (permit-pty etc.), no critical options. Kept in memory with the grant.
- The agent lists the certificate as an extra identity while it is valid. Signing with it still needs the grant.

## Open question: first login

ssh asks for identities once, before the first sign request. A certificate created at the first approval only appears in the next connection's list, so the first login to a CA-only host fails. Options:

1. Accept it: the first connection asks, fails, the second works.
2. Explicit request command: the agent (or user) runs e.g. `secretive-grant request --host H --user U --for 4h` before connecting; approval creates grant and certificate in advance.
3. Issue at listing time: when a process with an active login grant lists identities, offer certificates for all its grants (needs a grant first, so same as 1 for the very first time).

## Notes

- OpenSSH certificates cannot be chained. The offline recovery key can be a second entry in TrustedUserCAKeys.
