# Short-lived certificates for login grants

## Summary

When a login grant is created and a grant CA is set, the agent signs an OpenSSH user certificate for the grant's key: principal = the approved user, valid from now - 60 s until the grant expires. The agent lists the certificate while it is valid. Signing with it still needs the grant.

## Acceptance Criteria

- Unit tests: certificate fields, validity, signature verifies with the CA key (ssh-keygen -L accepts it), listed only while valid.
- e2e: sshd with TrustedUserCAKeys accepts the login; after expiry it refuses.
