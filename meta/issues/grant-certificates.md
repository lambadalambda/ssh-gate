# Short-lived certificates for login grants

## Summary

When a login grant is created and a grant CA is set, the agent signs an OpenSSH user certificate for the grant's key: principal = the approved user, valid from now - 60 s until the grant expires. The agent lists the certificate while it is valid. Signing with it still needs the grant.

## Acceptance Criteria

- Unit tests: certificate fields, validity, signature verifies with the CA key (ssh-keygen -L accepts it), listed only while valid.
- e2e: sshd with TrustedUserCAKeys accepts the login; after expiry it refuses.

## Notes

- Done. After review: clients can neither list nor use the CA key; principals with `,`, whitespace, `*`, `?`, `!` get no certificate; a renewal replaces the earlier certificate; certificates of all supported key types map to their plain key.
- Open: manual test by the user with `scripts/manual-certificate-test.sh` (approval needs Touch ID). Agent-side steps up to the window are tested live.
- Manual test by the user passed (2026-10-30): sshd with only TrustedUserCAKeys refused the plain key, ssh-grant login was approved, the agent listed a certificate (principal = user, valid 15 min + 60 s back-dated, CA = grant-ca), and the login with it worked without a window.
