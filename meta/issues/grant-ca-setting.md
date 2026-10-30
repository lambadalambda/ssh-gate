# Mark a key as grant CA in the host app

## Summary

A setting in the shared keychain settings store names the secret that signs grant certificates. The host app shows a switch for it and the CA's public key line for TrustedUserCAKeys or `cert-authority` in authorized_keys.

## Acceptance Criteria

- The agent reads the setting; the host app can set and clear it.
- Manual test by the user.
