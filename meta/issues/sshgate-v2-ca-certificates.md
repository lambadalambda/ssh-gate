# sshgate v2: short-lived certificates from an SSH CA

## Summary

For hosts that trust an SSH user CA: each grant gets a new key and a certificate valid for the grant TTL, signed by a CA key in the Secure Enclave (Secretive, Touch ID per use). The server then enforces the expiry.

## Requirements

- One CA signature per grant, not per connection.
- Certificate principals and options come from the grant.
- The CA key is never reachable through a grant socket.

## Notes

- OpenSSH certificates cannot be chained. The offline recovery key can be a second entry in TrustedUserCAKeys.
