# Allow hosts with host certificates

## Summary

When a host uses a host certificate, session-bind sends the certificate, not the plain key. sshgate then always denies the login. This is safe but limits use.

## Requirements

- Accept a bind whose certificate's underlying key is pinned, or trust a host CA with principals.

## Notes

- Found in review of the v1 parser. Not needed for v1.
- Same in the Secretive fork: `HostKeySignatureVerifier` refuses `*-cert-v01@openssh.com` host keys, so such hosts cannot get login grants. Pinning the certificate blob would also break on certificate rotation; pin the inner key or the host CA instead.
