# Grant CLI and socket server

## Summary

`sshgate grant` creates one socket for one grant, serves it until the TTL ends, then removes it.

## Requirements

- Flags: name, upstream socket, keys (public key file or SHA256 fingerprint), hosts (looked up in a known_hosts file at grant time), users, namespaces, TTL.
- Socket in a 0700 directory, socket mode 0600. Print the socket path.
- One upstream connection per client connection.
- Log decisions with the grant name and the peer PID (LOCAL_PEERPID on macOS, SO_PEERCRED on Linux).
- Clean shutdown on expiry and on SIGINT/SIGTERM.

## Acceptance Criteria

- Unit tests for flag and known_hosts handling.
- Manual run: socket appears, `ssh-add -l` through it shows only granted keys, socket is removed after the TTL.
