# DEVLOG

## 2026-10-30: v1 design and protocol findings

- The agent protocol has no hostname. Since OpenSSH 8.9, ssh sends
  `session-bind@openssh.com` with the server host key, the session ID and the
  host's signature over the session ID. The proxy pins host keys and requires
  the userauth session ID to equal the bound one.
- Git signing sends an SSHSIG blob (`"SSHSIG"` magic + namespace). We allow
  namespace `git` only. A git grant can sign any commit content.
- The two formats cannot be confused: a userauth blob starts with a uint32
  session ID length, and "SSHS" as a length is about 1.4 GB.
- Forwarded agent connections (`is_forwarding = 1`) are refused. A second bind
  with another session ID on one connection poisons it.
- Identity is the per-grant socket, not the peer PID. Same-uid processes can
  fake their process ancestry, and PIDs get reused.
- Hosts with host certificates are denied for now: the bind carries the
  certificate, not the pinned key.

## 2026-10-30: server, CLI, e2e

- Go timers and `time.Now()` differences use the monotonic clock, which stops
  while a Mac sleeps. Grant expiry is `Round(0)` (wall clock), and Serve polls
  the wall clock every 10s. Signatures are refused at the exact expiry time;
  the socket closes up to 10s later.
- `knownhosts.KeyError.Want` also returns `@cert-authority` keys. They are
  filtered out, because sshgate pins plain host keys only.
- macOS sshd cannot run inside a sandboxed session (`sandbox_init` fails), so
  the e2e test runs sshd in an Alpine podman container. Files go in through
  environment variables, because the podman VM cannot see /tmp.
- Verified against OpenSSH 10.5: `ssh` sends session-bind and uses the
  hostbound method; `ssh-keygen -Y sign` and `git commit -S` work through a
  grant socket.
