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
