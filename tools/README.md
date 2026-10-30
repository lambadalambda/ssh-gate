# sshgate

A filtering ssh-agent proxy. Each grant gets its own socket. A process that
uses the socket can only:

- log in to hosts whose host key is pinned in the grant, and
- make SSHSIG signatures in the allowed namespaces (for example `git`),

with the keys of the grant, until the grant expires.

## Usage

```sh
go build ./cmd/sshgate

sshgate grant --name claude-repoX \
    --upstream ~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh \
    --key ~/.ssh/agent-key.pub \
    --host git.example.com --user git \
    --namespace git \
    --ttl 4h
# export SSH_AUTH_SOCK=/Users/you/.sshgate/claude-repoX.sock
```

Give the printed `SSH_AUTH_SOCK` to the agent. The command runs in the
foreground and logs every decision to stderr. When the TTL ends, or on
Ctrl-C, the socket is removed.

Host keys for `--host` come from `~/.ssh/known_hosts` (or `--known-hosts`)
when the grant starts. Connect to the host once yourself first.

Run `sshgate` without arguments for all flags.

## How it works

- **Logins.** Since OpenSSH 8.9, `ssh` sends `session-bind@openssh.com` to
  the agent: the server host key, the session ID and the host's signature
  over it. sshgate verifies this message, and signs a login only if the bound
  host key is pinned and the session IDs match. Older clients cannot log in.
- **Signing.** `ssh-keygen -Y sign` (which git uses) sends an SSHSIG blob with
  a namespace. Only the namespaces of the grant are signed.
- **Everything else** is refused: other sign data, forwarded agent
  connections, adding or removing keys, locking.

## Limits

- The socket path is the identity. Use a sandbox so that the agent cannot
  reach the upstream socket, other grant sockets or private key files.
- A `git` grant can sign any commit or tag content.
- Hosts that present host certificates are refused for now.
- If you use Secretive with "require authentication", each signature asks
  for Touch ID. Use a separate key without it for unattended agents.

## Tests

```sh
go test -short ./...   # unit tests
go test ./e2e          # real OpenSSH in a podman container
```
