# sshgate

> The main work has moved to SSH Gate, a fork of Secretive with scoped grants
> (`lambadalambda/ssh-gate`, branch `scoped-grants`): a Mac app that holds the keys
> in the Secure Enclave and asks in a window, with Touch ID, which process may
> use which key for which purpose and for how long. This repo has the
> `ssh-grant` command and the agent skill for it, the e2e and fixture tools,
> and the original proxy below.

## ssh-grant and the agent skill

```sh
go build -o ssh-grant ./cmd/ssh-grant      # put it on the agent's PATH
ssh-grant login git@git.example.com --for 1h --reason "push branch x"
ssh-grant sign --for 1h --reason "sign the release tag"
```

`ssh-grant` asks the fork's agent (`SSH_AUTH_SOCK`) for a grant before the key
is used. For coding agents, install the skill:

```sh
ln -s "$PWD/skills/ssh-grant" ~/.claude/skills/ssh-grant
```

If a key is marked as grant CA in the fork's host app, each login grant also
gets a user certificate that is valid only for the granted user and until the
grant expires. Servers trust the CA with one line in `authorized_keys`
(`cert-authority,principals="USER" <CA key>`) or with `TrustedUserCAKeys`.
`scripts/manual-certificate-test.sh` tests this end to end.

## The original proxy

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
