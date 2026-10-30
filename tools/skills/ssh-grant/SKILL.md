---
name: ssh-grant
description: Ask the user for permission before using their SSH key. Use before ssh, scp, rsync, git push/pull/fetch/clone over SSH, and signed git commits or tags (git commit -S, git tag -s), when the `ssh-grant` command is available.
---

# Requesting SSH key access with ssh-grant

The user's SSH agent does not let you use their key without permission. Each
permission (a "grant") covers one purpose for a limited time: logins to one
host as one user, or git signatures. The user approves it in a window on their
Mac.

You can ask in advance with `ssh-grant`. Do this before the first command that
needs the key. Then you can give a reason, and the following commands work
without interruption. (If you do not ask, the first ssh or git command opens
the window anyway, but without your reason. Servers that accept only
certificates need the grant in advance.)

## Check that it is available

```sh
command -v ssh-grant
```

If it is not available, use ssh and git as usual.

## Logins (ssh, scp, rsync, git over SSH)

Find the user, host and port. For git, read the remote URL:

```sh
git remote -v
# git@github.com:org/repo.git                  -> git@github.com
# ssh://git@git.example.com:2222/org/repo.git  -> git@git.example.com:2222
```

Then ask:

```sh
ssh-grant login git@github.com --for 1h --reason "push branch fix-login to origin for review"
```

For a plain ssh session, `ssh-grant ssh` does both steps: it finds user, host
and port like ssh does (also through `~/.ssh/config` aliases), asks for the
grant, and then runs ssh with the same arguments:

```sh
ssh-grant ssh --reason "check disk space on the backup server" root@backup.example.com df -h
```

## Signed commits and tags

```sh
ssh-grant sign --for 1h --reason "sign the commits of the fix-login branch"
```

The namespace is `git` by default. Use `--namespace NAME` only if a tool needs
another SSHSIG namespace.

## Choosing duration and reason

- Use the shortest duration that covers the task: `15m`, `1h`, `4h` or `8h`.
  The window offers these and preselects the closest one; the user can change it.
- Write the reason as one short, concrete sentence: what you will do and why.
  The user sees it as your claim. Do not claim instructions that the user did
  not give, and never put secrets in it.
- Ask once per host and purpose. A grant covers you and every process you
  start, until it expires.

## Results

The command waits until the user decides (at most about two minutes).

| Exit status | Meaning |
|---|---|
| 0 | Granted. Continue. |
| 1 | Not granted: denied, timed out, host not in known_hosts, or no agent support. |
| 2 | Wrong arguments. |

## When the user does not grant

- Stop and tell the user what you wanted to do and why. Ask how to continue.
- Do not retry in a loop. After a denial, the same request is refused for 30
  seconds without asking.
- Do not try workarounds: no other keys (`ssh -i`), no other agent sockets, no
  changes to `SSH_AUTH_SOCK`, `~/.ssh/config` or `~/.ssh/known_hosts`, no HTTPS
  remotes with stored tokens.
- If the host is not in the user's `~/.ssh/known_hosts`, the agent refuses the
  request. Ask the user to connect to the host once themselves. Hashed
  known_hosts entries are not supported.
