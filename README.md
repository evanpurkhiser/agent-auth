# agent-auth

`agent-auth` lets coding agents such as Codex or Claude use an SSH identity
without putting its private key on the machine where the agent runs. It is most
useful when an agent runs as a long-lived service on a remote machine—for
example, a home server from which it needs to push Git commits, deploy software,
or perform another authenticated operation.

Applications receive a normal `SSH_AUTH_SOCK`. When they ask the SSH agent to
sign data, `agent-auth` forwards the request to one of two backends:

- a ready MacBook and its 1Password SSH agent, reached over Tailscale; or
- [Agent Witness](https://github.com/evanpurkhiser/agent-witness), which lets
  you authorize signing requests from any browser-capable device, with the SSH
  keys stored in a passkey-protected vault—for example, on an iPhone.

Only the data to sign and the resulting signature travel between machines. The
private key remains on the MacBook or in Agent Witness.

## Context for signing requests

An SSH-agent request normally says which key should sign which bytes, but not
why. `ssh-agent-ctx` adds a small protocol extension containing the reason for
the request, the command being run, a group ID for related requests, and an
optional backend selection.

For example:

```sh
ssh-agent-ctx "Push the agent-auth release" -- git push origin main
```

The notification emitted for the signing request can then explain what is
happening:

```text
🔐 Agent key request (remote-agent-host via agent-witness)
Reason: Push the agent-auth release
Command: git push origin main
```

> [!NOTE]
> Agent Witness does not yet receive this context or display it alongside its
> approval request. Support for passing the context through to Agent Witness is
> planned.

Direct connections to the proxy are rejected unless they begin with this
context. The proxy sends a notification when the wrapped command first asks for
a signature; operations such as listing public keys do not notify.

The same mechanism can cover privilege escalation when the remote host uses
`pam_ssh_agent_auth` for sudo authentication:

```sh
ssh-agent-ctx "Restart nginx after updating its configuration" -- \
  sudo systemctl restart nginx
```

That setup lets sudo authenticate with an approved SSH signature instead of
giving the remote agent a password or private key.

## Security model

The primary boundary is physical separation: private keys never exist on the
agent host and cannot be copied from it. The host can ask an approved backend to
sign data, but it cannot extract the key material.

Context enforcement also depends on backend isolation. The account running an
untrusted workload must be able to reach the `agent-auth` socket without being
able to open the Agent Witness socket or read the MacBook relay credential
directly. Use a separate service account or equivalent access controls when the
context protocol must be a strict authorization boundary.

## How MacBook routing works

The proxy uses [`tailscale status`](https://tailscale.com/) to find online
MacBooks, tries the most recently active machines first, and checks that the
display and 1Password SSH agent are available. It then opens an SSH connection
using a dedicated relay key.

That key is restricted by `authorized_keys` to a forced command, so it cannot
open a shell or request forwarding. The command is
[`ssh-agent-proxy-serve`](https://github.com/evanpurkhiser/dots-personal/blob/86764c4453c31d38cabacba9279ce9fc9e56d797/common/platform-osx/ssh/ssh-agent-proxy-serve),
which handles readiness probes and relays SSH-agent protocol bytes to the
MacBook's 1Password socket.

If no MacBook is ready, the proxy falls back to the local Agent Witness socket.
A specific backend can also be selected explicitly:

```sh
ssh-agent-ctx --route=macbook-work "Push the release" -- git push
ssh-agent-ctx --route=agent-witness "Push the release" -- git push
```

## Requirements

- Linux with systemd socket activation and Python 3.12 or newer.
- At least one signing backend: Agent Witness, or a MacBook with an SSH agent.
- Tailscale connectivity between the proxy host and MacBook when using MacBook
  routing. A local Agent Witness backend does not require Tailscale.
- Backend credentials and sockets isolated from untrusted workload accounts
  when context must be enforced rather than supplied by convention.
- `pam_ssh_agent_auth` and an authorized public key if SSH-backed sudo is
  desired.

## Installation

Install the Arch package from the
[`evanpurkhiser` package repository](https://github.com/evanpurkhiser/PKGBUILDs):

```sh
sudo pacman -S agent-auth
sudo systemctl enable --now ssh-agent-proxy.socket
export SSH_AUTH_SOCK=/run/ssh-agent-proxy.sock
```

For MacBook routing, place the dedicated relay key at
`/etc/ssh-agent-proxy-key`, readable only by the account that manages backend
connections. Routing can be configured in `/etc/agent-auth/config.toml`:

```toml
[routing]
computer_pattern = "macbook-.*"
ssh_key = "/etc/ssh-agent-proxy-key"
ssh_user = "evan"
agent_witness_socket = "/run/agent-witness/agent.sock"
```

Every setting is optional. The values above are the defaults. Set
`AGENT_AUTH_CONFIG` to load another path. The service also supports environment
overrides, which take precedence over the TOML file:

- `AGENT_AUTH_SSH_KEY`: relay key path; defaults to
  `/etc/ssh-agent-proxy-key`.
- `AGENT_AUTH_SSH_USER`: remote SSH user; defaults to `evan`.
- `AGENT_AUTH_TAILSCALE_MACBOOK_PATTERN`: regular expression used to select
  MacBook peers; defaults to `macbook-.*`.
- `AGENT_AUTH_AGENT_WITNESS_SOCKET`: fallback Agent Witness socket; defaults to
  `/run/agent-witness/agent.sock`.

## Development and releases

```sh
mise install
prek install
prek run --all-files
python -m unittest discover -s tests -v
```

The runtime uses only the Python standard library. Tests cover protocol bounds,
routing, notification behavior, connection relaying, peer diagnostics, and the
command wrapper.

Run the `Bump` workflow with the next semantic version to release. It waits for
CI on `main`, updates `pyproject.toml`, creates the release commit and tag, and
dispatches the `agent-auth` build in the
[`PKGBUILDs`](https://github.com/evanpurkhiser/PKGBUILDs) repository. That
repository owns the Arch package recipe, package signing, and pacman repository
publication.
