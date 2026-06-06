# Agent API

All routes accept `Authorization: Bearer <AGENT_TOKEN>` when `AGENT_TOKEN` is configured.

## `GET /v1/status`

Runs:

```text
birdc show protocols
```

## `POST /v1/lg/ping`

Body:

```json
{"target":"172.20.0.1"}
```

Target must be a single IP inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
ping -c 4 -W 3 <target>
```

## `POST /v1/lg/mtr`

Target must be a single IP inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
mtr -r -c 5 -w <target>
```

## `POST /v1/lg/route`

Target must be an IP or CIDR prefix fully inside DN42 address space (`172.20.0.0/14` or `fd00::/8`).

Runs fixed argv:

```text
birdc show route <target>
```

Targets are validated against DN42 address ranges and never passed through a shell.

## `POST /v1/peers/deploy`

Body:

```json
{
  "request_id": 12,
  "asn": "4242420000",
  "agent": "local",
  "protocol_name": "dn42p12",
  "wireguard_config": "[Interface]\nPrivateKey = {{WIREGUARD_PRIVATE_KEY}}\nListenPort = 20090\n",
  "bird_config": "protocol bgp dn42p12 { ... }\n"
}
```

The agent validates the request, replaces `{{WIREGUARD_PRIVATE_KEY}}` with its
`WIREGUARD_PRIVATE_KEY` environment value, writes one WireGuard `wg-quick` config and one BIRD
snippet, runs `wg-quick down/up` for the WireGuard file, and returns the written file paths. If
`AGENT_DEPLOY_RELOAD_CMD` is set, it is split into fixed argv and run after the files are written.

## `POST /v1/peers/remove`

Body:

```json
{
  "request_id": 12,
  "protocol_name": "dn42p12"
}
```

Tears a peer down: runs `wg-quick down` on its WireGuard file (if present), deletes the WireGuard
and BIRD snippet files for `protocol_name`, and runs `AGENT_DEPLOY_RELOAD_CMD` if set. Used by the
backend when a peer is disabled or deleted so revoked peers do not keep an active tunnel or BGP
session. `protocol_name` is validated and resolved only inside the agent's peer directories.

## Concurrency

Looking glass endpoints (`/v1/status`, `/v1/lg/*`) are bounded by `AGENT_MAX_CONCURRENCY`
(default 4). When that many commands are already running, further requests get `429 Too Many
Requests` instead of queueing, so a flood of public queries cannot exhaust the router.
