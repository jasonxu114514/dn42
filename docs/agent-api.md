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

Target must be a single IP address (any IPv4 or IPv6) or a DNS hostname; ping/traceroute resolve
the hostname themselves.

Runs fixed argv:

```text
ping -c 4 -W 3 <target>
```

## `POST /v1/lg/trace`

Target must be a single IP address (any IPv4 or IPv6) or a DNS hostname; ping/traceroute resolve
the hostname themselves.

Runs fixed argv (`-6` is added for IPv6 targets):

```text
traceroute -n -q 1 -w 2 -m 20 <target>
```

`POST /v1/lg/mtr` is kept as a back-compat alias that runs the same traceroute.

## `POST /v1/lg/route`

Target must be an IP or CIDR prefix (any IPv4 or IPv6).

Runs fixed argv:

```text
birdc show route for <target>
```

`for` makes BIRD do a longest-prefix forwarding lookup, so a bare host IP resolves to its covering
route and a prefix such as `1.1.1.0/24` resolves to the route used for it. Targets are validated as
well-formed IP addresses or prefixes and never passed through a shell.

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

## `POST /v1/peers/status`

Body:

```json
{
  "protocol_name": "dn42p12"
}
```

Runs fixed argv:

```text
birdc show protocols all <protocol_name>
```

Returns the detailed BIRD state for a single peer (BGP state, last error such as `Connection
reset`, route counts). Used by the Telegram `/status` command, which queries each of the caller's
own peers. `protocol_name` is validated against the same safe-name pattern as deploy/remove, and
the call is bounded by `AGENT_MAX_CONCURRENCY` like the other looking-glass reads.

## Concurrency

Looking glass endpoints (`/v1/status`, `/v1/lg/*`) are bounded by `AGENT_MAX_CONCURRENCY`
(default 4). When that many commands are already running, further requests get `429 Too Many
Requests` instead of queueing, so a flood of public queries cannot exhaust the router.
