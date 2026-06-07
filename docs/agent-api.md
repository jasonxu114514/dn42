# Agent API

The agent loads all settings from a JSON config file (default `./config.json`, override with
`-config /path/config.json`). All routes accept `Authorization: Bearer <token>` when a `token` is
configured in that file.

## `GET /v1/status`

Runs:

```text
birdc show protocols
```

## `GET /v1/pubkey`

Returns the agent's own WireGuard public key (set via `wireguard_public_key` in the config file).
The control plane caches it per PoP and substitutes it into each peer's generated config:

```json
{"public_key": "<44-character base64 key>"}
```

Runs no command (so it is not bounded by `max_concurrency`), but still requires the bearer
token. The agent refuses to start without a valid `wireguard_public_key`, so this never returns an
empty value.

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
  "asn": "4242420090",
  "agent": "local",
  "protocol_name": "DN42_0090",
  "wireguard_config": "[Interface]\nPrivateKey = {{WIREGUARD_PRIVATE_KEY}}\nListenPort = 20090\n",
  "bird_config": "protocol bgp DN42_0090 { ... }\n"
}
```

The agent validates the request, replaces `{{WIREGUARD_PRIVATE_KEY}}` with the
`wireguard_private_key` from its config, writes one WireGuard `wg-quick` config and one BIRD
snippet, runs `wg-quick down/up` for the WireGuard file, and returns the written file paths. If
`deploy_reload_cmd` is set, it is split into fixed argv and run after the files are written.

The BIRD peer directory and its snippet are group-owned by `bird_peer_group` (default `bird`, mode
left at `0750`/`0640`) so the unprivileged BIRD daemon can read the include when `birdc configure`
runs; set `bird_peer_group` to `""` to disable this. The WireGuard file is never chowned — it holds
the private key and stays root-only.

## `POST /v1/peers/remove`

Body:

```json
{
  "request_id": 12,
  "protocol_name": "DN42_0090"
}
```

Tears a peer down: runs `wg-quick down` on its WireGuard file (if present), deletes the WireGuard
and BIRD snippet files for `protocol_name`, and runs `deploy_reload_cmd` if set. Used by the
backend when a peer is disabled or deleted so revoked peers do not keep an active tunnel or BGP
session. `protocol_name` is validated and resolved only inside the agent's peer directories.

## `POST /v1/peers/status`

Body:

```json
{
  "protocol_name": "DN42_0090"
}
```

Runs fixed argv:

```text
birdc show protocols all <protocol_name>
```

Returns the detailed BIRD state for a single peer (BGP state, last error such as `Connection
reset`, route counts). Used by the Telegram `/peer` (alias `/status`) command, which queries each
of the caller's own peers. `protocol_name` is validated against the same safe-name pattern as
deploy/remove, and the call is bounded by `max_concurrency` like the other looking-glass reads.

## Concurrency

Looking glass endpoints (`/v1/status`, `/v1/lg/*`) are bounded by `max_concurrency`
(default 4). When that many commands are already running, further requests get `429 Too Many
Requests` instead of queueing, so a flood of public queries cannot exhaust the router.
