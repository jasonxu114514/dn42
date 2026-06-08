# Agent API

The agent is the router-side service used by the backend over an agent-initiated WSS connection. It
has two jobs:

- run looking-glass and peer-status commands with fixed argv;
- deploy or remove generated WireGuard and BIRD peer config.

The agent does not perform ASN authentication. It trusts the authenticated backend connection, so
keep the token private.

## Common Contract

### Authentication

Every agent connection should use:

```http
Authorization: Bearer <token>
```

The token is checked by the backend in constant time against the token stored on the agent record.

### WSS transport

For normal backend communication, the agent connects to:

```text
wss://<backend>/api/agents/ws?name=<agent-name>
Authorization: Bearer <token>
```

If `backend_wss_url` is configured as a bare backend `http(s)` URL, the agent converts it to
`ws(s)` and uses `/api/agents/ws`. The `name` value must match the node record in Admin > Nodes.

After connecting, the agent sends:

```json
{
  "type": "hello",
  "public_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=",
  "system": {
    "hostname": "router1",
    "os": "linux",
    "arch": "amd64",
    "uptime_seconds": 123456,
    "load_1": 0.12,
    "load_5": 0.08,
    "load_15": 0.05,
    "goroutines": 8,
    "wireguard": {
      "ok": true,
      "output": "wg show output for all interfaces"
    },
    "bird": {
      "ok": true,
      "output": "birdc show status + birdc show protocols all output"
    }
  }
}
```

The same shape is sent periodically as `type: "heartbeat"`. The backend uses the active WSS
connection for online/offline state and stores the last heartbeat as system status. WireGuard status
comes from `wg show`; BIRD status combines `birdc show status` and `birdc show protocols all`.

Backend requests use a request/response envelope:

```json
{
  "type": "request",
  "id": "opaque-request-id",
  "command": "peers.status",
  "payload": {"protocol_name": "DN42_0090"}
}
```

The agent replies:

```json
{
  "type": "response",
  "id": "opaque-request-id",
  "result": {"ok": true, "output": "..."}
}
```

Errors that are not command results are returned as `{"type":"response","id":"...","error":"..."}`.
Command results keep the JSON shapes described below.

### JSON payloads

Command payloads accept one JSON object and reject:

- malformed JSON;
- unknown JSON fields;
- trailing data after the first JSON object;

### Response shapes

Most commands return:

```json
{
  "ok": true,
  "output": "command output"
}
```

Deploy and remove routes return:

```json
{
  "ok": true,
  "applied": true,
  "output": "deployed peer config",
  "files": [
    "/etc/wireguard/DN42_0090.conf",
    "/etc/bird/peers/DN42_0090.conf"
  ]
}
```

`ok` means the requested operation completed successfully. `applied` means the agent already wrote
or removed files before a later step failed; callers should surface `output` to the operator.

## Commands

| Command | Purpose | Concurrency-capped |
| --- | --- | --- |
| `pubkey` | Return this node's WireGuard public key | no |
| `lg.ping` | Run ping against a target | yes |
| `lg.trace` | Run traceroute against a target | yes |
| `lg.mtr` | Run mtr report mode against a target | yes |
| `lg.route` | Run `birdc show route for <target>` | yes |
| `peers.deploy` | Write and apply one peer's WireGuard/BIRD config | no |
| `peers.remove` | Tear down and delete one peer's config | no |
| `peers.status` | Return BIRD and WireGuard status for one peer | yes |

Concurrency-capped commands share the `max_concurrency` semaphore. When the semaphore is full, the
agent returns `{"ok": false, "output": "agent is busy, try again shortly"}` instead of queueing work.

## `pubkey`

Returns the agent's configured `wireguard_public_key`.

```json
{
  "public_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="
}
```

The agent validates this key during startup and refuses to start if it is missing or malformed. The
backend stores it on the node record and includes it in peer-facing generated config.

## Looking-Glass Commands

All looking-glass commands take:

```json
{
  "target": "172.20.0.1"
}
```

`target` validation rejects control characters, whitespace, shell metacharacters, a leading `-`, and
values longer than 255 characters.

### `lg.ping`

Accepts any IPv4/IPv6 address or a DNS hostname. Hostnames are syntax-checked and resolved by the
agent-side `ping` command.

Runs:

```text
ping -c 4 -W 3 <target>
```

### `lg.trace`

Accepts the same target shape as ping. For IPv6 literal targets, the agent adds `-6`.

Runs:

```text
traceroute -n -q 1 -w 2 -m 20 [-6] <target>
```

### `lg.mtr`

Accepts the same target shape as trace. The command runs in non-interactive report mode. For IPv6
literal targets, the agent adds `-6`.

Runs:

```text
mtr --report --report-cycles 4 --no-dns --report-wide [-6] <target>
```

### `lg.route`

Accepts an IPv4/IPv6 address or CIDR prefix. Hostnames are not accepted because BIRD does not
resolve names for this query.

Runs:

```text
birdc show route for <target>
```

The `for` keyword asks BIRD for the route actually used to reach the target, rather than only an
exact-prefix match.

## `peers.status`

Request:

```json
{
  "protocol_name": "DN42_0090"
}
```

`protocol_name` must match:

```text
^[A-Za-z0-9_][A-Za-z0-9_-]{0,79}$
```

The agent runs two commands inside one concurrency slot:

```text
birdc show protocols all <protocol_name>
wg show <protocol_name>
```

Response:

```json
{
  "ok": true,
  "output": "BIRD protocol detail",
  "wireguard": "WireGuard tunnel detail"
}
```

`ok` reflects the BIRD command. The `wireguard` field is still returned even when the interface is
down, because `wg show` output such as "No such device" is useful status.

## `peers.deploy`

Request:

```json
{
  "request_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "asn": "4242420090",
  "node": "sin1",
  "protocol_name": "DN42_0090",
  "wireguard_config": "# Generated...\n[Interface]\nPrivateKey = {{WIREGUARD_PRIVATE_KEY}}\nListenPort = 20090\nTable = off\nMTU = 1420\nPostUp = ip addr add fe80::1/64 dev %i\n\n[Peer]\nEndpoint = 198.51.100.10:51820\nPersistentKeepalive = 15\nPublicKey = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=\nAllowedIPs = 10.0.0.0/8, 172.20.0.0/14, 172.31.0.0/16, fd00::/8, fe80::/64\n",
  "bird_config": "# Generated...\nprotocol bgp DN42_0090 from dnpeers {\n  enable extended messages on;\n  neighbor fe80::90%DN42_0090 as 4242420090;\n  source address fe80::1;\n  direct;\n  ipv4 {\n    extended next hop on;\n  };\n}\n"
}
```

Notes:

- MTU is part of `wireguard_config`; there is no separate agent-side MTU JSON field.
- The backend currently renders `MTU = <value>` in the WireGuard `[Interface]` section.
- The default MTU is `1420`; backend validation allows `1280-9000`.
- The agent replaces `{{WIREGUARD_PRIVATE_KEY}}` with `wireguard_private_key` from its config.
- If the placeholder is present and the private key is empty, deployment fails.

Validation:

- `request_id` is required (non-empty, max 64 chars).
- `asn` is required, max 32 chars, and must not contain unsafe target characters.
- `node` is required, max 64 chars, and must not contain `/` or `\`.
- `protocol_name` must match the safe-name regex above.
- `wireguard_config` and `bird_config` are required, max 16 KiB each, and must not contain NUL.

Deploy behavior:

1. Trim request strings.
2. Validate the request.
3. Build output paths:
   - `<wireguard_peer_dir>/<protocol_name>.conf`
   - `<bird_peer_dir>/<protocol_name>.conf`
4. Replace the WireGuard private-key placeholder if present.
5. Verify both output paths remain inside their configured directories.
6. Write both files atomically with restrictive permissions.
7. Set group ownership on the BIRD directory and BIRD snippet if `bird_peer_group` is configured.
8. Run `wg-quick down <wireguard-file>`.
9. Run `wg-quick up <wireguard-file>`.
10. Run `deploy_reload_cmd` if configured.

Example success:

```json
{
  "ok": true,
  "applied": true,
  "output": "deployed peer config\nwg-quick up:\n...",
  "files": [
    "/etc/wireguard/DN42_0090.conf",
    "/etc/bird/peers/DN42_0090.conf"
  ]
}
```

If file writes succeed but `wg-quick up` or the reload command fails, `applied` is `true` and `ok`
is `false`.

## `peers.remove`

Request:

```json
{
  "request_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "protocol_name": "DN42_0090"
}
```

Behavior:

1. Validate `request_id` and `protocol_name`.
2. Resolve the WireGuard and BIRD file paths.
3. Verify both paths remain inside their configured directories.
4. If the WireGuard file exists, run `wg-quick down <wireguard-file>`.
5. Remove both files.
6. Run `deploy_reload_cmd` if configured.

Example response:

```json
{
  "ok": true,
  "applied": true,
  "output": "removed peer config\nwg-quick down:\n...",
  "files": [
    "/etc/wireguard/DN42_0090.conf",
    "/etc/bird/peers/DN42_0090.conf"
  ]
}
```

## Timeouts

Every external command runs with the configured `command_timeout_seconds` timeout. On timeout, the
agent returns `ok: false` and appends `command timed out` to the command output.

## Files and Permissions

- WireGuard files stay root-only because they contain the private key.
- BIRD files are written with restrictive permissions and can be group-owned by `bird_peer_group`.
- Path traversal is blocked by resolving the final path and verifying it remains inside the
  configured directory.

## Backend Relationship

Normal operators do not call this protocol manually. The backend sends WSS commands over the active
agent connection when users create, edit, redeploy, disable, or delete peers. It also sends WSS
commands for public looking-glass queries, Telegram looking-glass queries, public-key refresh, and
live peer status.
