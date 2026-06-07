# Agent API

The agent is the router-side HTTP service used by the backend. It has two jobs:

- run looking-glass and peer-status commands with fixed argv;
- deploy or remove generated WireGuard and BIRD peer config.

The agent does not perform ASN authentication. It trusts the backend that calls it, so it should be
reachable only by the backend or a trusted management network.

## Common Contract

### Authentication

If `token` is set in `config.json`, every route requires:

```http
Authorization: Bearer <token>
```

The token is compared in constant time. If `token` is empty, agent auth is disabled.

### JSON bodies

POST routes accept one JSON object and reject:

- non-POST methods;
- unsupported `Content-Type` values when a content type is sent;
- malformed JSON;
- unknown JSON fields;
- trailing data after the first JSON object;
- bodies larger than the route limit.

### Response shapes

Most command routes return:

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

## Endpoints

| Method | Path | Purpose | Concurrency-capped |
| --- | --- | --- | --- |
| `GET` | `/v1/status` | `birdc show protocols` | yes |
| `GET` | `/v1/pubkey` | Return this PoP's WireGuard public key | no |
| `POST` | `/v1/lg/ping` | Run ping against a target | yes |
| `POST` | `/v1/lg/trace` | Run traceroute against a target | yes |
| `POST` | `/v1/lg/mtr` | Run mtr report mode against a target | yes |
| `POST` | `/v1/lg/route` | Run `birdc show route for <target>` | yes |
| `POST` | `/v1/peers/deploy` | Write and apply one peer's WireGuard/BIRD config | no |
| `POST` | `/v1/peers/remove` | Tear down and delete one peer's config | no |
| `POST` | `/v1/peers/status` | Return BIRD and WireGuard status for one peer | yes |

Concurrency-capped routes share the `max_concurrency` semaphore. When the semaphore is full, the
agent returns `429` instead of queueing work.

## `GET /v1/status`

Runs:

```text
birdc show protocols
```

Example response:

```json
{
  "ok": true,
  "output": "BIRD protocol table..."
}
```

This is used by the public looking glass `status` query.

## `GET /v1/pubkey`

Returns the agent's configured `wireguard_public_key`.

```json
{
  "public_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx="
}
```

The agent validates this key during startup and refuses to start if it is missing or malformed. The
backend stores it on the agent record and includes it in peer-facing generated config.

## Looking-Glass Routes

All looking-glass routes take:

```json
{
  "target": "172.20.0.1"
}
```

`target` validation rejects control characters, whitespace, shell metacharacters, a leading `-`, and
values longer than 255 characters.

### `POST /v1/lg/ping`

Accepts any IPv4/IPv6 address or a DNS hostname. Hostnames are syntax-checked and resolved by the
agent-side `ping` command.

Runs:

```text
ping -c 4 -W 3 <target>
```

### `POST /v1/lg/trace`

Accepts the same target shape as ping. For IPv6 literal targets, the agent adds `-6`.

Runs:

```text
traceroute -n -q 1 -w 2 -m 20 [-6] <target>
```

### `POST /v1/lg/mtr`

Accepts the same target shape as trace. The command runs in non-interactive report mode. For IPv6
literal targets, the agent adds `-6`.

Runs:

```text
mtr --report --report-cycles 4 --no-dns --report-wide [-6] <target>
```

### `POST /v1/lg/route`

Accepts an IPv4/IPv6 address or CIDR prefix. Hostnames are not accepted because BIRD does not
resolve names for this query.

Runs:

```text
birdc show route for <target>
```

The `for` keyword asks BIRD for the route actually used to reach the target, rather than only an
exact-prefix match.

## `POST /v1/peers/status`

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

## `POST /v1/peers/deploy`

Request:

```json
{
  "request_id": 123,
  "asn": "4242420090",
  "agent": "sin1",
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

- `request_id` must be positive.
- `asn` is required, max 32 chars, and must not contain unsafe target characters.
- `agent` is required, max 64 chars, and must not contain `/` or `\`.
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

## `POST /v1/peers/remove`

Request:

```json
{
  "request_id": 123,
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

Normal operators do not call this API manually. The backend calls it when users create, edit,
redeploy, disable, or delete peers. The backend also calls:

- `GET /v1/pubkey` when registering or refreshing an agent;
- `POST /v1/peers/status` when showing live peer status;
- looking-glass routes for public Web UI and Telegram queries.
