# dn42 Autopeer

**English** | [Traditional Chinese](README.zh-TW.md)

Self-service autopeering and a public looking glass for dn42.

The project has three parts:

- **Backend**: a FastAPI control plane with a server-rendered Web UI, ASN login, peer lifecycle
  management, and the bot-only REST API.
- **Node service**: a small Go service that runs on each node (router) as root. It executes fixed-argument
  looking-glass commands and applies per-peer WireGuard and BIRD config.
- **Telegram bot**: a guided interface for login, peer create/edit/delete, peer status, and
  looking-glass queries.

Peers prove control of an ASN, choose a node, submit their WireGuard public key (and an optional
endpoint), and receive the operator-side parameters they need to configure their tunnel. The backend
renders WireGuard and BIRD snippets and sends them to the selected node service.

> [!WARNING]
> The node service runs as root because it writes router config and calls `wg-quick`. Treat every value that
> can reach a node service as security-sensitive. The backend and node service validate user input, but this is
> still infrastructure automation.

## Contents

- [Architecture](#architecture)
- [How Peering Works](#how-peering-works)
- [Generated Defaults](#generated-defaults)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Web UI](#web-ui)
- [Telegram Bot](#telegram-bot)
- [Node Service and BIRD](#node-service-and-bird)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)

## Architecture

```text
Browser                 Telegram bot
   |                         |
   | HTTP(S)                 | HTTP + X-Backend-Secret
   v                         v
+------------------------------------------------+
| Backend: FastAPI, SQLite, Web UI, bot API       |
| - verifies ASN ownership                        |
| - stores users, nodes, peers, sessions          |
| - renders WireGuard and BIRD peer config        |
+------------------------------------------------+
                         |
                         | Node-initiated WSS
                         v
+------------------------------------------------+
| Node service on each router                     |
| - writes /etc/wireguard/*.conf                  |
| - writes /etc/bird/peers/*.conf                 |
| - runs wg-quick, birdc, ping, traceroute, mtr   |
+------------------------------------------------+
```

The backend can run on the same host as the bot. Node services usually run on routers, one service per node.
Each node service keeps a bearer-token WSS connection to the backend; the public address stored in the
admin panel is the endpoint host used for generated WireGuard configs. Each node carries its own
dn42 identity (ASN, DN42 IPv4/IPv6); the ASN falls back to `LOCAL_ASN` when left blank.

## How Peering Works

1. A user logs in and proves control of a dn42 ASN using Kioubit.dn42 or the optional FindNOC
   Telegram quick login.
2. The user creates a peer in the Web portal or Telegram bot:
   - selects an enabled node;
   - enters their WireGuard public key;
   - optionally enters their WireGuard endpoint (`host:port`); blank means the peer dials us;
   - chooses their in-tunnel IP — link-local by default, a ULA (`fd00::/8`) is also accepted;
   - chooses a WireGuard MTU, default `1420`.
3. The backend validates the values, enforces one peer per ASN per node, stores the peer as
   approved, and renders the WireGuard and BIRD config. Our-side address is derived from the node.
4. The backend sends a `peers.deploy` command over the node service's WSS connection.
5. The node service writes the config files, runs `wg-quick down` and `wg-quick up`, then runs the optional
   BIRD reload command.
6. After deployment, the Web UI and bot show the peer the operator-side values:
   - our WireGuard endpoint;
   - our WireGuard public key for the chosen node;
   - our tunnel IP, used as the peer's BGP neighbor;
   - the WireGuard MTU.

Disabling or deleting a peer asks the node service to run `wg-quick down` and remove both the WireGuard and
BIRD snippets.

## Generated Defaults

| Value | Rule | Example for `AS4242420090` |
| --- | --- | --- |
| WireGuard listen port | Last 5 digits of the peer ASN | `20090` |
| Interface/config/BIRD protocol name | `DN42_` + last 4 digits | `DN42_0090` |
| Peer link-local address | `fe80::<asn-suffix>` | `fe80::90` |
| WireGuard MTU | User-editable, default `1420`, range `1280-9000` | `1420` |
| BGP extensions | Enabled by default; emits extended messages and IPv4 extended nexthop | `on` |

The host part of our endpoint is taken from the node's public address registered in the admin panel.
The backend adds the ASN-derived WireGuard listen port.

Peer creation now asks for DN42 IPv4, DN42 IPv6, and link-local/BGP address separately. Blank
address fields are skipped, but at least one of the three must be provided. If the link-local/BGP
address is blank, the backend derives the traditional `fe80::<asn-suffix>` neighbor before showing
the confirmation step.

Generated WireGuard configs include the MTU in `[Interface]`:

```ini
[Interface]
PrivateKey = {{WIREGUARD_PRIVATE_KEY}}
ListenPort = 20090
Table = off
MTU = 1420
PostUp = ip addr add fe80::1/64 dev %i
```

## Quickstart

### Backend and bot

Linux / macOS:

```sh
cp .env.example .env
python3 -m pip install -r requirements.txt
python3 start.py
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
python -m pip install -r requirements.txt
python start.py
```

Edit `.env` before production use. At minimum set:

- `DOMAIN`
- `LOCAL_ASN`
- `SESSION_SECRET`
- `TELEGRAM_BACKEND_SECRET`
- `TELEGRAM_BOT_TOKEN` if using the bot

Place Kioubit's signing public key at `app/keys/public_key.pem`.

Useful launcher flags:

| Flag | Effect |
| --- | --- |
| `--allow-http` | Local testing mode. Allows non-HTTPS `DOMAIN` and placeholder secrets. Do not use in production. |
| `--backend-only` | Start only FastAPI. |
| `--bot-only` | Start only the Telegram bot. |
| `--host` / `--port` | Override backend bind host/port. |

### Node service

Build and run the node service on each router:

```sh
go build -o node ./cmd/node
cp config.example.json config.json
./node -config ./config.json
```

The backend starts with no nodes. Register each node in **Admin > Nodes**, then copy the node name,
generated token, and backend WSS URL into the matching router's `config.json`. Once connected, the
node service sends heartbeat/system status, all-server WireGuard/BIRD status, and its configured
`wireguard_public_key`, which the backend caches and shows to peers.

## Configuration

### Backend `.env`

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_NAME` | `dn42 Autopeer` | Display name in the Web UI. |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Uvicorn bind address. Keep it behind a reverse proxy for production. |
| `DOMAIN` | `example.com` in `.env.example` | Public domain used for login links. No scheme means `https://`. |
| `SESSION_SECRET` | `change-me` | Signed-cookie session secret. Must be changed. |
| `DATABASE_URL` | `sqlite:///./autopeer.db` | SQLAlchemy database URL. |
| `LOCAL_ASN` | `4242420000` in `.env.example` | Operator ASN. A login for this ASN becomes admin. Also used for default local link-local address. |
| `KIOUBIT_PUBLIC_KEY_PATH` | `app/keys/public_key.pem` | Kioubit ECDSA public key. |
| `TELEGRAM_BOT_TOKEN` | empty | BotFather token. Required only for the bot process. |
| `TELEGRAM_BACKEND_SECRET` | `change-me-too` | Shared secret between bot and backend. Must be changed. |
| `TELEGRAM_BACKEND_URL` | `http://127.0.0.1:8000` | Internal URL the bot uses to reach the backend. |
| `FINDNOC_API_URL` | `https://findnoc.ox5.cc` | Optional FindNOC API base URL. |
| `FINDNOC_API_TOKEN` | empty | Enables Telegram FindNOC quick login when set. |
| `ALLOW_INSECURE_DEFAULTS` | `0` | Allows placeholder secrets only for local testing. |
| `LG_RATE_LIMIT` | `20` | Public looking-glass requests per client IP per window. `0` disables. |
| `LG_RATE_WINDOW_SECONDS` | `60` | Rate-limit window length. |
| `FORWARDED_IP_HEADER` | empty | Trusted client-IP header, such as `X-Forwarded-For`, only behind a trusted proxy. |

Generate strong secrets with:

```sh
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Node service `config.json`

| Key | Default | Purpose |
| --- | --- | --- |
| `name` | empty | Node name matching the backend node record; required for WSS. |
| `token` | empty | Bearer token used for the WSS connection. |
| `backend_wss_url` | required | Backend websocket URL, usually `wss://example.com/api/nodes/ws`. `http(s)` base URLs are accepted and converted to `ws(s)`. |
| `max_concurrency` | `4` | Concurrent looking-glass commands. `0` disables the cap. |
| `command_timeout_seconds` | `12` | Timeout for each external command. |
| `birdc_path` | `birdc` | Path to `birdc`. |
| `ping_path` | `ping` | Path to `ping`. |
| `traceroute_path` | `traceroute` | Path to `traceroute`. |
| `mtr_path` | `mtr` | Path to `mtr`. |
| `wg_path` | `wg` | Path to `wg`, used for live tunnel status. |
| `wg_quick_path` | `wg-quick` | Path to `wg-quick`, used to bring peer interfaces up/down. |
| `wireguard_peer_dir` | `/etc/wireguard` | Directory for generated WireGuard configs. |
| `bird_peer_dir` | `/etc/bird/peers` | Directory for generated BIRD snippets. |
| `bird_peer_group` | `bird` | Group assigned to BIRD snippets so an unprivileged BIRD daemon can read them. `""` disables chown. |
| `deploy_reload_cmd` | empty | Fixed-argv command run after deploy/remove, such as `birdc c`. |
| `wireguard_private_key` | empty | Router private key substituted for `{{WIREGUARD_PRIVATE_KEY}}`. |
| `wireguard_public_key` | required | Router public key reported to the backend and peers. |

Keep the node config root-owned and mode `0600`; it contains the node token and WireGuard private
key.

## Web UI

| Route | Purpose |
| --- | --- |
| `/` | Home: network intro, a how-to-peer guide, and live node status. |
| `/lg` | Public looking glass (ping, traceroute, mtr, route). |
| `/login` | Web Kioubit login. |
| `/portal` | My Peers: overview of your peers. |
| `/portal/new` | Create a peer. |
| `/portal/peers/{id}` | Peer detail: ids, our-side parameters, node addressing, live status; delete. |
| `/admin` | Operator overview. |
| `/admin/nodes` | Register/edit nodes (ASN, DN42 addresses, enable/disable), refresh pubkeys, reset tokens. |
| `/admin/peers` | Edit, redeploy, disable, delete peers. |
| `/admin/users` | Manage users and Telegram bindings. |
| `/admin/lg-log` | Audit log for looking-glass queries. |

Both the New Peer form and the admin peer form collect DN42 IPv4, DN42 IPv6, link-local/BGP address,
WireGuard MTU, and the BGP extension switch. The Web portal shows a confirmation page before
creating the peer; the admin form can also correct addresses and redeploy. Disabled nodes are hidden
from the public site and the looking glass.

## Telegram Bot

Commands:

```text
/login        Log in to a dn42 ASN
/logout       Unlink Telegram from the current ASN
/listpeers    Show peer status, our-side parameters, WireGuard, and BIRD details
/create       Guided peer creation
/edit         Guided peer edit, including MTU
/delete       Guided peer deletion
/ping         Run ping from a node
/trace        Run traceroute from a node
/mtr          Run mtr from a node
/route        Run a BIRD route lookup from a node
/cancel       Abort the current guided action
```

For `/create`, the bot asks for node, endpoint (send `skip` for none), public key, DN42 IPv4, DN42
IPv6, link-local/BGP address, MTU, and whether BGP extensions should stay enabled. It shows a
confirmation block before creating the peer. Sending `default` at the MTU step uses `1420`. For
`/edit`, sending `keep` keeps the current MTU. Peers are picked from a numbered menu rather than by
id.

## Node Service and BIRD

WireGuard configs are complete `wg-quick` files. The interface name, WireGuard file name, and BIRD
protocol name are the same value, such as `DN42_0090`.

Deployment writes:

- `<wireguard_peer_dir>/<protocol_name>.conf`
- `<bird_peer_dir>/<protocol_name>.conf`

A minimal BIRD setup should include the peer snippet directory:

```text
include "/etc/bird/peers/*.conf";
```

The generated peer snippets expect a BGP template named `dnpeers`:

```text
template bgp dnpeers {
  local as 4242420000;
  ipv4 {
    import all;
    export all;
  };
  ipv6 {
    import all;
    export all;
  };
}
```

Adjust the template to your routing policy before production use. When a peer's BGP extension switch
is enabled, the generated snippet includes `enable extended messages on;` and an IPv4 block with
`extended next hop on;`. Turning the switch off omits those lines.

The full node API is documented in [docs/node-api.md](docs/node-api.md). Authentication details
are documented in [docs/auth-flow.md](docs/auth-flow.md).

## Security Model

- The backend verifies ASN ownership before creating or managing peers.
- Admin access is granted only when the verified ASN equals `LOCAL_ASN`.
- Backend sessions are signed cookies.
- The backend rejects placeholder secrets unless insecure defaults are explicitly allowed.
- The bot-only API requires `X-Backend-Secret`.
- Node WSS connections require `Authorization: Bearer <token>`.
- Node and bot secrets are compared in constant time.
- User-supplied router config fields are validated before rendering.
- Node commands use fixed argv, never a shell.
- Node writes are confined to configured peer directories.
- Looking-glass queries are rate-limited by the backend and concurrency-limited by the node service.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Backend refuses to start with insecure defaults | Set strong `SESSION_SECRET` and `TELEGRAM_BACKEND_SECRET`, or use `--allow-http` for local testing. |
| Telegram Mini App login does not work | `DOMAIN` must be a public HTTPS URL. |
| Node stays offline | Check `name`, `backend_wss_url`, TLS reachability, and that the token matches **Admin > Nodes**. |
| Node returns `unauthorized` | Backend node token and node `config.json` token do not match. |
| Peer config shows `<our-wireguard-public-key>` | Connect the node service or refresh the pubkey in **Admin > Nodes**, then check `wireguard_public_key`. |
| Deploy fails with missing private key | Set `wireguard_private_key` in the node config. |
| Deploy fails with BIRD permission errors | Set `bird_peer_group` to the group used by the BIRD daemon, often `bird`. |
| BGP session stays down | Check link-local addresses, MTU, allowed routes, BIRD template, and `wg show <interface>`. |
| Looking glass returns `429` | Backend rate limit or node concurrency limit was hit. |

## Project Layout

```text
app/api/            Bot-only REST API
app/auth/           Kioubit, FindNOC, sessions, user binding
app/bot/            Telegram bot
app/db/             SQLAlchemy models and schema bootstrap
app/lg/             Looking-glass client, validation, rate limit
app/peer/           Peer validation, config rendering, deploy/remove
app/node_ws.py      Node WSS hub (node connections, live status)
app/templates/      Jinja templates
app/static/         CSS and small browser scripts
cmd/node/           Node service entry point
internal/api/       Node command dispatcher
internal/config/    Node JSON config loader
internal/runner/    Command execution and deploy logic
docs/               Node API and authentication flow
start.py            Backend + bot launcher
```

