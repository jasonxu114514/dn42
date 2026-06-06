# dn42 Autopeer

**English** · [繁體中文](README.zh-TW.md)

A self-service autopeer and looking-glass service for [dn42](https://dn42.dev): a Python control
plane that authenticates ASN owners and pushes WireGuard + BIRD2 configs to your routers, and a Go
agent that applies them. Peers can be created from a web portal or a Telegram bot.

- **WebUI** — public looking glass, authenticated user portal, admin panel
- **Kioubit.dn42 auth** — proves ASN ownership before any config is generated
- **Telegram** — Mini App verification plus a guided bot for peer create/edit/delete and status
- **Go agent** — runs `ping` / `traceroute` / `birdc` and deploys per-peer WireGuard + BIRD configs
- **SQLite by default** — zero-setup local testing; point `DATABASE_URL` elsewhere for production

> **Heads up:** the agent runs on your router **as root** (it calls `wg-quick` and writes BIRD
> snippets). Treat every value that can reach a router config as security-sensitive, and read the
> [Security model](#security-model) before exposing the service publicly.

## Contents

- [Architecture](#architecture)
- [How peering works](#how-peering-works)
- [Quickstart](#quickstart)
- [Configuration reference](#configuration-reference)
- [Looking glass](#looking-glass)
- [Telegram](#telegram)
- [Agent](#agent)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Layout](#layout)

## Architecture

```text
                 Kioubit.dn42 (ASN ownership, ECDSA-signed tokens)
                        │ verify
   Browser / Telegram ──┤
            │           ▼
            │     ┌───────────────┐   Bearer-token HTTP    ┌──────────────────┐
            └────▶│   Backend     │ ─────────────────────▶ │   Agent (root)   │
   Telegram bot ─▶│  (FastAPI)    │   /v1/lg/* /v1/peers/* │  per router/PoP  │
   X-Backend-Secret   │  SQLite    │ ◀───────────────────── │  wg-quick + bird │
                  └───────────────┘     JSON results        └──────────────────┘
```

- **Backend** (`backend/`, FastAPI) — serves the WebUI, the bot-only REST API, and the control
  plane. It talks **directly** to agents over HTTP using a per-agent bearer token it generates.
- **Agent** (`agent/`, Go) — one per router ("PoP"). Executes fixed-argv looking-glass commands and
  writes/reloads per-peer WireGuard and BIRD config. Looking-glass concurrency is capped so public
  queries can't exhaust the router.
- **Telegram bot** (`backend/app/bot/`, aiogram) — a separate process that calls the backend over
  HTTP, authenticated with a shared `TELEGRAM_BACKEND_SECRET`.

## How peering works

1. **Authenticate** your ASN with Kioubit (web `/login` or the Telegram `/login` Mini App). The
   backend only ever trusts Kioubit-signed data.
2. **Create a peer** — in the portal or via the `/create` bot wizard — choosing a PoP (agent), your
   WireGuard endpoint (`host:port`), and your WireGuard public key. The link-local BGP addresses
   default to `fe80::<asn-suffix>` (e.g. `4242420099` → `fe80::99`); use the web portal for custom
   addresses.
3. The backend **validates** every field, enforces **one peer per ASN per PoP**, **auto-approves**
   the peer, renders the WireGuard + BIRD2 snippets, and `POST`s them to the agent's
   `/v1/peers/deploy`.
4. The agent writes `dn42p<peer-id>.conf` for WireGuard and BIRD, runs `wg-quick down/up`, and
   reloads BIRD if configured.
5. **Deleting or disabling** a peer tears it down on the router (`/v1/peers/remove`: `wg-quick down`
   plus snippet removal), so revoked peers stop forwarding immediately.

The WireGuard listen port is derived from the remote ASN's last five digits (`4242420090` →
`20090`); the endpoint a peer dials is the agent host plus that port.

## Quickstart

### Backend (Linux)

```sh
cd backend
cp .env.example .env            # then edit: set DOMAIN, LOCAL_ASN, and strong secrets
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cd ..
python3 start.py                # starts backend + Telegram bot
```

`start.py` launches both the FastAPI backend and the Telegram bot and streams their logs. Useful
flags:

| Flag | Effect |
| --- | --- |
| `--allow-http` | Start even when `DOMAIN` is not HTTPS (sets `ALLOW_INSECURE_DEFAULTS=1`). Local testing only — Telegram Mini App verification will not work. |
| `--backend-only` | Start only the FastAPI backend. |
| `--bot-only` | Start only the Telegram bot. |
| `--host` / `--port` | Override the backend bind address without editing `.env`. |

Place Kioubit's public key at `backend/app/keys/public_key.pem`.

### Backend (Windows)

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\pip install -e .
cd ..
python start.py
```

### Agent (on each router)

```sh
cd agent
go build ./cmd/agent
AGENT_LISTEN=:8080 AGENT_TOKEN=<token-from-admin-panel> ./agent
```

The backend starts with no agents. Add each router in the admin panel (name, location, Agent API
URL); the backend generates each agent's bearer token for you. Set that token as `AGENT_TOKEN` on
the corresponding router.

## Configuration reference

### Backend (`backend/.env`)

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_NAME` | `dn42 Autopeer` | Display name in the WebUI. |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Uvicorn bind address. Use `0.0.0.0` only for direct external access; keep `127.0.0.1` behind a reverse proxy. |
| `DOMAIN` | `127.0.0.1:8000` | Public domain for generated links and Kioubit verification. No scheme ⇒ treated as `https://`. |
| `SESSION_SECRET` | `dev-session-secret` | Web session signing key. **Must** be changed (see below). |
| `DATABASE_URL` | `sqlite:///./autopeer.db` | SQLAlchemy URL. |
| `LOCAL_ASN` | _(empty)_ | Your local BGP ASN; also the ASN granted admin after Kioubit login. |
| `KIOUBIT_PUBLIC_KEY_PATH` | `app/keys/public_key.pem` | Kioubit signing public key (PEM). |
| `TELEGRAM_BOT_TOKEN` | _(empty)_ | BotFather token; required for the bot. |
| `TELEGRAM_BACKEND_SECRET` | `dev-telegram-secret` | Shared secret between bot and backend. **Must** be changed. |
| `TELEGRAM_BACKEND_URL` | _(falls back to `DOMAIN`)_ | Internal URL the bot uses to reach the backend — keep `http://127.0.0.1:8000` when co-located. |
| `ALLOW_INSECURE_DEFAULTS` | `0` | `1` tolerates placeholder secrets (local testing). |
| `LG_RATE_LIMIT` | `20` | Max looking-glass queries per window per client IP (`0` disables). |
| `LG_RATE_WINDOW_SECONDS` | `60` | Rate-limit window length. |
| `FORWARDED_IP_HEADER` | _(empty)_ | e.g. `X-Forwarded-For`, **only** behind a trusted proxy that sets it; otherwise all clients share one bucket. |

Generate strong secrets with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. The
backend **refuses to start** while `SESSION_SECRET` or `TELEGRAM_BACKEND_SECRET` is a placeholder
(`change-me`, `dev-…`, empty) unless `ALLOW_INSECURE_DEFAULTS=1` (or `start.py --allow-http`).

### Agent (environment)

| Variable | Default | Purpose |
| --- | --- | --- |
| `AGENT_LISTEN` | `:8080` | Listen address. |
| `AGENT_TOKEN` | _(empty)_ | Bearer token required on every request (from the admin panel). Empty ⇒ no auth. |
| `AGENT_MAX_CONCURRENCY` | `4` | Concurrent looking-glass commands; extra requests get `429` instead of queueing (`0` disables the cap). |
| `BIRDC_PATH` / `TRACEROUTE_PATH` / `PING_PATH` / `WG_QUICK_PATH` | `birdc` / `traceroute` / `ping` / `wg-quick` | Tool paths. |
| `AGENT_DEPLOY_DIR` | `/etc/dn42-autopeer` | Base directory for written configs. |
| `WIREGUARD_PEER_DIR` / `BIRD_PEER_DIR` | `<deploy>/wireguard` / `/etc/bird/peers` | Per-peer snippet directories. |
| `WIREGUARD_PRIVATE_KEY` | _(empty)_ | Router private key substituted into generated WireGuard configs. |
| `AGENT_DEPLOY_RELOAD_CMD` | _(empty)_ | Command run (fixed argv) after writing files, e.g. `systemctl reload bird`. |

## Looking glass

The public looking glass dispatches `ping`, `traceroute` (`trace`), `birdc show route for`
(`route`), and `birdc show protocols` (`status`) to an enabled agent. `ping`/`trace` also accept a
DNS hostname (resolved on the agent); `route` does a longest-prefix lookup so a host IP or a prefix
such as `1.1.1.0/24` both resolve to the route actually used.

> **Target range:** the looking glass accepts **any** IPv4/IPv6 address or prefix (and a hostname
> for `ping`/`trace`) — not just dn42
> space. This is deliberate. Abuse is bounded by the per-IP rate limit (`LG_RATE_LIMIT`) and the
> agent concurrency cap (`AGENT_MAX_CONCURRENCY`), and targets are validated and passed as fixed
> argv (never through a shell). If you do not want public reachability of arbitrary addresses, put
> the service behind authentication or a network boundary.

## Telegram

```text
/login                 link your dn42 ASN (Kioubit)
/peer                  list your peers
/status                detailed BGP status of your own peers
/create                create a peer (guided wizard)
/edit                  edit one of your peers (guided wizard)
/delete                delete one of your peers (guided wizard)
/ping  <ip-or-host>              random PoP, switch with the buttons
/trace <ip-or-host>              random PoP, switch with the buttons (/mtr is an alias)
/route <prefix-or-ip>            random PoP, switch with the buttons
/cancel                abort the current guided action
```

Each looking-glass command (`/ping`, `/trace`/`/mtr`, `/route`) takes only the target; the bot
runs it on a random PoP immediately and shows the output with one inline button per PoP — tap a
button to re-run on that PoP, editing the result in place. (The old `/ping <ip> <agent>` positional
argument is gone.)

Run the bot alongside the backend with `python start.py`, or on its own:

```powershell
cd backend
.\.venv\Scripts\python -m app.bot.main
```

Telegram Mini App verification requires `DOMAIN` to resolve to a public `https://` URL. For local
backend testing without Telegram, use `python start.py --allow-http`.

## Agent

WireGuard configs are complete `wg-quick` files written as `dn42p<peer-id>.conf`; the agent runs
`wg-quick down`/`up` and then reloads BIRD if `AGENT_DEPLOY_RELOAD_CMD` is set. BIRD snippets follow
the dn42 wiki MP-BGP-over-IPv6 (Extended Next Hop) style, so your main BIRD config must define a
`template bgp dnpeers` and include the peer directory, for example:

```text
include "/etc/bird/peers/*.conf";
```

The full request/response shape of every agent route is documented in
[`docs/agent-api.md`](docs/agent-api.md).

## Security model

- **Agent runs as root.** Every user-supplied value that can reach a router config is strictly
  validated: WireGuard endpoint and public key, ASN, and the protocol name (which becomes a file
  name and a `birdc` argument). Commands use fixed argv, never a shell; targets are screened for
  shell/format metacharacters, and writes are confined to the agent's peer directories (no path
  traversal).
- **Secrets are compared in constant time** (agent bearer token, Telegram backend secret).
- **The backend refuses placeholder secrets** at startup unless explicitly allowed.
- **Web sessions** are signed cookies, `HttpOnly`/`SameSite=Lax` and `Secure` unless insecure
  defaults are enabled.
- **The public looking glass** is rate-limited per client IP and bounded by agent concurrency;
  failures return a generic message rather than leaking the internal agent URL.
- **Auth** is delegated to Kioubit: the backend verifies the ECDSA signature, a short replay window,
  and the issuing domain before trusting any ASN claim.

See the [auth flow](docs/auth-flow.md) for the full web and Telegram login sequences.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| Backend exits: *"Refusing to start with insecure default secrets"* | Set strong `SESSION_SECRET` and `TELEGRAM_BACKEND_SECRET`, or pass `--allow-http` for local testing. |
| *"Telegram verification needs HTTPS"* on start | `DOMAIN` is not an HTTPS URL. Use a public HTTPS domain, or `--allow-http` (Mini App verification stays disabled). |
| `uvicorn`/`httpx` missing in an existing `.venv` | Reinstall: `pip install -e .` inside the venv. |
| Looking glass: *"could not reach the looking glass agent"* | Agent not running, wrong Agent URL, or token mismatch between the admin panel and `AGENT_TOKEN`. |
| Looking glass returns `429` | Per-IP rate limit (`LG_RATE_LIMIT`) or agent busy (`AGENT_MAX_CONCURRENCY`). |
| BGP session never comes up | Ensure the main BIRD config defines `template bgp dnpeers` and includes the peer directory. |

## Layout

```text
backend/            Python FastAPI control plane
  app/web/          web routers: pages, portal, admin, looking glass (+ shared deps)
  app/api/          bot-only REST API (telegram)
  app/bot/          aiogram Telegram bot
  app/peer/         peer lifecycle: validation, config rendering, deploy/teardown
  app/lg/           agent client, target validation, rate limiter
  app/auth/         Kioubit verification, sessions, user/ASN service
  app/db/           SQLAlchemy models, session, schema/seed
agent/              Go agent
  cmd/agent/        entrypoint
  internal/api/     HTTP server (auth, concurrency cap, JSON decode)
  internal/runner/  command execution, IP validation, config deploy
deploy/systemd/     example systemd units
docs/               agent API and auth flow
start.py            one-command launcher (backend + bot)
```
