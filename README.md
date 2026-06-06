# dn42 Autopeer MVP

Python control plane + Go agent for a dn42 autopeer and looking glass service.

This first version includes:

- WebUI with public looking glass, user portal, and admin panel
- Kioubit.dn42 authentication for ASN ownership
- Telegram Mini App verification flow
- Telegram bot commands for peer status and LG queries
- Go agent for `ping`, `traceroute`, `birdc show route`, `birdc show protocols`, and peer config deployment
- SQLite by default for local testing

## Layout

```text
backend/      Python FastAPI control plane, WebUI, Telegram bot
agent/        Go agent for router-side commands
deploy/       systemd examples
docs/         notes and API flow
```

## Backend

On a Linux server:

```sh
cd ~/dn42/backend
cp .env.example .env
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cd ..
python3 start.py
```

If `.venv` already exists but `uvicorn` or `httpx` is missing, reinstall the backend dependencies:

```sh
cd ~/dn42/backend
. .venv/bin/activate
python -m pip install -e .
```

On Windows:

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\pip install -e .
.\.venv\Scripts\uvicorn app.main:app --reload
```

Place Kioubit's `public_key.pem` at:

```text
backend/app/keys/public_key.pem
```

Important `.env` values:

```text
HOST=127.0.0.1
PORT=8000
DOMAIN=your-service.example
SESSION_SECRET=<random secret>
LOCAL_ASN=424242xxxx
TELEGRAM_BOT_TOKEN=<from BotFather>
TELEGRAM_BACKEND_SECRET=<random shared secret>
TELEGRAM_BACKEND_URL=http://127.0.0.1:8000
DEFAULT_AGENT_URL=http://127.0.0.1:8080
```

`LOCAL_ASN` is both the local BGP ASN and the ASN that receives admin access after Kioubit
authentication. `TELEGRAM_BACKEND_SECRET` is a random shared secret used only between the Telegram
bot and backend; set the same value for both processes. You can generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.
The backend refuses to start while `SESSION_SECRET` or `TELEGRAM_BACKEND_SECRET` is left at a
placeholder value (such as `change-me` or `dev-...`). Set strong random values, or pass
`--allow-http` to `start.py` (which sets `ALLOW_INSECURE_DEFAULTS=1`) for local testing only.
`TELEGRAM_BACKEND_URL` is the internal URL the bot uses to call the FastAPI backend. Keep it as
`http://127.0.0.1:8000` when the bot and backend run on the same host, even when `DOMAIN` is a
public HTTPS URL.

Local and remote peer addresses are requested in the portal and default to link-local addresses
generated from ASNs: `4242420099` becomes `fe80::99`, and `4242421260` becomes `fe80::1260`.
Peer creation is fully automatic: the backend immediately approves the peer, calls the selected
agent, and posts generated WireGuard and BIRD configs to `/v1/peers/deploy`.

Each PoP (agent) accepts at most one peer per ASN; if you already have a peer on an agent, edit or
delete the existing one instead of creating a second. Deleting or disabling a peer tears it down on
the router (the agent runs `wg-quick down` and removes the WireGuard and BIRD snippets) so revoked
peers stop forwarding immediately. User-supplied endpoint and WireGuard public key are strictly
validated before they are written into any router config.

The control plane talks directly to agents: `Backend -> Agent`. Create each controlled router as
an Agent in the admin panel with its display name, location, and Agent API URL. The backend
generates the agent bearer token automatically. The admin panel also shows the configured control
plane URL (`DOMAIN`) as read-only reference. Looking glass, peer creation, and deployment only
use enabled agents.

`HOST` and `PORT` control where Uvicorn listens. `DOMAIN` is the public domain used in generated
links and Kioubit verification. Use `HOST=0.0.0.0` only when the backend should accept direct
connections from outside the server; keep `HOST=127.0.0.1` when running behind nginx or another
reverse proxy. If `DOMAIN` has no scheme, the public URL is treated as `https://<DOMAIN>`.

Run the Telegram bot:

```powershell
cd backend
.\.venv\Scripts\python -m app.bot.main
```

Or start the backend and Telegram bot together from the repository root:

```powershell
python start.py
```

You can also override the backend bind address without editing `.env`:

```powershell
python start.py --host 0.0.0.0 --port 8000
```

Telegram Mini App verification requires `DOMAIN` to resolve to a public `https://` URL. For local backend
testing without Telegram verification, run `python start.py --allow-http`.

## Agent

```powershell
cd agent
go build ./cmd/agent
```

On a Linux router:

```sh
AGENT_LISTEN=:8080 AGENT_TOKEN=change-me ./agent
```

Optional paths:

```text
BIRDC_PATH=/usr/sbin/birdc
TRACEROUTE_PATH=/usr/bin/traceroute
PING_PATH=/bin/ping
```

The agent writes generated snippets on the router:

```text
AGENT_DEPLOY_DIR=/etc/dn42-autopeer
WIREGUARD_PEER_DIR=/etc/dn42-autopeer/wireguard
BIRD_PEER_DIR=/etc/dn42-autopeer/bird
WIREGUARD_PRIVATE_KEY=<router wireguard private key>
WG_QUICK_PATH=/usr/bin/wg-quick
AGENT_DEPLOY_RELOAD_CMD=systemctl reload bird
AGENT_MAX_CONCURRENCY=4
```

`AGENT_MAX_CONCURRENCY` bounds how many looking glass commands run at once; extra requests get
`429` instead of queueing (set `0` to disable the limit).

WireGuard configs are complete `wg-quick` configs. The agent writes `dn42p<peer-id>.conf`, runs
`wg-quick down <file>` and `wg-quick up <file>`, then reloads BIRD if configured. The WireGuard
listen port is derived from the remote ASN's last five digits, so `4242420090` listens on
`20090`.

BIRD snippets are generated for BIRD2 using the dn42 wiki MP-BGP over IPv6 with Extended Next Hop
style. Your main BIRD config must define a `template bgp dnpeers` and include the agent peer
directory, for example `include "/etc/dn42-autopeer/bird/*";`.

## Telegram Commands

```text
/login                 link your dn42 ASN (Kioubit)
/peer                  list your peers
/status                detailed BGP status of your own peers
/create                create a peer (guided wizard)
/edit                  edit one of your peers (guided wizard)
/delete                delete one of your peers (guided wizard)
/ping <dn42-ip> [agent]
/trace <dn42-ip> [agent]
/route <dn42-prefix|dn42-ip> [agent]
/cancel                abort the current guided action
```

`/create`, `/edit`, and `/delete` are step-by-step wizards: the bot asks for the PoP, WireGuard
endpoint, and public key one at a time. Link-local addresses are auto-derived from the ASNs (the
same defaults the web portal prefills); use the web portal if you need custom addresses. `/trace`
runs `traceroute` (`/mtr` is kept as an alias). `/status` reports each of your own peers'
`birdc show protocols all` detail (Established / Idle / Connection reset, route counts).
