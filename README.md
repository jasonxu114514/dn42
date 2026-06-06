# dn42 Autopeer MVP

Python control plane + Go agent for a dn42 autopeer and looking glass service.

This first version includes:

- WebUI with public looking glass, user portal, and admin panel
- Kioubit.dn42 authentication for ASN ownership
- Telegram Mini App verification flow
- Telegram bot commands for peer status and LG queries
- Go agent for `ping`, `mtr`, `birdc show route`, `birdc show protocols`, and peer config deployment
- SQLite by default for local testing

## Layout

```text
backend/      Python FastAPI control plane, WebUI, Telegram bot
agent/        Go agent for router-side commands
deploy/       systemd examples
docs/         notes and API flow
```

## Backend

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
BASE_URL=https://your-service.example
AUTH_DOMAIN=your-service.example
SESSION_SECRET=<random secret>
LOCAL_ASN=424242xxxx
TELEGRAM_BOT_TOKEN=<from BotFather>
TELEGRAM_BACKEND_SECRET=<random shared secret>
DEFAULT_AGENT_URL=http://127.0.0.1:8080
```

`LOCAL_ASN` is both the local BGP ASN and the ASN that receives admin access after Kioubit
authentication. `TELEGRAM_BACKEND_SECRET` is a random shared secret used only between the Telegram
bot and backend; set the same value for both processes. You can generate one with
`python -c "import secrets; print(secrets.token_urlsafe(32))"`.

Local and remote peer addresses are requested in the portal and default to link-local addresses
generated from ASNs: `4242420099` becomes `fe80::99`, and `4242421260` becomes `fe80::1260`.
Peer creation is fully automatic: the backend immediately approves the peer, calls the selected
agent, and posts generated WireGuard and BIRD configs to `/v1/peers/deploy`.

The control plane talks directly to agents: `Backend -> Agent`. Create each controlled router as
an Agent in the admin panel with its display name, location, and Agent API URL. The backend
generates the agent bearer token automatically. The admin panel also shows the configured control
plane URL (`BASE_URL`) as read-only reference. Looking glass, peer creation, and deployment only
use enabled agents.

Run the Telegram bot:

```powershell
cd backend
.\.venv\Scripts\python -m app.bot.main
```

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
MTR_PATH=/usr/bin/mtr
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
```

WireGuard configs are complete `wg-quick` configs. The agent writes `dn42p<peer-id>.conf`, runs
`wg-quick down <file>` and `wg-quick up <file>`, then reloads BIRD if configured. The WireGuard
listen port is derived from the remote ASN's last five digits, so `4242420090` listens on
`20090`.

## Telegram Commands

```text
/verify
/peer
/status [agent]
/ping <dn42-ip> [agent]
/mtr <dn42-ip> [agent]
/route <dn42-prefix|dn42-ip> [agent]
```
