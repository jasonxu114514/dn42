# dn42 Autopeer MVP

Python control plane + Go node agent for a dn42 autopeer and looking glass service.

This first version includes:

- WebUI with public looking glass, user portal, and admin panel
- Kioubit.dn42 authentication for ASN ownership
- Telegram Mini App verification flow
- Telegram bot commands for peer status and LG queries
- Go node agent for `ping`, `mtr`, `birdc show route`, and `birdc show protocols`
- SQLite by default for local testing

## Layout

```text
backend/      Python FastAPI control plane, WebUI, Telegram bot
agent/        Go node agent for router-side commands
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
ADMIN_ASNS=424242xxxx
TELEGRAM_BOT_TOKEN=<from BotFather>
TELEGRAM_BACKEND_SECRET=<shared secret>
DEFAULT_AGENT_URL=http://127.0.0.1:8080
DEFAULT_AGENT_TOKEN=<agent bearer token>
```

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

## Telegram Commands

```text
/verify
/peer
/status [node]
/ping <target> [node]
/mtr <target> [node]
/route <prefix|ip> [node]
```

Admin actions are intentionally Web-only.
