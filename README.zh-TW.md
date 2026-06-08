# dn42 Autopeer

[English](README.md) | **繁體中文**

dn42 自助對等與公開 looking glass 服務。

本專案包含三個部分：

- **Backend**：FastAPI 控制平面，提供 Web UI、ASN 登入、對等生命週期管理，以及 bot 專用 REST API。
- **Agent**：在每個節點（路由器）上以 root 執行的 Go 服務，負責執行固定參數的 looking-glass 指令，並套用每個 peer 的 WireGuard 與 BIRD 設定。
- **Telegram bot**：提供登入、建立／編輯／刪除 peer、查詢 peer 狀態與 looking-glass 指令。

使用者驗證 ASN 後，可以選擇節點、提交自己的 WireGuard 公鑰（endpoint 可選），並取得建立隧道所需的我方參數。Backend 會產生 WireGuard 與 BIRD 片段，再送到對應節點上的 agent。

> [!WARNING]
> Agent 會以 root 執行，因為它需要寫入路由器設定並呼叫 `wg-quick`。任何可能進入 agent 或路由器設定的值，都應視為安全敏感輸入。

## 目錄

- [架構](#架構)
- [對等流程](#對等流程)
- [自動產生的預設值](#自動產生的預設值)
- [快速開始](#快速開始)
- [設定](#設定)
- [Web UI](#web-ui)
- [Telegram Bot](#telegram-bot)
- [Agent 與 BIRD](#agent-與-bird)
- [安全模型](#安全模型)
- [疑難排解](#疑難排解)
- [專案結構](#專案結構)

## 架構

```text
Browser                 Telegram bot
   |                         |
   | HTTP(S)                 | HTTP + X-Backend-Secret
   v                         v
+------------------------------------------------+
| Backend: FastAPI, SQLite, Web UI, bot API       |
| - 驗證 ASN 擁有權                               |
| - 儲存 users, nodes, peers, sessions            |
| - 產生 WireGuard 與 BIRD peer 設定              |
+------------------------------------------------+
                         |
                         | Agent-initiated WSS
                         v
+------------------------------------------------+
| 每個節點（路由器）上的 Agent                    |
| - 寫入 /etc/wireguard/*.conf                    |
| - 寫入 /etc/bird/peers/*.conf                   |
| - 執行 wg-quick, birdc, ping, traceroute, mtr   |
+------------------------------------------------+
```

Backend 可以與 bot 跑在同一台主機上。Agent 通常放在各節點的路由器上，一個節點一個 agent。每個 agent 會以 bearer token 主動建立 WSS 長連線到 backend；admin panel 中的公開位址則作為產生 WireGuard 設定時使用的 endpoint 主機。每個節點有自己的 dn42 身分（ASN、DN42 IPv4/IPv6），ASN 留空時退回 `LOCAL_ASN`。

## 對等流程

1. 使用者透過 Kioubit.dn42，或可選的 FindNOC Telegram 快速登入，證明自己控制某個 dn42 ASN。
2. 使用者在 Web portal 或 Telegram bot 建立 peer：
   - 選擇啟用中的節點；
   - 輸入自己的 WireGuard public key；
   - 可選輸入自己的 WireGuard endpoint（`host:port`），留空表示由對方撥入；
   - 選擇隧道內 IP——預設 link-local，亦支援 ULA（`fd00::/8`）；
   - 選擇 WireGuard MTU，預設 `1420`。
3. Backend 驗證所有欄位，套用每個 ASN 在每個節點只能有一個 peer 的規則，將 peer 自動核准，並產生 WireGuard 與 BIRD 設定。我方位址由節點推導。
4. Backend 透過 agent 的 WSS 長連線送出 `peers.deploy` 指令。
5. Agent 寫入設定檔，執行 `wg-quick down` 與 `wg-quick up`，並在設定了 reload 指令時重新載入 BIRD。
6. 部署成功後，Web UI 與 bot 會顯示使用者設定自己端點所需的我方參數：
   - 我方 WireGuard endpoint；
   - 該節點的我方 WireGuard public key；
   - 我方 tunnel IP，也就是對方 BGP neighbor；
   - WireGuard MTU。

停用或刪除 peer 時，backend 會要求 agent 執行 `wg-quick down`，並刪除 WireGuard 與 BIRD 片段。

## 自動產生的預設值

| 值 | 規則 | `AS4242420090` 範例 |
| --- | --- | --- |
| WireGuard listen port | peer ASN 後 5 位 | `20090` |
| Interface / config / BIRD protocol 名稱 | `DN42_` + peer ASN 後 4 位 | `DN42_0090` |
| Peer link-local 位址 | `fe80::<asn-suffix>` | `fe80::90` |
| WireGuard MTU | 使用者可修改，預設 `1420`，範圍 `1280-9000` | `1420` |

Endpoint 的主機部分來自 admin panel 中註冊的節點公開位址，backend 會加上由 ASN 推導出的 WireGuard listen port。

產生的 WireGuard 設定會在 `[Interface]` 內包含 MTU：

```ini
[Interface]
PrivateKey = {{WIREGUARD_PRIVATE_KEY}}
ListenPort = 20090
Table = off
MTU = 1420
PostUp = ip addr add fe80::1/64 dev %i
```

## 快速開始

### Backend 與 bot

Linux / macOS：

```sh
cp backend/.env.example backend/.env
python3 -m pip install -r requirements.txt
python3 start.py
```

Windows PowerShell：

```powershell
Copy-Item backend\.env.example backend\.env
python -m pip install -r requirements.txt
python start.py
```

正式使用前請編輯 `backend/.env`。至少應設定：

- `DOMAIN`
- `LOCAL_ASN`
- `SESSION_SECRET`
- `TELEGRAM_BACKEND_SECRET`
- 如果使用 bot，設定 `TELEGRAM_BOT_TOKEN`

Kioubit 簽章公鑰放在 `backend/app/keys/public_key.pem`。

常用啟動參數：

| 參數 | 作用 |
| --- | --- |
| `--allow-http` | 本機測試模式，允許非 HTTPS `DOMAIN` 與佔位 secret。正式環境不要使用。 |
| `--backend-only` | 只啟動 FastAPI backend。 |
| `--bot-only` | 只啟動 Telegram bot。 |
| `--host` / `--port` | 覆寫 backend 綁定地址與 port。 |

### Agent

在每台路由器上建置並執行 agent：

```sh
cd agent
go build ./cmd/agent
cp config.example.json config.json
./agent -config ./config.json
```

Backend 初始沒有任何節點。請在 **Admin > Nodes** 註冊每個節點，然後把節點 name、產生的 token 與 backend WSS URL 複製到對應路由器的 `config.json`。Agent 連線後會透過 WSS 回報 heartbeat/system status、整台伺服器的 WireGuard/BIRD 狀態與 `wireguard_public_key`，backend 會快取並顯示給 peer 使用。

### 從舊版本遷移

本版本之前使用自增整數 ID，並把節點稱為「agent」。既有資料庫需要一次性遷移到 UUID 的節點／peer ID。請先停止 backend，再執行：

```sh
python3 backend/scripts/migrate_to_uuid_nodes.py            # 使用 backend/autopeer.db
python3 backend/scripts/migrate_to_uuid_nodes.py --db /path/to/autopeer.db
```

它會先寫出帶時間戳的備份，再以 UUID 重建 `agents` → `nodes`、`peer_requests` 與 `lg_queries` 三個表。全新安裝不需要執行——backend 首次啟動會建立最新 schema。Go agent 也需以本版本重新建置（部署協定有變更）；WSS 路徑與 `config.json` 不變，因此各路由器無需修改設定。

## 設定

### Backend `.env`

| 變數 | 預設值 | 用途 |
| --- | --- | --- |
| `APP_NAME` | `dn42 Autopeer` | Web UI 顯示名稱。 |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Uvicorn 綁定地址。正式環境建議放在 reverse proxy 後面。 |
| `DOMAIN` | `.env.example` 中為 `example.com` | 產生登入連結用的公開網域。沒有 scheme 時視為 `https://`。 |
| `SESSION_SECRET` | `change-me` | Session cookie 簽章 secret。必須更換。 |
| `DATABASE_URL` | `sqlite:///./autopeer.db` | SQLAlchemy database URL。 |
| `LOCAL_ASN` | `.env.example` 中為 `4242420000` | 操作者 ASN。登入此 ASN 會成為 admin，也用於產生我方 link-local 預設值。 |
| `KIOUBIT_PUBLIC_KEY_PATH` | `app/keys/public_key.pem` | Kioubit ECDSA public key。 |
| `TELEGRAM_BOT_TOKEN` | 空 | BotFather token。只在使用 bot 時需要。 |
| `TELEGRAM_BACKEND_SECRET` | `change-me-too` | Bot 與 backend 間的共享 secret。必須更換。 |
| `TELEGRAM_BACKEND_URL` | `http://127.0.0.1:8000` | Bot 連到 backend 的內部 URL。 |
| `FINDNOC_API_URL` | `https://findnoc.ox5.cc` | 可選 FindNOC API base URL。 |
| `FINDNOC_API_TOKEN` | 空 | 設定後啟用 Telegram FindNOC 快速登入。 |
| `ALLOW_INSECURE_DEFAULTS` | `0` | 只供本機測試時允許佔位 secret。 |
| `LG_RATE_LIMIT` | `20` | 每個 client IP 每個時間窗的 looking-glass 請求上限。`0` 表示停用。 |
| `LG_RATE_WINDOW_SECONDS` | `60` | Rate-limit 時間窗長度。 |
| `FORWARDED_IP_HEADER` | 空 | 信任的 client IP header，例如 `X-Forwarded-For`，只應在可信任 proxy 後使用。 |

產生強 secret：

```sh
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Agent `config.json`

| Key | 預設值 | 用途 |
| --- | --- | --- |
| `name` | 空 | 與 backend node record 相同的節點名稱；使用 WSS 時必填。 |
| `token` | 空 | WSS 連線使用的 bearer token。 |
| `backend_wss_url` | 必填 | Backend websocket URL，通常是 `wss://example.com/api/agents/ws`。也接受 `http(s)` base URL 並轉成 `ws(s)`。 |
| `max_concurrency` | `4` | 同時執行的 looking-glass 指令數。`0` 表示不限制。 |
| `command_timeout_seconds` | `12` | 每個外部指令的 timeout。 |
| `birdc_path` | `birdc` | `birdc` 路徑。 |
| `ping_path` | `ping` | `ping` 路徑。 |
| `traceroute_path` | `traceroute` | `traceroute` 路徑。 |
| `mtr_path` | `mtr` | `mtr` 路徑。 |
| `wg_path` | `wg` | `wg` 路徑，用於查詢即時 tunnel 狀態。 |
| `wg_quick_path` | `wg-quick` | `wg-quick` 路徑，用於啟動或關閉 peer interface。 |
| `wireguard_peer_dir` | `/etc/wireguard` | 產生 WireGuard 設定檔的位置。 |
| `bird_peer_dir` | `/etc/bird/peers` | 產生 BIRD 片段的位置。 |
| `bird_peer_group` | `bird` | 指派給 BIRD 片段的 group，讓非 root BIRD daemon 可讀取。`""` 表示停用 chown。 |
| `deploy_reload_cmd` | 空 | deploy/remove 後執行的固定 argv 指令，例如 `birdc c`。 |
| `wireguard_private_key` | 空 | 路由器私鑰，用於取代 `{{WIREGUARD_PRIVATE_KEY}}`。 |
| `wireguard_public_key` | 必填 | 路由器 public key，提供給 backend 與 peer。 |

Agent 設定檔包含 token 與 WireGuard private key，請保持 root 擁有並設為 `0600`。

## Web UI

| Route | 用途 |
| --- | --- |
| `/` | 首頁：網路介紹、對等引導，以及各節點即時狀態。 |
| `/lg` | 公開 looking glass（ping、traceroute、mtr、route）。 |
| `/login` | Web Kioubit 登入。 |
| `/portal` | 我的 Peer：總覽自己的 peer。 |
| `/portal/new` | 建立 peer。 |
| `/portal/peers/{id}` | Peer 詳情：id、我方參數、節點位址、即時狀態；可刪除。 |
| `/admin` | 操作者總覽。 |
| `/admin/nodes` | 註冊／編輯節點（ASN、DN42 位址、啟用／停用）、更新 pubkey、重設 token。 |
| `/admin/peers` | 編輯、redeploy、停用、刪除 peer。 |
| `/admin/users` | 管理 users 與 Telegram bindings。 |
| `/admin/lg-log` | Looking-glass 查詢紀錄。 |

New Peer 表單與 admin peer 表單皆可設定 WireGuard MTU；admin 表單還能修正位址後 redeploy。停用的節點會對公開頁面與 looking glass 隱藏。

## Telegram Bot

指令：

```text
/login        登入 dn42 ASN
/logout       解除 Telegram 與目前 ASN 的綁定
/listpeers    顯示 peer 狀態、我方參數、WireGuard 與 BIRD 細節
/create       引導式建立 peer
/edit         引導式編輯 peer，包含 MTU
/delete       引導式刪除 peer
/ping         從某個節點執行 ping
/trace        從某個節點執行 traceroute
/mtr          從某個節點執行 mtr
/route        從某個節點執行 BIRD route lookup
/cancel       中止目前引導流程
```

`/create` 會詢問節點、endpoint（輸入 `skip` 表示不填）、public key 與 MTU。MTU 步驟輸入 `default` 會使用 `1420`。`/edit` 的 MTU 步驟輸入 `keep` 會保留目前值。peer 以編號選單挑選，而非輸入 id。

## Agent 與 BIRD

WireGuard 設定是完整的 `wg-quick` 檔案。Interface 名稱、WireGuard 檔名與 BIRD protocol 名稱相同，例如 `DN42_0090`。

部署會寫入：

- `<wireguard_peer_dir>/<protocol_name>.conf`
- `<bird_peer_dir>/<protocol_name>.conf`

BIRD 主設定至少需要 include peer 片段目錄：

```text
include "/etc/bird/peers/*.conf";
```

產生的 peer 片段預期存在名為 `dnpeers` 的 BGP template：

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

正式環境請依自己的 routing policy 調整 template。

Agent API 詳見 [docs/agent-api.md](docs/agent-api.md)。驗證流程詳見 [docs/auth-flow.md](docs/auth-flow.md)。

## 安全模型

- Backend 在建立或管理 peer 前會驗證 ASN 擁有權。
- 已驗證 ASN 等於 `LOCAL_ASN` 時才授予 admin。
- Backend session 使用簽章 cookie。
- Backend 預設拒絕佔位 secret，除非明確允許 insecure defaults。
- Bot 專用 API 需要 `X-Backend-Secret`。
- Agent WSS 連線需要 `Authorization: Bearer <token>`。
- Agent token 與 bot secret 以 constant-time comparison 檢查。
- 可進入路由器設定的使用者輸入都會先驗證。
- Agent 執行指令時使用固定 argv，不經 shell。
- Agent 寫檔限制在設定的 peer directories 內。
- Looking glass 同時受到 backend rate limit 與 agent concurrency limit 保護。

## 疑難排解

| 症狀 | 可能原因與修正 |
| --- | --- |
| Backend 因 insecure defaults 拒絕啟動 | 設定強 `SESSION_SECRET` 與 `TELEGRAM_BACKEND_SECRET`，或本機測試時使用 `--allow-http`。 |
| Telegram Mini App 登入失敗 | `DOMAIN` 必須是公開 HTTPS URL。 |
| Agent 一直顯示 offline | 檢查 `name`、`backend_wss_url`、TLS 連線，以及 token 是否與 **Admin > Nodes** 相同。 |
| Agent 回傳 `unauthorized` | Backend 裡的 agent token 與 agent `config.json` 的 token 不一致。 |
| Peer 設定顯示 `<our-wireguard-public-key>` | 讓 agent 連上 WSS 或到 **Admin > Nodes** refresh pubkey，並確認 agent 設定了 `wireguard_public_key`。 |
| Deploy 顯示缺少 private key | 在 agent config 設定 `wireguard_private_key`。 |
| Deploy 發生 BIRD permission error | 將 `bird_peer_group` 設為 BIRD daemon 使用的 group，常見為 `bird`。 |
| BGP session 不起來 | 檢查 link-local 位址、MTU、路由匯出政策、BIRD template，以及 `wg show <interface>`。 |
| Looking glass 回傳 `429` | 觸發 backend rate limit 或 agent concurrency limit。 |

## 專案結構

```text
backend/
  app/api/          Bot 專用 REST API
  app/auth/         Kioubit, FindNOC, sessions, user binding
  app/bot/          Telegram bot
  app/db/           SQLAlchemy models 與 schema bootstrap
  app/lg/           Looking-glass client, validation, rate limit
  app/peer/         Peer validation, config rendering, deploy/remove
  app/node_ws.py    節點 WSS hub（agent 連線、即時狀態）
  app/templates/    Jinja templates
  app/static/       CSS 與少量瀏覽器 JS
  scripts/          一次性維運腳本（v1→v2 資料庫遷移）
agent/
  cmd/agent/        Agent entry point
  internal/api/     Agent HTTP server
  internal/config/  Agent JSON config loader
  internal/runner/  Command execution 與 deploy 邏輯
deploy/systemd/     systemd unit 範例
docs/               Agent API 與驗證流程
start.py            Backend + bot launcher
```
