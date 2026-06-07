# dn42 Autopeer

[English](README.md) · **繁體中文**

為 [dn42](https://dn42.dev) 打造的自助 autopeer 與 looking glass 服務：一個會驗證 ASN 擁有權、
並將 WireGuard + BIRD2 設定推送到你路由器的 Python 控制平面，以及一個負責套用設定的 Go agent。
對等連線可從網頁入口或 Telegram bot 建立。

- **WebUI** — 公開 looking glass、需登入的使用者入口、管理面板
- **Kioubit.dn42 認證** — 在產生任何設定前先證明 ASN 擁有權
- **Telegram** — Mini App 驗證，加上可建立／編輯／刪除對等與查詢狀態的引導式 bot
- **Go agent** — 執行 `ping` / `traceroute` / `birdc`，並部署各對等的 WireGuard + BIRD 設定
- **預設 SQLite** — 免設定即可本地測試；正式環境可將 `DATABASE_URL` 指向他處

> **注意：** agent 以 **root** 身分在你的路由器上執行（會呼叫 `wg-quick` 並寫入 BIRD 片段）。
> 請將任何可能進入路由器設定的值都視為具安全敏感性，公開部署前務必閱讀[安全模型](#安全模型)。

## 目錄

- [架構](#架構)
- [對等連線流程](#對等連線流程)
- [快速開始](#快速開始)
- [設定參考](#設定參考)
- [Looking glass](#looking-glass)
- [Telegram](#telegram)
- [Agent](#agent)
- [安全模型](#安全模型)
- [疑難排解](#疑難排解)
- [專案結構](#專案結構)

## 架構

```text
                 Kioubit.dn42（ASN 擁有權，ECDSA 簽章權杖）
                        │ 驗證
   瀏覽器 / Telegram ───┤
            │           ▼
            │     ┌───────────────┐     Bearer token HTTP   ┌──────────────────┐
            └────▶│   Backend     │ ─────────────────────▶ │   Agent（root）  │
   Telegram bot ─▶│  (FastAPI)    │   /v1/lg/* /v1/peers/* │  每台路由器/PoP  │
   X-Backend-Secret   │  SQLite    │ ◀───────────────────── │  wg-quick + bird │
                  └───────────────┘       JSON 結果         └──────────────────┘
```

- **Backend**（`backend/`，FastAPI）— 提供 WebUI、僅供 bot 使用的 REST API，以及控制平面。它使用
  自行產生的各 agent bearer token，**直接**透過 HTTP 與 agent 溝通。
- **Agent**（`agent/`，Go）— 每台路由器（「PoP」）一個。以固定 argv 執行 looking-glass 指令，
  並寫入／重載各對等的 WireGuard 與 BIRD 設定。looking-glass 併發量有上限，避免公開查詢耗盡路由器資源。
- **Telegram bot**（`backend/app/bot/`，aiogram）— 獨立行程，透過 HTTP 以共享的
  `TELEGRAM_BACKEND_SECRET` 與後端溝通。

## 對等連線流程

1. 透過 Kioubit **驗證** 你的 ASN（網頁 `/login` 或 Telegram `/login` Mini App）。後端只信任
   Kioubit 簽章過的資料。
2. **建立對等** — 於入口或 `/create` bot 精靈中 — 選擇 PoP（agent）、你的 WireGuard 端點
   （`host:port`）與 WireGuard 公鑰。BGP link-local 位址預設為 `fe80::<asn-後綴>`
   （例如 `4242420099` → `fe80::99`）；若需自訂位址請使用網頁入口。
3. 後端**驗證**每個欄位、實施 **每個 PoP 對每個 ASN 至多一個對等**、**自動核准**，接著產生
   WireGuard + BIRD2 片段並 `POST` 到 agent 的 `/v1/peers/deploy`。
4. agent 寫入 WireGuard 與 BIRD 的 `DN42_<對方 ASN 後 4 位>.conf`，執行 `wg-quick down/up`，並在有設定時重載 BIRD。
5. 部署成功後，網頁入口與 bot 會顯示對端建立其端所需的**我方**參數：我方 WireGuard 端點、本 PoP 的公鑰，
   以及我方隧道內（link-local）位址——亦即對端 BGP 應指向的鄰居位址。
6. **刪除或停用** 對等時會在路由器上拆除（`/v1/peers/remove`：`wg-quick down` 加上移除片段），
   讓被撤銷的對等立即停止轉送。

WireGuard 監聽埠取自遠端 ASN 後 5 位數字（`4242420090` → `20090`）；對等撥接的端點即 agent 主機加上該埠。

## 快速開始

### 後端（Linux）

```sh
cd backend
cp .env.example .env            # 接著編輯：設定 DOMAIN、LOCAL_ASN，以及高強度的密鑰
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cd ..
python3 start.py                # 同時啟動後端與 Telegram bot
```

`start.py` 會同時啟動 FastAPI 後端與 Telegram bot 並串流兩者的日誌。常用旗標：

| 旗標 | 作用 |
| --- | --- |
| `--allow-http` | 即使 `DOMAIN` 非 HTTPS 也啟動（會設定 `ALLOW_INSECURE_DEFAULTS=1`）。僅供本地測試——Telegram Mini App 驗證將無法運作。 |
| `--backend-only` | 只啟動 FastAPI 後端。 |
| `--bot-only` | 只啟動 Telegram bot。 |
| `--host` / `--port` | 不改 `.env` 即可覆寫後端綁定位址。 |

請將 Kioubit 公鑰放在 `backend/app/keys/public_key.pem`。

### 後端（Windows）

```powershell
cd backend
Copy-Item .env.example .env
python -m venv .venv
.\.venv\Scripts\pip install -e .
cd ..
python start.py
```

### Agent（於每台路由器）

```sh
cd agent
go build ./cmd/agent
cp config.example.json config.json    # 接著編輯 config.json：金鑰、token、工具路徑
./agent                               # 讀取 ./config.json；或：./agent -config /etc/dn42-autopeer/agent.json
```

後端啟動時不會內建任何 agent。請在管理面板新增每個路由器（名稱、位置、Agent API URL）；後端會為每個
agent 產生 bearer token。請將該 token 設為對應路由器 `config.json` 中的 `token`。

## 設定參考

### 後端（`backend/.env`）

| 變數 | 預設 | 用途 |
| --- | --- | --- |
| `APP_NAME` | `dn42 Autopeer` | WebUI 顯示名稱。 |
| `HOST` / `PORT` | `127.0.0.1` / `8000` | Uvicorn 綁定位址。僅在需直接對外時用 `0.0.0.0`；置於反向代理後請維持 `127.0.0.1`。 |
| `DOMAIN` | `127.0.0.1:8000` | 用於產生連結與 Kioubit 驗證的公開網域。未帶 scheme ⇒ 視為 `https://`。 |
| `SESSION_SECRET` | `dev-session-secret` | 網頁工作階段簽章金鑰。**必須**更換（見下）。 |
| `DATABASE_URL` | `sqlite:///./autopeer.db` | SQLAlchemy 連線字串。 |
| `LOCAL_ASN` | _（空）_ | 你的本地 BGP ASN；也是 Kioubit 登入後取得管理權的 ASN。 |
| `KIOUBIT_PUBLIC_KEY_PATH` | `app/keys/public_key.pem` | Kioubit 簽章公鑰（PEM）。 |
| `TELEGRAM_BOT_TOKEN` | _（空）_ | BotFather token；bot 必需。 |
| `TELEGRAM_BACKEND_SECRET` | `dev-telegram-secret` | bot 與後端間的共享密鑰。**必須**更換。 |
| `TELEGRAM_BACKEND_URL` | _（退回 `DOMAIN`）_ | bot 連到後端所用的內部 URL——同機時維持 `http://127.0.0.1:8000`。 |
| `FINDNOC_API_URL` | `https://findnoc.ox5.cc` | FindNOC 基底 URL，供選用的 Telegram 快速登入。 |
| `FINDNOC_API_TOKEN` | _（空）_ | FindNOC API token。設定後 bot 的 `/login` 會先試 FindNOC（失敗則回退 Kioubit）；留空即停用。 |
| `ALLOW_INSECURE_DEFAULTS` | `0` | `1` 容忍佔位密鑰（本地測試）。 |
| `LG_RATE_LIMIT` | `20` | 每個來源 IP 每個窗口的 looking-glass 查詢上限（`0` 停用）。 |
| `LG_RATE_WINDOW_SECONDS` | `60` | 速率限制窗口長度。 |
| `FORWARDED_IP_HEADER` | _（空）_ | 例如 `X-Forwarded-For`，**僅**在會設定它的可信代理後使用；否則所有用戶端會共用同一個桶。 |

可用 `python -c "import secrets; print(secrets.token_urlsafe(32))"` 產生高強度密鑰。當
`SESSION_SECRET` 或 `TELEGRAM_BACKEND_SECRET` 仍為佔位值（`change-me`、`dev-…`、空）時，後端會
**拒絕啟動**，除非設定 `ALLOW_INSECURE_DEFAULTS=1`（或 `start.py --allow-http`）。

### Agent（`config.json`）

agent 讀取單一 JSON 檔——預設 `./config.json`，或 `-config` 指定的路徑。請複製
`agent/config.example.json` 後填寫。此檔含祕密（bearer token 與 WireGuard 私鑰），故須由 root 擁有且
`chmod 0600`。

| 鍵 | 預設 | 用途 |
| --- | --- | --- |
| `listen` | `:8080` | 監聽位址。 |
| `token` | _（空）_ | 每個請求必須帶的 bearer token（來自管理面板）。空 ⇒ 不驗證。 |
| `max_concurrency` | `4` | 同時執行的 looking-glass 指令數；超出的請求得到 `429` 而非排隊（`0` 停用上限）。 |
| `command_timeout_seconds` | `12` | 每個外部命令（`ping`／`traceroute`／`birdc`／`wg-quick`）的逾時秒數。 |
| `birdc_path` / `traceroute_path` / `ping_path` / `wg_quick_path` | `birdc` / `traceroute` / `ping` / `wg-quick` | 工具路徑。 |
| `wireguard_peer_dir` / `bird_peer_dir` | `/etc/wireguard` / `/etc/bird/peers` | 各對等片段目錄。 |
| `bird_peer_group` | `bird` | 賦予 BIRD 對等目錄與片段的群組,讓非特權的 BIRD 守護程序能讀取(權限位維持 `0750`／`0640`,非全域可讀)。`""` 停用此行為(BIRD 以 root 執行／以 setgid 目錄管理)。 |
| `wireguard_private_key` | _（空）_ | 代入產生的 WireGuard 設定的路由器私鑰。 |
| `wireguard_public_key` | _（必填）_ | 本 PoP 的路由器公鑰。agent 缺少有效值會拒絕啟動，並於 `GET /v1/pubkey` 提供；後端會快取並填入每個對等端產生的設定。 |
| `deploy_reload_cmd` | _（空）_ | 寫檔後執行的指令（固定 argv），例如 `systemctl reload bird`。 |

## Looking glass

公開 looking glass 會將 `ping`、`traceroute`（`trace`）、`birdc show route for`（`route`）與
`birdc show protocols`（`status`）派送到一個已啟用的 agent。`ping`／`trace` 亦接受 DNS 主機名（於
agent 端解析）；`route` 採最長前綴查找,故單一主機 IP 或 `1.1.1.0/24` 之類的前綴都會解析到實際使用的
路由。

> **目標範圍：** looking glass 接受**任意** IPv4/IPv6 位址或前綴（`ping`／`trace` 亦含主機名）——不僅限 dn42 空間。此為刻意設計。
> 濫用由每 IP 速率限制（`LG_RATE_LIMIT`）與 agent 併發上限（`max_concurrency`）約束，且目標
> 會經驗證並以固定 argv 傳遞（絕不經 shell）。若你不希望任意位址可被公開探測，請將服務置於認證或
> 網路邊界之後。

## Telegram

```text
/login                 登入你的 dn42 ASN（FindNOC 快速登入，否則 Kioubit）
/logout                登出你的 dn42 ASN（解除連結；對等保留）
/listpeers             你的對等：我方端點／公鑰／隧道內 IP、WireGuard 與 BGP 狀態
/create                建立對等（引導式精靈）
/edit                  編輯你的某個對等（引導式精靈）
/delete                刪除你的某個對等（引導式精靈）
/ping  <ip-或-主機名>            隨機 PoP，可用按鈕切換
/trace <ip-或-主機名>            隨機 PoP，可用按鈕切換
/mtr   <ip-或-主機名>            隨機 PoP，可用按鈕切換
/route <前綴-或-ip>              隨機 PoP，可用按鈕切換
/cancel                中止目前的引導式動作
```

各 looking glass 指令（`/ping`、`/trace`、`/mtr`、`/route`）只接受目標；bot 會立即在隨機 PoP 上執行
並顯示輸出，並附上每個 PoP 一個內嵌按鈕——點按鈕即在該 PoP 重跑並就地更新結果。（舊的
`/ping <ip> <agent>` 位置參數已移除。）

以 `python start.py` 與後端一起執行 bot，或單獨執行：

```powershell
cd backend
.\.venv\Scripts\python -m app.bot.main
```

Telegram Mini App 驗證需要 `DOMAIN` 解析為公開的 `https://` URL。若要在無 Telegram 的情況下做本地
後端測試，請用 `python start.py --allow-http`。

## Agent

WireGuard 設定為完整的 `wg-quick` 檔，寫成 `DN42_<對方 ASN 後 4 位>.conf`（WireGuard 介面與 BIRD
protocol 同名，皆取自對方 ASN 後 4 位）；agent 會執行 `wg-quick down`/`up`，
並在設定了 `deploy_reload_cmd` 時重載 BIRD。BIRD 片段採用 dn42 wiki 的 MP-BGP-over-IPv6
（Extended Next Hop）樣式，因此你的主 BIRD 設定必須定義 `template bgp dnpeers` 並 include 對等目錄，例如：

```text
include "/etc/bird/peers/*.conf";
```

每個 agent 路由的完整請求／回應格式記錄於 [`docs/agent-api.md`](docs/agent-api.md)。

## 安全模型

- **Agent 以 root 執行。** 每個可能進入路由器設定的使用者輸入都經嚴格驗證：WireGuard 端點與公鑰、
  ASN，以及 protocol name（它會成為檔名與 `birdc` 參數）。指令使用固定 argv 而非 shell；目標會檢查
  shell／格式化中介字元，且寫入限制在 agent 的對等目錄內（無路徑穿越）。
- **密鑰以定時比較核對**（agent bearer token、Telegram 後端密鑰）。
- **後端在啟動時拒絕佔位密鑰**，除非明確允許。
- **網頁工作階段** 為簽章 cookie，`HttpOnly`／`SameSite=Lax`，且除非啟用不安全預設否則為 `Secure`。
- **公開 looking glass** 依來源 IP 限速並受 agent 併發約束；失敗時回傳通用訊息，不洩漏內部 agent URL。
- **認證** 委由 Kioubit：後端在信任任何 ASN 主張前，會驗證 ECDSA 簽章、短重放窗口與簽發 domain。

完整的網頁與 Telegram 登入流程見[認證流程](docs/auth-flow.md)。

## 疑難排解

| 症狀 | 可能原因／解法 |
| --- | --- |
| 後端結束並顯示 *"Refusing to start with insecure default secrets"* | 設定高強度的 `SESSION_SECRET` 與 `TELEGRAM_BACKEND_SECRET`，或以 `--allow-http` 做本地測試。 |
| 啟動時出現 *"Telegram verification needs HTTPS"* | `DOMAIN` 非 HTTPS URL。請用公開 HTTPS 網域，或 `--allow-http`（Mini App 驗證維持停用）。 |
| 既有 `.venv` 缺少 `uvicorn`／`httpx` | 在 venv 內重裝：`pip install -e .`。 |
| Looking glass：*"could not reach the looking glass agent"* | agent 未執行、Agent URL 錯誤，或管理面板與 agent `config.json` 中 `token` 不一致。 |
| Looking glass 回傳 `429` | 每 IP 速率限制（`LG_RATE_LIMIT`）或 agent 忙碌（`max_concurrency`）。 |
| BGP 工作階段始終無法建立 | 確認主 BIRD 設定有定義 `template bgp dnpeers` 並 include 對等目錄。 |

## 專案結構

```text
backend/            Python FastAPI 控制平面
  app/web/          網頁路由：pages、portal、admin、looking glass（+ 共用 deps）
  app/api/          僅供 bot 的 REST API（telegram）
  app/bot/          aiogram Telegram bot
  app/peer/         對等生命週期：驗證、設定產生、部署／拆除
  app/lg/           agent 用戶端、目標驗證、速率限制器
  app/auth/         Kioubit 驗證、工作階段、使用者／ASN 服務
  app/db/           SQLAlchemy 模型、session、建表／植入
agent/              Go agent
  cmd/agent/        進入點
  internal/api/     HTTP 伺服器（驗證、併發上限、JSON 解碼）
  internal/runner/  指令執行、IP 驗證、設定部署
deploy/systemd/     systemd 單元範例
docs/               agent API 與認證流程
start.py            一鍵啟動器（後端 + bot）
```
