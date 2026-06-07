# Kioubit + Telegram Auth Flow

## Web Login

1. User opens `/login`.
2. Backend creates an `auth_challenges` row with purpose `web`.
3. WebUI renders `kioubit-auth-btn` with:
   - `return=https://<DOMAIN>/auth/kioubit/callback`
   - `token=<challenge token>`
4. Kioubit redirects back with `params` and `signature`.
5. Backend verifies:
   - ECDSA signature (SHA-512) over the original `params` string, using Kioubit's EC public key
   - decoded JSON `time` (short replay window)
   - decoded JSON `domain`
   - decoded JSON `user_token`
6. Backend creates or updates the user and starts a session.

## Telegram Login

1. User sends `/login`.
2. Bot asks backend for a Telegram challenge.
3. Bot sends a Telegram Web App button for `/telegram/auth?token=<challenge>`.
4. Mini App renders the Kioubit button.
5. Kioubit redirects back to the Mini App page with `params` and `signature`.
6. Mini App calls `Telegram.WebApp.sendData(...)`.
7. Bot receives `web_app_data` and posts it to backend.
8. Backend verifies Kioubit data and binds Telegram user id to the verified ASN.

The bot never trusts decoded Kioubit JSON by itself. It only transports the signed envelope to the backend.

## FindNOC Telegram login (optional)

A lighter alternative to the Kioubit Mini App, enabled only when `FINDNOC_API_TOKEN` is set.

1. User sends `/login`.
2. Bot POSTs the sender's Telegram id/chat/username to `/api/telegram/findnoc/login`.
3. Backend calls FindNOC `GET /queryUser?userid=<uid>` (token passed as the `token` query param):
   - one ASN → backend binds the Telegram id to that ASN and returns `{ok: true, asn}`.
   - several ASNs → backend returns `{need_choice: true, asns: [...]}`; the bot shows one button per
     ASN, and the chosen one is re-checked with `GET /verify?userid=&ASN=` before binding.
   - none (HTTP 404) or FindNOC off/unreachable (HTTP 503) → the bot falls back to the Kioubit flow.
4. Identity/admin handling is identical to Kioubit (`upsert_user_from_findnoc` shares
   `_upsert_user_for_asn`), so a FindNOC login and a Kioubit login for the same ASN resolve to one
   account. The ASN is recorded with `authtype="findnoc"`.

FindNOC is a third-party directory (weaker than Kioubit's signed proof), so the backend treats its
answers as advisory: it re-queries the live API on every login and never trusts a UID→ASN claim
forwarded by the bot. The Telegram UID used is always the bot-vouched message sender.
