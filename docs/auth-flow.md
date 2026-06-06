# Kioubit + Telegram Auth Flow

## Web Login

1. User opens `/login`.
2. Backend creates an `auth_challenges` row with purpose `web`.
3. WebUI renders `kioubit-auth-btn` with:
   - `return=https://<DOMAIN>/auth/kioubit/callback`
   - `token=<challenge token>`
4. Kioubit redirects back with `params` and `signature`.
5. Backend verifies:
   - ECDSA P-521 signature over the original `params` string
   - decoded JSON `time`
   - decoded JSON `domain`
   - decoded JSON `user_token`
6. Backend creates or updates the user and starts a session.

## Telegram Login

1. User sends `/verify`.
2. Bot asks backend for a Telegram challenge.
3. Bot sends a Telegram Web App button for `/telegram/auth?token=<challenge>`.
4. Mini App renders the Kioubit button.
5. Kioubit redirects back to the Mini App page with `params` and `signature`.
6. Mini App calls `Telegram.WebApp.sendData(...)`.
7. Bot receives `web_app_data` and posts it to backend.
8. Backend verifies Kioubit data and binds Telegram user id to the verified ASN.

The bot never trusts decoded Kioubit JSON by itself. It only transports the signed envelope to the backend.
