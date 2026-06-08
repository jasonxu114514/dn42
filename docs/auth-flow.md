# Authentication Flow

Every peer operation starts from a verified dn42 ASN. The backend supports three login paths:

- Web login with Kioubit.dn42.
- Telegram login with the Kioubit Mini App.
- Optional Telegram quick login with FindNOC.

All paths converge on the same `users` table. A user becomes admin when the verified ASN equals
`LOCAL_ASN`.

## Identity Model

Core tables:

| Table | Purpose |
| --- | --- |
| `users` | One row per primary ASN. Stores admin flag and last login time. |
| `asn_identities` | Audit history for login proofs and metadata returned by Kioubit or FindNOC. |
| `auth_challenges` | One-time login challenges with purpose, token, expiry, and consumed time. |
| `telegram_bindings` | Maps a Telegram user id to a `users` row. |
| `peer_requests` | Peers belong to a `users` row, not directly to Telegram. |

Because peers reference `users`, `/logout` from Telegram only removes the Telegram binding. Peers are
kept and become visible again after the Telegram account logs in to the same ASN.

## Common Rules

### ASN normalization

ASNs are stored as bare numbers, for example `4242420090`. Inputs may include an `AS` prefix where
the relevant handler supports it, but the final user key is numeric.

### Admin rule

On every login, the backend recomputes:

```text
user.is_admin = normalize(verified_asn) == normalize(LOCAL_ASN)
```

This means admin status follows the current deployment config and is refreshed on login.

### Challenge lifetime

`auth_challenges` tokens are random `secrets.token_urlsafe(32)` strings. They expire after 600
seconds by default and are consumed exactly once.

The challenge stores a `purpose`:

- `web`
- `telegram`

The callback must consume the challenge with the matching purpose.

## Kioubit Verification

Kioubit returns:

- `params`: base64-encoded JSON;
- `signature`: base64 ECDSA signature over the raw `params` string.

The backend verifies:

1. The configured Kioubit public key exists and is an EC public key.
2. The signature is valid using ECDSA with SHA-512.
3. `params` decodes to JSON.
4. The token timestamp is within 60 seconds of the current backend time.
5. The token `domain` exactly matches this deployment's `DOMAIN` after stripping scheme and trailing
   slash.
6. The token contains an ASN.
7. The `user_token` maps to an unexpired, unconsumed challenge with the expected purpose.

Only after those checks does the backend create or update the user.

Kioubit metadata stored in `asn_identities` includes:

- `asn`
- `mnt`
- `effective_mnt`
- `allowed4`
- `allowed6`
- `authtype`
- `first_email` on the user row when present

## Web Login

Entry point: `GET /login`

Flow:

1. Browser opens `/login`.
2. Backend creates an `auth_challenges` row:
   - `purpose = "web"`
   - random `token`
   - 600 second expiry
3. The page renders the Kioubit auth button.
4. Kioubit redirects back to:

   ```text
   /auth/kioubit/callback?params=...&signature=...
   ```

5. Backend verifies the Kioubit envelope.
6. Backend consumes the `web` challenge from `user_token`.
7. Backend creates or updates the user for the verified ASN.
8. Backend writes an `asn_identities` audit row.
9. Backend stores `user_id` in the signed session cookie.
10. Browser is redirected to `/portal`.

Logout:

```text
GET /logout
```

This removes `user_id` from the browser session.

## Telegram Kioubit Mini App Login

This path is used when FindNOC quick login is disabled, unavailable, or does not know the user's
Telegram account.

Actors:

- Telegram user
- Telegram bot process
- Backend
- Kioubit.dn42
- Telegram Mini App page served by the backend

Flow:

1. User sends `/login`.
2. Bot calls:

   ```http
   POST /api/telegram/challenge
   X-Backend-Secret: <secret>
   ```

   Body:

   ```json
   {
     "telegram_user_id": "123456",
     "telegram_chat_id": "123456"
   }
   ```

3. Backend creates a challenge:
   - `purpose = "telegram"`
   - the Telegram user id
   - the Telegram chat id
   - 600 second expiry
4. Backend returns:

   ```json
   {
     "token": "<challenge-token>",
     "url": "https://example.com/telegram/auth?token=<challenge-token>"
   }
   ```

5. Bot sends a Telegram Web App button for that URL.
6. User opens the Mini App.
7. The Mini App page renders Kioubit login for the challenge token.
8. Kioubit redirects back to the Mini App page with `params` and `signature`.
9. Browser-side Mini App code calls `Telegram.WebApp.sendData(...)` with the signed envelope.
10. Bot receives `web_app_data` and calls:

    ```http
    POST /api/telegram/verify
    X-Backend-Secret: <secret>
    ```

    Body:

    ```json
    {
      "telegram_user_id": "123456",
      "telegram_chat_id": "123456",
      "username": "optional_username",
      "params": "<kioubit-params>",
      "signature": "<kioubit-signature>"
    }
    ```

11. Backend verifies the Kioubit envelope.
12. Backend consumes the `telegram` challenge from `user_token`.
13. Backend checks the challenge's stored `telegram_user_id` matches the sender supplied by the bot.
14. Backend creates or updates the user for the verified ASN.
15. Backend writes an `asn_identities` audit row.
16. Backend creates or updates the `telegram_bindings` row.

The bot never trusts decoded Kioubit JSON by itself. It only transports the signed envelope. The
backend is the only verifier.

## FindNOC Quick Login

FindNOC quick login is enabled when `FINDNOC_API_TOKEN` is set.

FindNOC is a third-party directory that maps Telegram UIDs to dn42 ASNs. It is weaker than Kioubit's
signed proof, so the backend treats it as advisory and rechecks FindNOC on every login.

Entry point:

```http
POST /api/telegram/findnoc/login
X-Backend-Secret: <secret>
```

Initial body:

```json
{
  "telegram_user_id": "123456",
  "telegram_chat_id": "123456",
  "username": "optional_username"
}
```

Flow:

1. User sends `/login`.
2. Bot calls `/api/telegram/findnoc/login`.
3. Backend calls FindNOC:

   ```text
   GET <FINDNOC_API_URL>/queryUser?userid=<uid>&token=<token>
   ```

4. Possible outcomes:

   | Outcome | Backend response | Bot behavior |
   | --- | --- | --- |
   | FindNOC returns no ASN / 404 | HTTP 404 | Bot falls back to Kioubit Mini App. |
   | FindNOC is disabled or unreachable | HTTP 503 | Bot falls back to Kioubit Mini App. |
   | FindNOC returns one ASN | `{"ok": true, "asn": "...", "method": "findnoc"}` | Bot reports success. |
   | FindNOC returns several ASNs | `{"need_choice": true, "asns": [...]}` | Bot asks user to pick one. |

5. If several ASNs were returned, the bot calls the same endpoint again with `asn`:

   ```json
   {
     "telegram_user_id": "123456",
     "telegram_chat_id": "123456",
     "username": "optional_username",
     "asn": "AS4242420090"
   }
   ```

6. Backend normalizes the selected ASN and verifies it live:

   ```text
   GET <FINDNOC_API_URL>/verify?userid=<uid>&ASN=AS<asn>&token=<token>
   ```

7. If FindNOC confirms control, backend creates or updates the user and Telegram binding.
8. Backend writes an `asn_identities` row with `authtype = "findnoc"`.

### FindNOC token safety

FindNOC expects the API token in a URL query parameter. Because URLs can leak through logs and
exception strings, the FindNOC client avoids logging request URLs or raw `httpx` exception text.

## Bot-Only API Security

All `/api/telegram/*` endpoints are intended for the local bot process, not browsers or users. They
require:

```http
X-Backend-Secret: <TELEGRAM_BACKEND_SECRET>
```

The backend checks this secret using constant-time comparison.

Important endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/telegram/challenge` | Create Telegram Kioubit challenge. |
| `POST /api/telegram/verify` | Verify Kioubit envelope and bind Telegram. |
| `POST /api/telegram/findnoc/login` | Optional FindNOC login. |
| `POST /api/telegram/logout` | Remove Telegram binding. |
| `GET /api/telegram/peer/{telegram_user_id}` | List peers for wizard selection. |
| `GET /api/telegram/nodes` | List enabled nodes. |
| `POST /api/telegram/peer/create` | Create and deploy a peer. |
| `POST /api/telegram/peer/edit` | Edit and redeploy a peer. |
| `POST /api/telegram/peer/delete` | Delete a peer. |
| `POST /api/telegram/status` | Fetch peer, WireGuard, and BIRD status. |
| `POST /api/telegram/lg` | Run a looking-glass query. |

## Peer Authorization

Web portal routes use the signed session to load `current_user`. A user can only view their own
peers and generated config.

Telegram peer routes load the `User` through `telegram_bindings`. The backend verifies ownership
before editing or deleting a peer.

Admin routes require `user.is_admin == true`, which comes from the verified ASN matching
`LOCAL_ASN`.

## Session Cookies

The backend uses Starlette signed session cookies:

- `HttpOnly`
- `SameSite=Lax`
- `Secure` unless insecure defaults are allowed

The cookie stores `user_id`; user details are loaded from the database on each request.

## Failure Modes

| Error | Meaning |
| --- | --- |
| `Kioubit public key is not installed` | `KIOUBIT_PUBLIC_KEY_PATH` is missing. |
| `Invalid Kioubit signature` | Signature did not verify against the configured key. |
| `Kioubit token has expired` | Token timestamp is outside the 60 second replay window. |
| `Kioubit token was issued for a different domain` | `DOMAIN` does not match the token domain. |
| `Unknown auth challenge` | `user_token` is not a known challenge. |
| `Auth challenge purpose mismatch` | Challenge was created for another flow. |
| `Auth challenge was already used` | One-time challenge was consumed. |
| `Auth challenge has expired` | Challenge is older than its TTL. |
| `Telegram user mismatch` | Signed Telegram login was not bound to the requesting Telegram sender. |
| `FindNOC is currently unavailable` | FindNOC is disabled, unreachable, or returned an unusable response. |

## Trust Boundaries

- Kioubit is the strongest proof because it signs the ASN assertion.
- FindNOC is a weaker third-party lookup and is rechecked live.
- The Telegram UID is trusted only because it comes from the bot process.
- User-supplied Telegram JSON cannot grant ASN access without backend verification.
- The backend is the trust boundary for peer creation.
- Node services trust the backend and should not be exposed as public unauthenticated services.

