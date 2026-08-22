# API reference

Base path `/v1`. Requests and responses are JSON; `Content-Type` must be
`application/json` when a body is present. Bodies are capped at 1 MiB by default
and unknown fields are rejected.

## Authenticating a request

Two interchangeable mechanisms:

**Cookies (browsers).** `POST /v1/auth/login` sets `access_token`,
`refresh_token`, and `csrf_token`. Send them automatically, and echo the
`csrf_token` value in an `X-CSRF-Token` header on every state-changing request.

**Bearer (everything else).** Send `Authorization: Bearer <access_token>`. CSRF
is not required — an `Authorization` header cannot be forged cross-site. Pass
the refresh token in the request body for `/v1/auth/refresh` and
`/v1/auth/logout`.

If an `Authorization` header is present it takes precedence; the access cookie
is ignored.

## Common headers

| Header | Direction | Meaning |
|---|---|---|
| `X-Request-ID` | both | Echoed if it is a well-formed UUID, otherwise generated. Present on every response and in the error envelope. |
| `X-CSRF-Token` | request | Required for state-changing cookie-authenticated requests |
| `X-RateLimit-Limit` | response | Ceiling for the rule that was evaluated |
| `X-RateLimit-Remaining` | response | Requests left in the window |
| `X-RateLimit-Reset` | response | Seconds until the bucket fully refills |
| `Retry-After` | response | Seconds to wait, on `429` only |

---

## Error envelope

Every non-2xx response, including router `404`s and `405`s:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "The request payload failed validation.",
    "request_id": "0b0f6ad1-3d2f-4e33-9d4f-1f0f0a2b0c3d",
    "details": [
      { "field": "email", "issue": "must be a valid email address" },
      { "field": "password", "issue": "must be at least 12 characters" }
    ]
  }
}
```

`details` is present only on `4xx` validation failures. `5xx` responses never
carry `details` and never expose an internal error string.

### Error codes

The vocabulary is closed. Clients may switch on `code`.

| Code | Status | Meaning |
|---|---|---|
| `validation_failed` | 422 | One or more fields failed validation; see `details` |
| `weak_password` | 422 | The password does not meet the policy |
| `password_unchanged` | 422 | The new password matches the current one |
| `malformed_json` | 400 | Body is not a single well-formed JSON value |
| `unsupported_media_type` | 415 | `Content-Type` is not `application/json` |
| `payload_too_large` | 413 | Body exceeded the configured limit |
| `invalid_credentials` | 401 | Email or password is incorrect |
| `unauthorized` | 401 | Authentication is required and was not supplied |
| `invalid_token` | 401 | A token is malformed, expired, revoked, or already used |
| `forbidden` | 403 | Authenticated but not permitted |
| `csrf_failed` | 403 | CSRF token missing or mismatched |
| `account_locked` | 403 | Too many failed logins; try again later |
| `email_not_verified` | 403 | Verification is required and has not happened |
| `origin_not_allowed` | 403 | Origin is not in the CORS allowlist |
| `not_found` | 404 | No such route or resource |
| `method_not_allowed` | 405 | Route exists, method does not |
| `conflict` | 409 | Resource is in a conflicting state |
| `rate_limited` | 429 | A rate limit tripped; see `Retry-After` |
| `service_unavailable` | 503 | A required dependency is unavailable |
| `request_timeout` | 504 | The request exceeded its deadline |
| `internal_error` | 500 | Unexpected failure; correlate via `request_id` |

---

## Objects

### `user`

```json
{
  "id": "0e1b7d2c-4d5f-4c6a-9d3e-2b1a0c9f8e7d",
  "email": "Ada@Example.com",
  "name": "Ada Lovelace",
  "email_verified": true,
  "email_verified_at": "2026-05-01T09:12:00Z",
  "created_at": "2026-05-01T09:00:00Z",
  "updated_at": "2026-05-01T09:12:00Z"
}
```

`email` is the display form as supplied at registration. Matching is
case-insensitive. `email_verified_at` is omitted when unverified.

### `session`

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "kQ3n8Zx1...",
  "token_type": "Bearer",
  "expires_in": 900,
  "access_expires_at": "2026-05-01T09:15:00Z",
  "refresh_expires_at": "2026-05-31T09:00:00Z",
  "csrf_token": "9pQ2m...",
  "user": { }
}
```

The same values are set as cookies. Browser clients should ignore
`access_token` and `refresh_token` in the body and rely on the cookies; only
`csrf_token` needs to be read.

---

## Endpoints

### `POST /v1/auth/register`

Creates an account and emails a verification link. Does **not** sign the user
in.

```json
{ "email": "ada@example.com", "password": "an-adequately-long-passphrase", "name": "Ada Lovelace" }
```

`name` is optional and capped at 200 characters. The password must satisfy the
policy: 12–128 characters, not a common password, and not containing the local
part of the email address.

**202 Accepted** — always, whether or not the address is already registered.

```json
{ "status": "accepted", "message": "If the address can receive mail, a verification link is on its way." }
```

Errors: `validation_failed`, `weak_password`, `rate_limited` (5/hour per IP).

---

### `POST /v1/auth/verify-email`

```json
{ "token": "<token from the verification email>" }
```

**200 OK**

```json
{ "status": "ok", "message": "Your email address has been verified." }
```

Errors: `validation_failed`, `invalid_token` (unknown, expired, or already
used), `rate_limited` (10/hour per IP).

---

### `POST /v1/auth/login`

```json
{ "email": "ada@example.com", "password": "an-adequately-long-passphrase" }
```

**200 OK** — a `session` object, plus `Set-Cookie` for all three cookies.

Errors:

- `invalid_credentials` (401) — wrong password, or no such account. Identical
  body and comparable timing in both cases.
- `account_locked` (403) — correct password, but the account is locked.
- `email_not_verified` (403) — only when `REQUIRE_VERIFIED_EMAIL=true`.
- `rate_limited` (429) — 5 per 15 minutes per IP and per email.

---

### `POST /v1/auth/refresh`

Rotates the refresh token and issues a new access token. The presented token is
consumed; presenting it again revokes the entire family.

Cookie clients send nothing but the cookies plus `X-CSRF-Token`. Bearer clients
send:

```json
{ "refresh_token": "kQ3n8Zx1..." }
```

**200 OK** — a fresh `session`, and new cookies.

Errors: `invalid_token` (401, also clears cookies), `account_locked` (403),
`csrf_failed` (403), `rate_limited` (429, 30/hour per IP).

---

### `POST /v1/auth/logout`

Revokes the current refresh-token family and clears all three cookies. Requires
authentication; requires a CSRF token when cookie-authenticated. Bearer clients
may pass `{"refresh_token": "..."}` to revoke a specific family.

**204 No Content**

Errors: `unauthorized`, `csrf_failed`.

---

### `POST /v1/auth/logout-all`

Revokes every refresh token for the user, on every device, and clears cookies.

**204 No Content**

Errors: `unauthorized`, `csrf_failed`.

---

### `POST /v1/auth/forgot-password`

```json
{ "email": "ada@example.com" }
```

Issues a single-use, 15-minute reset token and emails it. Any previously issued
reset token for that user is invalidated.

**202 Accepted** — always, whether or not the account exists.

```json
{ "status": "accepted", "message": "If an account exists for that address, a password reset link is on its way." }
```

Errors: `validation_failed`, `rate_limited` (3/hour per IP and per email).

---

### `POST /v1/auth/reset-password`

```json
{ "token": "<token from the reset email>", "new_password": "another-entirely-different-phrase" }
```

Sets the new password, consumes the token, invalidates any other outstanding
reset tokens, revokes **every** refresh token for the user, and sends a
notification email.

**200 OK**

```json
{ "status": "ok", "message": "Your password has been changed and all sessions were signed out." }
```

Errors: `validation_failed`, `weak_password`, `invalid_token`, `rate_limited`
(10/hour per IP).

---

### `GET /v1/me`

Requires authentication. No CSRF token needed (safe method).

**200 OK** — a `user` object.

Errors: `unauthorized`, `invalid_token`.

---

### `PATCH /v1/me`

```json
{ "name": "Ada King" }
```

`name` is required in the body (send `""` to clear it) and capped at 200
characters.

**200 OK** — the updated `user`.

Errors: `unauthorized`, `invalid_token`, `csrf_failed`, `validation_failed`.

---

### `POST /v1/me/change-password`

```json
{ "current_password": "an-adequately-long-passphrase", "new_password": "another-entirely-different-phrase" }
```

Verifies the current password, revokes every existing session, invalidates
outstanding reset tokens, sends a notification email, and returns a brand-new
session so the caller stays signed in.

**200 OK** — a `session` object with new cookies.

Errors: `unauthorized`, `csrf_failed`, `invalid_credentials` (wrong current
password), `password_unchanged`, `weak_password`, `validation_failed`,
`rate_limited` (5/hour per user).

---

### `GET /healthz`

Liveness. Touches no dependency and is exempt from the global rate limit.

**200 OK**

```json
{ "status": "ok", "version": "0.1.0" }
```

---

### `GET /readyz`

Readiness. Pings Postgres, and Redis when configured.

**200 OK**

```json
{ "status": "ok", "version": "0.1.0", "checks": { "database": "ok", "redis": "ok" } }
```

**503 Service Unavailable** when any dependency fails:

```json
{ "status": "degraded", "version": "0.1.0", "checks": { "database": "unavailable" } }
```

---

## Rate limit summary

| Route | Rule |
|---|---|
| `POST /v1/auth/login` | 5 / 15 min per IP and per email |
| `POST /v1/auth/register` | 5 / hour per IP |
| `POST /v1/auth/forgot-password` | 3 / hour per IP and per email |
| `POST /v1/auth/refresh` | 30 / hour per IP |
| `POST /v1/auth/reset-password` | 10 / hour per IP |
| `POST /v1/auth/verify-email` | 10 / hour per IP |
| `POST /v1/me/change-password` | 5 / hour per user |
| everything except `/healthz` and `/readyz` | 100 / minute per IP |
