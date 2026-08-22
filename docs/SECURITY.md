# Security

This document is the acceptance bar for the boilerplate: what it defends
against, how each control is implemented, where the sharp edges are, and what it
deliberately does not do.

## Threat model

**Assets.** User credentials, session tokens, password-reset and
email-verification tokens, and the account records behind them.

**Assumed attacker.** An unauthenticated party on the internet who can send
arbitrary HTTP requests, run a malicious web page in a victim's browser, read
any response the API returns, and observe response timing. They cannot read the
application's environment or the database directly.

**In scope**

| Threat | Control |
|---|---|
| Credential stuffing / brute force | Per-IP and per-email rate limits, progressive account lockout |
| Offline cracking after a database leak | Argon2id, 64 MiB / t=3 / p=2, per-password salt |
| Account enumeration | Identical responses and comparable timing on register, login, and forgot-password |
| Session theft via XSS | `HttpOnly` cookies; CSP `default-src 'none'` |
| Cross-site request forgery | `SameSite=Strict` plus a double-submit CSRF token |
| Stolen refresh token | Rotation on every use with family-wide revocation on reuse |
| Token forgery | HS256 with algorithm pinning and full claim validation |
| Token theft from the database | Only SHA-256 digests are stored, never plaintext |
| SQL injection | Parameterised statements only; no string-concatenated SQL |
| Resource exhaustion | Server timeouts, header and body caps, bounded limiter memory |
| Rate-limit evasion via forged headers | Trust-aware client-IP resolution |
| Secret leakage through logs | `slog` `ReplaceAttr` redaction of a fixed key set |
| Information leakage through errors | Closed error-code vocabulary; causes logged, never returned |

**Out of scope** — see [Explicitly out of scope](#explicitly-out-of-scope).

---

## Authentication and tokens

### Access tokens

HS256 JWTs signed with a secret of at least 32 bytes; the process refuses to
boot with anything shorter. Every token carries `sub`, `iat`, `exp`, `nbf`,
`jti`, `iss`, `aud`, and `typ: "access"`, and **all** of them are validated on
every request:

- The algorithm is pinned with `jwt.WithValidMethods([]string{"HS256"})` and the
  keyfunc additionally asserts the method is `*jwt.SigningMethodHMAC`. `alg:
  none` and any other family are rejected before the signature is checked.
- `iss` and `aud` must match the configured values exactly.
- `exp` is required; `nbf` and `iat` must be present and satisfied.
- `jti` and `sub` must be non-empty.
- `typ` must be `access`, so a token minted for another purpose cannot be
  replayed as an access token.
- A configurable `JWT_CLOCK_SKEW` (default 30s) is the only tolerance applied to
  `exp`, `nbf`, and `iat`, so modest clock drift between hosts does not reject
  valid tokens while the window stays far shorter than the token lifetime.

Default lifetime is 15 minutes. Access tokens are stateless by design: revoking
a session invalidates the refresh family immediately, but an already-issued
access token remains valid until it expires. Shorten `ACCESS_TOKEN_TTL` if that
window is unacceptable; a denylist keyed by `jti` is the usual next step and
`jti` is already present for exactly that reason.

### Refresh tokens

32 bytes from `crypto/rand`, base64url-encoded for transport. They are never
JWTs and carry no structure an attacker can read or forge.

Only `sha256(token)` is stored. Lookups are by digest, and comparisons use
`subtle.ConstantTimeCompare` (via `security.ConstantTimeEqual`) so a timing
oracle cannot walk the digest byte by byte.

**Rotation with reuse detection.** Each login mints a token family. Refreshing
burns the presented token and issues a successor in the same family, using one
conditional `UPDATE ... WHERE used_at IS NULL AND revoked_at IS NULL AND
expires_at > now RETURNING ...`. That statement is atomic, so two concurrent
refreshes cannot both succeed.

If a token is presented that exists but is already used, that is a replay — the
legitimate holder and the thief now both have tokens from the same lineage. The
entire family is revoked, both branches die, and `auth.refresh_reuse_detected`
is logged at `WARN` with the user and family IDs.

Refreshing also re-checks the account lock. A locked account's family is revoked
on the spot.

### Cookies

Set on login, refresh, and password change:

| Cookie | HttpOnly | Path | Purpose |
|---|---|---|---|
| `access_token` | yes | `/` | Bearer credential for browsers |
| `refresh_token` | yes | `/v1/auth` | Rotation credential |
| `csrf_token` | **no** | `/` | Double-submit value, read by JavaScript |

All three are `Secure` (mandatory in production — boot fails otherwise),
`SameSite=Strict`, and carry an explicit `MaxAge`. Logout overwrites all three
with `MaxAge=-1` and an epoch `Expires`.

> **Note on the refresh cookie path.** `COOKIE_REFRESH_PATH` defaults to
> `/v1/auth` rather than `/v1/auth/refresh`. A browser only sends a cookie to
> paths at or below its `Path`, so scoping it to the refresh endpoint alone
> would mean `/v1/auth/logout` never receives it — and logout could then only
> revoke *every* session rather than the current one. `/v1/auth` is the
> narrowest scope that covers both endpoints; nothing outside the auth subtree
> ever sees the cookie. If you would rather have the tighter scope, set
> `COOKIE_REFRESH_PATH=/v1/auth/refresh` and expect cookie-based logout to fall
> back to clearing cookies without server-side revocation, in which case have
> clients call `/v1/auth/logout-all`.

### CSRF

Double-submit cookie. On session creation the server generates 32 random bytes,
returns them both in the JavaScript-readable `csrf_token` cookie and in the
response body, and expects them echoed in the `X-CSRF-Token` header on every
state-changing request.

The comparison hashes both sides with SHA-256 before a constant-time compare, so
neither length nor content leaks through timing.

The check applies when the request is **cookie-authenticated**: an unsafe method
(anything but `GET`, `HEAD`, `OPTIONS`, `TRACE`) with an auth cookie present and
no `Authorization` header. Bearer-token clients are exempt because a cross-site
request cannot attach an `Authorization` header the attacker does not already
possess. Failures return `403` and log `csrf.failed`.

---

## Passwords

### Hashing

Argon2id at 64 MiB, 3 iterations, parallelism 2, a 16-byte random salt, and a
32-byte key. The encoded hash is the standard PHC string
(`$argon2id$v=19$m=65536,t=3,p=2$<salt>$<key>`), so the parameters travel with
the hash and can be raised later without a migration.

`NeedsRehash` compares a stored hash's embedded parameters against the current
configuration. On a successful login with a stale hash the password is
re-hashed with today's parameters and written back — invisibly, in the same
request. Malformed hashes are treated as needing a rehash.

### Policy

- Minimum 12 characters, maximum 128. The upper bound is a denial-of-service
  guard: Argon2id at 64 MiB is intentionally expensive, and unbounded input
  would let a client choose how much RAM and CPU the server burns.
- Length is counted in runes, so multi-byte passphrases are not unfairly
  rejected.
- A bundled list of common passwords is rejected, case-insensitively.
- A password containing the local part of the user's email address (three
  characters or longer) is rejected.
- No composition rules. Forced symbol-and-digit requirements push users toward
  predictable patterns and buy little.

The policy is enforced identically on register, reset, and change.

### Reset flow

- 32 random bytes, SHA-256 hashed at rest, 15-minute TTL, single use.
- Issuing a new reset token invalidates every outstanding one for that user, so
  a token captured earlier is dead the moment the user asks again.
- Consuming a token is the same atomic conditional `UPDATE` used for refresh
  tokens, so it cannot be redeemed twice even under a race.
- A completed reset revokes **all** refresh tokens for the user and invalidates
  any remaining reset tokens, then sends a notification email.
- A password change does the same — every session is revoked and a fresh one is
  returned in the response, so the caller stays signed in while every other
  device is signed out.

### No user enumeration

- `register` returns `202` with a fixed body whether or not the address is
  taken. If the address exists and is unverified, a fresh verification email is
  sent; if it exists and is verified, nothing is sent. The response is identical
  either way, and the existing account's password is never touched.
- `forgot-password` returns `202` with a fixed body regardless of whether the
  account exists.
- `login` returns the same `401` body for an unknown address as for a wrong
  password. Against a missing user the server still runs a full Argon2id verify
  against a dummy hash generated at boot, so the response time does not reveal
  whether the lookup found anything.

Regression tests assert byte-for-byte equality of these responses (modulo the
request ID).

---

## Rate limiting and lockout

### Limits

| Route | Rule |
|---|---|
| `POST /v1/auth/login` | 5 / 15 min per IP **and** 5 / 15 min per email |
| `POST /v1/auth/register` | 5 / hour per IP |
| `POST /v1/auth/forgot-password` | 3 / hour per IP **and** 3 / hour per email |
| `POST /v1/auth/refresh` | 30 / hour per IP |
| `POST /v1/auth/reset-password` | 10 / hour per IP |
| `POST /v1/auth/verify-email` | 10 / hour per IP |
| `POST /v1/me/change-password` | 5 / hour per user |
| global fallback | 100 / minute per IP |

Whichever rule trips first wins. Rejections return `429` with `Retry-After`,
`X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`.

The in-process limiter shards buckets across 32 maps keyed by a hash of
`rule|key`, so concurrent requests rarely contend on the same mutex, and a
janitor goroutine evicts idle buckets so a spray of unique keys cannot grow the
map without bound. With `REDIS_URL` set, Redis becomes the primary and the
in-process limiter is the automatic fallback: an outage degrades enforcement
from cluster-wide to per-instance and logs a warning, rather than failing
requests or removing the limit entirely.

If the limiter returns an error the request is allowed and the failure is logged
at `ERROR`. This is a deliberate fail-open: with the failover limiter in place, a
total failure means both backends are broken, and refusing all traffic is the
worse outcome. Change `middleware.RateLimitWith` if your risk appetite differs.

### Trusted proxies — read this

`X-Forwarded-For` and `X-Real-IP` are honoured **only** when `RemoteAddr` falls
inside `TRUSTED_PROXY_CIDRS`. With the list empty (the default), proxy headers
are ignored completely.

When the peer is trusted, the resolver walks the forwarded chain right to left
and returns the first hop that is not itself in the trusted set — the last
address your infrastructure actually observed, rather than the leftmost value,
which any client can prepend.

**Getting this wrong makes every IP-keyed control useless.** If you list a range
you do not control — worst of all `0.0.0.0/0` — an attacker sets
`X-Forwarded-For` to a fresh address on every request, lands in a fresh rate-limit
bucket every time, and brute-forces logins unimpeded. Set it to the CIDR of your
own load balancer and nothing else, and leave it empty when the API is exposed
directly.

### Account lockout

Independent of rate limiting, and keyed to the account rather than the caller.
After `LOCKOUT_THRESHOLD` consecutive failures (default 10) the account is locked
for `LOCKOUT_BASE_WINDOW` (default 15 minutes). The window doubles every
`LOCKOUT_BACKOFF_STEP` further failures, capped at `LOCKOUT_MAX_WINDOW`. A
successful login clears the counter and the lock, as does a password change or
reset.

The lock is checked **after** the password is verified. A caller who supplies the
wrong password always sees `invalid_credentials`; only a caller who supplies the
*correct* password learns the account is locked. That preserves the
no-enumeration property — an attacker who does not know the password learns
nothing — while still telling the legitimate user what is going on.
`auth.account_locked` is logged at `WARN` in both cases.

---

## Transport and server hardening

`http.Server` is configured with `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`,
`WriteTimeout: 20s`, `IdleTimeout: 60s`, and `MaxHeaderBytes: 1 << 20`. Every
request body passes through `http.MaxBytesReader` at 1 MiB by default,
configurable per route; oversize bodies produce `413`.

JSON decoding uses `DisallowUnknownFields()` and then asserts the reader is at
EOF, so a body containing a second JSON value is rejected rather than silently
ignored. `Content-Type` must be `application/json` when present.

`SIGINT` and `SIGTERM` trigger a graceful shutdown: the listener closes, in-flight
requests finish within `HTTP_SHUTDOWN_TIMEOUT`, and anything still running when
the window expires is closed hard.

### Response headers

Set on every response:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), …
X-Permitted-Cross-Domain-Policies: none
```

`Strict-Transport-Security: max-age=31536000; includeSubDomains` is added when
the connection is TLS, or when the deployment is configured as TLS-terminated in
production. It is driven by configuration rather than by an inbound
`X-Forwarded-Proto` header, because that header is attacker-controllable unless
a trusted proxy is confirmed.

### CORS

Strict allowlist from `CORS_ALLOWED_ORIGINS`. A disallowed origin gets a `403`
with the standard error envelope — the origin is never reflected. `*` cannot be
combined with credentials: configuration rejects it at boot, and the middleware
refuses it again at runtime. Methods and headers are explicit allowlists;
preflights are cached for `CORS_MAX_AGE`. `Vary: Origin` is always set.

### Panics

A panic is caught, the stack is logged at `ERROR` alongside the request ID, and
the client receives a generic `500` with no detail. `http.ErrAbortHandler` is
re-panicked so the server can drop the connection as intended.

---

## Data and operational security

- Every query is parameterised. No SQL is built by string concatenation; the two
  one-time-token tables share behaviour through pre-declared constant query
  sets, not by interpolating a table name.
- Every database call carries a context deadline (`DB_QUERY_TIMEOUT`).
- Emails are stored normalised (trimmed, lowercased) in a `citext` column with a
  unique index; the original display form is kept separately for outbound mail.
- Refresh, reset, and verification tokens are stored as `bytea` digests with a
  `CHECK (octet_length(token_hash) = 32)` constraint and a unique index.
- `refresh_tokens`, `password_reset_tokens`, and `email_verification_tokens` all
  cascade on user delete.
- `service.Cleanup` purges expired tokens hourly. The same queries are available
  for an external cron job if you would rather not run it in-process.
- Secrets come from the environment only. `.env.example` contains placeholders;
  no real secret is committed. Boot fails fast when a required secret is missing
  or a JWT secret is under 32 bytes.
- Migrations never run automatically at startup.
- The container image is a multi-stage build producing a static binary on
  distroless, running as `nonroot`.
- `gosec` and `govulncheck` run clean in CI; the `go` directive pins a toolchain
  free of known standard-library vulnerabilities.

---

## Logging discipline

A `ReplaceAttr` hook redacts these keys anywhere in the attribute tree,
case-insensitively: `password`, `new_password`, `current_password`,
`confirm_password`, `token`, `refresh_token`, `access_token`, `reset_token`,
`authorization`, `cookie`, `set-cookie`, `set_cookie`, `csrf`, `csrf_token`,
`secret`, `jwt_secret`, `api_key`, `private_key`. Values become `[REDACTED]`.

Never logged, at any level: credentials, raw tokens, reset or verification
links, cookie headers, or request bodies. The development mail driver logs only
the template name, subject, and a masked recipient — the message body, which
contains the link, is not written anywhere. Use MailHog to read it.

Access logs record the **route template**, not the raw path, so identifiers in
URLs cannot leak into log storage and cardinality stays bounded.

Security events carry a stable `event` attribute at `WARN`:
`auth.login_failed`, `auth.account_locked`, `auth.refresh_reuse_detected`,
`auth.password_reset_requested`, `auth.password_reset_completed`,
`ratelimit.exceeded`, `csrf.failed`. Alert on
`auth.refresh_reuse_detected` — it means a refresh token was used twice, which
is either a broken client or a stolen credential.

---

## Security regression tests

These behaviours are asserted in `internal/server/security_test.go` and fail the
build if they regress:

- `login` returns an identical body and status for an unknown and a known email.
- `register` and `forgot-password` return identical responses regardless of
  account existence.
- A reused refresh token revokes the whole family, including descendants issued
  after the original was burnt.
- An expired reset token is rejected and leaves the old password working.
- A reset token cannot be used twice.
- Eight concurrent refreshes with the same token produce exactly one rotation;
  the losers are treated as reuse and revoke the family.
- Sixteen concurrent `ConsumeByHash` calls against real Postgres claim the token
  exactly once.
- Issuing a new reset token invalidates the previous one.
- An expired verification token is rejected.
- A request over the body limit returns `413`.
- A state-changing cookie request without — or with a wrong — CSRF token returns
  `403` on `/v1/me`, `/v1/auth/refresh`, `/v1/auth/logout`,
  `/v1/auth/logout-all`, and `/v1/me/change-password`.
- Rate limits trip at exactly the configured threshold and emit `Retry-After`
  plus the `X-RateLimit-*` headers.
- Repeated failures lock the account, the lock expires, and a success resets the
  counter.
- Weak passwords are rejected on register, change, and reset alike.
- Error envelopes never contain internal error strings.
- Passwords, access tokens, refresh tokens, CSRF tokens, and reset links never
  appear in the log stream.

---

## Explicitly out of scope

The following are **not** implemented. Each note says where it would hook in.

**Web application firewall / DDoS protection.** The rate limiter defends the
application layer, not the network. Volumetric attacks belong at the CDN or load
balancer. Nothing in the app changes; put the API behind the WAF and set
`TRUSTED_PROXY_CIDRS` to the WAF's egress ranges.

**Multi-factor authentication (TOTP, WebAuthn).** Would slot into
`AuthService.Login`: after the password verifies and before `startSession`,
return a "second factor required" result and issue a short-lived challenge token
instead of a session. Storage would be a new `user_mfa_factors` table and a new
repository interface; the handler would gain `POST /v1/auth/mfa/verify`.

**OAuth / OIDC social login.** Would be a sibling of the password flow: a new
`internal/service/oauth.go` handling the authorisation-code exchange, a
`user_identities` table linking provider subject IDs to users, and routes under
`/v1/auth/oauth/{provider}`. Session issuance would reuse `startSession`
unchanged.

**Audit log retention and tamper-evidence.** Security events go to `slog` and
nowhere else. Durable, queryable, tamper-evident audit trails need a dedicated
sink — an append-only table or an external service. The hook is
`logging.Security`: give it a second destination.

**Secrets manager integration.** Configuration reads the process environment
only. Vault, AWS Secrets Manager, or GCP Secret Manager would be wired into
`config.Load` — resolve `vault://…`-style references before validation, or
inject via a sidecar that populates the environment before the process starts.

**Authorisation beyond authentication.** Every authenticated user has identical
permissions. Roles, scopes, or per-resource ACLs would live in `domain` and be
enforced by a new middleware sitting after `Authenticate`.

**Access-token revocation before expiry.** Access tokens are stateless for their
15-minute lifetime. A `jti` denylist in Redis, checked in
`middleware.Authenticate`, is the usual approach; `jti` is already issued and
validated for that purpose.

**Absolute session lifetime.** A refresh token has a 30-day idle TTL and rotates
on every use, so an actively used session can be extended indefinitely. Capping
it means recording `family_created_at` on the token family and refusing rotation
past an absolute maximum (90 days is typical). `refresh_tokens.family_id` and
`created_at` already carry everything needed; the check would go in
`AuthService.Refresh` beside the existing lock check.

**Device and session management UI.** `refresh_tokens` records `user_agent`, `ip`,
and `created_at` per family, which is enough to build "your active sessions" —
but no endpoint exposes or selectively revokes them yet.

**Email address change.** Only the name is mutable through `PATCH /v1/me`.
Changing an email safely needs a double-confirmation flow (verify the new
address, notify the old one) built on the existing verification-token machinery.

**Encryption at rest and key rotation.** Assumed to be handled by the database
and infrastructure. The JWT signing secret is single-valued; supporting rotation
means accepting a set of verification keys while signing with the newest, which
is a change to `security.TokenIssuer`.

---

## Reporting a vulnerability

This is a boilerplate, not a hosted service. If you find a flaw in the template
itself, open an issue describing the impact and the affected file. Do not
include working exploit payloads against anyone else's deployment.
