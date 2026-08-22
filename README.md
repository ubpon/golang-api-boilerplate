# golang-api-boilerplate

A production-grade authentication API in Go, built on the standard library's
`net/http` router. No web framework, no ORM, no third-party logging library —
just `http.ServeMux`, `database/sql`, and `log/slog`, wired together the way a
team can extend on day one.

- **Routing** — Go 1.22+ `http.ServeMux` method + wildcard patterns
- **Storage** — PostgreSQL 16 via `pgx/v5` behind `database/sql`, hand-written SQL only
- **Sessions** — HS256 access JWTs (15 min) plus opaque, hashed, rotating refresh tokens (30 days) with reuse detection
- **Transport** — `HttpOnly; Secure; SameSite=Strict` cookies with a double-submit CSRF token, or `Authorization: Bearer` for non-browser clients
- **Passwords** — Argon2id (64 MiB / t=3 / p=2), upgradeable parameters, rehash-on-login
- **Abuse controls** — per-route sharded token-bucket rate limiting (in-process or Redis) plus progressive account lockout
- **Observability** — structured `log/slog` output with request IDs, route-template access logs, and automatic redaction of sensitive keys

---

## Quickstart

```bash
git clone https://github.com/ubpon/golang-api-boilerplate.git
cd golang-api-boilerplate

cp .env.example .env
# Generate a real secret and paste it into .env as JWT_SECRET
openssl rand -base64 48

docker compose up -d       # postgres + redis + mailhog
make migrate-up            # apply migrations/*.up.sql
make run                   # serves on :8080
```

Check it is alive:

```bash
curl -s localhost:8080/healthz | jq
curl -s localhost:8080/readyz  | jq
```

MailHog's web UI is at <http://localhost:8025> — verification and reset emails
land there in development.

### Everyday commands

| Command | What it does |
|---|---|
| `make run` | Run the API from source |
| `make build` | Build a static binary into `bin/api` |
| `make test` | `go test -race -short ./...` (no containers needed) |
| `make test-integration` | Every test, including testcontainers-backed Postgres tests |
| `make lint` | `golangci-lint run ./...` |
| `make sec` | `gosec` + `govulncheck` |
| `make migrate-up` / `make migrate-down` | Apply / roll back migrations |
| `make migrate-create name=add_widgets` | Scaffold a new migration pair |
| `make docker-up` / `make docker-down` | Start / tear down the dependency stack |

Migrations run through the `golang-migrate` CLI in a container, so no local
install is required. Migrations are **never** applied automatically at boot.

---

## Endpoints

All JSON in, JSON out, under `/v1`.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/auth/register` | none | Create an account and send a verification email. Does not log you in. |
| POST | `/v1/auth/login` | none | Issue an access token and a refresh token |
| POST | `/v1/auth/refresh` | refresh cookie or body | Rotate the refresh token and mint a new access token |
| POST | `/v1/auth/logout` | access | Revoke the current refresh-token family and clear cookies |
| POST | `/v1/auth/logout-all` | access | Revoke every refresh token for the user |
| POST | `/v1/auth/forgot-password` | none | Issue a single-use reset token and email it |
| POST | `/v1/auth/reset-password` | reset token | Set a new password and revoke all sessions |
| POST | `/v1/auth/verify-email` | verify token | Mark the email address verified |
| GET | `/v1/me` | access | Return the current profile |
| PATCH | `/v1/me` | access | Update profile fields |
| POST | `/v1/me/change-password` | access | Requires the current password; revokes other sessions |
| GET | `/healthz` | none | Liveness — never touches a dependency |
| GET | `/readyz` | none | Readiness — pings Postgres (and Redis when enabled) |

Full request and response shapes live in [`docs/API.md`](docs/API.md).

---

## `curl` walkthrough

Every call below works against a fresh `make run`. The cookie jar keeps the
session so the CSRF flow behaves exactly as a browser would.

```bash
BASE=http://localhost:8080
JAR=$(mktemp)
```

**1. Register.** The response is identical whether or not the address already
exists, and never logs you in.

```bash
curl -sS -X POST $BASE/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"an-adequately-long-passphrase","name":"Ada Lovelace"}' | jq
# {"status":"accepted","message":"If the address can receive mail, a verification link is on its way."}
```

**2. Verify the email.** Open <http://localhost:8025>, copy the `token` query
parameter out of the link in the message, then:

```bash
curl -sS -X POST $BASE/v1/auth/verify-email \
  -H 'Content-Type: application/json' \
  -d '{"token":"PASTE_VERIFICATION_TOKEN"}' | jq
```

**3. Log in.** Cookies are stored in `$JAR`; the body also carries the tokens
for non-browser clients.

```bash
curl -sS -c $JAR -b $JAR -X POST $BASE/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com","password":"an-adequately-long-passphrase"}' | jq
```

Pull the values you need out of the cookie jar:

```bash
CSRF=$(awk '$6=="csrf_token" {print $7}' $JAR)
ACCESS=$(awk '$6=="access_token" {print $7}' $JAR)
```

**4. Read and update the profile.** `GET` needs no CSRF token; `PATCH` does,
because it is a state-changing cookie-authenticated request.

```bash
curl -sS -c $JAR -b $JAR $BASE/v1/me | jq

curl -sS -c $JAR -b $JAR -X PATCH $BASE/v1/me \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"name":"Ada King"}' | jq
```

The same call as a non-browser client — bearer token, no CSRF token needed:

```bash
curl -sS $BASE/v1/me -H "Authorization: Bearer $ACCESS" | jq
```

**5. Rotate the session.** The old refresh token is burnt; presenting it again
revokes the whole family.

```bash
curl -sS -c $JAR -b $JAR -X POST $BASE/v1/auth/refresh \
  -H "X-CSRF-Token: $CSRF" | jq
CSRF=$(awk '$6=="csrf_token" {print $7}' $JAR)
```

**6. Change the password.** Every other session is revoked and a fresh one is
returned.

```bash
curl -sS -c $JAR -b $JAR -X POST $BASE/v1/me/change-password \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" \
  -d '{"current_password":"an-adequately-long-passphrase","new_password":"another-entirely-different-phrase"}' | jq
CSRF=$(awk '$6=="csrf_token" {print $7}' $JAR)
```

**7. Forgot and reset password.** The response never reveals whether the
account exists.

```bash
curl -sS -X POST $BASE/v1/auth/forgot-password \
  -H 'Content-Type: application/json' \
  -d '{"email":"ada@example.com"}' | jq

# Copy the token from the MailHog message, then:
curl -sS -X POST $BASE/v1/auth/reset-password \
  -H 'Content-Type: application/json' \
  -d '{"token":"PASTE_RESET_TOKEN","new_password":"a-third-completely-new-phrase"}' | jq
```

**8. Log out.** `logout` kills the current session; `logout-all` kills every
session on every device.

```bash
curl -sS -c $JAR -b $JAR -X POST $BASE/v1/auth/logout \
  -H "X-CSRF-Token: $CSRF" -i | head -1
# HTTP/1.1 204 No Content

curl -sS -X POST $BASE/v1/auth/logout-all \
  -H "Authorization: Bearer $ACCESS" -i | head -1
```

**9. See the guard rails.** Rate limiting, CSRF, and the body cap all return
the same JSON envelope.

```bash
for i in $(seq 1 6); do
  curl -sS -o /dev/null -w '%{http_code} ' -X POST $BASE/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"email":"nobody@example.com","password":"some-long-enough-password"}'
done; echo
# 401 401 401 401 401 429

curl -sS -D- -o /dev/null -X POST $BASE/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"nobody@example.com","password":"some-long-enough-password"}' \
  | grep -Ei 'retry-after|x-ratelimit'
```

---

## Configuration

Every setting is read from the environment, validated at boot, and the process
refuses to start if anything is missing or malformed. `.env.example` is the
canonical list.

### Application

| Variable | Default | Notes |
|---|---|---|
| `APP_ENV` | `development` | `development`, `production`, or `test` |
| `APP_BASE_URL` | `http://localhost:8080` | Base for verification and reset links |
| `HTTP_ADDR` | `:8080` | Listen address |

### Logging

| Variable | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `text` in dev, `json` in prod | Handler selection |
| `LOG_ADD_SOURCE` | `false` | Include file and line |

### Database — **required**

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | — | **Required.** Postgres DSN |
| `DB_MAX_OPEN_CONNS` | `25` | |
| `DB_MAX_IDLE_CONNS` | `25` | |
| `DB_CONN_MAX_LIFETIME` | `30m` | |
| `DB_CONN_MAX_IDLE_TIME` | `5m` | |
| `DB_QUERY_TIMEOUT` | `5s` | Per-query context deadline |

### Redis — optional

| Variable | Default | Notes |
|---|---|---|
| `REDIS_URL` | empty | When empty the in-process limiter is used. When set, Redis becomes the primary limiter and the in-process limiter is the automatic fallback. |

> Credentials in `docker-compose.yml` and `.env.example` are development
> placeholders. Never deploy with them.

### Tokens

| Variable | Default | Notes |
|---|---|---|
| `JWT_SECRET` | — | **Required, ≥ 32 bytes.** The process will not start otherwise. |
| `JWT_ISSUER` | `golang-api-boilerplate` | `iss` claim, validated on every request |
| `JWT_AUDIENCE` | `golang-api-boilerplate-clients` | `aud` claim, validated on every request |
| `ACCESS_TOKEN_TTL` | `15m` | Must be shorter than the refresh TTL |
| `JWT_CLOCK_SKEW` | `30s` | Tolerance applied to `exp`, `nbf`, and `iat` |
| `REFRESH_TOKEN_TTL` | `720h` | 30 days |
| `RESET_TOKEN_TTL` | `15m` | Single use |
| `VERIFY_TOKEN_TTL` | `24h` | Single use |
| `REQUIRE_VERIFIED_EMAIL` | `false` | Block login until the address is verified |

### Cookies

| Variable | Default | Notes |
|---|---|---|
| `COOKIE_SECURE` | `false` in dev, `true` in prod | Boot fails if false in production |
| `COOKIE_DOMAIN` | empty | Host-only cookies when empty |
| `COOKIE_REFRESH_PATH` | `/v1/auth` | Must cover both `/v1/auth/refresh` and `/v1/auth/logout` |
| `COOKIE_ACCESS_NAME` | `access_token` | |
| `COOKIE_REFRESH_NAME` | `refresh_token` | |
| `COOKIE_CSRF_NAME` | `csrf_token` | Readable by JavaScript by design |

### CORS

| Variable | Default | Notes |
|---|---|---|
| `CORS_ALLOWED_ORIGINS` | empty | **Required in production.** Disallowed origins are rejected, never echoed. |
| `CORS_ALLOWED_METHODS` | `GET,POST,PATCH,DELETE,OPTIONS` | |
| `CORS_ALLOWED_HEADERS` | `Content-Type,Authorization,X-CSRF-Token,X-Request-ID` | |
| `CORS_EXPOSED_HEADERS` | request-id and rate-limit headers | |
| `CORS_ALLOW_CREDENTIALS` | `true` | Cannot be combined with `*` |
| `CORS_MAX_AGE` | `10m` | Preflight cache |

### Reverse proxies

| Variable | Default | Notes |
|---|---|---|
| `TRUSTED_PROXY_CIDRS` | empty | See the warning below |

> **Read this before deploying behind a load balancer.**
> `X-Forwarded-For` and `X-Real-IP` are honoured **only** when the immediate
> peer (`RemoteAddr`) falls inside one of these CIDRs. Leave the variable empty
> when the API is exposed directly — an empty list means proxy headers are
> ignored entirely and `RemoteAddr` is authoritative.
>
> Set it to the CIDR of *your* load balancer and nothing else. If you list a
> range you do not control — or worse, `0.0.0.0/0` — any client can forge
> `X-Forwarded-For` and give itself a fresh rate-limit bucket on every request,
> which makes login brute-force protection and account lockout trivially
> bypassable. When the header is trusted, the resolver walks the chain from
> right to left and takes the first hop that is *not* in your trusted set.

### HTTP server hardening

| Variable | Default | Notes |
|---|---|---|
| `HTTP_READ_HEADER_TIMEOUT` | `5s` | Slowloris guard |
| `HTTP_READ_TIMEOUT` | `15s` | |
| `HTTP_WRITE_TIMEOUT` | `20s` | |
| `HTTP_IDLE_TIMEOUT` | `60s` | |
| `HTTP_MAX_HEADER_BYTES` | `1048576` | 1 MiB |
| `HTTP_MAX_BODY_BYTES` | `1048576` | 1 MiB; oversize bodies get `413` |
| `HTTP_HANDLER_TIMEOUT` | `15s` | Per-request context deadline |
| `HTTP_SHUTDOWN_TIMEOUT` | `20s` | Graceful drain window |

### Account lockout

| Variable | Default | Notes |
|---|---|---|
| `LOCKOUT_THRESHOLD` | `10` | Consecutive failures before the first lock |
| `LOCKOUT_BASE_WINDOW` | `15m` | First lock duration |
| `LOCKOUT_MAX_WINDOW` | `24h` | Ceiling for exponential backoff |
| `LOCKOUT_BACKOFF_STEP` | `5` | Failures per doubling |

### Mail

| Variable | Default | Notes |
|---|---|---|
| `MAILER_DRIVER` | `log` | `log`, `smtp`, or `noop` |
| `MAIL_FROM` | `no-reply@example.com` | |
| `MAIL_SEND_TIMEOUT` | `10s` | |
| `SMTP_HOST` | empty | Required when the driver is `smtp` |
| `SMTP_PORT` | `1025` | |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | empty | PLAIN auth when a username is set |
| `SMTP_TLS` | `false` | Requires the server to advertise STARTTLS |

Delivery is always queued onto a worker goroutine — a slow or dead mail server
can never stall a request.

---

## Rate limits

| Route | Rule |
|---|---|
| `POST /v1/auth/login` | 5 per 15 min per IP **and** 5 per 15 min per email |
| `POST /v1/auth/register` | 5 per hour per IP |
| `POST /v1/auth/forgot-password` | 3 per hour per IP **and** 3 per hour per email |
| `POST /v1/auth/refresh` | 30 per hour per IP |
| `POST /v1/auth/reset-password` | 10 per hour per IP |
| `POST /v1/auth/verify-email` | 10 per hour per IP |
| `POST /v1/me/change-password` | 5 per hour per user |
| everything else | 100 per minute per IP |

Rejections return `429` with `Retry-After`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, and `X-RateLimit-Reset`. Health endpoints are exempt
from the global fallback so probes never trip it.

---

## Error envelope

Every failure — including `404` and `405` from the router — comes back in the
same shape:

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Email or password is incorrect.",
    "request_id": "0b0f6ad1-3d2f-4e33-9d4f-1f0f0a2b0c3d",
    "details": [{ "field": "email", "issue": "must be a valid email address" }]
  }
}
```

`details` appears only on `4xx` validation failures. `5xx` responses never carry
`details` and never leak an internal error string. The `code` set is closed and
documented in [`docs/API.md`](docs/API.md).

---

## Project layout

```
cmd/api/main.go        composition root: config → deps → server → shutdown
internal/
  config/              env parsing, validation, fail-fast
  server/              http.Server setup, routes, graceful shutdown, wiring
  middleware/          requestid, clientip, accesslog, recover, cors,
                       secheaders, ratelimit, maxbytes, csrf, auth, timeout
  handler/             HTTP only — decode, delegate, encode
  service/             auth workflows and the token-cleanup job
  repository/          interfaces + the Postgres implementation
  domain/              entities and domain errors; imports nothing internal
  security/            argon2id, JWT, opaque tokens, CSRF, constant-time helpers
  ratelimit/           Limiter interface, memory + Redis + failover, rules
  logging/             slog setup, redaction, context helpers, event names
  validation/          request validators and the password policy
  mailer/              interface, SMTP, log/noop, templates, async dispatcher
  httpx/               JSON encode/decode, error envelope, context accessors
migrations/            numbered .sql pairs for golang-migrate
docs/                  ARCHITECTURE.md, SECURITY.md, API.md
```

Dependencies point strictly inward: `handler → service → repository → domain`.
Nothing is global or mutable at package scope — every dependency is passed to a
constructor.

---

## Dependencies

Third-party modules are deliberately few:

| Module | Why |
|---|---|
| `github.com/jackc/pgx/v5` | Postgres driver, used through `database/sql` |
| `github.com/golang-jwt/jwt/v5` | Access-token signing and validation |
| `github.com/google/uuid` | Request IDs and token-family identifiers |
| `golang.org/x/crypto` | Argon2id |
| `golang.org/x/time` | Token-bucket rate limiter |
| `github.com/redis/go-redis/v9` | Optional distributed limiter |
| `github.com/stretchr/testify` | Test assertions (test-only) |
| `github.com/testcontainers/testcontainers-go` | Real Postgres in integration tests (test-only) |

Routing, logging, validation, migrations at runtime, and the ORM layer are all
absent on purpose.

---

## Testing

```bash
make test              # unit + handler tests, no containers required
make test-integration  # adds testcontainers-backed Postgres tests
```

Handler tests drive the real router through `httptest.NewServer` against an
in-memory repository, so the whole request path — middleware chain, cookies,
CSRF, rate limiting, error envelopes — is exercised without a database.
Integration tests run the Postgres repository against a real PostgreSQL 16
container and are skipped automatically under `-short` or when no container
runtime is available.

Time is injected everywhere it matters. No test sleeps to observe an expiry.

---

## Further reading

- [`docs/GUIDE.md`](docs/GUIDE.md) — step-by-step walkthrough for adding a feature or module
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — layering, request lifecycle, extension points
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, every control, and what is explicitly out of scope
- [`docs/API.md`](docs/API.md) — request/response reference and the full error-code table
