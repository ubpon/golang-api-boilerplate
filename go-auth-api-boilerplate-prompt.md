# Build Prompt — Production-Grade Go Auth API Boilerplate (stdlib `net/http`)

> Paste everything below the line into Claude Code (or your agent of choice) as the initial task.
> Adjust the **Tunable Decisions** block first if you want different defaults.

---

## Role

You are a senior Go engineer building a production-grade, security-hardened REST API boilerplate. You write idiomatic, dependency-light Go. You do not scaffold placeholder code — every file you produce compiles, is tested, and is ready to run.

## Objective

Build a complete Go 1.23+ HTTP API boilerplate providing authentication and account endpoints, using **only the standard library `net/http`** for routing and serving. The result must be a repository a team can clone and extend for a real product on day one.

## Tunable Decisions (change these before starting if needed)

| Decision | Default | Notes |
|---|---|---|
| Module path | `github.com/ubpon/golang-api-boilerplate` | Initialize with `go mod init github.com/ubpon/golang-api-boilerplate`; all internal imports use this prefix |
| Database | PostgreSQL 16 via `pgx/v5` (stdlib `database/sql` interface) | Swap driver only; keep repository interfaces intact |
| Access token | JWT (HS256), 15 min TTL | Signed with a 32-byte secret from env |
| Refresh token | Opaque 32-byte random, SHA-256 hashed at rest, 30 day TTL, rotated on every use | Stored in `refresh_tokens` table |
| Token transport | `HttpOnly; Secure; SameSite=Strict` cookies + CSRF double-submit token | Also support `Authorization: Bearer` for non-browser clients |
| Password hashing | Argon2id (`golang.org/x/crypto/argon2`) | 64 MiB memory, 3 iterations, parallelism 2, 16-byte salt, 32-byte key |
| Rate limiting | In-process sharded token bucket (`golang.org/x/time/rate`) with a Redis-backed implementation behind the same interface | Redis optional via env; must degrade cleanly |
| Email delivery | `Mailer` interface with an SMTP impl and a logging no-op impl for dev | Never block the request on send |
| Migrations | Plain numbered `.sql` files + `golang-migrate` CLI | No ORM, no auto-migrate at boot |

## Hard Constraints

1. **Routing is `net/http` only.** Use Go 1.22+ `http.ServeMux` method+wildcard patterns (`mux.HandleFunc("POST /v1/auth/login", h.Login)`). No chi, gin, echo, fiber, gorilla/mux.
2. **No ORM.** Hand-written SQL with `database/sql`, prepared/parameterized statements only. String-concatenated SQL is an automatic failure.
3. **Structured logging is `log/slog` only.** No logrus, zap, zerolog. A single configured `*slog.Logger` is injected through the app; handlers pull a request-scoped logger from `context`.
4. **Dependency budget.** Permitted third-party modules and nothing else without justification in the README:
   - `github.com/jackc/pgx/v5`
   - `github.com/golang-jwt/jwt/v5`
   - `github.com/google/uuid`
   - `golang.org/x/crypto`
   - `golang.org/x/time`
   - `github.com/redis/go-redis/v9` (optional path only)
   - test-only: `github.com/stretchr/testify`, `github.com/testcontainers/testcontainers-go`
5. **No global mutable state.** No `init()` side effects, no package-level DB handles or loggers. Everything is constructor-injected.
6. **Every error path returns a typed JSON envelope.** No leaked internals, no raw `err.Error()` to clients.

## Endpoints

All under `/v1`. JSON in, JSON out.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/auth/register` | none | Create account, send verification email, do **not** auto-login |
| POST | `/v1/auth/login` | none | Issue access + refresh tokens |
| POST | `/v1/auth/refresh` | refresh cookie | Rotate refresh token, issue new access token |
| POST | `/v1/auth/logout` | access | Revoke current refresh token, clear cookies |
| POST | `/v1/auth/logout-all` | access | Revoke every refresh token for the user |
| POST | `/v1/auth/forgot-password` | none | Issue single-use reset token, email it |
| POST | `/v1/auth/reset-password` | reset token | Set new password, revoke all sessions |
| POST | `/v1/auth/verify-email` | verify token | Mark email verified |
| GET | `/v1/me` | access | Return current user profile |
| PATCH | `/v1/me` | access | Update name / profile fields |
| POST | `/v1/me/change-password` | access | Requires current password; revokes other sessions |
| GET | `/healthz` | none | Liveness — no dependency checks |
| GET | `/readyz` | none | Readiness — pings DB (and Redis if enabled) |

## Security Requirements

Treat this section as the acceptance bar. Each item must be demonstrably implemented.

### Authentication & tokens
- Access token JWT claims: `sub`, `iat`, `exp`, `nbf`, `jti`, `iss`, `aud`, `typ: "access"`. Validate **all** of them on every request, including algorithm pinning (reject `alg: none` and any algorithm other than the configured one).
- Refresh tokens are opaque random bytes from `crypto/rand`, never JWTs. Store only `sha256(token)`. Compare with `subtle.ConstantTimeCompare`.
- **Refresh rotation with reuse detection**: on refresh, mark the old token used and issue a new one. If an already-used token is presented, revoke the entire token family for that user and log a `WARN` security event.
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path` scoped (`/v1/auth/refresh` for the refresh cookie), explicit `MaxAge`. Cleared properly on logout.
- CSRF: double-submit cookie pattern for all state-changing cookie-authenticated requests. Non-readable CSRF cookie + `X-CSRF-Token` header, compared in constant time.

### Passwords & reset flow
- Argon2id with the parameters above; the encoded hash string embeds the params so they can be upgraded later. Include a `needsRehash` check on successful login.
- Enforce a password policy: minimum 12 characters, maximum 128 (to bound hashing cost), reject a bundled list of the most common passwords, reject passwords containing the user's email local-part. No forced composition rules.
- **No user enumeration anywhere.** `register`, `login`, and `forgot-password` return identical responses and take comparable time whether or not the account exists. On login against a missing user, still run an Argon2id verify against a dummy hash.
- Reset tokens: 32 random bytes, SHA-256 hashed at rest, 15-minute TTL, single use, invalidated on use and on password change. Issuing a new one invalidates prior outstanding tokens.
- Password change or reset revokes all refresh tokens except (optionally) the current session.

### Rate limiting
Define a `Limiter` interface with `Allow(ctx, key string, rule Rule) (Decision, error)` and provide both in-memory and Redis implementations.
- Per-route rules, at minimum:
  - `POST /v1/auth/login` — 5 per 15 min per IP **and** 5 per 15 min per email, whichever trips first
  - `POST /v1/auth/forgot-password` — 3 per hour per IP and per email
  - `POST /v1/auth/register` — 5 per hour per IP
  - `POST /v1/auth/refresh` — 30 per hour per IP
  - global fallback — 100 per minute per IP
- Return `429` with `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
- The in-memory limiter must be sharded by key hash to avoid a single mutex hotspot, and must evict idle buckets on a janitor goroutine so it cannot grow unbounded.
- Client IP resolution must be **trust-aware**: only honour `X-Forwarded-For` / `X-Real-IP` when the immediate peer is in a configured trusted-proxy CIDR list. Otherwise use `RemoteAddr`. Document this in the README — getting it wrong makes the limiter trivially bypassable.
- Independently, add progressive account lockout: after 10 consecutive failed logins, lock the account for 15 minutes with exponential backoff on repeat offences. Reset the counter on success.

### Transport & server hardening
- `http.Server` with `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 20s`, `IdleTimeout: 60s`, `MaxHeaderBytes: 1 << 20`.
- `http.MaxBytesReader` capping request bodies at 1 MiB by default (configurable per route).
- JSON decoding with `DisallowUnknownFields()` and a check that the body contains exactly one JSON value.
- Graceful shutdown on `SIGINT`/`SIGTERM` with a configurable drain timeout; in-flight requests finish, new ones are refused.
- Security headers middleware: `Strict-Transport-Security` (when TLS), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Permissions-Policy`.
- CORS: strict origin allowlist from config, no wildcard when credentials are allowed, explicit method/header allowlists, preflight caching. Reject disallowed origins rather than echoing them.
- Panic recovery middleware that logs the stack at `ERROR` with the request ID and returns a generic `500`.

### Data & operational security
- All queries parameterized. Use `context` with timeouts on every DB call.
- Store emails normalized (lowercased, trimmed) with a unique index; keep the original display form separately if needed.
- Secrets come from environment only. Provide `.env.example`; commit no real secrets. The app must fail fast at boot if a required secret is missing or too short (e.g. JWT secret < 32 bytes).
- `govulncheck` and `gosec` run clean in CI.

## Logging Requirements (`log/slog`)

- Configure at boot: `slog.NewJSONHandler` in production, `slog.NewTextHandler` in development, level from `LOG_LEVEL`.
- A `ReplaceAttr` hook that **redacts** sensitive keys anywhere in the tree: `password`, `new_password`, `current_password`, `token`, `refresh_token`, `access_token`, `authorization`, `cookie`, `set-cookie`, `csrf`, `secret`. Values become `[REDACTED]`.
- Request ID middleware: accept an inbound `X-Request-ID` if it is a well-formed UUID, otherwise generate one. Echo it in the response header and attach it to the context logger.
- A context-scoped logger helper (`logging.FromContext(ctx)`) returning a logger pre-loaded with `request_id`, and `user_id` once authentication resolves.
- Access log middleware emitting one line per request at `INFO` (or `WARN` for 4xx, `ERROR` for 5xx): method, path template (not the raw path — avoid unbounded cardinality and leaked IDs), status, duration_ms, bytes, client IP, user agent, request_id, user_id.
- Dedicated security events at `WARN` with a stable `event` attribute: `auth.login_failed`, `auth.account_locked`, `auth.refresh_reuse_detected`, `auth.password_reset_requested`, `auth.password_reset_completed`, `ratelimit.exceeded`, `csrf.failed`.
- **Never log** credentials, raw tokens, reset links, full cookie headers, or full request bodies.

## Project Layout

```
.
├── cmd/api/main.go              # composition root only: config → deps → server → shutdown
├── internal/
│   ├── config/                  # env parsing, validation, fail-fast
│   ├── server/                  # http.Server setup, routes.go, graceful shutdown
│   ├── middleware/              # requestid, logger, recover, cors, secheaders, ratelimit, auth, csrf, maxbytes
│   ├── handler/                 # auth.go, me.go, health.go — HTTP only, no business logic
│   ├── service/                 # auth service: register/login/refresh/reset/etc.
│   ├── repository/              # interfaces + postgres implementations
│   ├── domain/                  # entities, domain errors, no external imports
│   ├── security/                # argon2, tokens (jwt + opaque), csrf, constant-time helpers
│   ├── ratelimit/               # Limiter interface, memory + redis impls, rules
│   ├── logging/                 # slog setup, redaction, context helpers
│   ├── validation/              # request validators, password policy
│   ├── mailer/                  # interface, smtp, noop/log impls, templates
│   └── httpx/                   # JSON encode/decode, error envelope, response helpers
├── migrations/                  # 0001_users.up.sql / .down.sql, etc.
├── docs/                        # ARCHITECTURE.md, SECURITY.md, API.md
├── docker-compose.yml           # postgres, redis, mailhog
├── Dockerfile                   # multi-stage, distroless/scratch, non-root, static build
├── Makefile
├── .env.example
├── .golangci.yml
└── README.md
```

Internal packages are imported by their full module path, e.g. `github.com/ubpon/golang-api-boilerplate/internal/security`.

Dependency direction is strictly inward: `handler → service → repository → domain`. `domain` imports nothing from the project.

## Database Schema

Write migrations for:
- `users` — `id uuid pk`, `email citext unique not null`, `password_hash text not null`, `name text`, `email_verified_at timestamptz`, `failed_login_attempts int not null default 0`, `locked_until timestamptz`, `created_at`, `updated_at`
- `refresh_tokens` — `id uuid pk`, `user_id fk on delete cascade`, `token_hash bytea unique not null`, `family_id uuid not null`, `expires_at`, `used_at`, `revoked_at`, `user_agent`, `ip inet`, `created_at`; index on `user_id`, `family_id`, `expires_at`
- `password_reset_tokens` — `id uuid pk`, `user_id fk`, `token_hash bytea unique not null`, `expires_at`, `used_at`, `created_at`
- `email_verification_tokens` — same shape as above

Include a cleanup query/job for expired tokens.

## Error Envelope

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Email or password is incorrect.",
    "request_id": "0b0f...",
    "details": [{ "field": "email", "issue": "must be a valid email address" }]
  }
}
```

Codes are a closed, documented set. Validation failures return `422` with `details`; auth failures return `401`; authorization failures `403`; rate limits `429`; unexpected failures `500` with no `details`.

## Testing Requirements

- Unit tests for: Argon2id hash/verify + rehash detection, JWT sign/verify including tampered and wrong-alg tokens, CSRF comparison, password policy, rate limiter behaviour over time (inject a clock — do not `time.Sleep`), redaction of every sensitive key.
- Handler tests with `httptest.NewServer` covering the full flow: register → verify → login → `/me` → refresh → change password → logout → refresh-with-revoked-token fails.
- Explicit security regression tests:
  - login returns identical body and status for unknown vs. known email
  - reused refresh token revokes the family
  - expired reset token is rejected
  - reset token cannot be used twice
  - request exceeding the body limit returns `413`
  - state-changing cookie request without a CSRF token returns `403`
  - rate limit trips at the configured threshold and emits `Retry-After`
- Integration tests against real Postgres via testcontainers, skipped with `-short`.
- Everything passes `go test -race ./...`.

## Deliverables

1. The complete repository as described, compiling with `go build ./...` and passing `go vet ./...` and `go test -race ./...`.
2. `Makefile` with: `run`, `build`, `test`, `test-integration`, `lint`, `sec` (gosec + govulncheck), `migrate-up`, `migrate-down`, `migrate-create`, `docker-up`, `docker-down`.
3. `README.md` with quickstart (clone → `docker compose up` → `make migrate-up` → `make run`), the full env var table, and a `curl` walkthrough of every endpoint.
4. `docs/SECURITY.md` documenting the threat model, every control implemented, the trusted-proxy configuration warning, and an explicit list of what is **out of scope** (WAF, MFA/TOTP, OAuth providers, audit log retention, secrets manager integration) with notes on where each would hook in.
5. `.golangci.yml` enabling at minimum `errcheck`, `gosec`, `govet`, `staticcheck`, `bodyclose`, `contextcheck`, `noctx`, `sqlclosecheck`, `revive`.
6. A GitHub Actions workflow running lint, vet, race tests, gosec, and govulncheck.

## Execution Plan

Work in these phases. After each phase, state what you built, run the build and tests, and confirm they pass before continuing. Do not skip ahead.

1. **Skeleton** — run `go mod init github.com/ubpon/golang-api-boilerplate`, then layout, config with fail-fast validation, slog setup with redaction, `httpx` helpers, health endpoints, graceful shutdown. Verify: server boots, `/healthz` responds, logs are JSON and redacted.
2. **Persistence** — migrations, domain entities and errors, repository interfaces and Postgres implementations, testcontainers harness.
3. **Security primitives** — Argon2id, JWT access tokens, opaque refresh tokens, CSRF, constant-time helpers, password policy. Unit tests here before any handler exists.
4. **Middleware chain** — request ID, access log, recover, security headers, CORS, max-bytes, trust-aware client IP, rate limiter (memory impl + interface).
5. **Auth handlers & service** — register, login, refresh with rotation and reuse detection, logout, logout-all, verify-email.
6. **Password flows** — forgot-password, reset-password, change-password, mailer interface with SMTP and log impls, session revocation on change.
7. **`/me` endpoints** — auth middleware, profile read and update.
8. **Redis limiter + hardening pass** — Redis `Limiter` impl, account lockout, security event logging, full security regression test suite.
9. **Docs & CI** — README, SECURITY.md, API.md, Dockerfile, compose, golangci config, Actions workflow. Final full test and scan run.

## Do Not

- Do not introduce a router library, ORM, or logging library outside the dependency budget.
- Do not write `TODO`, `FIXME`, or stubbed handlers that return `501`.
- Do not auto-run migrations at application startup.
- Do not return different responses or timings for existing vs. non-existing accounts.
- Do not log secrets, tokens, or reset links, even at `DEBUG`.
- Do not trust proxy headers unconditionally.
- Do not store refresh, reset, or verification tokens in plaintext.
- Do not silently swallow errors — every ignored error needs an explicit comment justifying it.

## Definition of Done

`git clone` → `docker compose up -d` → `make migrate-up` → `make run` → the README's `curl` walkthrough completes end to end on a clean machine, and `make test lint sec` is green.
