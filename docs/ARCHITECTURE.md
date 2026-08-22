# Architecture

## Shape of the thing

Four layers, dependencies pointing strictly inward:

```
cmd/api  ─┐
          ▼
      server (wiring, routes, middleware chain)
          ▼
      handler  ── HTTP only: decode, validate shape, delegate, encode
          ▼
      service  ── workflows: register, login, rotate, reset, change
          ▼
    repository ── interfaces here, SQL in repository/postgres
          ▼
      domain   ── entities and errors; imports nothing else in this module
```

Cross-cutting packages (`httpx`, `logging`, `security`, `validation`,
`ratelimit`, `mailer`, `config`) are leaves that any layer may import. They hold
no state of their own beyond what a constructor is given.

There is no global mutable state anywhere: no package-level `*sql.DB`, no
package-level logger, no `init()` with side effects. `cmd/api/main.go` loads
configuration, builds a logger, calls `server.Build`, and waits for a signal.

## Request lifecycle

Global middleware wraps the mux, outermost first:

1. **RequestID** — accept an inbound `X-Request-ID` if it parses as a UUID,
   otherwise mint one. Echo it, and seed the context logger with it.
2. **ClientIP** — resolve the client address, honouring `X-Forwarded-For` only
   when the peer is inside `TRUSTED_PROXY_CIDRS`.
3. **AccessLog** — wrap the writer to capture status and byte count, install the
   route and identity capture slots, and emit one line when the handler returns.
4. **Recover** — catch panics, log the stack at `ERROR` with the request ID, and
   return a generic `500`.
5. **JSONRoutingErrors** — rewrite the mux's plain-text `404`/`405` into the
   JSON error envelope.
6. **SecurityHeaders** — CSP, frame options, referrer policy, COOP/CORP/COEP,
   permissions policy, and HSTS when TLS is in play.
7. **CORS** — strict allowlist; a disallowed origin is rejected outright rather
   than echoed back.
8. **RateLimit (global)** — 100/min per IP, skipped for `/healthz` and `/readyz`.
9. **MaxBytes** — cap the body and record the limit in the context.
10. **Timeout** — attach a per-request context deadline.

Per-route middleware is attached at registration in `internal/server/routes.go`:
the route-specific rate limit, then CSRF, then authentication. Because the
pattern is known at registration time, the access log records the *route
template* (`POST /v1/auth/login`) rather than the raw path — no unbounded
cardinality and no user IDs leaking into log indexes.

### Propagating values back up the chain

`http.Request.WithContext` produces a new request, so a value stored by an inner
middleware is invisible to an outer one. The access log needs two such values —
the matched route and the authenticated user — so `httpx` installs small pointer
holders in the context (`WithRouteCapture`, `WithIdentityCapture`) which inner
layers fill in via `SetRoute` and `SetUserID`. Everything else uses ordinary
immutable context values.

## Sessions

An access token is a short-lived HS256 JWT. A refresh token is 32 bytes from
`crypto/rand`, stored only as its SHA-256 digest, and belongs to a **family**
identified by a UUID minted at login.

Rotation is a single conditional `UPDATE`:

```sql
UPDATE refresh_tokens SET used_at = $2
WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
RETURNING ...
```

That statement is the concurrency control. Two simultaneous refreshes with the
same token cannot both win: exactly one updates a row, the other gets no rows
back. The service then looks the token up; if it exists and is already `used_at`,
that is a replay, so the entire family is revoked and
`auth.refresh_reuse_detected` is logged at `WARN`. No explicit transaction is
needed, which keeps the repository interface small and the failure modes obvious.

The same conditional-update pattern retires password-reset and email-verification
tokens, giving single-use semantics for free.

## Rate limiting

`ratelimit.Limiter` is one method:

```go
Allow(ctx context.Context, key string, rule Rule) (Decision, error)
```

Three implementations satisfy it:

- **Memory** — `golang.org/x/time/rate` buckets sharded across 32 maps keyed by a
  `maphash` of `rule|key`, so there is no single mutex hotspot. A janitor
  goroutine evicts buckets idle beyond `IdleTTL`, which bounds memory under a
  spray of unique keys. The clock is injectable, so tests observe refill without
  sleeping.
- **Redis** — an `INCR` + `PEXPIRE` fixed window in a Lua script, one round trip.
- **Failover** — Redis primary, memory fallback. The first error logs a warning
  and flips a flag; recovery logs once too. A Redis outage degrades the limiter
  from cluster-wide to per-instance instead of taking the API down.

IP-keyed rules run as middleware. Email- and user-keyed rules run inside the
handler, because the key is in the request body and must be validated first.

## Errors

`httpx.APIError` carries an HTTP status, a stable machine-readable code, a
human-readable message, optional field details, and an optional wrapped cause.
The cause is logged; it never reaches the client. Sentinel values in
`internal/httpx/errors.go` are the closed vocabulary, and `WithCause` /
`WithDetails` clone rather than mutate them, so a handler cannot corrupt the
shared sentinel.

The service layer speaks its own sentinel errors (`service.ErrInvalidToken`,
`service.ErrAccountLocked`, …). `internal/handler/errors.go` is the single
translation point to HTTP. Anything unrecognised becomes a `500` with no detail.

## Logging

One `*slog.Logger` is built at boot and injected. Its `ReplaceAttr` hook redacts
a fixed set of sensitive keys anywhere in the attribute tree, which means an
accidental `slog.String("password", …)` cannot leak even in new code.

`logging.FromContext(ctx)` returns the request-scoped logger, pre-loaded with
`request_id` and — once authentication resolves — `user_id`. Outside a request
it returns a discarding logger, so library code can log unconditionally without
a nil check.

Security events use `logging.Security`, which stamps a stable `event` attribute
and logs at `WARN`: `auth.login_failed`, `auth.account_locked`,
`auth.refresh_reuse_detected`, `auth.password_reset_requested`,
`auth.password_reset_completed`, `ratelimit.exceeded`, `csrf.failed`.

## Mail

`mailer.Mailer` is an interface with SMTP, log, and no-op implementations.
`mailer.NewAsync` wraps any of them with a bounded queue and worker pool, so a
handler's `Send` is a channel write. If the queue is full the message is dropped
with a warning rather than blocking the request; a delivery panic is recovered
inside the worker. Bodies are rendered from `text/template` and `html/template`
pairs, so a name containing markup cannot inject HTML into an email.

## Testing strategy

- **Unit tests** cover Argon2id, JWT validation (including `alg: none`, wrong
  algorithm family, tampered payload and signature), CSRF comparison, the
  password policy, redaction, config validation, and limiter behaviour over an
  injected clock.
- **Handler tests** run the real middleware chain and router through
  `httptest.NewServer` against an in-memory repository. They cover the full
  lifecycle and the explicit security regressions listed in
  [`SECURITY.md`](SECURITY.md).
- **Integration tests** exercise the Postgres repository against a real
  PostgreSQL 16 container, including the unique constraints, the `citext`
  case-insensitive email index, `ON DELETE CASCADE`, and the conditional-update
  rotation semantics. They skip under `-short` and when no container runtime is
  available.

Every clock the application reads is injectable through `server.BuildOptions`,
so expiry is tested by advancing time, never by sleeping.

## Extending it

[`GUIDE.md`](GUIDE.md) walks through a complete vertical feature file by file.
The short version:

**A new endpoint.** Add the handler method, register it in
`internal/server/routes.go` with the middleware it needs, and put the business
logic in a service. Handlers stay free of business rules.

**A different database.** Implement `repository.Store` and its four interfaces.
Nothing above the repository layer knows about SQL.

**A new rate-limit rule.** Add it to `ratelimit.Rules`, then apply it as
middleware (IP-keyed) or via `Auth.enforce` (body- or user-keyed).

**Custom claims.** Extend `security.AccessClaims`. Validation is centralised in
`TokenIssuer.Verify`, including algorithm pinning.

**Background work.** `service.Cleanup` is the model: a struct with a `Run(ctx)`
loop started from `main`, cancelled by the same signal context that stops the
server.
