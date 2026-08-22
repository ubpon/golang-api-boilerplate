Changes I strongly recommend
1. Fix the pgx / database/sql ambiguity

This is probably the biggest technical issue.

You say:

PostgreSQL 16 via pgx/v5 (stdlib database/sql interface)

and later:

hand-written SQL with database/sql

But pgx/v5 has several ways to interact with PostgreSQL. You should explicitly mandate one.

I'd change the database decision to something like:

PostgreSQL 16 using database/sql with github.com/jackc/pgx/v5/stdlib as the driver. Do not use pgx.Conn, pgxpool, or pgx-native APIs in application/repository code.

That makes your repository abstraction and testing expectations unambiguous.

Also specify:

sql.DB lifecycle
SetMaxOpenConns
SetMaxIdleConns
SetConnMaxLifetime
SetConnMaxIdleTime

Otherwise the agent may create a technically correct but poorly tuned DB layer.

2. Your dependency constraint conflicts with golang-migrate

You explicitly say:

Permitted third-party modules and nothing else

but then require:

golang-migrate CLI

That's an external dependency outside your listed Go dependency budget.

This should be clarified as:

golang-migrate/migrate is permitted only as a CLI/tooling dependency, not imported by application code.

Or, if you don't actually want it in go.mod, make the migration CLI an external developer prerequisite.

Otherwise an agent has to violate one requirement to satisfy another.

3. JWT HS256 needs a more precise key requirement

You currently say:

Signed with a 32-byte secret from env

For HS256, 32 bytes is a reasonable minimum, but the important requirement is entropy, not merely length.

A config containing a 32-character human-readable string technically satisfies “32 bytes” but isn't necessarily a strong signing key.

I'd specify:

JWT_SECRET must decode to at least 32 bytes of cryptographically random material. Fail fast if shorter. Document generation using openssl rand -base64 32 or equivalent.

Even better, permit a 64-byte secret.

Also explicitly state:

The JWT secret is never logged, included in errors, or exposed through health/readiness endpoints.

4. JWT validation needs to specify exact semantics

You say:

Validate all of them on every request

Good, but define what “validate” means.

For example:

iss must equal configured issuer
aud must contain configured audience
typ == "access"
sub must be a valid UUID
jti must be a valid UUID
iat must be present and sane
nbf must be respected
exp must be present and unexpired
acceptable clock skew, e.g. 30–60 seconds
signing method must be exactly HS256

I'd explicitly require a small configurable clock skew rather than leaving it to the implementation.

5. Refresh-token reuse detection needs a race-safe transaction specification

This is a major one.

The prompt says:

mark the old token used and issue a new one

and:

If an already-used token is presented, revoke the entire token family

But this is susceptible to concurrent refresh requests unless the DB operation is carefully designed.

You should require something along the lines of:

Refresh rotation MUST execute in a database transaction. The presented token row must be locked (SELECT ... FOR UPDATE) or atomically transitioned so concurrent refresh requests cannot both successfully rotate the same token.

Otherwise two simultaneous refreshes could both observe an unused token.

I'd make this an explicit security acceptance test:

Two concurrent refresh requests using the same refresh token must result in exactly one successful rotation; the other must trigger reuse handling.

That's a very valuable regression test.

6. Clarify what “family” means

You have family_id, which is good, but don't leave its lifecycle implicit.

Define:

Login creates a new family_id.
Every rotation retains the same family.
Logout revokes the current token—or entire family?
Logout-all revokes every family.
Password reset revokes every family.
Password change revokes every other session.
Reuse detection revokes the entire family.

I'd explicitly document this state machine.

Otherwise different reasonable implementations will emerge.

7. Logout semantics are underspecified

You currently say:

/logout — Revoke current refresh token

But authentication is listed as:

access

The access token is stateless, so “current refresh token” has to be obtained somehow.

You need to define whether logout requires:

access JWT + refresh cookie
access JWT only, with server-side session lookup
refresh cookie as the actual revocation target

I'd recommend:

Logout requires a valid access token and the refresh cookie. The server identifies the presented refresh token, revokes that token, and clears authentication cookies.

Also specify behavior if the refresh cookie is absent.

8. The “Bearer clients + CSRF” model needs clarification

This is another important ambiguity.

You have:

cookies + CSRF double-submit

and:

Also support Authorization: Bearer for non-browser clients

Then:

double-submit cookie pattern for all state-changing cookie-authenticated requests

Good, but explicitly distinguish:

Cookie authentication

Requires:

Cookie: access_token=...
Cookie: csrf_token=...
X-CSRF-Token: ...
Bearer authentication

Requires:

Authorization: Bearer ...

and does not require CSRF, because the browser doesn't automatically attach an Authorization header.

I'd explicitly state that CSRF applies only when authentication is derived from cookies.

Otherwise an agent may accidentally demand a CSRF token from API clients.

9. Decide whether the access token is actually in a cookie

You say:

HttpOnly; Secure; SameSite=Strict cookies

and:

Also support Authorization: Bearer

but don't explicitly name the cookies.

Define:

access_token
refresh_token
csrf_token

and their exact paths.

I'd recommend:

access_token:
  Path=/v1
  HttpOnly
  Secure
  SameSite=Strict


refresh_token:
  Path=/v1/auth/refresh
  HttpOnly
  Secure
  SameSite=Strict


csrf_token:
  Path=/v1
  HttpOnly=false
  Secure
  SameSite=Strict

You specifically say:

Non-readable CSRF cookie

That is actually contradictory with the double-submit pattern.

The browser must be able to read the CSRF cookie if the frontend is going to copy it into X-CSRF-Token.

So change:

Non-readable CSRF cookie

to:

A non-HttpOnly CSRF cookie readable by browser JavaScript, paired with the X-CSRF-Token header.

This is an important correction.

10. Add origin checking as a CSRF defense

For a modern browser API, I would add:

For cookie-authenticated state-changing requests, validate Origin when present against the configured allowed origins. Optionally validate Referer as a defense-in-depth fallback where appropriate.

The double-submit token remains the primary CSRF control.

This gives you another barrier against misconfiguration.

11. “Comparable timing” is too vague

You correctly require:

comparable time

But an automated agent cannot reliably prove that.

Instead, define the mechanism:

always Argon2 verify on login
perform the same basic normalization/validation path
avoid database behavior that obviously leaks existence
don't introduce explicit sleeps

Then test:

The code path for unknown users must perform a dummy Argon2 verification.

Don't require a statistical timing guarantee in unit tests.

12. Registration enumeration is tricky

You say:

register ... identical responses whether or not the account exists

That's reasonable for privacy, but then what happens when a user registers an already-existing email?

You need to specify whether the endpoint:

returns 202 with generic wording and sends no email
returns 201 only for newly created users
always returns 202

I'd strongly recommend:

202 Accepted
"We've received your request. If verification is required, you'll receive an email."

for both cases.

But there is another issue: what about the database unique constraint?

The service should catch the uniqueness conflict and convert it to the same generic response rather than leaking duplicate email.

13. Password reset enumeration needs the same treatment

You already say it, but make the response explicit:

202 Accepted
"If an account exists for that email, you'll receive password reset instructions."

Same HTTP status, same response body.

And don't let rate-limit behavior reveal whether the account exists.

14. Add email verification semantics

You have verification tokens but don't define:

verification token TTL
whether verification tokens rotate
whether verification is idempotent
what happens after email is already verified
whether login is allowed before verification

Most importantly:

Does login require verified email?

That should be explicit.

For example:

Accounts may authenticate before email verification, but privileged operations require verification.

or:

Login succeeds only after email verification.

Neither is inherently correct; the product needs to choose.

15. Add email-change handling

You have:

PATCH /v1/me

and email is presumably part of the user profile, but you don't say whether email can be changed.

I'd explicitly say:

Email is immutable through PATCH /v1/me.

Or define a separate email-change flow.

Otherwise the agent may allow:

{
  "email": "attacker@example.com"
}

without a verification flow.

For a boilerplate, I'd make email immutable initially.

16. Define PATCH semantics

PATCH /v1/me needs a contract.

Specify:

allowed fields
whether null is meaningful
maximum name length
empty string behavior
unknown fields → 422
whether email is immutable
whether updates are partial

For example:

{
  "name": "Jane Doe"
}

and:

Only name is mutable. Maximum 200 Unicode characters.

17. Your “domain imports nothing” rule conflicts with UUID types

You specify:

domain — no external imports

but your entities have:

id uuid

If domain entities use github.com/google/uuid, then domain imports an external package.

You need to choose.

I'd actually recommend:

type UserID string

or [16]byte, depending on preference.

Then conversion to/from PostgreSQL UUID happens at repository boundaries.

Alternatively allow google/uuid in domain and change the statement to:

Domain imports no infrastructure/framework packages.

The latter is probably more pragmatic.

18. Add transaction boundaries explicitly

The prompt needs a section defining operations that must be transactional.

At minimum:

Login failure/account lock

Increment failure counter and potentially lock account atomically.

Refresh

Token consumption + new token creation.

Password reset

Consume reset token + change password + revoke sessions.

Password change

Change password + revoke sessions.

Logout-all

Revoke sessions atomically enough to provide predictable semantics.

This will prevent an agent from spreading related operations across multiple independent DB calls.

19. Add database constraints, not just application validation

Your schema should enforce invariants where possible.

For example:

failed_login_attempts >= 0
timestamps sensible
token expiry not null
foreign keys
indexes
potentially partial indexes for active tokens

For refresh tokens, consider an index specifically supporting active-token lookup:

(user_id, family_id)

and potentially:

(user_id, revoked_at)

depending on query patterns.

20. citext is a hidden PostgreSQL dependency

You specify:

email citext

but don't explicitly require:

CREATE EXTENSION IF NOT EXISTS citext;

The migration should do that.

Also, you already say emails are normalized in Go. Decide whether citext is actually needed.

I'd probably keep it as defense in depth.

21. “Prepared statements” needs clarification

You say:

prepared/parameterized statements only

Parameterized SQL is essential. Explicitly preparing every query with PrepareContext isn't necessarily desirable with database/sql, because the driver/database may handle statement preparation differently.

I'd phrase this:

All dynamic values MUST use SQL parameters ($1, $2, ...). Never interpolate user-controlled values into SQL. Explicit prepared statements may be used where beneficial.

That avoids an unnecessarily rigid implementation requirement.

22. Rate limiting needs an atomic multi-rule model

This:

5 per 15 min per IP and 5 per 15 min per email, whichever trips first

means one request consumes both buckets.

The interface:

Allow(ctx, key string, rule Rule)

doesn't naturally express that.

I'd change the interface to something like:

Allow(ctx context.Context, keys []LimitKey) (Decision, error)

or define a higher-level:

AllowAll(ctx context.Context, checks ...Check) (Decision, error)

This becomes particularly important with Redis, where checking and incrementing multiple keys should ideally be atomic.

Otherwise:

IP bucket succeeds
email bucket fails
IP token was consumed anyway

That's not necessarily wrong, but it needs intentional semantics.

23. Redis “degrade cleanly” is dangerous for security

This phrase deserves much more precision:

Redis optional via env; must degrade cleanly

If Redis is the configured distributed limiter and Redis goes down, falling back to an in-process limiter may weaken protection dramatically across multiple API instances.

I'd specify:

If Redis is configured and unavailable, fail closed for security-sensitive rate limits, unless RATE_LIMIT_REDIS_FAIL_OPEN=true is explicitly configured.

Or, if availability is more important:

Fail open only for global/general limits; authentication limits fail closed.

For an auth boilerplate, I'd favor fail-closed for login/reset endpoints.

24. In-memory limiter should define clock and janitor behavior

You correctly request an injectable clock for tests.

Make that part of the design:

type Clock interface {
    Now() time.Time
}

Then the limiter, token service, account lockout, and expiration logic can all use it.

That will make your tests much cleaner.

25. Add database timeout expectations

You say:

context with timeouts on every DB call

Good, but specify the default.

For example:

DB operation timeout: 3 seconds
transaction timeout: 5 seconds
readiness DB ping timeout: 1 second

Otherwise every repository implementation will invent its own behavior.

26. context timeout layering needs care

Don't create arbitrary context.WithTimeout deep inside every repository method if the service already owns the request deadline.

A better rule:

Every externally initiated DB operation must execute under a context with a finite deadline. Repository methods may apply a bounded operation timeout only when the caller has not already supplied a shorter deadline.

This avoids fighting the HTTP request deadline.

27. Add authentication middleware behavior

You say it exists but don't define it sufficiently.

Specify:

missing credential → 401
malformed JWT → 401
invalid JWT → 401
valid JWT but wrong typ → 401
valid token but deleted user → 401
locked account → should existing sessions work?
revoked access token → impossible unless you maintain a denylist

That last point is important.

If logout only revokes refresh tokens, the current JWT remains valid until its 15-minute expiry.

That's normally acceptable, but the prompt should say so.

I'd add:

Access tokens are intentionally not individually revocable; logout/revocation invalidates refresh capability and access tokens naturally expire within 15 minutes.

28. Consider a token_version / session-version mechanism

For password reset and logout-all, revoking all refresh tokens is enough to stop future access-token renewal, but existing JWTs remain valid.

If you want immediate invalidation of all sessions, you'd need something like a user/session version claim and DB/cache check.

I wouldn't necessarily add that—it reduces the simplicity of the boilerplate—but explicitly document:

JWT access tokens are not server-side session state and remain valid until expiry.

That's an important security tradeoff.

29. Add absolute session lifetime

A 30-day refresh token that rotates forever can effectively become an indefinite session.

You should decide whether that's intended.

I'd recommend:

refresh token idle TTL: 30 days
absolute session lifetime: e.g. 90 days

Then each family has:

family_created_at

and cannot be extended beyond the absolute maximum.

If indefinite sessions are intentional, document that instead.

30. Add refresh-token cookie naming/path behavior to API docs

The current prompt is detailed about security but surprisingly vague about actual HTTP wire contracts.

Define:

cookie names
response status codes
response schemas
request schemas
headers
error codes
which endpoints accept Bearer
which endpoints require cookies

This is especially important because you're calling this an API boilerplate.

31. Be more explicit about status codes

For example:

register       202
login          200
refresh        200
logout         204
logout-all     204
forgot         202
reset          204
verify         204
GET /me        200
PATCH /me      200
change-pass    204

You don't necessarily have to use these exact choices, but define them.

32. Add response content-type behavior

Specify:

Content-Type: application/json; charset=utf-8

for JSON responses.

And:

204 responses contain no body.

Small thing, but useful for generated APIs.

33. CORS and SameSite need an explicit deployment model

SameSite=Strict is very restrictive.

If your frontend is hosted at:

https://app.example.com

and API at:

https://api.example.com

they are same-site, so Strict can work.

But if frontend/API are genuinely cross-site, cookies won't behave as expected.

I'd add:

The default deployment assumes frontend and API are same-site. Cross-site cookie deployments require explicitly changing SameSite to None and enabling Secure, with corresponding CSRF/origin controls.

34. Security headers should distinguish API from browser app

Your CSP:

default-src 'none'

is perfectly reasonable for a JSON API.

But document that this API serves no HTML/browser UI.

Otherwise someone later adds Swagger UI and wonders why it doesn't work.

35. The access-log “path template” requirement needs a concrete mechanism

With Go 1.22 ServeMux, the handler can potentially obtain the matched pattern via request context/request pattern APIs depending on implementation.

Don't tell the agent simply:

path template

Tell it how you expect the implementation to obtain it, or allow:

Route middleware must attach the logical route template to context before the access logger executes.

Otherwise agents can fall back to raw r.URL.Path, violating your requirement.

36. Add log injection protection

Since user-controlled values can enter logs through:

User-Agent
IP
request IDs
potentially user ID

ensure slog structured attributes are used rather than manually concatenating strings.

I'd add:

Never construct log lines through string formatting. All variable data must be structured slog attributes.

37. Redaction should be case-insensitive

Your list includes:

authorization
cookie
set-cookie

but header names and application structures can vary in capitalization.

Specify:

Redaction key matching is case-insensitive and applies recursively to nested slog.GroupValue structures.

Also test variants such as:

Password
PASSWORD
Authorization
Set-Cookie
38. Add URL redaction

You prohibit reset links, which is good, but access tokens can leak through URLs in general.

Add:

Never log query strings or fragments by default. If URLs are logged, query parameters must be excluded/redacted.

For a JSON API, I'd simply log the route template and not the URL.

39. Email links need explicit construction rules

You say:

Never log reset links

Good.

But also specify:

Email links must use a configured public frontend/base URL. Never construct links from the request Host header.

This prevents Host-header poisoning.

Same for verification URLs.

40. SMTP “never block the request” needs architecture

This requirement:

Never block the request on send

has operational consequences.

You need either:

background worker + bounded channel
asynchronous mailer interface
job queue

But a plain:

go mailer.Send(...)

is not production-grade because shutdown can lose emails and unbounded goroutines can occur.

I'd specify:

Use a bounded in-process mail queue with a worker pool and graceful draining. If the queue is full, record the failure and return the endpoint's generic response without exposing mail-delivery state.

For a boilerplate, that is much safer.

Alternatively, explicitly scope the requirement to:

Mailer.Send is invoked asynchronously through an application-managed worker.

41. Add an outbox warning

For registration/password reset, email delivery and DB state can become inconsistent.

A truly production-grade architecture would use an outbox pattern:

DB transaction
   ↓
account state + email event
   ↓
outbox worker
   ↓
SMTP

But this adds significant complexity.

I wouldn't necessarily force it into this boilerplate. Instead document:

The SMTP implementation is intentionally not transactional with PostgreSQL; production deployments requiring guaranteed email delivery should replace the mailer boundary with an outbox/event mechanism.

That is a much more honest production posture.

42. “Distroless/scratch” is potentially contradictory with debugging

A scratch image is great for minimal attack surface, but TLS/CA certificates/timezone data need consideration.

If using SMTP TLS or HTTPS, you'll need CA certificates.

I'd specify:

Prefer a distroless non-root runtime image with CA certificates; use scratch only if the build explicitly copies required CA certificates and other runtime assets.

I'd choose distroless for this boilerplate.

43. Add container hardening

Your Docker requirements could be stronger:

non-root UID
read-only filesystem
no shell
dropped capabilities where supported
minimal writable directories
no secrets baked into image
healthcheck

This fits the security goal nicely.

44. docker-compose.yml should not imply production Redis/Postgres security

For development:

exposed local ports are fine
default credentials are acceptable in .env.example

But explicitly state:

Docker Compose credentials are development-only and must never be used in production.

45. Add dependency pinning/reproducibility

For a boilerplate intended for cloning:

Go version pinned
dependencies recorded in go.mod/go.sum
GitHub Actions uses explicit Go version
Docker build uses explicit Go base version

I would also require:

CI runs with -mod=readonly.

That catches accidental dependency drift.

46. Add go test coverage

Not necessarily 100%, but establish a floor.

For example:

CI must enforce at least 80% statement coverage for internal/security, internal/service, and internal/middleware.

I'd avoid enforcing 80% globally because generated/test helper code can make that annoying.

47. Add fuzz tests

Go's fuzzing is particularly useful for:

JSON decoding
JWT parsing
token parsing
password policy
HTTP header parsing
CSRF comparison
error envelope serialization

I'd add a modest requirement:

Include fuzz tests for token parsing and JSON request decoding; they must run successfully with a bounded CI fuzz duration.

48. Add race tests specifically around security state

You already require -race, which is excellent.

But I'd explicitly test concurrent:

refresh
login lockout
rate limiter
token revocation

The refresh race is particularly important.

49. Your “complete repository” requirement is excellent, but tell the agent how to behave when a phase fails

Right now:

After each phase, state what you built, run the build and tests, and confirm they pass before continuing.

I'd strengthen it:

If any command fails, stop the phase, diagnose and fix the failure, rerun the relevant checks, and do not proceed until green. Never claim a check passed unless you actually ran it.

This is extremely useful for coding agents.

50. Add an explicit “do not fake verification” rule

Agents sometimes respond:

go test ./... passes

without actually running it.

Add:

Never state that a build, test, lint, security scan, migration, or endpoint walkthrough passed unless the command was actually executed and its result observed.

This complements your phase design.

Recommended revised structure

I would restructure the prompt slightly so the agent has less opportunity to miss requirements:

1. Role
2. Objective
3. Non-negotiable architecture
4. Tunable decisions
5. API contract
6. Authentication/session model
7. Security requirements
8. Database model + transaction requirements
9. Middleware
10. Rate limiting
11. Logging
12. Mail delivery
13. Project layout
14. Testing requirements
15. Operational requirements
16. Deliverables
17. Execution protocol
18. Do-not rules
19. Definition of done

The current prompt mixes architecture, security, API behavior, and operational requirements somewhat. It's still understandable, but separating security invariants from implementation preferences would make an agent more reliable.

Three things I'd change immediately

If you don't want to revise the entire prompt, these are the highest-value changes:

A. Fix CSRF wording

Change:

Non-readable CSRF cookie + X-CSRF-Token header

to:

A Secure, SameSite=Strict, non-HttpOnly/readable CSRF cookie whose value must be echoed in the X-CSRF-Token header for state-changing cookie-authenticated requests. Compare values using constant-time comparison.

B. Add transactional refresh rotation

Add:

Refresh rotation MUST be performed transactionally. The presented refresh-token row must be atomically claimed/locked so two concurrent uses cannot both succeed. Exactly one concurrent request may rotate a token; subsequent reuse must trigger family revocation and a WARN security event.

C. Resolve the dependency contradiction

Change the dependency section to:

Application dependencies are limited to the listed modules. Developer/CI tooling dependencies such as golang-migrate, gosec, govulncheck, and golangci-lint are permitted as external tools and must not be imported by application packages.

Bottom line

This is already substantially better than most agent prompts for production Go APIs. The security thinking is strong.

The main thing I'd avoid is adding more and more security features. You already have enough. Instead, spend the next revision making the existing requirements deterministic:

Who owns what state? What exactly happens concurrently? What are the HTTP semantics? What is transactional? What does failure mean?
