# Adding a feature

A step-by-step walkthrough for extending this boilerplate, from the first file
to a green `make test lint sec`.

The worked example builds a complete **`projects`** resource — a user-owned
record with create, list, read, update, and delete. It is not in the repository;
it exists here so every layer has a concrete, copy-adaptable illustration. Every
snippet below was compiled, linted, and run against real PostgreSQL before being
written down.

If you only need a small change — one new field, one config value, one
middleware — skip to [Smaller recipes](#smaller-recipes).

---

## 1. The one rule

Dependencies point **inward**, and never back out:

```
handler  ──▶  service  ──▶  repository  ──▶  domain
   │             │              │              │
   │             │              │              └── entities + errors, imports
   │             │              │                  nothing else in this module
   │             │              └── interfaces here,
   │             │                  SQL in repository/postgres
   │             └── business rules, transactions, workflow
   └── HTTP only: decode, validate shape, delegate, encode
```

`server` sits outside all of it and wires everything together. Leaf packages
(`httpx`, `logging`, `security`, `validation`, `ratelimit`, `mailer`, `config`)
may be imported by any layer.

Practical consequences:

- A handler never touches `*sql.DB`. It calls a service.
- A service never sees `http.Request`, `http.ResponseWriter`, or a status code.
  It returns domain values and sentinel errors.
- A repository never makes a policy decision. It reads and writes rows.
- `domain` imports only the standard library. Not `uuid`, not `pgx`.

If you find yourself wanting to break one of these, the fix is almost always to
move the decision one layer out, not to add an import.

---

## 2. The touch list

A full vertical feature touches around twenty files: nine new ones, plus edits
to the existing wiring. Nothing here is optional except where marked.

### New files

| File | Purpose |
|---|---|
| `migrations/000N_<feature>.up.sql` | Table, constraints, indexes |
| `migrations/000N_<feature>.down.sql` | The exact inverse |
| `internal/domain/<feature>.go` | Entity and any pure helpers |
| `internal/repository/postgres/<feature>.go` | SQL implementation |
| `internal/service/<feature>.go` | Business rules and sentinel errors |
| `internal/handler/<feature>.go` | HTTP handlers |
| `internal/handler/<feature>_dto.go` | Request and response shapes |
| `internal/server/<feature>_test.go` | Handler tests through the real router |
| `internal/repository/postgres/<feature>_integration_test.go` | Real-Postgres tests |

### Existing files to edit

| File | What changes |
|---|---|
| `internal/repository/repository.go` | Param structs, the repository interface, one method on `Store` |
| `internal/repository/postgres/postgres.go` | Struct field, both constructors, the `Store` accessor |
| `internal/service/…` | Nothing, unless another service needs to call yours |
| `internal/handler/errors.go` | Map your sentinel errors to HTTP |
| `internal/httpx/errors.go` | Only if you need a new error code |
| `internal/ratelimit/rules.go` | Only if the feature needs its own limit |
| `internal/config/config.go` | Only if the feature needs configuration |
| `internal/server/routes.go` | The `Routes` struct and the route registrations |
| `internal/server/server.go` | The constructor's nil-guard |
| `internal/server/build.go` | Construct the service and handler |
| `internal/server/fakestore_test.go` | Implement the new repository for handler tests |
| `docs/API.md` | Document the endpoints |

Work the list top to bottom. Each step compiles on its own, so you get a working
`go build ./...` after every one.

---

## 3. Worked example: `projects`

### Step 1 — Write the migration

```bash
make migrate-create name=projects
# creates migrations/0006_projects.up.sql and .down.sql
```

Put invariants in the database, not only in Go. The application can be wrong;
a `CHECK` constraint cannot.

**`migrations/0006_projects.up.sql`**

```sql
CREATE TABLE projects (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    archived_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT projects_name_length CHECK (char_length(name) BETWEEN 1 AND 120),
    CONSTRAINT projects_description_length CHECK (char_length(description) <= 2000)
);

CREATE UNIQUE INDEX projects_owner_id_name_key ON projects (owner_id, lower(name));
CREATE INDEX projects_owner_id_created_at_idx ON projects (owner_id, created_at DESC, id DESC);
```

**`migrations/0006_projects.down.sql`**

```sql
DROP TABLE IF EXISTS projects;
```

Four things to copy from this:

- **`ON DELETE CASCADE`** on the owner. Deleting a user must not leave orphans.
- **`lower(name)`** in the unique index gives case-insensitive uniqueness without
  a `citext` column, and turns "duplicate name" into a `23505` the repository
  already knows how to translate.
- **The list index matches the list query's `ORDER BY` exactly**
  (`created_at DESC, id DESC`). If you change one, change the other.
- **Length `CHECK`s** mirror the validator. Belt and braces.

Apply and roll back before writing any Go:

```bash
make migrate-up
make migrate-down   # confirm the down file actually works
make migrate-up
```

### Step 2 — Define the domain entity

`domain` is the innermost layer. Standard library imports only.

**`internal/domain/project.go`**

```go
package domain

import (
	"strings"
	"time"
)

type Project struct {
	ID          string
	OwnerID     string
	Name        string
	Description string
	ArchivedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (p *Project) IsArchived() bool {
	return p.ArchivedAt != nil
}

func NormalizeProjectName(name string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(name)), " ")
}
```

IDs are `string`, not `uuid.UUID` — that is what keeps `domain` free of external
imports. Conversion and validation happen at the edges. Nullable columns are
pointers, so "unset" and "zero" stay distinguishable.

If your feature needs its own failure modes that are genuinely about the *data*
rather than the *workflow*, add them to `internal/domain/errors.go`. Most
features do not: `ErrNotFound` and `ErrConflict` already cover what a repository
can meaningfully report.

### Step 3 — Declare the repository interface

Interfaces live in `internal/repository/repository.go`, next to the ones they sit
beside. Implementations live one package down.

Add to **`internal/repository/repository.go`**:

```go
type CreateProjectParams struct {
	OwnerID     string
	Name        string
	Description string
}

type UpdateProjectParams struct {
	ID          string
	OwnerID     string
	Name        *string
	Description *string
}

type ListProjectsParams struct {
	OwnerID string
	Limit   int
	Offset  int
}

type ProjectRepository interface {
	Create(ctx context.Context, params CreateProjectParams) (*domain.Project, error)
	GetForOwner(ctx context.Context, id, ownerID string) (*domain.Project, error)
	ListForOwner(ctx context.Context, params ListProjectsParams) ([]domain.Project, error)
	CountForOwner(ctx context.Context, ownerID string) (int, error)
	Update(ctx context.Context, params UpdateProjectParams) (*domain.Project, error)
	Delete(ctx context.Context, id, ownerID string) error
}
```

and one line to the `Store` interface:

```go
type Store interface {
	Users() UserRepository
	RefreshTokens() RefreshTokenRepository
	PasswordResetTokens() OneTimeTokenRepository
	EmailVerificationTokens() OneTimeTokenRepository
	Projects() ProjectRepository          // <-- new
	Ping(ctx context.Context) error
	Close() error
}
```

Two conventions worth absorbing:

- **Ownership is a query parameter, not a post-hoc check.** `GetForOwner(id,
  ownerID)` cannot accidentally return another user's row; a `Get(id)` followed
  by `if row.OwnerID != me` can, the first time someone forgets the second line.
- **Pointer fields mean "leave alone".** `UpdateProjectParams.Name == nil` is
  "don't touch the name", which is exactly what `PATCH` means.

Adding a method to `Store` breaks every implementation until you fix them — that
is the point. The compiler now hands you the remaining work.

### Step 4 — Implement it in Postgres

**`internal/repository/postgres/project.go`** — the shape of every method here is
identical: derive a timeout context, run one parameterised statement, translate
the error, scan.

```go
const projectColumns = `id, owner_id, name, description, archived_at, created_at, updated_at`

type ProjectRepo struct {
	db      *sql.DB
	timeout time.Duration
}

func (r *ProjectRepo) Create(ctx context.Context, params repository.CreateProjectParams) (*domain.Project, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		INSERT INTO projects (owner_id, name, description)
		VALUES ($1, $2, $3)
		RETURNING ` + projectColumns

	project, err := scanProject(r.db.QueryRowContext(ctx, query, params.OwnerID, params.Name, params.Description))
	if err != nil {
		return nil, fmt.Errorf("postgres: create project: %w", translate(err))
	}
	return project, nil
}
```

`translate` is the existing package helper that maps `sql.ErrNoRows` to
`domain.ErrNotFound` and a `23505` unique violation to `domain.ErrConflict`.
Always wrap through it — the layers above match on domain errors, not driver
errors.

The partial update uses `COALESCE`, which is why the params are pointers. A
`nil` pointer becomes SQL `NULL`, and `COALESCE(NULL, name)` keeps the existing
value:

```go
func (r *ProjectRepo) Update(ctx context.Context, params repository.UpdateProjectParams) (*domain.Project, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		UPDATE projects
		SET name        = COALESCE($3, name),
		    description = COALESCE($4, description),
		    updated_at  = now()
		WHERE id = $1 AND owner_id = $2
		RETURNING ` + projectColumns

	project, err := scanProject(r.db.QueryRowContext(ctx, query, params.ID, params.OwnerID, params.Name, params.Description))
	if err != nil {
		return nil, fmt.Errorf("postgres: update project: %w", translate(err))
	}
	return project, nil
}
```

Multi-row reads need the full `rows` dance — close it, and check `rows.Err()`
after the loop, or `sqlclosecheck` and `rowserrcheck` will fail the lint:

```go
func (r *ProjectRepo) ListForOwner(ctx context.Context, params repository.ListProjectsParams) ([]domain.Project, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	const query = `
		SELECT ` + projectColumns + `
		FROM projects
		WHERE owner_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.QueryContext(ctx, query, params.OwnerID, params.Limit, params.Offset)
	if err != nil {
		return nil, fmt.Errorf("postgres: list projects: %w", translate(err))
	}
	defer func() {
		// The rows error is surfaced through rows.Err() below.
		_ = rows.Close()
	}()

	projects := make([]domain.Project, 0, params.Limit)
	for rows.Next() {
		project, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan project: %w", translate(err))
		}
		projects = append(projects, *project)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate projects: %w", translate(err))
	}
	return projects, nil
}
```

A `DELETE` has no `RETURNING`, so check the row count yourself and turn zero into
`ErrNotFound`:

```go
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: delete project: rows affected: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("postgres: delete project: %w", domain.ErrNotFound)
	}
	return nil
```

The scan helper takes the package's existing `rowScanner` interface, so the same
function serves both `QueryRowContext` and `rows`:

```go
func scanProject(row rowScanner) (*domain.Project, error) {
	var (
		p          domain.Project
		archivedAt sql.NullTime
	)
	if err := row.Scan(&p.ID, &p.OwnerID, &p.Name, &p.Description, &archivedAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	if archivedAt.Valid {
		t := archivedAt.Time.UTC()
		p.ArchivedAt = &t
	}
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return &p, nil
}
```

Nullable columns scan into `sql.NullX` and convert to pointers. Timestamps are
normalised to UTC on the way out so nothing downstream has to think about it.

> **Never build SQL with `fmt.Sprintf` or `+` on anything a user can influence.**
> Values are always `$1`, `$2`. Even the two one-time-token tables, which share
> an implementation, select between pre-declared constant query sets rather than
> interpolating a table name.

### Step 5 — Wire the repository into the store

Three edits to **`internal/repository/postgres/postgres.go`**:

```go
type Store struct {
	db      *sql.DB
	timeout time.Duration

	users    *UserRepo
	refresh  *RefreshTokenRepo
	resets   *OneTimeTokenRepo
	verifies *OneTimeTokenRepo
	projects *ProjectRepo          // <-- 1. the field
}
```

```go
	s.projects = &ProjectRepo{db: db, timeout: timeout}   // <-- 2. in Open(), and again in NewStore()
```

```go
func (s *Store) Projects() repository.ProjectRepository { return s.projects }  // <-- 3. the accessor
```

`NewStore` is the constructor the integration tests use; forgetting it there is
the usual cause of a nil-pointer panic that only shows up under
`make test-integration`.

### Step 6 — Write the service

This is where business rules live: quotas, normalisation, and the translation
from repository errors into workflow errors.

**`internal/service/project.go`**

```go
var (
	ErrProjectNotFound  = errors.New("service: project not found")
	ErrProjectNameTaken = errors.New("service: a project with that name already exists")
	ErrProjectQuota     = errors.New("service: project quota exhausted")
)

const (
	DefaultProjectPageSize = 20
	MaxProjectPageSize     = 100
)

type ProjectDeps struct {
	Projects repository.ProjectRepository
	Logger   *slog.Logger
	Quota    int
}

type ProjectService struct {
	deps ProjectDeps
}

func NewProjectService(deps ProjectDeps) (*ProjectService, error) {
	if deps.Projects == nil {
		return nil, errors.New("service: project repository is required")
	}
	if deps.Logger == nil {
		return nil, errors.New("service: logger is required")
	}
	if deps.Quota <= 0 {
		deps.Quota = 100
	}
	return &ProjectService{deps: deps}, nil
}
```

Follow the house pattern exactly: a `Deps` struct, a constructor returning
`(*T, error)` that rejects missing dependencies, and no package-level state. If
your service needs the current time, take a `service.Clock` in `Deps` and call
`s.now()` — never `time.Now()` directly, or expiry becomes untestable without
sleeping.

The interesting part is error translation. The repository speaks
`domain.ErrConflict`; the service turns that into something the workflow
understands:

```go
func (s *ProjectService) Create(ctx context.Context, in CreateProjectInput) (*domain.Project, error) {
	used, err := s.deps.Projects.CountForOwner(ctx, in.OwnerID)
	if err != nil {
		return nil, fmt.Errorf("service: count projects: %w", err)
	}
	if used >= s.deps.Quota {
		return nil, ErrProjectQuota
	}

	project, err := s.deps.Projects.Create(ctx, repository.CreateProjectParams{
		OwnerID:     in.OwnerID,
		Name:        domain.NormalizeProjectName(in.Name),
		Description: in.Description,
	})
	switch {
	case err == nil:
		s.deps.Logger.InfoContext(ctx, "project created",
			slog.String("project_id", project.ID),
			slog.String("user_id", in.OwnerID))
		return project, nil
	case errors.Is(err, domain.ErrConflict):
		return nil, ErrProjectNameTaken
	default:
		return nil, fmt.Errorf("service: create project: %w", err)
	}
}
```

Note what the service does **not** do: it does not return `409`, does not know
what a status code is, and does not format a message for a human. It returns a
sentinel. Step 9 maps it.

Clamp pagination in the service, not the handler, so every caller gets the same
bounds:

```go
	perPage := in.PerPage
	switch {
	case perPage <= 0:
		perPage = DefaultProjectPageSize
	case perPage > MaxProjectPageSize:
		perPage = MaxProjectPageSize
	}
```

An unbounded `per_page` is a denial-of-service vector, not a feature request.

### Step 7 — Define the DTOs

Never serialise a domain entity directly. A separate response type is what stops
a future `PasswordHash` field from silently appearing in JSON.

**`internal/handler/project_dto.go`**

```go
type createProjectRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateProjectRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type projectResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Archived    bool       `json:"archived"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type projectListResponse struct {
	Data []projectResponse `json:"data"`
	Meta paginationMeta    `json:"meta"`
}

type paginationMeta struct {
	Total   int `json:"total"`
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
}

func newProjectResponse(p *domain.Project) projectResponse {
	return projectResponse{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		Archived:    p.IsArchived(),
		ArchivedAt:  p.ArchivedAt,
		CreatedAt:   p.CreatedAt.UTC(),
		UpdatedAt:   p.UpdatedAt.UTC(),
	}
}
```

Request DTOs use **pointers for `PATCH` fields** so the handler can tell "absent"
from "set to empty". Response DTOs use values. Note that `OwnerID` is absent from
the response — the caller already knows who they are, and leaking internal
foreign keys buys nothing.

Because `DecodeJSON` calls `DisallowUnknownFields()`, any field you forget to
declare becomes a `422` rather than being silently dropped.

### Step 8 — Write the handlers

Handlers do five things in order: identify the caller, decode, validate,
delegate, encode. Anything else belongs in a service.

**`internal/handler/project.go`**

```go
func (h *Project) Create(w http.ResponseWriter, r *http.Request) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return
	}

	var req createProjectRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	v := validation.New()
	name := v.Required("name", req.Name)
	v.MaxLen("name", name, maxProjectNameLength)
	description := v.MaxLen("description", strings.TrimSpace(req.Description), maxProjectDescriptionLength)
	if !v.OK() {
		httpx.WriteError(w, r, validationError(v))
		return
	}

	if blocked := enforceRate(w, r, h.deps.Limiter, h.deps.Rules.ProjectWriteUID, principal.UserID); blocked {
		return
	}

	project, err := h.deps.Service.Create(r.Context(), service.CreateProjectInput{
		OwnerID:     principal.UserID,
		Name:        name,
		Description: description,
	})
	if err != nil {
		httpx.WriteError(w, r, mapServiceError(err))
		return
	}

	w.Header().Set("Location", "/v1/projects/"+project.ID)
	httpx.WriteJSON(w, r, http.StatusCreated, newProjectResponse(project))
}
```

`httpx.CurrentPrincipal` is populated by the `Authenticate` middleware. Check it
even on routes you registered behind that middleware — it costs one branch and
it means the handler is safe if someone later re-registers the route without
auth.

Path parameters come from Go 1.22's `ServeMux` wildcards. **Parse and reject
malformed IDs before they reach the database**, and return `404` rather than
`400` so a probe cannot distinguish "malformed" from "not yours":

```go
func projectScope(w http.ResponseWriter, r *http.Request) (httpx.Principal, string, bool) {
	principal, ok := httpx.CurrentPrincipal(r.Context())
	if !ok {
		httpx.WriteError(w, r, httpx.ErrUnauthorized)
		return httpx.Principal{}, "", false
	}

	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, httpx.ErrNotFound)
		return httpx.Principal{}, "", false
	}
	return principal, id.String(), true
}
```

`PATCH` needs one extra guard — an empty body is a client bug, not a no-op:

```go
	if req.Name == nil && req.Description == nil {
		httpx.WriteError(w, r, httpx.ErrValidation.WithDetails(httpx.FieldError{
			Field: "body",
			Issue: "must set at least one of name or description",
		}))
		return
	}
```

Query parameters get validated like anything else:

```go
func positiveQueryInt(v *validation.Validator, r *http.Request, field string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(field))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < 1 {
		v.Add(field, "must be a positive integer")
		return fallback
	}
	return parsed
}
```

#### A refactor you will hit here

Rate limiting keyed by user or by request body cannot run as middleware — the key
is not known until after decoding. The auth handler had a private `enforce`
method for this. The moment a second feature needs it, promote it to a shared
package-level helper rather than reaching into `Auth`:

**`internal/handler/ratelimit.go`**

```go
func enforceRate(w http.ResponseWriter, r *http.Request, limiter ratelimit.Limiter, rule ratelimit.Rule, key string) bool {
	if limiter == nil || !rule.Valid() || key == "" {
		return false
	}

	ctx := r.Context()
	decision, err := limiter.Allow(ctx, key, rule)
	if err != nil {
		logging.FromContext(ctx).Error("rate limiter unavailable, allowing request",
			slog.String("rule", rule.Name), slog.Any("error", err))
		return false
	}

	ratelimit.WriteHeaders(w, decision)
	if decision.Allowed {
		return false
	}

	logging.Security(ctx, logging.EventRateLimitExceeded,
		"rule", rule.Name,
		"route", httpx.Route(ctx),
		"client_ip", httpx.ClientIP(ctx),
	)
	httpx.WriteError(w, r, httpx.ErrRateLimited)
	return true
}
```

and collapse the old method to a one-line delegation:

```go
func (h *Auth) enforce(w http.ResponseWriter, r *http.Request, rule ratelimit.Rule, key string) bool {
	return enforceRate(w, r, h.deps.Limiter, rule, key)
}
```

### Step 9 — Map your errors to HTTP

One switch, in one file, is the only place the service vocabulary becomes status
codes. Add to **`internal/handler/errors.go`**:

```go
	case errors.Is(err, service.ErrProjectNotFound):
		return httpx.ErrNotFound.WithCause(err)
	case errors.Is(err, service.ErrProjectNameTaken):
		return httpx.ErrConflict.WithCause(err)
	case errors.Is(err, service.ErrProjectQuota):
		return httpx.ErrQuotaExceeded.WithCause(err)
```

`WithCause` clones the sentinel and attaches the real error. The cause is logged;
it never reaches the client. Anything you forget to map falls through to
`internal_error` and a `500` — deliberately loud, so gaps surface in testing.

If no existing code fits, add one to **`internal/httpx/errors.go`**. The code set
is closed and documented, so this is a two-line change plus a docs entry:

```go
	CodeQuotaExceeded ErrorCode = "quota_exceeded"
```

```go
	ErrQuotaExceeded = NewError(http.StatusUnprocessableEntity, CodeQuotaExceeded,
		"You have reached the limit for this resource.")
```

Messages are user-facing, complete sentences, and reveal nothing about internals.

### Step 10 — Add a rate-limit rule

Only if the feature warrants one. Writes usually do; reads are usually covered by
the 100/min global fallback.

**`internal/ratelimit/rules.go`**

```go
type Rules struct {
	// ...
	ChangePasswdUID Rule
	ProjectWriteUID Rule          // <-- new
}

func DefaultRules() Rules {
	return Rules{
		// ...
		ProjectWriteUID: Rule{Name: "project_write.user", Limit: 60, Window: time.Hour},
	}
}
```

Rule names are `<scope>.<key-kind>` and appear verbatim in the
`ratelimit.exceeded` security event, so keep them greppable.

### Step 11 — Add configuration

Only if the feature needs a knob. **`internal/config/config.go`**:

```go
type ProjectsConfig struct {
	PerUserQuota int
}
```

Add the field to `Config`, then populate it inside `Load`:

```go
		Projects: ProjectsConfig{
			PerUserQuota: c.integer("PROJECT_PER_USER_QUOTA", 100),
		},
```

The `collector` helpers (`str`, `required`, `boolean`, `integer`, `integer64`,
`duration`, `list`) accumulate every problem rather than failing on the first, so
a misconfigured deployment reports all its mistakes at once. Add cross-field
checks near the bottom of `Load` with `c.fail(...)`.

Then document it in `.env.example` and the README's env table. A setting that is
not in `.env.example` does not exist as far as the next person is concerned.

### Step 12 — Register the routes

**`internal/server/routes.go`** — add the handler to `Routes`:

```go
type Routes struct {
	Auth     *handler.Auth
	Me       *handler.Me
	Health   *handler.Health
	Projects *handler.Project      // <-- new
}
```

and register the endpoints inside `mux()`, just before `return mux`:

```go
	register(mux, "POST /v1/projects", d.Routes.Projects.Create, csrf, authenticate)
	register(mux, "GET /v1/projects", d.Routes.Projects.List, authenticate)
	register(mux, "GET /v1/projects/{id}", d.Routes.Projects.Show, authenticate)
	register(mux, "PATCH /v1/projects/{id}", d.Routes.Projects.Update, csrf, authenticate)
	register(mux, "DELETE /v1/projects/{id}", d.Routes.Projects.Delete, csrf, authenticate)
```

Rules for this block:

- **`register`, not `mux.Handle`.** The wrapper records the route pattern in the
  context so the access log reports `GET /v1/projects/{id}` instead of a raw path
  containing a UUID. Bypassing it leaks identifiers into log storage and blows up
  log cardinality.
- **Middleware runs left to right.** `csrf, authenticate` means CSRF is checked
  first, so a forged cross-site request gets `403` without ever touching the
  token verifier.
- **CSRF on every unsafe method.** `GET` never needs it; `POST`, `PATCH`, and
  `DELETE` always do. The middleware no-ops for `Authorization: Bearer` clients
  on its own.
- **Per-route IP limits go here** as `perIP(rules.YourRule)`. User-keyed limits go
  in the handler, as in step 8.

Then extend the nil-guard in **`internal/server/server.go`** so a wiring mistake
fails at boot rather than as a nil dereference on first request:

```go
	case deps.Routes.Auth == nil || deps.Routes.Me == nil || deps.Routes.Health == nil || deps.Routes.Projects == nil:
		return nil, errors.New("server: all route handlers are required")
```

### Step 13 — Wire it in the composition root

**`internal/server/build.go`** is the only place that constructs anything. Build
the service before the `New(Deps{...})` call:

```go
	projectService, err := service.NewProjectService(service.ProjectDeps{
		Projects: store.Projects(),
		Logger:   log,
		Quota:    cfg.Projects.PerUserQuota,
	})
	if err != nil {
		return nil, err
	}
```

and the handler inside `Routes`:

```go
		Routes: Routes{
			Auth:   handler.NewAuth(handlerDeps),
			Me:     handler.NewMe(handlerDeps),
			Health: handler.NewHealth(Version, 2*time.Second, probes...),
			Projects: handler.NewProject(handler.ProjectDeps{
				Service: projectService,
				Limiter: limiter,
				Rules:   rules,
			}),
		},
```

If your feature owns a background loop, model it on `service.Cleanup`: a struct
with `Run(ctx)`, stored on `App`, started from `cmd/api/main.go` with the same
signal context that stops the server. If it owns a closable resource, append its
`Close` to `app.closers` — they run in reverse order on shutdown.

At this point `go build ./...` and `make run` both work.

### Step 14 — Teach the fake store

Handler tests run the real router and middleware against an in-memory store, so
they need no database and stay fast. Adding a repository means implementing it
there too — **`internal/server/fakestore_test.go`**.

Add the backing map and the accessor:

```go
type fakeStore struct {
	mu       sync.Mutex
	// ...
	projects map[string]*domain.Project
	pingErr  error
}

func (s *fakeStore) Projects() repository.ProjectRepository { return &fakeProjects{s} }
```

Then implement the interface. Mirror the real semantics — that is the whole point
of the double:

```go
func (r *fakeProjects) Create(_ context.Context, params repository.CreateProjectParams) (*domain.Project, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	for _, existing := range r.s.projects {
		if existing.OwnerID == params.OwnerID && strings.EqualFold(existing.Name, params.Name) {
			return nil, domain.ErrConflict
		}
	}
	// ...
}

func (r *fakeProjects) GetForOwner(_ context.Context, id, ownerID string) (*domain.Project, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	project, ok := r.s.projects[id]
	if !ok || project.OwnerID != ownerID {
		return nil, domain.ErrNotFound
	}
	clone := *project
	return &clone, nil
}
```

Three things that matter:

- **Lock.** Tests run with `-race` and the concurrency tests really do hammer it.
- **Return clones**, never the stored pointer, or a handler mutating its result
  silently corrupts the store and the test lies to you.
- **Reproduce the constraints** — case-insensitive uniqueness here mirrors the
  `lower(name)` index. A double that is more permissive than the database turns
  integration failures into production failures.

### Step 15 — Write the tests

Three layers, three purposes.

**Handler tests** (`internal/server/project_test.go`) go through the real router,
middleware chain, cookies, and error envelopes. This is where you assert
behaviour a user can observe. The most valuable one is authorisation:

```go
func TestProjectsAreScopedToTheirOwner(t *testing.T) {
	h := newHarness(t, harnessOptions{noJar: true})

	owner := h.registerVerifiedUser("owner@example.com")
	intruder := h.registerVerifiedUser("intruder@example.com")

	created := h.do(http.MethodPost, "/v1/projects",
		map[string]string{"name": "Private"}, bearer(owner.AccessToken))
	require.Equal(t, http.StatusCreated, created.Status)

	var project projectPayload
	created.decode(t, &project)

	for _, tc := range []struct {
		method string
		body   any
	}{
		{http.MethodGet, nil},
		{http.MethodPatch, map[string]string{"name": "Stolen"}},
		{http.MethodDelete, nil},
	} {
		resp := h.do(tc.method, "/v1/projects/"+project.ID, tc.body, bearer(intruder.AccessToken))
		require.Equal(t, http.StatusNotFound, resp.Status,
			"%s must report 404, never 403, so it does not confirm the resource exists", tc.method)
	}

	listed := h.do(http.MethodGet, "/v1/projects", nil, bearer(intruder.AccessToken))
	var page projectListPayload
	listed.decode(t, &page)
	require.Empty(t, page.Data)
}
```

The harness in `internal/server/harness_test.go` gives you `newHarness`,
`registerVerifiedUser`, `bearer`, `h.do`, `h.doRaw`, a controllable clock
(`h.clock.Advance`), a capturing mailer (`h.mailer`), and log assertions
(`h.hasSecurityEvent`). Reuse it; do not stand up your own server.

Cover at minimum: the happy path, ownership isolation, validation failures,
conflict handling, malformed path parameters, and unauthenticated access.

**Integration tests** (`internal/repository/postgres/project_integration_test.go`)
exercise the SQL and the constraints against a real PostgreSQL 16 container. They
skip under `-short` and when no container runtime is present. Assert the things
only a real database can tell you:

```go
	_, err = projects.Create(ctx, repository.CreateProjectParams{OwnerID: owner.ID, Name: "APOLLO"})
	require.ErrorIs(t, err, domain.ErrConflict, "the unique index is on lower(name)")

	_, err = projects.Create(ctx, repository.CreateProjectParams{
		OwnerID: owner.ID, Name: strings.Repeat("a", 121),
	})
	require.Error(t, err, "the CHECK constraint bounds the name length")

	updated, err := projects.Update(ctx, repository.UpdateProjectParams{
		ID: created.ID, OwnerID: owner.ID, Name: &newName,
	})
	require.NoError(t, err)
	require.Equal(t, "Moon shots", updated.Description, "COALESCE leaves omitted columns alone")
```

Test the cascade too — it is the kind of thing nobody notices until a user
deletion fails in production:

```go
	_, err = store.DB().ExecContext(ctx, "DELETE FROM users WHERE id = $1", owner.ID)
	require.NoError(t, err)

	_, err = store.Projects().GetForOwner(ctx, created.ID, owner.ID)
	require.ErrorIs(t, err, domain.ErrNotFound)
```

**Unit tests** are for pure logic with interesting edges — normalisation, policy,
quota arithmetic. If a function has no dependencies, test it directly rather than
through HTTP.

Whatever you test, **inject the clock; never `time.Sleep`.** Every clock in this
codebase is injectable through `server.BuildOptions` for exactly this reason.

### Step 16 — Document it

Add the endpoints to `docs/API.md`: request and response bodies, every status
code, every error code they can return, and the rate limit. Add new environment
variables to `.env.example` and the README table. If the feature has a security
property worth stating — here, that ownership scoping returns `404` rather than
`403` — add it to `docs/SECURITY.md`.

### Step 17 — Run the gate

```bash
make test              # unit + handler tests, race detector, no containers
make test-integration  # adds the testcontainers Postgres suite
make lint              # golangci-lint
make sec               # gosec + govulncheck
```

All four must be green before you call it done. Running the example above through
this gate gives:

```
gofmt          clean
go vet ./...   ok
golangci-lint  0 issues
go test -race -count=1 ./...   9/9 packages ok
```

If `lint` complains about `contextcheck`, `noctx`, `sqlclosecheck`, or
`bodyclose`, it has almost certainly found a real bug. Fix the code rather than
adding a `//nolint`; when a suppression genuinely is correct, it needs a comment
saying why.

### What the example touched

Ten new files — the nine from the touch list, plus the extracted rate-limit
helper, which is a one-off you inherit rather than repeat:

```
migrations/0006_projects.up.sql
migrations/0006_projects.down.sql
internal/domain/project.go
internal/repository/postgres/project.go
internal/service/project.go
internal/handler/project.go
internal/handler/project_dto.go
internal/handler/ratelimit.go                              (the extracted helper)
internal/server/project_test.go
internal/repository/postgres/project_integration_test.go
```

Eleven edits:

```
internal/repository/repository.go        params, interface, Store method
internal/repository/postgres/postgres.go field, both constructors, accessor
internal/handler/auth.go                 enforce() delegates to the shared helper
internal/handler/errors.go               three error mappings
internal/httpx/errors.go                 one new error code
internal/ratelimit/rules.go              one new rule
internal/config/config.go                ProjectsConfig
internal/server/routes.go                Routes field, five registrations
internal/server/server.go                nil-guard
internal/server/build.go                 service + handler construction
internal/server/fakestore_test.go        the in-memory repository
```

---

## 4. Smaller recipes

### Add a field to an existing entity

1. New migration with `ALTER TABLE … ADD COLUMN`. Give it a default or allow
   `NULL`; a `NOT NULL` column with no default breaks a rolling deploy.
2. Add the field to the `domain` struct.
3. Add it to the column list constant and the scan helper in the repository.
   **Both, or the scan silently misaligns.**
4. Add it to the response DTO, and to the request DTO plus validator if it is
   writable.
5. Extend the fake store if it participates in any behaviour.
6. Update `docs/API.md`.

### Add a middleware

1. Create `internal/middleware/<name>.go` returning a `Middleware`
   (`func(http.Handler) http.Handler`).
2. Decide global or per-route. Global goes in `globalChain` in `routes.go` — mind
   the ordering comments there. Per-route is an extra argument to `register`.
3. If it needs to pass a value **outward** to an already-running outer middleware
   (as the access log needs the route and user ID), use the pointer-holder
   pattern in `httpx/context.go`; `r.WithContext` makes a new request, so a plain
   context value only flows inward.
4. Test it in isolation with `httptest`, the way `middleware_test.go` does.

### Add a config setting

1. Add the field to the relevant struct in `config.go`.
2. Read it in `Load` with a `collector` helper and a sensible default.
3. Add cross-field validation with `c.fail(...)` if it interacts with others.
4. Add it to `.env.example` **and** the README table.
5. Add a case to `config_test.go` — both the default and the rejection path.

### Add an email

1. Add the template pair to `templates` in `internal/mailer/templates.go`. Use
   `text/template` for plain text and `html/template` for HTML, so a hostile
   display name cannot inject markup.
2. Add a `Composer` method that builds the `Message`.
3. Send it through the injected `Mailer`, which is already the async wrapper —
   `Send` returns as soon as the message is queued.
4. Build links from `cfg.BaseURL`. **Never from the request `Host` header**, or
   you have host-header poisoning in your password reset flow.
5. Never log the body or the link.

### Add a background job

Copy `internal/service/cleanup.go`: a struct with a `Run(ctx context.Context)`
that selects on a ticker and `ctx.Done()`, plus a `Once(ctx)` doing one pass so
tests can drive it without waiting. Store it on `App` in `build.go` and start it
from `main.go` with the signal context.

### Swap the database

Implement `repository.Store` and its interfaces in a new package. Nothing above
the repository layer needs to change — that is what the interfaces are for. Point
`server.Build` at the new store, or pass it via `BuildOptions.Store`.

---

## 5. House rules

Conventions this codebase enforces. Most are checked by `golangci-lint`; the
rest are checked by review.

**No comments above functions or types.** This repository does not use doc
comments. Names carry the meaning. Inline comments are fine — and required —
where something is genuinely surprising, notably every deliberately ignored
error:

```go
	defer func() {
		// The rows error is surfaced through rows.Err() below.
		_ = rows.Close()
	}()
```

**No global mutable state.** No package-level `*sql.DB`, no package-level logger,
no `init()` with side effects. Everything arrives through a constructor.

**Constructors validate.** `New…` returns `(*T, error)` and rejects missing
dependencies. A nil dependency should fail at boot, not at 3am.

**Wrap errors with context, match with sentinels.** `fmt.Errorf("layer: doing
thing: %w", err)` on the way up; `errors.Is` on the way down. Never compare with
`==`.

**Every database call takes a context deadline.** `context.WithTimeout(ctx,
r.timeout)` at the top of every repository method. It composes correctly with a
shorter caller deadline.

**Parameterised SQL only.** `$1`, `$2`. No `fmt.Sprintf` into a query, ever.

**Structured logging only.** `slog.String("user_id", id)`, never
`fmt.Sprintf("user %s", id)`. Attributes are what makes redaction work and logs
queryable.

**Never log a secret.** Passwords, tokens, cookies, and reset links stay out of
the log stream at every level. The `ReplaceAttr` hook redacts a fixed key set
automatically — extend `sensitiveKeys` in `logging/redact.go` if your feature
introduces a new one.

**Don't leak existence.** Return `404` for another user's resource, not `403`.
Keep responses identical across "exists" and "does not exist" wherever an
attacker could learn something.

**Domain errors in, HTTP errors out.** Services return sentinels; only
`handler/errors.go` knows about status codes.

---

## 6. Common mistakes

| Symptom | Cause |
|---|---|
| Nil panic only under `make test-integration` | Forgot the new repo in `NewStore`; `Open` was updated but its twin was not |
| Scanned fields are shifted or wrongly typed | Column list constant and scan helper drifted apart |
| Access log shows `unmatched` | Registered with `mux.Handle` instead of the `register` wrapper |
| Access log shows a raw path with a UUID | Same cause — the route pattern never reached the context |
| Everything returns `500` with `internal_error` | Sentinel not added to `mapServiceError` |
| `PATCH` wipes fields the client omitted | Request DTO used values instead of pointers, or the SQL is missing `COALESCE` |
| `403 csrf_failed` from a browser client on a new route | Registered without the `csrf` middleware, so the cookie was never issued — or with it, and the client is not echoing `X-CSRF-Token` |
| Cross-user access succeeds | Repository query filters on `id` alone; ownership must be in the `WHERE` clause |
| Handler test passes, production fails | Fake store is more permissive than the real constraints |
| `contextcheck` / `noctx` lint failure | A call escaped the request context — usually a real bug |
| Test is flaky under load | Slept instead of advancing the injected clock |

---

## 7. Where to look

| Question | File |
|---|---|
| How is a request assembled? | `internal/server/routes.go` |
| What is constructed, and in what order? | `internal/server/build.go` |
| What can I return to a client? | `internal/httpx/errors.go` |
| How do I test a handler? | `internal/server/harness_test.go` |
| What does a repository look like? | `internal/repository/postgres/user.go` |
| What does a service look like? | `internal/service/auth.go` |
| Why is it built this way? | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| What are the security invariants? | [`SECURITY.md`](SECURITY.md) |
| What is the wire contract? | [`API.md`](API.md) |
