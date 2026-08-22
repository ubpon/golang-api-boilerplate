package server_test

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

type fakeStore struct {
	mu       sync.Mutex
	users    map[string]*domain.User
	byEmail  map[string]string
	refresh  map[string]*domain.RefreshToken
	resets   map[string]*oneTimeRecord
	verifies map[string]*oneTimeRecord
	pingErr  error
}

type oneTimeRecord struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:    make(map[string]*domain.User),
		byEmail:  make(map[string]string),
		refresh:  make(map[string]*domain.RefreshToken),
		resets:   make(map[string]*oneTimeRecord),
		verifies: make(map[string]*oneTimeRecord),
	}
}

func (s *fakeStore) Users() repository.UserRepository                 { return &fakeUsers{s} }
func (s *fakeStore) RefreshTokens() repository.RefreshTokenRepository { return &fakeRefresh{s} }
func (s *fakeStore) PasswordResetTokens() repository.OneTimeTokenRepository {
	return &fakeOneTime{store: s, pick: func(f *fakeStore) map[string]*oneTimeRecord { return f.resets }}
}
func (s *fakeStore) EmailVerificationTokens() repository.OneTimeTokenRepository {
	return &fakeOneTime{store: s, pick: func(f *fakeStore) map[string]*oneTimeRecord { return f.verifies }}
}
func (s *fakeStore) Ping(context.Context) error { return s.pingErr }
func (s *fakeStore) Close() error               { return nil }

type fakeUsers struct{ s *fakeStore }

func (r *fakeUsers) Create(_ context.Context, params repository.CreateUserParams) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if _, exists := r.s.byEmail[params.Email]; exists {
		return nil, domain.ErrConflict
	}
	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.NewString(),
		Email:        params.Email,
		DisplayEmail: params.DisplayEmail,
		PasswordHash: params.PasswordHash,
		Name:         params.Name,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	r.s.users[user.ID] = user
	r.s.byEmail[params.Email] = user.ID

	clone := *user
	return &clone, nil
}

func (r *fakeUsers) GetByID(_ context.Context, id string) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	clone := *user
	return &clone, nil
}

func (r *fakeUsers) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	id, ok := r.s.byEmail[domain.NormalizeEmail(email)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	clone := *r.s.users[id]
	return &clone, nil
}

func (r *fakeUsers) UpdateName(_ context.Context, id, name string) (*domain.User, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	user.Name = name
	user.UpdatedAt = time.Now().UTC()
	clone := *user
	return &clone, nil
}

func (r *fakeUsers) UpdatePasswordHash(_ context.Context, id, passwordHash string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	user.PasswordHash = passwordHash
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	user.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *fakeUsers) MarkEmailVerified(_ context.Context, id string, at time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	if user.EmailVerifiedAt == nil {
		stamp := at.UTC()
		user.EmailVerifiedAt = &stamp
	}
	return nil
}

func (r *fakeUsers) RecordFailedLogin(_ context.Context, id string, _ time.Time) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return 0, domain.ErrNotFound
	}
	user.FailedLoginAttempts++
	return user.FailedLoginAttempts, nil
}

func (r *fakeUsers) ApplyLock(_ context.Context, id string, until time.Time) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	stamp := until.UTC()
	user.LockedUntil = &stamp
	return nil
}

func (r *fakeUsers) ResetFailedLogins(_ context.Context, id string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	user, ok := r.s.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	return nil
}

type fakeRefresh struct{ s *fakeStore }

func (r *fakeRefresh) Create(_ context.Context, params repository.CreateRefreshTokenParams) (*domain.RefreshToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	key := string(params.TokenHash)
	if _, exists := r.s.refresh[key]; exists {
		return nil, domain.ErrConflict
	}
	token := &domain.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    params.UserID,
		TokenHash: params.TokenHash,
		FamilyID:  params.FamilyID,
		ExpiresAt: params.ExpiresAt.UTC(),
		UserAgent: params.UserAgent,
		IP:        params.IP,
		CreatedAt: time.Now().UTC(),
	}
	r.s.refresh[key] = token
	clone := *token
	return &clone, nil
}

func (r *fakeRefresh) GetByHash(_ context.Context, tokenHash []byte) (*domain.RefreshToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	token, ok := r.s.refresh[string(tokenHash)]
	if !ok {
		return nil, domain.ErrNotFound
	}
	clone := *token
	return &clone, nil
}

func (r *fakeRefresh) ConsumeByHash(_ context.Context, tokenHash []byte, at time.Time) (*domain.RefreshToken, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	token, ok := r.s.refresh[string(tokenHash)]
	if !ok || !token.IsActive(at) {
		return nil, domain.ErrNotFound
	}
	stamp := at.UTC()
	token.UsedAt = &stamp
	clone := *token
	return &clone, nil
}

func (r *fakeRefresh) RevokeFamily(_ context.Context, familyID string, at time.Time) (int64, error) {
	return r.revoke(func(t *domain.RefreshToken) bool { return t.FamilyID == familyID }, at), nil
}

func (r *fakeRefresh) RevokeAllForUser(_ context.Context, userID string, at time.Time) (int64, error) {
	return r.revoke(func(t *domain.RefreshToken) bool { return t.UserID == userID }, at), nil
}

func (r *fakeRefresh) RevokeAllForUserExceptFamily(_ context.Context, userID, familyID string, at time.Time) (int64, error) {
	return r.revoke(func(t *domain.RefreshToken) bool {
		return t.UserID == userID && t.FamilyID != familyID
	}, at), nil
}

func (r *fakeRefresh) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var deleted int64
	for key, token := range r.s.refresh {
		if token.ExpiresAt.Before(before) {
			delete(r.s.refresh, key)
			deleted++
		}
	}
	return deleted, nil
}

func (r *fakeRefresh) revoke(match func(*domain.RefreshToken) bool, at time.Time) int64 {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	stamp := at.UTC()
	var count int64
	for _, token := range r.s.refresh {
		if token.RevokedAt == nil && match(token) {
			token.RevokedAt = &stamp
			count++
		}
	}
	return count
}

type fakeOneTime struct {
	store *fakeStore
	pick  func(*fakeStore) map[string]*oneTimeRecord
}

func (r *fakeOneTime) Create(_ context.Context, params repository.CreateOneTimeTokenParams) (string, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	table := r.pick(r.store)
	key := string(params.TokenHash)
	if _, exists := table[key]; exists {
		return "", domain.ErrConflict
	}
	record := &oneTimeRecord{ID: uuid.NewString(), UserID: params.UserID, ExpiresAt: params.ExpiresAt.UTC()}
	table[key] = record
	return record.ID, nil
}

func (r *fakeOneTime) ConsumeByHash(_ context.Context, tokenHash []byte, at time.Time) (string, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	record, ok := r.pick(r.store)[string(tokenHash)]
	if !ok || record.UsedAt != nil || !record.ExpiresAt.After(at) {
		return "", domain.ErrNotFound
	}
	stamp := at.UTC()
	record.UsedAt = &stamp
	return record.UserID, nil
}

func (r *fakeOneTime) InvalidateForUser(_ context.Context, userID string, at time.Time) (int64, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	stamp := at.UTC()
	var count int64
	for _, record := range r.pick(r.store) {
		if record.UserID == userID && record.UsedAt == nil {
			record.UsedAt = &stamp
			count++
		}
	}
	return count, nil
}

func (r *fakeOneTime) DeleteExpired(_ context.Context, before time.Time) (int64, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	table := r.pick(r.store)
	var deleted int64
	for key, record := range table {
		if record.ExpiresAt.Before(before) {
			delete(table, key)
			deleted++
		}
	}
	return deleted, nil
}
