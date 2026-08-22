package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/repository"
)

func TestUserRepositoryLifecycle(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	users := store.Users()

	created, err := users.Create(ctx, repository.CreateUserParams{
		Email:        "person@example.com",
		DisplayEmail: "Person@Example.com",
		PasswordHash: "$argon2id$stub",
		Name:         "Person",
	})
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)
	require.Equal(t, "person@example.com", created.Email)
	require.Equal(t, "Person@Example.com", created.DisplayEmail)
	require.False(t, created.IsEmailVerified())

	byID, err := users.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, created.ID, byID.ID)

	byEmail, err := users.GetByEmail(ctx, "  PERSON@EXAMPLE.COM  ")
	require.NoError(t, err)
	require.Equal(t, created.ID, byEmail.ID)

	_, err = users.GetByEmail(ctx, "nobody@example.com")
	require.ErrorIs(t, err, domain.ErrNotFound)

	_, err = users.GetByID(ctx, uuid.NewString())
	require.ErrorIs(t, err, domain.ErrNotFound)

	renamed, err := users.UpdateName(ctx, created.ID, "Renamed Person")
	require.NoError(t, err)
	require.Equal(t, "Renamed Person", renamed.Name)

	require.NoError(t, users.UpdatePasswordHash(ctx, created.ID, "$argon2id$rotated"))
	reloaded, err := users.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, "$argon2id$rotated", reloaded.PasswordHash)

	verifiedAt := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, users.MarkEmailVerified(ctx, created.ID, verifiedAt))
	verified, err := users.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.True(t, verified.IsEmailVerified())

	require.NoError(t, users.MarkEmailVerified(ctx, created.ID, verifiedAt.Add(time.Hour)))
	stable, err := users.GetByID(ctx, created.ID)
	require.NoError(t, err)
	require.WithinDuration(t, *verified.EmailVerifiedAt, *stable.EmailVerifiedAt, time.Millisecond)
}

func TestUserRepositoryEnforcesCaseInsensitiveUniqueEmail(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	users := store.Users()

	_, err := users.Create(ctx, repository.CreateUserParams{
		Email: "dupe@example.com", DisplayEmail: "dupe@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	_, err = users.Create(ctx, repository.CreateUserParams{
		Email: "DUPE@example.com", DisplayEmail: "DUPE@example.com", PasswordHash: "h",
	})
	require.ErrorIs(t, err, domain.ErrConflict)
}

func TestUserRepositoryLockoutCounters(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()
	users := store.Users()

	user, err := users.Create(ctx, repository.CreateUserParams{
		Email: "lock@example.com", DisplayEmail: "lock@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	for expected := 1; expected <= 3; expected++ {
		attempts, err := users.RecordFailedLogin(ctx, user.ID, now)
		require.NoError(t, err)
		require.Equal(t, expected, attempts)
	}

	until := now.Add(15 * time.Minute)
	require.NoError(t, users.ApplyLock(ctx, user.ID, until))

	locked, err := users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.True(t, locked.IsLocked(now))
	require.False(t, locked.IsLocked(until.Add(time.Second)))

	require.NoError(t, users.ResetFailedLogins(ctx, user.ID))
	unlocked, err := users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.Zero(t, unlocked.FailedLoginAttempts)
	require.Nil(t, unlocked.LockedUntil)

	require.NoError(t, users.ResetFailedLogins(ctx, user.ID))

	_, err = users.RecordFailedLogin(ctx, uuid.NewString(), now)
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestRefreshTokenRotationAndReuseDetection(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "refresh@example.com", DisplayEmail: "refresh@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	tokens := store.RefreshTokens()
	family := uuid.NewString()
	now := time.Now().UTC()

	first, err := tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: hash(1),
		FamilyID:  family,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
		UserAgent: "curl/8.0",
		IP:        "203.0.113.9",
	})
	require.NoError(t, err)
	require.Equal(t, "203.0.113.9", first.IP)
	require.True(t, first.IsActive(now))

	consumed, err := tokens.ConsumeByHash(ctx, hash(1), now)
	require.NoError(t, err)
	require.NotNil(t, consumed.UsedAt)
	require.Equal(t, family, consumed.FamilyID)

	_, err = tokens.ConsumeByHash(ctx, hash(1), now)
	require.ErrorIs(t, err, domain.ErrNotFound)

	replayed, err := tokens.GetByHash(ctx, hash(1))
	require.NoError(t, err)
	require.NotNil(t, replayed.UsedAt)

	_, err = tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(2), FamilyID: family, ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	revoked, err := tokens.RevokeFamily(ctx, family, now)
	require.NoError(t, err)
	require.Equal(t, int64(2), revoked)

	_, err = tokens.ConsumeByHash(ctx, hash(2), now)
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestRefreshTokenRejectsDuplicateHashAndExpiry(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "dup-token@example.com", DisplayEmail: "dup-token@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	tokens := store.RefreshTokens()
	now := time.Now().UTC()

	_, err = tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(5), FamilyID: uuid.NewString(), ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	_, err = tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(5), FamilyID: uuid.NewString(), ExpiresAt: now.Add(time.Hour),
	})
	require.ErrorIs(t, err, domain.ErrConflict)

	_, err = tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(9), FamilyID: uuid.NewString(), ExpiresAt: now.Add(-time.Hour),
	})
	require.NoError(t, err)

	_, err = tokens.ConsumeByHash(ctx, hash(9), now)
	require.ErrorIs(t, err, domain.ErrNotFound)

	deleted, err := tokens.DeleteExpired(ctx, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)
}

func TestRefreshTokenRevocationScopes(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "scopes@example.com", DisplayEmail: "scopes@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	tokens := store.RefreshTokens()
	now := time.Now().UTC()
	keep := uuid.NewString()
	drop := uuid.NewString()

	for i, family := range []string{keep, drop} {
		_, err := tokens.Create(ctx, repository.CreateRefreshTokenParams{
			UserID: user.ID, TokenHash: hash(byte(20 + i*10)), FamilyID: family, ExpiresAt: now.Add(time.Hour),
		})
		require.NoError(t, err)
	}

	revoked, err := tokens.RevokeAllForUserExceptFamily(ctx, user.ID, keep, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), revoked)

	surviving, err := tokens.ConsumeByHash(ctx, hash(20), now)
	require.NoError(t, err)
	require.Equal(t, keep, surviving.FamilyID)

	_, err = tokens.ConsumeByHash(ctx, hash(30), now)
	require.ErrorIs(t, err, domain.ErrNotFound)

	all, err := tokens.RevokeAllForUser(ctx, user.ID, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), all)
}

func TestRefreshTokensCascadeOnUserDelete(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "cascade@example.com", DisplayEmail: "cascade@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	_, err = store.RefreshTokens().Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(40), FamilyID: uuid.NewString(),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)

	_, err = store.DB().ExecContext(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, err)

	_, err = store.RefreshTokens().GetByHash(ctx, hash(40))
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestOneTimeTokenRepositories(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "onetime@example.com", DisplayEmail: "onetime@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	for name, repo := range map[string]repository.OneTimeTokenRepository{
		"password_reset":     store.PasswordResetTokens(),
		"email_verification": store.EmailVerificationTokens(),
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC()

			id, err := repo.Create(ctx, repository.CreateOneTimeTokenParams{
				UserID: user.ID, TokenHash: hash(100), ExpiresAt: now.Add(15 * time.Minute),
			})
			require.NoError(t, err)
			require.NotEmpty(t, id)

			owner, err := repo.ConsumeByHash(ctx, hash(100), now)
			require.NoError(t, err)
			require.Equal(t, user.ID, owner)

			_, err = repo.ConsumeByHash(ctx, hash(100), now)
			require.ErrorIs(t, err, domain.ErrNotFound)

			_, err = repo.Create(ctx, repository.CreateOneTimeTokenParams{
				UserID: user.ID, TokenHash: hash(110), ExpiresAt: now.Add(-time.Minute),
			})
			require.NoError(t, err)
			_, err = repo.ConsumeByHash(ctx, hash(110), now)
			require.ErrorIs(t, err, domain.ErrNotFound)

			_, err = repo.Create(ctx, repository.CreateOneTimeTokenParams{
				UserID: user.ID, TokenHash: hash(120), ExpiresAt: now.Add(time.Hour),
			})
			require.NoError(t, err)

			invalidated, err := repo.InvalidateForUser(ctx, user.ID, now)
			require.NoError(t, err)
			require.Equal(t, int64(2), invalidated)

			_, err = repo.ConsumeByHash(ctx, hash(120), now)
			require.ErrorIs(t, err, domain.ErrNotFound)

			deleted, err := repo.DeleteExpired(ctx, now)
			require.NoError(t, err)
			require.Equal(t, int64(1), deleted)
		})
	}
}

func TestStorePing(t *testing.T) {
	store := newIntegrationStore(t)
	require.NoError(t, store.Ping(context.Background()))
}

func TestConcurrentConsumeAllowsExactlyOneWinner(t *testing.T) {
	store := newIntegrationStore(t)
	ctx := context.Background()

	user, err := store.Users().Create(ctx, repository.CreateUserParams{
		Email: "race@example.com", DisplayEmail: "race@example.com", PasswordHash: "h",
	})
	require.NoError(t, err)

	tokens := store.RefreshTokens()
	now := time.Now().UTC()
	_, err = tokens.Create(ctx, repository.CreateRefreshTokenParams{
		UserID: user.ID, TokenHash: hash(200), FamilyID: uuid.NewString(), ExpiresAt: now.Add(time.Hour),
	})
	require.NoError(t, err)

	const racers = 16
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)

	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := tokens.ConsumeByHash(ctx, hash(200), now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, domain.ErrNotFound):
			default:
				t.Errorf("unexpected error from a concurrent consume: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Equal(t, 1, succeeded, "exactly one concurrent consume may claim the token")
}
