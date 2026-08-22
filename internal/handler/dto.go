package handler

import (
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/domain"
	"github.com/ubpon/golang-api-boilerplate/internal/service"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type updateProfileRequest struct {
	Name *string `json:"name"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type userResponse struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	EmailVerified bool       `json:"email_verified"`
	VerifiedAt    *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type sessionResponse struct {
	AccessToken      string       `json:"access_token"`
	RefreshToken     string       `json:"refresh_token"`
	TokenType        string       `json:"token_type"`
	ExpiresIn        int          `json:"expires_in"`
	AccessExpiresAt  time.Time    `json:"access_expires_at"`
	RefreshExpiresAt time.Time    `json:"refresh_expires_at"`
	CSRFToken        string       `json:"csrf_token"`
	User             userResponse `json:"user"`
}

type acceptedResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func newUserResponse(u *domain.User) userResponse {
	return userResponse{
		ID:            u.ID,
		Email:         u.DisplayEmail,
		Name:          u.Name,
		EmailVerified: u.IsEmailVerified(),
		VerifiedAt:    u.EmailVerifiedAt,
		CreatedAt:     u.CreatedAt.UTC(),
		UpdatedAt:     u.UpdatedAt.UTC(),
	}
}

func newSessionResponse(s *service.Session) sessionResponse {
	return sessionResponse{
		AccessToken:      s.AccessToken,
		RefreshToken:     s.RefreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        int(time.Until(s.AccessExpiresAt).Seconds()),
		AccessExpiresAt:  s.AccessExpiresAt.UTC(),
		RefreshExpiresAt: s.RefreshExpiresAt.UTC(),
		CSRFToken:        s.CSRFToken,
		User:             newUserResponse(s.User),
	}
}
