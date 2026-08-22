package httpx

import (
	"context"
	"net/http"
)

const DefaultBodyLimit int64 = 1 << 20

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyRoute
	ctxKeyClientIP
	ctxKeyUserID
	ctxKeyBodyLimit
	ctxKeyPrincipal
)

func WithBodyLimit(ctx context.Context, limit int64) context.Context {
	return context.WithValue(ctx, ctxKeyBodyLimit, limit)
}

func BodyLimit(ctx context.Context) int64 {
	if limit, ok := ctx.Value(ctxKeyBodyLimit).(int64); ok && limit > 0 {
		return limit
	}
	return DefaultBodyLimit
}

func currentBodyLimit(r *http.Request) int64 {
	return BodyLimit(r.Context())
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

type routeHolder struct {
	pattern string
}

func WithRouteCapture(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyRoute, &routeHolder{})
}

func SetRoute(ctx context.Context, pattern string) {
	if holder, ok := ctx.Value(ctxKeyRoute).(*routeHolder); ok {
		holder.pattern = pattern
	}
}

func Route(ctx context.Context) string {
	if holder, ok := ctx.Value(ctxKeyRoute).(*routeHolder); ok {
		return holder.pattern
	}
	return ""
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxKeyClientIP, ip)
}

func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(ctxKeyClientIP).(string)
	return ip
}

type identityHolder struct {
	userID string
}

func WithIdentityCapture(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, &identityHolder{})
}

func SetUserID(ctx context.Context, id string) {
	if holder, ok := ctx.Value(ctxKeyUserID).(*identityHolder); ok {
		holder.userID = id
	}
}

func UserID(ctx context.Context) string {
	if holder, ok := ctx.Value(ctxKeyUserID).(*identityHolder); ok {
		return holder.userID
	}
	return ""
}

type Principal struct {
	UserID  string
	TokenID string
}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

func CurrentPrincipal(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKeyPrincipal).(Principal)
	return p, ok
}
