package middleware

import (
	"net"
	"net/http"
	"strings"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
)

const (
	headerForwardedFor = "X-Forwarded-For"
	headerRealIP       = "X-Real-IP"
)

type ClientIPResolver struct {
	trusted []*net.IPNet
}

func NewClientIPResolver(trusted []*net.IPNet) *ClientIPResolver {
	return &ClientIPResolver{trusted: trusted}
}

func (c *ClientIPResolver) Resolve(r *http.Request) string {
	peer := remoteIP(r.RemoteAddr)
	if peer == nil {
		return ""
	}
	if len(c.trusted) == 0 || !c.isTrusted(peer) {
		return peer.String()
	}

	if forwarded := r.Header.Get(headerForwardedFor); forwarded != "" {
		hops := strings.Split(forwarded, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(hops[i]))
			if candidate == nil {
				continue
			}
			if !c.isTrusted(candidate) {
				return candidate.String()
			}
		}
	}

	if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get(headerRealIP))); realIP != nil {
		return realIP.String()
	}
	return peer.String()
}

func (c *ClientIPResolver) isTrusted(ip net.IP) bool {
	for _, network := range c.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ClientIP(resolver *ClientIPResolver) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := httpx.WithClientIP(r.Context(), resolver.Resolve(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}
