package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
)

func mustCIDRs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		_, network, err := net.ParseCIDR(entry)
		require.NoError(t, err)
		out = append(out, network)
	}
	return out
}

func TestClientIPIgnoresProxyHeadersWithoutTrustList(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.9:34567"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	require.Equal(t, "198.51.100.9", resolver.Resolve(r))
}

func TestClientIPIgnoresProxyHeadersFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.9:34567"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	require.Equal(t, "198.51.100.9", resolver.Resolve(r))
}

func TestClientIPHonoursForwardedForFromTrustedPeer(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:44444"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.1.2.4")

	require.Equal(t, "203.0.113.5", resolver.Resolve(r))
}

func TestClientIPPicksRightmostUntrustedHop(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:44444"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 203.0.113.5, 10.1.2.4, 10.1.2.5")

	require.Equal(t, "203.0.113.5", resolver.Resolve(r))
}

func TestClientIPFallsBackToRealIPHeader(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:44444"
	r.Header.Set("X-Real-IP", "203.0.113.77")

	require.Equal(t, "203.0.113.77", resolver.Resolve(r))
}

func TestClientIPFallsBackToPeerWhenEveryHopIsTrusted(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:44444"
	r.Header.Set("X-Forwarded-For", "10.1.2.4, 10.1.2.5")

	require.Equal(t, "10.1.2.3", resolver.Resolve(r))
}

func TestClientIPSkipsGarbageHops(t *testing.T) {
	t.Parallel()

	resolver := NewClientIPResolver(mustCIDRs(t, "10.0.0.0/8"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:44444"
	r.Header.Set("X-Forwarded-For", "203.0.113.5, unknown, not-an-ip")

	require.Equal(t, "203.0.113.5", resolver.Resolve(r))
}

func TestClientIPMiddlewarePopulatesContext(t *testing.T) {
	t.Parallel()

	var seen string
	handler := ClientIP(NewClientIPResolver(nil))(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = httpx.ClientIP(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.44:1234"
	handler.ServeHTTP(httptest.NewRecorder(), r)

	require.Equal(t, "192.0.2.44", seen)
}
