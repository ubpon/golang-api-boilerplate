package ratelimit

import (
	"math"
	"net/http"
	"strconv"
	"time"
)

const (
	HeaderLimit      = "X-RateLimit-Limit"
	HeaderRemaining  = "X-RateLimit-Remaining"
	HeaderReset      = "X-RateLimit-Reset"
	HeaderRetryAfter = "Retry-After"
)

func WriteHeaders(w http.ResponseWriter, d Decision) {
	h := w.Header()
	// Assigning directly preserves the documented mixed-case spelling; Header.Set
	// would canonicalise these to X-Ratelimit-*.
	h[HeaderLimit] = []string{strconv.Itoa(d.Limit)}
	h[HeaderRemaining] = []string{strconv.Itoa(d.Remaining)}
	h[HeaderReset] = []string{strconv.Itoa(seconds(d.ResetAfter))}
	if !d.Allowed {
		h.Set(HeaderRetryAfter, strconv.Itoa(seconds(d.RetryAfter)))
	}
}

func seconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
