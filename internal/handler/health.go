package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/ubpon/golang-api-boilerplate/internal/httpx"
	"github.com/ubpon/golang-api-boilerplate/internal/logging"
)

type Probe struct {
	Name  string
	Check func(ctx context.Context) error
}

type Health struct {
	version string
	probes  []Probe
	timeout time.Duration
}

func NewHealth(version string, timeout time.Duration, probes ...Probe) *Health {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &Health{version: version, probes: probes, timeout: timeout}
}

type healthResponse struct {
	Status  string            `json:"status"`
	Version string            `json:"version"`
	Checks  map[string]string `json:"checks,omitempty"`
}

func (h *Health) Live(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, r, http.StatusOK, healthResponse{Status: "ok", Version: h.version})
}

func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	checks := make(map[string]string, len(h.probes))
	healthy := true
	for _, probe := range h.probes {
		if err := probe.Check(ctx); err != nil {
			healthy = false
			checks[probe.Name] = "unavailable"
			logging.FromContext(ctx).Warn("readiness probe failed",
				slog.String("probe", probe.Name), slog.Any("error", err))
			continue
		}
		checks[probe.Name] = "ok"
	}

	if !healthy {
		httpx.WriteJSON(w, r, http.StatusServiceUnavailable, healthResponse{
			Status: "degraded", Version: h.version, Checks: checks,
		})
		return
	}
	httpx.WriteJSON(w, r, http.StatusOK, healthResponse{
		Status: "ok", Version: h.version, Checks: checks,
	})
}
