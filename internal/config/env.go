package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type collector struct {
	errs []string
}

func (c *collector) fail(format string, args ...any) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

func (c *collector) err() error {
	if len(c.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(c.errs, "\n  - "))
}

func (c *collector) str(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func (c *collector) required(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		c.fail("%s is required", key)
	}
	return v
}

func (c *collector) boolean(key string, fallback bool) bool {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		c.fail("%s must be a boolean, got %q", key, raw)
		return fallback
	}
	return v
}

func (c *collector) integer(key string, fallback int) int {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		c.fail("%s must be an integer, got %q", key, raw)
		return fallback
	}
	return v
}

func (c *collector) integer64(key string, fallback int64) int64 {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		c.fail("%s must be an integer, got %q", key, raw)
		return fallback
	}
	return v
}

func (c *collector) duration(key string, fallback time.Duration) time.Duration {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	v, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		c.fail("%s must be a Go duration such as 15m, got %q", key, raw)
		return fallback
	}
	if v <= 0 {
		c.fail("%s must be positive, got %q", key, raw)
		return fallback
	}
	return v
}

func (c *collector) list(key string, fallback []string) []string {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
