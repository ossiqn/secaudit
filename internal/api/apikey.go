package api

import (
	"net/http"
	"os"
	"strings"
)

type APIKeyGuard struct {
	keys map[string]bool
}

func NewAPIKeyGuard() *APIKeyGuard {
	g := &APIKeyGuard{keys: make(map[string]bool)}
	raw := os.Getenv("SECAUDIT_API_KEYS")
	if raw != "" {
		for _, k := range strings.Split(raw, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				g.keys[k] = true
			}
		}
	}
	return g
}

func (g *APIKeyGuard) Enabled() bool {
	return len(g.keys) > 0
}

func (g *APIKeyGuard) Valid(key string) bool {
	if !g.Enabled() {
		return true
	}
	return g.keys[key]
}

func (g *APIKeyGuard) Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.Enabled() {
			next(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if !g.Valid(key) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "gecersiz veya eksik api anahtari"})
			return
		}
		next(w, r)
	}
}
