package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/bishoku/jvmdiag/internal/config"
	"github.com/bishoku/jvmdiag/internal/mcp"
)

type adminContextKey struct{}

type accessConfig struct {
	adminToken   string
	workspaces   map[string]string
	valid        bool
	publicOrigin string
}

func loadAccessConfig() accessConfig {
	a := accessConfig{adminToken: os.Getenv("JVMDIAG_ADMIN_TOKEN"), valid: true, publicOrigin: os.Getenv("JVMDIAG_PUBLIC_ORIGIN")}
	if a.publicOrigin != "" {
		u, err := url.Parse(a.publicOrigin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			a.valid = false
		}
	}
	raw := os.Getenv("JVMDIAG_WORKSPACE_TOKENS")
	if raw != "" {
		if json.Unmarshal([]byte(raw), &a.workspaces) != nil {
			a.valid = false
		}
	}
	seen := make(map[string]bool)
	for ws, token := range a.workspaces {
		if ws != config.SanitizeWorkspaceID(ws) || ws == "" || ws == config.DefaultWorkspace || len(token) < 32 || seen[token] || token == a.adminToken {
			a.valid = false
		}
		seen[token] = true
	}
	if a.adminToken != "" && len(a.adminToken) < 32 {
		a.valid = false
	}
	return a
}

func sameToken(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) isAdmin(r *http.Request) bool {
	if !s.cfg.IsMultiUser() {
		return true
	}
	admin, _ := r.Context().Value(adminContextKey{}).(bool)
	return admin
}

func (s *Server) secureHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		// Reject cross-origin browser requests, including against a local server.
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			sameOrigin := err == nil && u.Scheme == scheme && strings.EqualFold(u.Host, r.Host) && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
			if !sameOrigin && (s.access.publicOrigin == "" || origin != s.access.publicOrigin || !s.access.valid) {
				writeJSON(w, http.StatusForbidden, map[string]any{"error": "Cross-origin requests are not allowed"})
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Cross-site requests are not allowed"})
			return
		}
		protected := strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/mcp" && r.Method != http.MethodGet || strings.HasPrefix(r.URL.Path, "/mcp/") || r.URL.Path == "/mcp" && !strings.Contains(r.Header.Get("Accept"), "text/html")
		if !protected {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		admin := !s.cfg.IsMultiUser()
		if s.cfg.IsMultiUser() {
			if !s.access.valid || s.access.adminToken == "" && len(s.access.workspaces) == 0 {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Multi-user access tokens are not configured correctly"})
				return
			}
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				token = ""
			}
			admin = sameToken(token, s.access.adminToken)
			if !admin {
				workspace := ""
				for ws, expected := range s.access.workspaces {
					if sameToken(token, expected) {
						workspace = ws
					}
				}
				if workspace == "" {
					w.Header().Set("WWW-Authenticate", "Bearer")
					writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "A valid workspace access token is required"})
					return
				}
				// Bind all selectors to the authenticated workspace; reject conflicting selectors.
				selectors := []string{r.Header.Get("X-Workspace-ID"), r.URL.Query().Get("workspace")}
				if cookie, err := r.Cookie("jvmdiag_ws"); err == nil {
					selectors = append(selectors, cookie.Value)
				}
				for _, ws := range selectors {
					if ws != "" && ws != workspace {
						writeJSON(w, http.StatusForbidden, map[string]any{"error": "Workspace access denied"})
						return
					}
				}
				r.Header.Set("X-Workspace-ID", workspace)
			}
		}
		if !admin && (r.URL.Path == "/api/mat/download" || strings.HasPrefix(r.URL.Path, "/api/jvm/")) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Administrator access required"})
			return
		}
		ctx := context.WithValue(r.Context(), adminContextKey{}, admin)
		if !admin {
			ctx = mcp.WithoutHostAccess(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, sid string) bool {
	if sid != "" && s.store.GetSession(resolveWorkspace(r), sid) == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Session not found"})
		return false
	}
	return true
}
