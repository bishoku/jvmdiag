package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bishoku/jvmdiag/v3/internal/testutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bishoku/jvmdiag/v3/internal/ai"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/mat"
	"github.com/bishoku/jvmdiag/v3/internal/config"
	"github.com/bishoku/jvmdiag/v3/internal/mcp"
	"github.com/bishoku/jvmdiag/v3/internal/model"
	"github.com/bishoku/jvmdiag/v3/internal/server"
	"github.com/bishoku/jvmdiag/v3/internal/store"
)

const alphaToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const betaToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const adminToken = "cccccccccccccccccccccccccccccccc"

type securityFixture struct {
	handler http.Handler
	cfg     *config.Manager
	store   *store.Store
	mcp     *mcp.Server
}

func newSecurityFixture(t *testing.T, multi bool) securityFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"OPENROUTER_API_KEY", "OPENAI_API_KEY"} {
		t.Setenv(key, "sk-placeholder")
	}
	for _, key := range []string{"OPENROUTER_BASE_URL", "AI_TRUST_INSECURE_CERTS", "AI_MODEL", "MULTI_USER_MODE"} {
		t.Setenv(key, "")
	}
	t.Setenv("JVMDIAG_WORKSPACE_TOKENS", `{"team-alpha":"`+alphaToken+`","team-beta":"`+betaToken+`"}`)
	t.Setenv("JVMDIAG_ADMIN_TOKEN", adminToken)
	t.Setenv("JVMDIAG_PUBLIC_ORIGIN", "")
	cfg := config.NewManagerWithOptions(t.TempDir(), config.Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
	cfg.SetMultiUser(multi)
	if err := cfg.SaveConfig("default", config.AIConfig{APIKey: "global-provider-secret", BaseURL: "https://provider.example/v1", Model: "test-model"}, true); err != nil {
		t.Fatal(err)
	}
	matSvc := mat.NewServiceWithOptions("", cfg.BaseDir(), "", "4g", mat.Options{SkipLegacy: true})
	st := store.NewStore(cfg, matSvc)
	t.Cleanup(st.Close)
	m := mcp.NewServer(st, matSvc)
	return securityFixture{server.NewServer(cfg, st, matSvc, m, ai.NewService(cfg, m)).Handler(), cfg, st, m}
}

func (f securityFixture) request(method, path, token, ws, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ws != "" {
		req.Header.Set("X-Workspace-ID", ws)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestWorkspaceAuthentication(t *testing.T) {
	f := newSecurityFixture(t, true)
	for _, tc := range []struct {
		name, token, ws, path string
		want                  int
	}{
		{"missing", "", "team-alpha", "/api/history", 401},
		{"wrong", "wrong", "team-alpha", "/api/history", 401},
		{"own", alphaToken, "team-alpha", "/api/history", 200},
		{"bound by token", alphaToken, "", "/api/history", 200},
		{"header spoof", betaToken, "team-alpha", "/api/history", 403},
		{"query spoof", betaToken, "team-beta", "/api/history?workspace=team-alpha", 403},
		{"sanitization alias", alphaToken, "team.alpha", "/api/history", 403},
		{"admin", adminToken, "team-alpha", "/api/history", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.request("GET", tc.path, tc.token, tc.ws, "")
			if r.Code != tc.want {
				t.Fatalf("got %d: %s", r.Code, r.Body.String())
			}
		})
	}
	r := f.request("GET", "/api/workspaces", alphaToken, "team-alpha", "")
	if bytes.Contains(r.Body.Bytes(), []byte("team-beta")) {
		t.Fatal("workspace enumeration leaked another tenant")
	}
	req := httptest.NewRequest("GET", "/api/history", nil)
	req.Header.Set("Authorization", "Bearer "+alphaToken)
	req.AddCookie(&http.Cookie{Name: "jvmdiag_ws", Value: "team-beta"})
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("conflicting cookie accepted: %d", rec.Code)
	}
}

func TestResourceIDsCannotCrossWorkspaces(t *testing.T) {
	f := newSecurityFixture(t, true)
	job := model.NewAnalysisState("alpha-job", "team-alpha", "alpha.hprof", model.AnalysisHeapDump, 1)
	job.SetStaticReport("private-alpha-report", "native")
	job.SetStatus(model.StatusCompleted)
	f.store.RegisterJob(job)
	f.store.SaveHistory(model.RecordFromState(job.Snapshot()))
	path := filepath.Join(t.TempDir(), "alpha.hprof")
	if err := os.WriteFile(path, makeMiniHprof(), 0600); err != nil {
		t.Fatal(err)
	}
	sess := f.store.CreateHeapSession("team-alpha", "alpha-session", "alpha.hprof", path, 1, false)
	if err := sess.Wait(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}
	parsed, parseErr, _ := sess.AnalysisData()
	if !parsed || parseErr != "" {
		t.Fatalf("parse failed: %s", parseErr)
	}

	f.store.RecordMcpLog("alpha-session", "IN", "private-alpha-log")
	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/analysis/alpha-job/status", ""},
		{"POST", "/api/analysis/alpha-job/save", ""},
		{"POST", "/api/analysis/alpha-job/ai", ""},
		{"GET", "/api/history/alpha-job", ""},
		{"DELETE", "/api/history/alpha-job", ""},
		{"GET", "/api/mcp/alpha-session/logs/recent", ""},
		{"GET", "/api/mcp/chat?sessionId=alpha-session", ""},
		{"DELETE", "/api/mcp/chat?sessionId=alpha-session", ""},
		{"DELETE", "/api/mcp/session?sessionId=alpha-session", ""},
		{"POST", "/api/mcp/chat", `{"sessionId":"alpha-session","message":"steal data"}`},
		{"POST", "/mcp/alpha-session", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := f.request(tc.method, tc.path, betaToken, "team-beta", tc.body)
			if r.Code != 404 {
				t.Fatalf("got %d: %s", r.Code, r.Body.String())
			}
		})
	}
	if f.store.GetSession("team-alpha", "alpha-session") == nil {
		t.Fatal("foreign deletion removed session")
	}
	if f.store.GetActiveSession("team-beta") != nil || f.store.GetActiveSession("default") != nil {
		t.Fatal("active session fallback crossed workspace")
	}
	if len(f.store.ListSessions("default")) != 0 {
		t.Fatal("default workspace enumerated other sessions")
	}
	if r := f.request("GET", "/api/analysis/alpha-job/status", alphaToken, "team-alpha", ""); r.Code != 200 || !strings.Contains(r.Body.String(), "private-alpha-report") {
		t.Fatalf("owner cannot read job: %s", r.Body.String())
	}
	if r := f.request("GET", "/api/mcp/status", betaToken, "team-beta", ""); strings.Contains(r.Body.String(), "alpha-session") {
		t.Fatal("status leaked another session")
	}
	if _, err := f.mcp.ExecuteTool(context.Background(), "team-beta", "alpha-session", "get_heap_summary", nil); err == nil {
		t.Fatal("direct MCP tool crossed workspace")
	}
}

func TestSettingsAreScopedAndAdminOnly(t *testing.T) {
	f := newSecurityFixture(t, true)
	for _, body := range []string{
		`{"applyGlobal":"true","model":"stolen"}`,
		`{"baseUrl":"https://attacker.example","apiKey":"own-key"}`,
		`{"trustInsecureCerts":"true"}`,
	} {
		if r := f.request("POST", "/api/settings", alphaToken, "team-alpha", body); r.Code != 403 {
			t.Fatalf("unsafe update accepted: %d %s", r.Code, r.Body.String())
		}
	}
	// An omitted applyGlobal must update only the tenant, including when the endpoint is omitted.
	r := f.request("POST", "/api/settings", alphaToken, "team-alpha", `{"model":"alpha-model","apiKey":"alpha-secret"}`)
	if r.Code != 200 {
		t.Fatalf("tenant update failed: %s", r.Body.String())
	}
	global, _ := f.cfg.GetEffectiveConfig("default")
	alpha, _ := f.cfg.GetEffectiveConfig("team-alpha")
	beta, _ := f.cfg.GetEffectiveConfig("team-beta")
	if global.Model != "test-model" || beta.APIKey != "global-provider-secret" || alpha.APIKey != "alpha-secret" || alpha.BaseURL != global.BaseURL {
		t.Fatal("tenant update changed global settings or lost endpoint")
	}
	if r := f.request("POST", "/api/settings", adminToken, "default", `{"applyGlobal":"true","baseUrl":"https://attacker.example"}`); r.Code != 400 {
		t.Fatalf("saved key silently moved to new endpoint: %d %s", r.Code, r.Body.String())
	}
	if r := f.request("POST", "/api/settings", adminToken, "default", `{"applyGlobal":"true","baseUrl":"https://new-provider.example/v1","apiKey":"new-key"}`); r.Code != 200 {
		t.Fatalf("admin explicit provider change failed: %s", r.Body.String())
	}
	if r := f.request("GET", "/api/settings", betaToken, "team-beta", ""); strings.Contains(r.Body.String(), "global-") || strings.Contains(r.Body.String(), "new-ke") {
		t.Fatal("server managed key prefix leaked")
	}
}

func TestTenantCannotUseHostTools(t *testing.T) {
	f := newSecurityFixture(t, true)
	for _, path := range []string{"/api/jvm/processes", "/api/jvm/capture", "/api/mat/download"} {
		method := "POST"
		if strings.HasSuffix(path, "processes") {
			method = "GET"
		}
		if r := f.request(method, path, alphaToken, "team-alpha", "{}"); r.Code != 403 {
			t.Fatalf("host endpoint accessible: %s %d", path, r.Code)
		}
	}
	for _, tool := range []string{"list_local_jvms", "capture_live_jvm", "analyze_thread_dump", "diff_thread_dumps", "analyze_gc_log", "analyze_jfr", "analyze_crash_or_nmt"} {
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{"path": "/etc/passwd", "paths": []string{"a", "b"}}}})
		r := f.request("POST", "/mcp", alphaToken, "team-alpha", string(payload))
		if !strings.Contains(r.Body.String(), "administrator privileges") {
			t.Fatalf("host tool was not denied: %s %s", tool, r.Body.String())
		}
	}
}

func TestCrossOriginRequestsRejected(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "shared"}[multi], func(t *testing.T) {
			f := newSecurityFixture(t, multi)
			for _, origin := range []string{"https://evil.example", "null", "http://example.com.evil", "http://example.com@evil.example"} {
				req := httptest.NewRequest("POST", "http://example.com/api/settings", strings.NewReader(`{"model":"stolen"}`))
				req.Header.Set("Origin", origin)
				req.Header.Set("Authorization", "Bearer "+adminToken)
				rec := httptest.NewRecorder()
				f.handler.ServeHTTP(rec, req)
				if rec.Code != 403 {
					t.Fatalf("origin %q accepted: %d", origin, rec.Code)
				}
			}
			req := httptest.NewRequest("GET", "http://example.com/api/history", nil)
			req.Header.Set("Origin", "http://example.com")
			req.Header.Set("Authorization", "Bearer "+alphaToken)
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatalf("same origin rejected: %d", rec.Code)
			}
		})
	}
}

func TestMultiUserFailsClosedForBadTokenConfiguration(t *testing.T) {
	for _, raw := range []string{"", `{`, `{"team-alpha":"short"}`, `{"team-alpha":"` + alphaToken + `","team-beta":"` + alphaToken + `"}`, `{"default":"` + alphaToken + `"}`} {
		t.Run(raw, func(t *testing.T) {
			f := newSecurityFixture(t, true)
			t.Setenv("JVMDIAG_WORKSPACE_TOKENS", raw)
			t.Setenv("JVMDIAG_ADMIN_TOKEN", "")
			matSvc := mat.NewServiceWithOptions("", f.cfg.BaseDir(), "", "4g", mat.Options{SkipLegacy: true})
			f.handler = server.NewServer(f.cfg, f.store, matSvc, f.mcp, ai.NewService(f.cfg, f.mcp)).Handler()
			if r := f.request("GET", "/api/history", alphaToken, "team-alpha", ""); r.Code != 503 {
				t.Fatalf("bad configuration did not fail closed: %d", r.Code)
			}
		})
	}
}

func TestMCPTransportSessionBoundToWorkspace(t *testing.T) {
	f := newSecurityFixture(t, true)
	r := f.request("POST", "/mcp", alphaToken, "team-alpha", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	sid := r.Header().Get(mcp.HeaderMcpSessionID)
	if r.Code != 200 || sid == "" {
		t.Fatalf("initialize failed: %s", r.Body.String())
	}
	for _, tc := range []struct {
		token, ws string
		want      int
	}{{alphaToken, "team-alpha", 200}, {betaToken, "team-beta", 404}} {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
		req.Header.Set("Authorization", "Bearer "+tc.token)
		req.Header.Set("X-Workspace-ID", tc.ws)
		req.Header.Set(mcp.HeaderMcpSessionID, sid)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("transport session scope: got %d want %d: %s", rec.Code, tc.want, rec.Body.String())
		}
	}
	if r := f.request("DELETE", "/mcp/"+sid, alphaToken, "team-alpha", ""); r.Code != 200 {
		t.Fatalf("session deletion failed: %d", r.Code)
	}
	if r := f.request("POST", "/mcp/"+sid, alphaToken, "team-alpha", `{"jsonrpc":"2.0","id":3,"method":"ping"}`); r.Code != 404 {
		t.Fatal("deleted transport session still valid")
	}
}

func TestExplicitPublicOriginBehindTLSProxy(t *testing.T) {
	f := newSecurityFixture(t, true)
	t.Setenv("JVMDIAG_PUBLIC_ORIGIN", "https://diag.example.com")
	matSvc := mat.NewServiceWithOptions("", f.cfg.BaseDir(), "", "4g", mat.Options{SkipLegacy: true})
	f.handler = server.NewServer(f.cfg, f.store, matSvc, f.mcp, ai.NewService(f.cfg, f.mcp)).Handler()
	for _, tc := range []struct {
		origin string
		want   int
	}{{"https://diag.example.com", 200}, {"https://evil.example", 403}} {
		req := httptest.NewRequest("GET", "http://backend:8080/api/history", nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Authorization", "Bearer "+alphaToken)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("origin %s: got %d want %d", tc.origin, rec.Code, tc.want)
		}
	}
}
