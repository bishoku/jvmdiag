package server_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"github.com/bishoku/jvmdiag/v3/internal/testutil"
	"io"
	"mime/multipart"
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
	"github.com/bishoku/jvmdiag/v3/internal/server"
	"github.com/bishoku/jvmdiag/v3/internal/store"
)

func makeMiniHprof() []byte {
	var buf bytes.Buffer
	buf.WriteString("JAVA PROFILE 1.0.2\x00")
	_ = binary.Write(&buf, binary.BigEndian, uint32(8))
	_ = binary.Write(&buf, binary.BigEndian, uint64(1700000000000))

	writeRecord := func(tag byte, payload []byte) {
		buf.WriteByte(tag)
		_ = binary.Write(&buf, binary.BigEndian, uint32(0))
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
		buf.Write(payload)
	}

	// UTF8 record for class name
	{
		var p bytes.Buffer
		_ = binary.Write(&p, binary.BigEndian, uint64(1))
		p.WriteString("com/example/LeakService")
		writeRecord(0x01, p.Bytes())
	}
	// LoadClass record
	{
		var p bytes.Buffer
		_ = binary.Write(&p, binary.BigEndian, uint32(1))
		_ = binary.Write(&p, binary.BigEndian, uint64(0x100))
		_ = binary.Write(&p, binary.BigEndian, uint32(1))
		_ = binary.Write(&p, binary.BigEndian, uint64(1))
		writeRecord(0x02, p.Bytes())
	}
	// Heap dump segment with 5 instances
	{
		var seg bytes.Buffer
		for i := 0; i < 5; i++ {
			seg.WriteByte(0x21)
			_ = binary.Write(&seg, binary.BigEndian, uint64(0x500+i))
			_ = binary.Write(&seg, binary.BigEndian, uint32(1))
			_ = binary.Write(&seg, binary.BigEndian, uint64(0x100))
			payload := make([]byte, 512)
			_ = binary.Write(&seg, binary.BigEndian, uint32(len(payload)))
			seg.Write(payload)
		}
		writeRecord(0x1C, seg.Bytes())
		writeRecord(0x2C, nil)
	}
	return buf.Bytes()
}

func TestServerMultiUserIsolationAndMcpTools(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("JVMDIAG_WORKSPACE_TOKENS", `{"team-alpha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","team-beta":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`)
	t.Setenv("JVMDIAG_ADMIN_TOKEN", "")
	t.Setenv("OPENROUTER_API_KEY", "sk-placeholder")
	t.Setenv("OPENAI_API_KEY", "sk-placeholder")
	baseDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(baseDir, "config.json"), []byte(`{"apiKey":""}`), 0o644)
	cfg := config.NewManagerWithOptions(baseDir, config.Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
	cfg.SetMultiUser(true)
	matSvc := mat.NewServiceWithOptions("", baseDir, "", "4g", mat.Options{SkipLegacy: true})
	st := store.NewStore(cfg, matSvc)
	t.Cleanup(st.Close)
	mcpSrv := mcp.NewServer(st, matSvc)
	aiSvc := ai.NewService(cfg, mcpSrv)
	srv := server.NewServer(cfg, st, matSvc, mcpSrv, aiSvc)
	h := srv.Handler()

	doReq := func(method, path, workspace, contentType string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, body)
		if workspace != "" {
			req.Header.Set("X-Workspace-ID", workspace)
			token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			if workspace == "team-beta" {
				token = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// 1. Verify UI and CSS load
	if rec := doReq(http.MethodGet, "/", "", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET / failed with status %d", rec.Code)
	}
	if rec := doReq(http.MethodGet, "/css/app.css", "", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /css/app.css failed with status %d", rec.Code)
	}

	if rec := doReq(http.MethodGet, "/js/marked.umd.js", "", "", nil); rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("marked")) {
		t.Fatal("embedded Markdown library missing")
	}
	// 2. Upload heap dump in Workspace "team-alpha"
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, _ := mw.CreateFormFile("file", "alpha.hprof")
	_, _ = part.Write(makeMiniHprof())
	mw.Close()

	upRec := doReq(http.MethodPost, "/api/heap/upload", "team-alpha", mw.FormDataContentType(), &body)
	if upRec.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", upRec.Code, upRec.Body.String())
	}
	var upData map[string]any
	_ = json.NewDecoder(upRec.Body).Decode(&upData)
	jobID := upData["analysisId"].(string)

	if err := st.GetJob("team-alpha", jobID).Wait(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}
	if state := st.GetJob("team-alpha", jobID).Snapshot(); state.Status != "COMPLETED" {
		t.Fatalf("job failed: %+v", state)
	}

	// Save to team-alpha history
	saveRec := doReq(http.MethodPost, "/api/analysis/"+jobID+"/save", "team-alpha", "", nil)
	if saveRec.Code != http.StatusOK {
		t.Fatalf("save failed: %d", saveRec.Code)
	}

	// Verify team-alpha has 1 history record, while team-beta has 0
	hAlphaRec := doReq(http.MethodGet, "/api/history", "team-alpha", "", nil)
	var alphaList []any
	_ = json.NewDecoder(hAlphaRec.Body).Decode(&alphaList)
	if len(alphaList) != 1 {
		t.Fatalf("expected 1 record in team-alpha, got %d", len(alphaList))
	}

	hBetaRec := doReq(http.MethodGet, "/api/history", "team-beta", "", nil)
	var betaList []any
	_ = json.NewDecoder(hBetaRec.Body).Decode(&betaList)
	if len(betaList) != 0 {
		t.Fatalf("expected 0 records in team-beta, got %d", len(betaList))
	}

	// 3. Test MCP Session & all 7 tools via Native HPROF Engine
	var mcpBody bytes.Buffer
	mmw := multipart.NewWriter(&mcpBody)
	mpart, _ := mmw.CreateFormFile("file", "mcp-test.hprof")
	_, _ = mpart.Write(makeMiniHprof())
	mmw.Close()

	mcpRec := doReq(http.MethodPost, "/api/mcp/upload", "team-alpha", mmw.FormDataContentType(), &mcpBody)
	var mcpData map[string]any
	_ = json.NewDecoder(mcpRec.Body).Decode(&mcpData)
	sid := mcpData["sessionId"].(string)

	if err := st.GetSession("team-alpha", sid).Wait(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}

	for _, tool := range []string{
		"get_heap_summary",
		"get_leak_suspects",
		"get_class_histogram",
		"get_largest_objects",
		"get_top_consumers",
		"get_thread_stacks",
	} {
		out, err := mcpSrv.ExecuteTool(context.Background(), "team-alpha", sid, tool, nil)
		if err != nil || out == "" {
			t.Errorf("tool %s failed: err=%v out=%q", tool, err, out)
		}
	}

	oqlOut, err := mcpSrv.ExecuteTool(context.Background(), "team-alpha", sid, "run_oql_query", map[string]any{
		"query": "SELECT * FROM com.example.LeakService",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported capability") || oqlOut != "" {
		t.Fatalf("unimplemented OQL presented as a result: %q %v", oqlOut, err)
	}

	// 4. Test MCP Streamable HTTP Transport (POST /mcp, notifications 202, GET 405 without SSE)
	initPayload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}`
	initRec := doReq(http.MethodPost, "/mcp", "team-alpha", "application/json", bytes.NewBufferString(initPayload))
	if initRec.Code != http.StatusOK {
		t.Fatalf("Streamable HTTP initialize failed: %d %s", initRec.Code, initRec.Body.String())
	}
	mcpSessHeader := initRec.Header().Get(mcp.HeaderMcpSessionID)
	if mcpSessHeader == "" {
		t.Fatalf("expected %s header on initialize response", mcp.HeaderMcpSessionID)
	}

	// Notification should return 202 Accepted with empty body
	notifPayload := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	notifReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(notifPayload))
	notifReq.Header.Set("X-Workspace-ID", "team-alpha")
	notifReq.Header.Set("Content-Type", "application/json")
	notifReq.Header.Set("Authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	notifReq.Header.Set(mcp.HeaderMcpSessionID, mcpSessHeader)
	notifRec := httptest.NewRecorder()
	h.ServeHTTP(notifRec, notifReq)
	if notifRec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for notification, got %d", notifRec.Code)
	}

	// tools/call over Streamable HTTP POST /mcp
	callPayload := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_heap_summary","arguments":{}}}`
	callReq := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(callPayload))
	callReq.Header.Set("X-Workspace-ID", "team-alpha")
	callReq.Header.Set("Content-Type", "application/json")
	callReq.Header.Set("Authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	callReq.Header.Set(mcp.HeaderMcpSessionID, mcpSessHeader)
	callRec := httptest.NewRecorder()
	h.ServeHTTP(callRec, callReq)
	if callRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tools/call, got %d: %s", callRec.Code, callRec.Body.String())
	}

	// GET on MCP endpoint with Mcp-Session-Id must return 405 Method Not Allowed (no SSE)
	getMcpReq := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	getMcpReq.Header.Set("Authorization", "Bearer aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	getMcpReq.Header.Set(mcp.HeaderMcpSessionID, mcpSessHeader)
	getMcpRec := httptest.NewRecorder()
	h.ServeHTTP(getMcpRec, getMcpReq)
	if getMcpRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed for GET /mcp (SSE disabled), got %d", getMcpRec.Code)
	}

	// Browser GET /mcp with Accept: text/html still serves the Web UI (200 OK)
	browserReq := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	browserReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	browserRec := httptest.NewRecorder()
	h.ServeHTTP(browserRec, browserReq)
	if browserRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for browser GET /mcp, got %d", browserRec.Code)
	}

	// Standalone MCP tool call (analyze_crash_or_nmt) over Streamable HTTP without needing a heap session
	nmtCallPayload := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_crash_or_nmt","arguments":{"content":"Native Memory Tracking:\nTotal: reserved=2048MB, committed=1024MB\n- Java Heap (reserved=1024MB, committed=512MB)\n- Internal (reserved=512MB, committed=512MB)\n"}}}`
	nmtCallRec := doReq(http.MethodPost, "/mcp", "team-beta", "application/json", bytes.NewBufferString(nmtCallPayload))
	if nmtCallRec.Code != http.StatusOK || !bytes.Contains(nmtCallRec.Body.Bytes(), []byte("Off-Heap Committed")) {
		t.Fatalf("expected analyze_crash_or_nmt MCP tool to succeed, got %d: %s", nmtCallRec.Code, nmtCallRec.Body.String())
	}
}
