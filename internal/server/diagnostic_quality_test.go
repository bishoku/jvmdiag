package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bishoku/jvmdiag/internal/testutil"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bishoku/jvmdiag/internal/analyzer/quality"
	"github.com/bishoku/jvmdiag/internal/config"
)

func TestInvalidDiagnosticsFailAndLimitedResultsStayExplicit(t *testing.T) {
	f := newSecurityFixture(t, true)
	// No provider calls are needed by these tests.
	if err := f.cfg.SaveConfig("default", config.AIConfig{APIKey: "sk-placeholder", BaseURL: "https://provider.example/v1"}, true); err != nil {
		t.Fatal(err)
	}
	validHeap := makeMiniHprof()
	limitedHeap := append([]byte(nil), validHeap...)
	// Unknown but length-delimited top-level metadata can be skipped, with an explicit warning.
	limitedHeap = append(limitedHeap, 0x88, 0, 0, 0, 0, 0, 0, 0, 0)
	for _, tc := range []struct {
		name, endpoint, filename string
		data                     []byte
		want, assessment         string
	}{
		{"truncated heap", "/api/heap/upload", "broken.hprof", validHeap[:len(validHeap)-9], "FAILED", "failed"},
		{"invalid JFR JSON", "/api/jfr/upload", "broken.json", []byte(`{"recording":{"events":[`), "FAILED", "failed"},
		{"arbitrary JFR text", "/api/jfr/upload", "broken.jfr", []byte("jdk.VirtualThreadPinned metadata is not an event"), "FAILED", "failed"},
		{"arbitrary thread text", "/api/thread-dump/upload", "broken.tdump", []byte("not JVM diagnostic data"), "FAILED", "failed"},
		{"malformed thread JSON", "/api/thread-dump/upload", "broken.json", []byte(`{"threadDump":`), "FAILED", "failed"},
		{"arbitrary native text", "/api/crash/upload", "broken.txt", []byte("not JVM diagnostic data"), "FAILED", "failed"},
		{"limited heap metadata", "/api/heap/upload", "limited.hprof", limitedHeap, "COMPLETED", "limited"},
		{"empty event export", "/api/jfr/upload", "empty.json", []byte(`{"recording":{"events":[]}}`), "COMPLETED", "limited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, err := mw.CreateFormFile("file", tc.filename)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := part.Write(tc.data); err != nil {
				t.Fatal(err)
			}
			if err := mw.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", tc.endpoint, &body)
			req.Header.Set("Content-Type", mw.FormDataContentType())
			req.Header.Set("Authorization", "Bearer "+alphaToken)
			req.Header.Set("X-Workspace-ID", "team-alpha")
			rec := httptest.NewRecorder()
			f.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("upload failed: %s", rec.Body.String())
			}
			var upload struct {
				ID string `json:"analysisId"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &upload); err != nil {
				t.Fatal(err)
			}
			var result struct {
				Status       string              `json:"status"`
				StaticReport string              `json:"staticReport"`
				AIResponse   string              `json:"aiResponse"`
				Assessment   *quality.Assessment `json:"assessment"`
			}
			if err := f.store.GetJob("team-alpha", upload.ID).Wait(testutil.Context(t)); err != nil {
				t.Fatal(err)
			}
			response := f.request("GET", "/api/analysis/"+upload.ID+"/status", alphaToken, "team-alpha", "")
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}

			if result.Status != tc.want || result.Assessment == nil || result.Assessment.Status != tc.assessment {
				t.Fatalf("incorrect data quality/status: %+v", result)
			}
			if tc.want == "FAILED" && (result.StaticReport != "" || result.AIResponse != "") {
				t.Fatal("failed parser produced a report or AI diagnosis")
			}
			if tc.assessment == "limited" && !bytes.Contains([]byte(result.StaticReport), []byte("Analysis status: limited")) {
				t.Fatal("limited analysis label missing from report")
			}
			if tc.assessment == "limited" {
				saved := f.request("POST", "/api/analysis/"+upload.ID+"/save", alphaToken, "team-alpha", "")
				history := f.request("GET", "/api/history/"+upload.ID, alphaToken, "team-alpha", "")
				if saved.Code != 200 || history.Code != 200 || !bytes.Contains(history.Body.Bytes(), []byte(`"status":"limited"`)) {
					t.Fatal("quality assessment lost when saving history")
				}
			}
		})
	}
	// A malformed heap MCP session must stay failed and unavailable to tools.
	path := writeTempDiagnostic(t, validHeap[:len(validHeap)-9])
	sess := f.store.CreateHeapSession("team-alpha", "bad-session", "bad.hprof", path, 1, false)
	if err := sess.Wait(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}
	parsed, errText, _ := sess.AnalysisData()
	if parsed || errText == "" {
		t.Fatal("bad session did not fail")
	}

}

func writeTempDiagnostic(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "test.hprof")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMCPUnsupportedCapabilityReturnsProtocolError(t *testing.T) {
	f := newSecurityFixture(t, true)
	path := writeTempDiagnostic(t, makeMiniHprof())
	sess := f.store.CreateHeapSession("team-alpha", "quality-session", "test.hprof", path, 1, false)
	if err := sess.Wait(testutil.Context(t)); err != nil {
		t.Fatal(err)
	}
	parsed, errText, _ := sess.AnalysisData()
	if !parsed || errText != "" {
		t.Fatal("session parse failed")
	}

	for _, tool := range []string{"get_dominator_tree", "run_oql_query"} {
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": map[string]any{"query": "SELECT * FROM A WHERE true"}}})
		req := httptest.NewRequest("POST", "/mcp/quality-session", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+alphaToken)
		req.Header.Set("X-Workspace-ID", "team-alpha")
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &rpc); err != nil {
			t.Fatal(err)
		}
		if !rpc.Result.IsError {
			t.Fatalf("unsupported capability reported successful: %s", rec.Body.String())
		}
	}
	if _, err := f.mcp.ExecuteTool(context.Background(), "team-beta", "quality-session", "get_largest_objects", nil); err == nil {
		t.Fatal("quality changes bypassed workspace scope")
	}
}
