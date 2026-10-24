package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bishoku/jvmdiag/v3/internal/ai"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/gclog"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/incident"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/jfr"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/mat"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/nmtcrash"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/threaddump"
	"github.com/bishoku/jvmdiag/v3/internal/capture"
	"github.com/bishoku/jvmdiag/v3/internal/config"
	"github.com/bishoku/jvmdiag/v3/internal/mcp"
	"github.com/bishoku/jvmdiag/v3/internal/model"
	"github.com/bishoku/jvmdiag/v3/internal/store"
)

//go:embed assets/*
var embeddedAssets embed.FS

type Server struct {
	access    accessConfig
	cfg       *config.Manager
	store     *store.Store
	matSvc    *mat.Service
	mcpServer *mcp.Server
	aiSvc     *ai.Service
	uploadDir string
}

func NewServer(cfg *config.Manager, st *store.Store, matSvc *mat.Service, mcpServer *mcp.Server, aiSvc *ai.Service) *Server {
	upDir := filepath.Join(cfg.BaseDir(), "uploads")
	_ = os.MkdirAll(upDir, 0o755)
	return &Server{
		access:    loadAccessConfig(),
		cfg:       cfg,
		store:     st,
		matSvc:    matSvc,
		mcpServer: mcpServer,
		aiSvc:     aiSvc,
		uploadDir: upDir,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static CSS
	cssSub, _ := fs.Sub(embeddedAssets, "assets/css")
	mux.Handle("GET /css/", http.StripPrefix("/css/", http.FileServer(http.FS(cssSub))))
	jsSub, _ := fs.Sub(embeddedAssets, "assets/js")
	mux.Handle("GET /js/", http.StripPrefix("/js/", http.FileServer(http.FS(jsSub))))

	// UI Routes (all served by embedded SPA shell)
	uiPaths := []string{
		"GET /{$}",
		"GET /heap",
		"GET /thread-dump",
		"GET /gc-log",
		"GET /crash",
		"GET /jfr",
		"GET /capture",
		"GET /diff",
		"GET /incident",
		"GET /settings",
		"GET /setup",
		"GET /history/{id}",
	}
	for _, pat := range uiPaths {
		mux.HandleFunc(pat, s.serveAppHTML)
	}

	// GET /mcp serves the Web UI for browsers (Accept: text/html), and returns 405 Method Not Allowed
	// for MCP Streamable HTTP clients probing GET for SSE streams.
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, r *http.Request) {
		accept := r.Header.Get("Accept")
		if r.Header.Get(mcp.HeaderMcpSessionID) != "" || (strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "text/html")) {
			ws := resolveWorkspace(r)
			s.mcpServer.HandleStreamableHTTP(w, r, ws, "")
			return
		}
		s.serveAppHTML(w, r)
	})

	// Settings & Prompts API
	mux.HandleFunc("GET /api/settings", s.handleGetSettings)
	mux.HandleFunc("POST /api/settings", s.handleSaveSettings)
	mux.HandleFunc("POST /api/settings/test", s.handleTestSettings)
	mux.HandleFunc("GET /api/workspaces", s.handleListWorkspaces)
	mux.HandleFunc("GET /api/prompts/{type}", s.handleGetPrompt)
	mux.HandleFunc("POST /api/prompts/{type}", s.handleSavePrompt)
	mux.HandleFunc("DELETE /api/prompts/{type}", s.handleResetPrompt)

	// MAT API
	mux.HandleFunc("GET /api/mat/status", s.handleMatStatus)
	mux.HandleFunc("GET /api/mat/config", s.handleMatConfig)
	mux.HandleFunc("POST /api/mat/download", s.handleMatDownload)

	// Analysis Upload & Status API
	mux.HandleFunc("POST /api/heap/upload", s.handleUploadHeap)
	mux.HandleFunc("POST /api/thread-dump/upload", s.handleUploadThreadDump)
	mux.HandleFunc("POST /api/gc-log/upload", s.handleUploadGCLog)
	mux.HandleFunc("POST /api/crash/upload", s.handleUploadCrashNMT)
	mux.HandleFunc("POST /api/jfr/upload", s.handleUploadJFR)
	mux.HandleFunc("POST /api/diff/upload", s.handleUploadDiff)
	mux.HandleFunc("POST /api/incident/upload", s.handleUploadIncident)
	mux.HandleFunc("GET /api/jvm/processes", s.handleListJVMProcesses)
	mux.HandleFunc("POST /api/jvm/capture", s.handleCaptureLiveJVM)
	mux.HandleFunc("GET /api/analysis/{id}/status", s.handleAnalysisStatus)
	mux.HandleFunc("POST /api/analysis/{id}/ai", s.handleRerunAI)
	mux.HandleFunc("POST /api/analysis/{id}/save", s.handleSaveAnalysis)

	// History API
	mux.HandleFunc("GET /api/history", s.handleListHistory)
	mux.HandleFunc("GET /api/history/{id}", s.handleGetHistory)
	mux.HandleFunc("DELETE /api/history/{id}", s.handleDeleteHistory)

	// MCP & Interactive Chat API
	mux.HandleFunc("POST /api/mcp/upload", s.handleMcpUpload)
	mux.HandleFunc("GET /api/mcp/status", s.handleMcpStatus)
	mux.HandleFunc("DELETE /api/mcp/session", s.handleMcpCloseSession)
	mux.HandleFunc("GET /api/mcp/chat", s.handleMcpGetChat)
	mux.HandleFunc("POST /api/mcp/chat", s.handleMcpChat)
	mux.HandleFunc("DELETE /api/mcp/chat", s.handleMcpClearChat)
	mux.HandleFunc("GET /api/mcp/{sessionId}/logs/recent", s.handleMcpRecentLogs)

	// MCP Streamable HTTP Transport Endpoints (MCP 2025-03-26 specification, no SSE)
	for _, method := range []string{"POST", "DELETE", "OPTIONS"} {
		mux.HandleFunc(method+" /mcp", func(w http.ResponseWriter, r *http.Request) {
			ws := resolveWorkspace(r)
			s.mcpServer.HandleStreamableHTTP(w, r, ws, "")
		})
	}
	for _, method := range []string{"GET", "POST", "DELETE", "OPTIONS"} {
		mux.HandleFunc(method+" /mcp/http", func(w http.ResponseWriter, r *http.Request) {
			ws := resolveWorkspace(r)
			s.mcpServer.HandleStreamableHTTP(w, r, ws, "")
		})
		mux.HandleFunc(method+" /mcp/{sessionId}", func(w http.ResponseWriter, r *http.Request) {
			ws := resolveWorkspace(r)
			sid := r.PathValue("sessionId")
			s.mcpServer.HandleStreamableHTTP(w, r, ws, sid)
		})
	}

	return s.secureHandler(mux)
}

func (s *Server) serveAppHTML(w http.ResponseWriter, r *http.Request) {
	data, err := embeddedAssets.ReadFile("assets/app.html")
	if err != nil {
		http.Error(w, "UI asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// Settings Handlers

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	aiCfg, hasOverride := s.cfg.GetEffectiveConfig(ws)
	maskedKey := s.cfg.MaskedAPIKey(ws)
	if !s.isAdmin(r) && !hasOverride {
		maskedKey = "Server managed"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"workspace":            ws,
		"multiUserMode":        s.cfg.IsMultiUser(),
		"canManageGlobal":      s.isAdmin(r),
		"configured":           s.cfg.IsConfigured(ws),
		"hasWorkspaceOverride": hasOverride,
		"maskedApiKey":         maskedKey,
		"baseUrl":              aiCfg.BaseURL,
		"model":                aiCfg.Model,
		"temperature":          aiCfg.Temperature,
		"trustInsecureCerts":   aiCfg.TrustInsecureCerts,
		"configFile":           s.cfg.ConfigFilePath(ws),
	})
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON body"})
		return
	}

	temp, err := strconv.ParseFloat(body["temperature"], 64)
	if err != nil || temp <= 0 {
		temp = config.DefaultTemperature
	}
	insecure := body["trustInsecureCerts"] == "true"
	applyGlobal := body["applyGlobal"] == "true"
	if applyGlobal && !s.isAdmin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "Administrator access required for global settings"})
		return
	}
	if !s.isAdmin(r) {
		base, _ := s.cfg.GetEffectiveConfig(config.DefaultWorkspace)
		if (body["baseUrl"] != "" && strings.TrimSpace(body["baseUrl"]) != base.BaseURL) || (body["trustInsecureCerts"] != "" && insecure != base.TrustInsecureCerts) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "Only administrators may change the AI endpoint or TLS policy"})
			return
		}
		body["baseUrl"] = base.BaseURL
		insecure = base.TrustInsecureCerts
	}
	// Local default workspace remains the global settings scope.
	if !s.cfg.IsMultiUser() && ws == config.DefaultWorkspace {
		applyGlobal = true
	}

	cfg := config.AIConfig{
		APIKey:             strings.TrimSpace(body["apiKey"]),
		BaseURL:            strings.TrimSpace(body["baseUrl"]),
		Model:              strings.TrimSpace(body["model"]),
		Temperature:        temp,
		TrustInsecureCerts: insecure,
	}

	if err := s.cfg.SaveConfig(ws, cfg, applyGlobal); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, config.ErrInvalidConfig) {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]any{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":    "Settings saved successfully.",
		"configured": s.cfg.IsConfigured(ws),
	})
}

func (s *Server) handleTestSettings(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	if !s.cfg.IsConfigured(ws) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "AI is not configured. Save your API key first."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	resp, err := s.aiSvc.Complete(ctx, ws, "You are a connectivity test assistant.", "Respond with: CONNECTION_OK")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "error",
			"message": "Connection failed: " + err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"message":  "Connection successful!",
		"response": resp,
	})
}

func (s *Server) handleListWorkspaces(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		writeJSON(w, http.StatusOK, map[string]any{"workspaces": []string{resolveWorkspace(r)}, "currentWorkspace": resolveWorkspace(r)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"workspaces": s.store.ListWorkspaces(),
	})
}

// Prompts Handlers

func (s *Server) handleGetPrompt(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	pType := r.PathValue("type")
	defPrompt, err := s.aiSvc.DefaultPrompt(pType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	curr, _ := s.aiSvc.EffectivePrompt(ws, pType)
	writeJSON(w, http.StatusOK, map[string]any{
		"type":     pType,
		"current":  curr,
		"default":  defPrompt,
		"isCustom": s.cfg.GetCustomPrompt(ws, pType) != "",
	})
}

func (s *Server) handleSavePrompt(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	if ws == config.DefaultWorkspace && !s.isAdmin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "Administrator access required for global prompts"})
		return
	}
	pType := r.PathValue("type")
	if _, err := s.aiSvc.DefaultPrompt(pType); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	content := strings.TrimSpace(body["content"])
	if content == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Prompt content is required"})
		return
	}
	if err := s.cfg.SaveCustomPrompt(ws, pType, content); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"message": "Custom prompt saved.", "isCustom": true})
}

func (s *Server) handleResetPrompt(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	if ws == config.DefaultWorkspace && !s.isAdmin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "Administrator access required for global prompts"})
		return
	}
	pType := r.PathValue("type")
	defPrompt, err := s.aiSvc.DefaultPrompt(pType)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = s.cfg.ResetCustomPrompt(ws, pType)
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "Prompt reset to default.",
		"isCustom": false,
		"current":  defPrompt,
	})
}

// MAT Handlers

func (s *Server) handleMatStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.matSvc.Status())
}

func (s *Server) handleMatConfig(w http.ResponseWriter, r *http.Request) {
	sz, _ := strconv.ParseInt(r.URL.Query().Get("fileSizeBytes"), 10, 64)
	finalHeap := "0m"
	if sz > 0 {
		finalHeap = s.matSvc.CalculateMatHeap(sz)
	}
	writeJSON(w, http.StatusOK, map[string]any{"finalHeapSize": finalHeap})
}

func (s *Server) handleMatDownload(w http.ResponseWriter, r *http.Request) {
	if s.matSvc.IsAvailable() {
		writeJSON(w, http.StatusOK, map[string]any{"message": "MAT is already installed."})
		return
	}
	go func() {
		_ = s.matSvc.DownloadAndInstall()
	}()
	writeJSON(w, http.StatusOK, map[string]any{"message": "MAT download started in background."})
}

// Upload & Async Pipeline Handlers

func (s *Server) handleUploadHeap(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	savedPath, origName, size, formVals, err := s.streamSingleUpload(r, jobID, "heap.hprof")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !strings.HasSuffix(strings.ToLower(origName), ".hprof") {
		_ = os.RemoveAll(filepath.Dir(savedPath))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Expected a .hprof file."})
		return
	}
	useDeepMat := formVals["deepMat"] == "true"

	state := model.NewAnalysisState(jobID, ws, origName, model.AnalysisHeapDump, size)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(filepath.Dir(savedPath))

		state.SetStatus(model.StatusAnalyzing)
		report, summary, engine, err := mat.AnalyzeHeapHybrid(context.Background(), s.matSvc, savedPath, useDeepMat)
		if err != nil {
			state.SetError(err.Error())
			return
		}
		if summary != nil {
			state.SetAssessment(summary.Assessment)
		}
		state.SetStaticReport(report, engine)
		s.completeWithAI(ws, ai.PromptHeapDump, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   origName,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleUploadThreadDump(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	savedPath, origName, size, _, err := s.streamSingleUpload(r, jobID, "thread-dump.txt")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	state := model.NewAnalysisState(jobID, ws, origName, model.AnalysisThreadDump, size)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(filepath.Dir(savedPath))

		state.SetStatus(model.StatusAnalyzing)
		report, _, err := threaddump.AnalyzeFile(savedPath)
		if err != nil {
			state.SetError(err.Error())
			return
		}
		state.SetStaticReport(report, "native-threaddump")
		s.completeWithAI(ws, ai.PromptThreadDump, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   origName,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleUploadGCLog(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	savedPath, origName, size, _, err := s.streamSingleUpload(r, jobID, "gc.log")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	state := model.NewAnalysisState(jobID, ws, origName, model.AnalysisGCLog, size)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(filepath.Dir(savedPath))

		state.SetStatus(model.StatusAnalyzing)
		report, _, err := gclog.AnalyzeFile(savedPath)
		if err != nil {
			state.SetError(err.Error())
			return
		}
		state.SetStaticReport(report, "native-gclog")
		s.completeWithAI(ws, ai.PromptGCLog, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   origName,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleUploadDiff(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	jobDir := filepath.Join(s.uploadDir, jobID)
	_ = os.MkdirAll(jobDir, 0o755)

	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Multipart form required"})
		return
	}

	var savedPaths []string
	var fileNames []string
	var totalSize int64

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if part.FileName() == "" {
			part.Close()
			continue
		}
		fname := filepath.Base(part.FileName())
		dest := filepath.Join(jobDir, fmt.Sprintf("%d_%s", len(savedPaths)+1, fname))
		out, err := os.Create(dest)
		if err != nil {
			part.Close()
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		n, _ := io.Copy(out, part)
		out.Close()
		part.Close()
		savedPaths = append(savedPaths, dest)
		fileNames = append(fileNames, fname)
		totalSize += n
	}

	if len(savedPaths) < 2 {
		_ = os.RemoveAll(jobDir)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "At least 2 files are required for diff analysis"})
		return
	}

	label := strings.Join(fileNames, " vs ")
	state := model.NewAnalysisState(jobID, ws, label, model.AnalysisDiff, totalSize)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(jobDir)

		state.SetStatus(model.StatusAnalyzing)
		var report string
		var err error
		var engine string
		if strings.HasSuffix(strings.ToLower(savedPaths[0]), ".hprof") {
			engine = "native-hprof-diff"
			report, err = hprof.CompareFiles(savedPaths[0], savedPaths[1])
		} else {
			engine = "native-threaddump-diff"
			report, err = threaddump.CompareFiles(savedPaths)
		}
		if err != nil {
			state.SetError(err.Error())
			return
		}
		state.SetStaticReport(report, engine)
		s.completeWithAI(ws, ai.PromptDiff, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   label,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleUploadIncident(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	jobDir := filepath.Join(s.uploadDir, jobID)
	_ = os.MkdirAll(jobDir, 0o755)

	mr, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Multipart form required"})
		return
	}

	var incInput incident.Input
	var names []string
	var totalSize int64

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if part.FileName() == "" {
			part.Close()
			continue
		}
		field := part.FormName()
		fname := filepath.Base(part.FileName())
		dest := filepath.Join(jobDir, fmt.Sprintf("%s_%d_%s", field, len(names)+1, fname))
		out, err := os.Create(dest)
		if err != nil {
			part.Close()
			continue
		}
		n, _ := io.Copy(out, part)
		out.Close()
		part.Close()
		totalSize += n
		names = append(names, fname)

		switch field {
		case "gcFile":
			incInput.GCLogPath = dest
		case "threadFiles":
			incInput.ThreadDumpPaths = append(incInput.ThreadDumpPaths, dest)
		case "heapFile":
			incInput.HeapDumpPath = dest
		}
	}

	if len(names) == 0 {
		_ = os.RemoveAll(jobDir)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "At least one file is required for incident analysis"})
		return
	}

	label := "Incident: " + strings.Join(names, " + ")
	state := model.NewAnalysisState(jobID, ws, label, model.AnalysisIncident, totalSize)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(jobDir)

		state.SetStatus(model.StatusAnalyzing)
		report, err := incident.Analyze(context.Background(), s.matSvc, incInput)
		if err != nil {
			state.SetError(err.Error())
			return
		}
		state.SetStaticReport(report, "incident-correlation")
		s.completeWithAI(ws, ai.PromptIncident, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   label,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) completeWithAI(ws, promptType, staticReport string, state *model.AnalysisState) {
	if snap := state.Snapshot(); snap.Assessment != nil && len(snap.Assessment.Findings) == 0 {
		state.SetAIResponse("> AI interpretation skipped: no supported runtime findings are available. See the report scope and missing-data warnings.")
		state.SetStatus(model.StatusCompleted)
		return
	}
	if !s.cfg.IsConfigured(ws) {
		log.Printf("[AI] Skipping LLM call for job %s (workspace=%s): API key not configured", state.ID, ws)
		state.SetAIResponse("> ⚠️ **AI (LLM) API Anahtarı Yapılandırılmamış:** Şu an yalnızca statik motor analiz raporu üretildi. Yapay zeka kök neden analizini (LLM) etkinleştirmek için sağ üstteki **⚙ Settings** (`/settings`) sayfasından OpenRouter / OpenAI API anahtarınızı kaydedin, ardından aşağıdaki **🔄 Re-run AI Analysis** butonuna tıklayın.")
		state.SetStatus(model.StatusCompleted)
		return
	}

	aiCfg, _ := s.cfg.GetEffectiveConfig(ws)
	log.Printf("[AI] Sending %s report (%d chars) to model %s (workspace=%s)...", promptType, len(staticReport), aiCfg.Model, ws)
	state.SetStatus(model.StatusGeneratingAIResponse)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	aiResp, err := s.aiSvc.AnalyzeReport(ctx, ws, promptType, staticReport)
	if err != nil {
		log.Printf("[AI] ERROR for job %s: %v", state.ID, err)
		state.SetAIResponse(fmt.Sprintf("> ❌ **AI (LLM) Hatası:** `%s`\n>\n> Lütfen **⚙ Settings** (`/settings`) sayfasından API anahtarınızı, Base URL ve Model ayarlarınızı kontrol edip **🔄 Re-run AI Analysis** butonuna tıklayın.", err.Error()))
		state.SetStatus(model.StatusCompleted)
		return
	}
	log.Printf("[AI] Received LLM diagnosis for job %s (%d chars)", state.ID, len(aiResp))
	state.SetAIResponse(aiResp)
	state.SetStatus(model.StatusCompleted)
}

func (s *Server) handleRerunAI(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	id := r.PathValue("id")
	job := s.store.GetJob(resolveWorkspace(r), id)
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Analysis job not found"})
		return
	}
	snap := job.Snapshot()
	if snap.StaticReport == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Static report is not ready yet"})
		return
	}

	promptType := promptTypeForAnalysis(snap.AnalysisType)
	job.SetAIResponse("")
	job.SetStatus(model.StatusGeneratingAIResponse)

	go func() {
		s.completeWithAI(ws, promptType, snap.StaticReport, job)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": id,
		"status":     model.StatusGeneratingAIResponse,
	})
}

func promptTypeForAnalysis(aType model.AnalysisType) string {
	switch aType {
	case model.AnalysisHeapDump:
		return ai.PromptHeapDump
	case model.AnalysisThreadDump:
		return ai.PromptThreadDump
	case model.AnalysisGCLog:
		return ai.PromptGCLog
	case model.AnalysisNMTCrash:
		return ai.PromptNMTCrash
	case model.AnalysisJFR:
		return ai.PromptJFR
	case model.AnalysisDiff:
		return ai.PromptDiff
	case model.AnalysisIncident:
		return ai.PromptIncident
	default:
		return ai.PromptHeapDump
	}
}

func (s *Server) handleUploadCrashNMT(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	savedPath, origName, size, _, err := s.streamSingleUpload(r, jobID, "hs_err_or_nmt.log")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	state := model.NewAnalysisState(jobID, ws, origName, model.AnalysisNMTCrash, size)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(filepath.Dir(savedPath))

		state.SetStatus(model.StatusAnalyzing)
		report, sum, err := nmtcrash.AnalyzeFile(savedPath)
		if err != nil {
			state.SetError(err.Error())
			return
		}
		engine := "native-nmt-crash"
		if sum != nil && sum.ReportType != "" {
			engine = strings.ToLower(sum.ReportType)
		}
		state.SetStaticReport(report, engine)
		s.completeWithAI(ws, ai.PromptNMTCrash, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   origName,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleUploadJFR(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	jobID := newUUID()
	savedPath, origName, size, _, err := s.streamSingleUpload(r, jobID, "recording.jfr")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	state := model.NewAnalysisState(jobID, ws, origName, model.AnalysisJFR, size)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()
		defer os.RemoveAll(filepath.Dir(savedPath))

		state.SetStatus(model.StatusAnalyzing)
		report, sum, err := jfr.AnalyzeFile(savedPath)
		if sum != nil {
			state.SetAssessment(sum.Assessment)
		}
		if err != nil {
			state.SetError(err.Error())
			return
		}
		engine := "native-jfr"
		if sum != nil && sum.EngineUsed != "" {
			engine = sum.EngineUsed
		}
		state.SetStaticReport(report, engine)
		s.completeWithAI(ws, ai.PromptJFR, report, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   origName,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleListJVMProcesses(w http.ResponseWriter, r *http.Request) {
	procs, err := capture.ListProcesses(r.Context())
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"processes": []capture.JVMProcess{},
			"error":     err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"processes": procs,
	})
}

func (s *Server) handleCaptureLiveJVM(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	var body struct {
		PID      int  `json:"pid"`
		Count    int  `json:"count"`
		Interval int  `json:"intervalSeconds"`
		WithHeap bool `json:"withHeap"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Valid PID is required"})
		return
	}
	if body.Count <= 0 {
		body.Count = 3
	}
	if body.Interval <= 0 {
		body.Interval = 2
	}

	jobID := newUUID()
	label := fmt.Sprintf("Live JVM Capture (PID %d, %d snapshots)", body.PID, body.Count)
	state := model.NewAnalysisState(jobID, ws, label, model.AnalysisIncident, 0)
	state.SetStatus(model.StatusQueued)
	s.store.RegisterJob(state)

	go func() {
		s.store.AcquireWorker()
		defer s.store.ReleaseWorker()

		state.SetStatus(model.StatusAnalyzing)
		outDir := filepath.Join(s.uploadDir, "capture-"+jobID)
		defer os.RemoveAll(outDir)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		bundle, err := capture.CaptureBundle(ctx, capture.Options{
			PID:       body.PID,
			Count:     body.Count,
			Interval:  time.Duration(body.Interval) * time.Second,
			WithHeap:  body.WithHeap,
			OutputDir: outDir,
		})
		if err != nil {
			state.SetError(err.Error())
			return
		}

		rep, err := incident.Analyze(ctx, s.matSvc, incident.Input{
			ThreadDumpPaths: bundle.ThreadDumpPaths,
			NMTCrashPath:    bundle.NMTCrashPath,
			HeapDumpPath:    bundle.HeapDumpPath,
		})
		if err != nil {
			state.SetError(err.Error())
			return
		}
		state.SetStaticReport(rep, "live-jvm-capture")
		s.completeWithAI(ws, ai.PromptIncident, rep, state)
	}()

	writeJSON(w, http.StatusOK, map[string]any{
		"analysisId": jobID,
		"fileName":   label,
		"status":     state.Snapshot().Status,
	})
}

func (s *Server) handleAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job := s.store.GetJob(resolveWorkspace(r), id)
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Analysis job not found"})
		return
	}
	writeJSON(w, http.StatusOK, job.Snapshot())
}

func (s *Server) handleSaveAnalysis(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	id := r.PathValue("id")
	job := s.store.GetJob(resolveWorkspace(r), id)
	if job == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Analysis job not found"})
		return
	}
	snap := job.Snapshot()
	if snap.Status != model.StatusCompleted {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Can only save completed analyses"})
		return
	}
	if snap.WorkspaceID == "" {
		snap.WorkspaceID = ws
	}
	rec := s.store.SaveHistory(model.RecordFromState(snap))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Analysis saved successfully.",
		"id":      rec.ID,
	})
}

func (s *Server) handleListHistory(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	list := s.store.ListHistory(ws)
	if list == nil {
		list = []model.AnalysisRecord{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleGetHistory(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	id := r.PathValue("id")
	rec, ok := s.store.FindHistory(ws, id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Record not found"})
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleDeleteHistory(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	id := r.PathValue("id")
	if s.store.DeleteHistory(ws, id) {
		writeJSON(w, http.StatusOK, map[string]any{"message": "Record deleted."})
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "Record not found"})
}

// MCP & Chat Handlers

func (s *Server) handleMcpUpload(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	sessionID := newUUID()
	savedPath, origName, size, formVals, err := s.streamSingleUpload(r, "mcp-"+sessionID, "dump.hprof")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !strings.HasSuffix(strings.ToLower(origName), ".hprof") {
		_ = os.RemoveAll(filepath.Dir(savedPath))
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Expected a .hprof file."})
		return
	}

	useDeepMat := formVals["deepMat"] == "true"
	s.store.CreateHeapSession(ws, sessionID, origName, savedPath, size, useDeepMat)

	writeJSON(w, http.StatusOK, map[string]any{
		"sessionId":   sessionID,
		"workspaceId": ws,
		"fileName":    origName,
		"message":     "Heap dump uploaded. Native HPROF parsing started.",
	})
}

func (s *Server) handleMcpStatus(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	sess := s.store.GetActiveSession(ws)
	resp := map[string]any{
		"active":                false,
		"workspaceId":           ws,
		"sessionTimeoutMinutes": 120,
		"mcpEnabled":            true,
		"mcpProtocol":           "streamable-http",
		"mcpEndpoint":           fmt.Sprintf("http://%s/mcp?workspace=%s", r.Host, ws),
	}
	if sess != nil {
		for k, v := range sess.StatusMap(120) {
			resp[k] = v
		}
		resp["mcpEndpoint"] = fmt.Sprintf("http://%s/mcp/%s?workspace=%s", r.Host, sess.SessionID, ws)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleMcpCloseSession(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	sid := r.URL.Query().Get("sessionId")
	if !s.requireSession(w, r, sid) {
		return
	}
	s.aiSvc.ClearChatHistory(ws, sid)
	s.store.CloseSession(ws, sid)
	writeJSON(w, http.StatusOK, map[string]any{"message": "MCP session closed."})
}

func (s *Server) handleMcpGetChat(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	sid := r.URL.Query().Get("sessionId")
	if !s.requireSession(w, r, sid) {
		return
	}
	if sid == "" {
		if active := s.store.GetActiveSession(ws); active != nil {
			sid = active.SessionID
		}
	}
	writeJSON(w, http.StatusOK, s.aiSvc.GetChatStatus(ws, sid))
}

func (s *Server) handleMcpClearChat(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	sid := r.URL.Query().Get("sessionId")
	if !s.requireSession(w, r, sid) {
		return
	}
	if sid == "" {
		if active := s.store.GetActiveSession(ws); active != nil {
			sid = active.SessionID
		}
	}
	s.aiSvc.ClearChatHistory(ws, sid)
	writeJSON(w, http.StatusOK, map[string]any{
		"message":   "Chat conversation memory cleared.",
		"turnCount": 0,
		"maxTurns":  ai.MaxChatTurns,
	})
}

func (s *Server) handleMcpChat(w http.ResponseWriter, r *http.Request) {
	ws := resolveWorkspace(r)
	var body struct {
		Message   string `json:"message"`
		SessionID string `json:"sessionId"`
		Stream    *bool  `json:"stream"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Invalid JSON"})
		return
	}
	if !s.requireSession(w, r, body.SessionID) {
		return
	}
	msg := strings.TrimSpace(body.Message)
	if msg == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Message cannot be empty"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Streamable HTTP NDJSON response (no SSE)
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	streamFlag := true
	if body.Stream != nil {
		streamFlag = *body.Stream
	}

	sid := body.SessionID
	if sid == "" {
		if active := s.store.GetActiveSession(ws); active != nil {
			sid = active.SessionID
		}
	}

	s.aiSvc.StreamHeapChat(r.Context(), ws, sid, msg, streamFlag, func(event string, data map[string]any) {
		b, _ := json.Marshal(map[string]any{
			"event": event,
			"data":  data,
		})
		fmt.Fprintf(w, "%s\n", string(b))
		flusher.Flush()
	})
}

func (s *Server) handleMcpRecentLogs(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sessionId")
	if !s.requireSession(w, r, sid) {
		return
	}
	writeJSON(w, http.StatusOK, s.store.GetRecentMcpLogs(sid))
}

// Helpers

func (s *Server) streamSingleUpload(r *http.Request, subDir, fallbackName string) (string, string, int64, map[string]string, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return "", "", 0, nil, fmt.Errorf("multipart form required: %w", err)
	}

	targetDir := filepath.Join(s.uploadDir, subDir)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", "", 0, nil, err
	}

	var (
		savedPath string
		origName  string
		size      int64
		formVals  = make(map[string]string)
	)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", 0, nil, err
		}
		if part.FileName() == "" {
			valBytes, _ := io.ReadAll(io.LimitReader(part, 4096))
			formVals[part.FormName()] = string(valBytes)
			part.Close()
			continue
		}
		origName = filepath.Base(part.FileName())
		if origName == "" {
			origName = fallbackName
		}
		savedPath = filepath.Join(targetDir, origName)
		out, err := os.Create(savedPath)
		if err != nil {
			part.Close()
			return "", "", 0, nil, err
		}
		n, cerr := copyPart(out, part)
		out.Close()
		part.Close()
		if cerr != nil {
			return "", "", 0, nil, cerr
		}
		size = n
	}

	if savedPath == "" {
		return "", "", 0, nil, fmt.Errorf("no file provided in request")
	}
	return savedPath, origName, size, formVals, nil
}

func copyPart(dst io.Writer, src *multipart.Part) (int64, error) {
	buf := make([]byte, 256*1024)
	return io.CopyBuffer(dst, src, buf)
}

func resolveWorkspace(r *http.Request) string {
	if ws := r.Header.Get("X-Workspace-ID"); ws != "" {
		return config.SanitizeWorkspaceID(ws)
	}
	if ws := r.URL.Query().Get("workspace"); ws != "" {
		return config.SanitizeWorkspaceID(ws)
	}
	if c, err := r.Cookie("jvmdiag_ws"); err == nil && c.Value != "" {
		return config.SanitizeWorkspaceID(c.Value)
	}
	return config.DefaultWorkspace
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}
