package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bishoku/jvmdiag/internal/analyzer/gclog"
	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/internal/analyzer/jfr"
	"github.com/bishoku/jvmdiag/internal/analyzer/mat"
	"github.com/bishoku/jvmdiag/internal/analyzer/nmtcrash"
	"github.com/bishoku/jvmdiag/internal/analyzer/threaddump"
	"github.com/bishoku/jvmdiag/internal/capture"
	"github.com/bishoku/jvmdiag/internal/store"
)

const (
	// DefaultProtocolVersion is the MCP Streamable HTTP specification version.
	DefaultProtocolVersion = "2025-03-26"
	HeaderMcpSessionID     = "Mcp-Session-Id"
)

type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func Tools() []ToolDef {
	return []ToolDef{
		{
			Name:        "get_heap_summary",
			Description: "Get analysis scope, evidence, decoded object/array counts, serialized payload totals and GC root record counts. Native mode does not measure runtime heap size or verify JVM properties.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "get_leak_suspects",
			Description: "Get evidence and confidence for payload-concentration hypotheses and exact duplicate-array observations. Native mode does not compute GC root paths or prove leaks.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "get_class_histogram",
			Description: "Get classes ranked by serialized payload bytes, with an optional validated regex filter.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"topN": map[string]any{
						"type":        "integer",
						"description": "Number of top classes to return (default 30, max 200)",
					},
					"pattern": map[string]any{
						"type":        "string",
						"description": "Optional regex to filter class names, e.g. 'com\\.myapp\\..*'",
					},
				},
			},
		},
		{Name: "get_largest_objects", Description: "Rank decoded object/array serialized payloads, not runtime shallow size, dominators or retained heap.", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"topN": map[string]any{"type": "integer"}}}},
		{
			Name:        "get_dominator_tree",
			Description: "Get a MAT dominator report excerpt if available. Native mode returns unsupported; largest payloads are not dominators.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"topN": map[string]any{
						"type":        "integer",
						"description": "Number of top dominator objects to return (default 20, max 100)",
					},
				},
			},
		},
		{
			Name:        "get_top_consumers",
			Description: "Get biggest memory consumers grouped by package and class.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "run_oql_query",
			Description: "OQL is currently unsupported: a validated MAT query result adapter is required. Use get_class_histogram for class filtering.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "OQL query string starting with SELECT",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "get_thread_stacks",
			Description: "Get thread stack traces from the heap dump.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "analyze_thread_dump",
			Description: "Analyze a JVM thread dump (classic text or Java 21+ JSON format) for deadlocks, lock contention graphs, thread pool saturation, and Java 21+ Virtual Thread carrier pinning.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path to thread dump file (.txt, .tdump, .json)",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "Optional inline thread dump text if path is not provided",
					},
				},
			},
		},
		{
			Name:        "diff_thread_dumps",
			Description: "Compare 2 or more sequential thread dump files to pinpoint stuck/unmoving RUNNABLE or BLOCKED threads and thread pool deltas.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"paths": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Array of 2 or more thread dump file paths in chronological order",
					},
				},
				"required": []string{"paths"},
			},
		},
		{
			Name:        "analyze_gc_log",
			Description: "Analyze a JVM GC log (Java 8 legacy or Java 9+ unified logging) for P50/P95/P99 pause times, throughput %, allocation rate, and post-GC memory leak baseline trend.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path to the GC log file",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "analyze_crash_or_nmt",
			Description: "Analyze a JVM fatal crash log (hs_err_pid.log) or Native Memory Tracking (jcmd VM.native_memory) output for off-heap leaks, container OOMKilled causes, and native segfaults.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path to hs_err_pid.log or NMT output file",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "Optional inline hs_err or NMT text if path is not provided",
					},
				},
			},
		},
		{
			Name:        "analyze_jfr",
			Description: "Analyze a Java Flight Recorder (.jfr binary or JSON/summary export) file for CPU hot methods, TLAB object allocation hotspots, monitor contention, and virtual thread pinning.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Path to the .jfr file or JFR JSON export",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "list_local_jvms",
			Description: "List running local JVM processes (PID, Main Class, JVM arguments) available for live diagnostic capture.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "capture_live_jvm",
			Description: "Capture sequential thread dumps and Native Memory (NMT) from a running local JVM PID and return a correlated multi-snapshot diff & thread analysis report.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pid": map[string]any{
						"type":        "integer",
						"description": "Target JVM process ID (PID)",
					},
					"count": map[string]any{
						"type":        "integer",
						"description": "Number of sequential thread dumps to capture (default 3)",
					},
				},
				"required": []string{"pid"},
			},
		},
	}
}

type Server struct {
	mu                sync.Mutex
	transportSessions map[string]string
	store             *store.Store
	matSvc            *mat.Service
}

func NewServer(st *store.Store, matSvc *mat.Service) *Server {
	return &Server{
		store:             st,
		transportSessions: make(map[string]string),
		matSvc:            matSvc,
	}
}

type hostAccessKey struct{}

// WithoutHostAccess limits untrusted tenant requests to uploaded artifacts and inline content.
func WithoutHostAccess(ctx context.Context) context.Context {
	return context.WithValue(ctx, hostAccessKey{}, true)
}

func (s *Server) ResolveSessionID(ws, id string) string {
	if id != "" {
		if s.store.GetSession(ws, id) != nil {
			return id
		}
		return ""
	}
	if sess := s.store.GetActiveSession(ws); sess != nil {
		return sess.SessionID
	}
	return ""
}

// ExecuteTool runs any of the 14 JVM diagnostic tools.
func (s *Server) ExecuteTool(ctx context.Context, workspaceID, sessionID, toolName string, args map[string]any) (string, error) {
	// Standalone tools that do not require an active .hprof session
	if out, handled, err := s.executeStandaloneTool(ctx, toolName, args); handled {
		return out, err
	}

	var sess *store.HeapSession
	if sessionID != "" {
		sess = s.store.GetSession(workspaceID, sessionID)
	}
	if sessionID == "" {
		sess = s.store.GetActiveSession(workspaceID)
	}
	if sess == nil {
		return "", fmt.Errorf("no active heap dump session found (upload a .hprof file first)")
	}
	parsed, parseError, native := sess.AnalysisData()
	if !parsed {
		if parseError != "" {
			return "", fmt.Errorf("heap dump parsing failed: %s", parseError)
		}
		return "", fmt.Errorf("heap dump is still being parsed, please wait a moment")
	}

	sess.Touch()
	output := s.ExecuteOnTarget(ctx, sess.HprofPath, native, toolName, args)
	if strings.HasPrefix(output, "Error:") {
		return "", fmt.Errorf("%s", output)
	}
	return output, nil
}

func (s *Server) executeStandaloneTool(ctx context.Context, toolName string, args map[string]any) (string, bool, error) {
	if restricted, _ := ctx.Value(hostAccessKey{}).(bool); restricted {
		if strArg(args, "path") != "" || args["paths"] != nil || toolName == "capture_live_jvm" || toolName == "list_local_jvms" {
			return "", true, fmt.Errorf("host filesystem and live JVM access require administrator privileges")
		}
	}
	switch toolName {
	case "analyze_thread_dump":
		path := strArg(args, "path")
		content := strArg(args, "content")
		if path != "" {
			rep, _, err := threaddump.AnalyzeFile(path)
			return rep, true, err
		}
		if content != "" {
			rep, _, err := threaddump.AnalyzeText("inline-threaddump.txt", content)
			return rep, true, err
		}
		return "", true, fmt.Errorf("either 'path' or 'content' is required for analyze_thread_dump")

	case "diff_thread_dumps":
		var paths []string
		if rawList, ok := args["paths"].([]any); ok {
			for _, item := range rawList {
				if p, ok := item.(string); ok && strings.TrimSpace(p) != "" {
					paths = append(paths, strings.TrimSpace(p))
				}
			}
		}
		if len(paths) < 2 {
			return "", true, fmt.Errorf("'paths' array with at least 2 thread dump files is required")
		}
		rep, err := threaddump.CompareFiles(paths)
		return rep, true, err

	case "analyze_gc_log":
		path := strArg(args, "path")
		if path == "" {
			return "", true, fmt.Errorf("'path' is required for analyze_gc_log")
		}
		rep, _, err := gclog.AnalyzeFile(path)
		return rep, true, err

	case "analyze_crash_or_nmt":
		path := strArg(args, "path")
		content := strArg(args, "content")
		if path != "" {
			rep, _, err := nmtcrash.AnalyzeFile(path)
			return rep, true, err
		}
		if content != "" {
			rep, _, err := nmtcrash.AnalyzeText(content)
			return rep, true, err
		}
		return "", true, fmt.Errorf("either 'path' or 'content' is required for analyze_crash_or_nmt")

	case "analyze_jfr":
		path := strArg(args, "path")
		if path == "" {
			return "", true, fmt.Errorf("'path' is required for analyze_jfr")
		}
		rep, _, err := jfr.AnalyzeFile(path)
		return rep, true, err

	case "list_local_jvms":
		procs, err := capture.ListProcesses(ctx)
		if err != nil {
			return "", true, err
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Running Local JVM Processes (%d found):\n", len(procs)))
		for _, p := range procs {
			sb.WriteString(fmt.Sprintf("  PID %-8d  %s  %s\n", p.PID, p.MainClass, p.Args))
		}
		return sb.String(), true, nil

	case "capture_live_jvm":
		pid := intArg(args, "pid", 0, 99999999)
		count := intArg(args, "count", 3, 10)
		if pid <= 0 {
			return "", true, fmt.Errorf("valid 'pid' is required")
		}
		bundle, err := capture.CaptureBundle(ctx, capture.Options{
			PID:      pid,
			Count:    count,
			Interval: 1500 * time.Millisecond,
		})
		if err != nil {
			return "", true, err
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Captured Live JVM Bundle for PID %d (%s)\n\n", pid, strings.Join(bundle.Notes, "; ")))
		if len(bundle.ThreadDumpPaths) >= 2 {
			diffRep, err := threaddump.CompareFiles(bundle.ThreadDumpPaths)
			if err != nil {
				return "", true, fmt.Errorf("captured thread snapshot comparison failed: %w", err)
			}
			sb.WriteString(diffRep + "\n")
		}
		if len(bundle.ThreadDumpPaths) >= 1 {
			tdRep, _, err := threaddump.AnalyzeFile(bundle.ThreadDumpPaths[0])
			if err != nil {
				return "", true, fmt.Errorf("captured thread dump analysis failed: %w", err)
			}
			sb.WriteString(tdRep + "\n")
		}
		if bundle.NMTCrashPath != "" {
			nmtRep, _, err := nmtcrash.AnalyzeFile(bundle.NMTCrashPath)
			if err != nil {
				return "", true, fmt.Errorf("captured NMT analysis failed: %w", err)
			}
			sb.WriteString(nmtRep + "\n")
		}
		return sb.String(), true, nil
	}
	return "", false, nil
}

func (s *Server) ExecuteOnTarget(ctx context.Context, hprofPath string, native *hprof.Summary, toolName string, args map[string]any) string {
	if out, handled, err := s.executeStandaloneTool(ctx, toolName, args); handled {
		if err != nil {
			return "Error: " + err.Error()
		}
		return out
	}
	switch toolName {
	case "get_heap_summary":
		return s.matSvc.QueryHeapSummary(hprofPath, native)
	case "get_leak_suspects":
		return s.matSvc.QueryLeakSuspects(hprofPath, native)
	case "get_class_histogram":
		topN := intArg(args, "topN", 30, 200)
		pattern := strArg(args, "pattern")
		return s.matSvc.QueryClassHistogram(hprofPath, topN, pattern, native)
	case "get_largest_objects":
		if native == nil {
			return "Error: no native payload summary available"
		}
		return native.QueryLargestObjects(intArg(args, "topN", 20, 100))
	case "get_dominator_tree":
		topN := intArg(args, "topN", 20, 100)
		return s.matSvc.QueryDominatorTree(hprofPath, topN, native)
	case "get_top_consumers":
		return s.matSvc.QueryTopConsumers(hprofPath, native)
	case "run_oql_query":
		q := strArg(args, "query")
		return s.matSvc.RunOQLQuery(ctx, hprofPath, q, native)
	case "get_thread_stacks":
		return s.matSvc.QueryThreadStacks(hprofPath, native)
	default:
		return fmt.Sprintf("Error: Unknown tool %q", toolName)
	}
}

// JSON-RPC 2.0 structures for MCP Streamable HTTP and Stdio transports
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

func (s *Server) handleSingleRPC(ctx context.Context, workspaceID, sessionID, staticHprofPath string, staticNative *hprof.Summary, req rpcRequest) (*rpcResponse, string) {
	resolvedSessionID := sessionID
	if resolvedSessionID == "" {
		if sess := s.store.GetActiveSession(workspaceID); sess != nil {
			resolvedSessionID = sess.SessionID
		}
	}

	// JSON-RPC notifications (no ID) do not produce a response object
	if req.ID == nil && (strings.HasPrefix(req.Method, "notifications/") || req.Method == "initialized") {
		return nil, resolvedSessionID
	}
	// Client JSON-RPC responses (no Method) also do not require a response
	if req.Method == "" && req.ID != nil {
		return nil, resolvedSessionID
	}

	var res any
	var rpcErr any

	switch req.Method {
	case "initialize":
		protoVer := DefaultProtocolVersion
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(req.Params) > 0 && json.Unmarshal(req.Params, &initParams) == nil && initParams.ProtocolVersion != "" {
			protoVer = initParams.ProtocolVersion
		}
		if resolvedSessionID == "" {
			var id [24]byte
			if _, err := rand.Read(id[:]); err != nil {
				return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: map[string]any{"code": -32603, "message": "Cannot create session"}}, ""
			}
			resolvedSessionID = "mcp-" + hex.EncodeToString(id[:])
			s.mu.Lock()
			s.transportSessions[resolvedSessionID] = workspaceID
			s.mu.Unlock()
		}
		res = map[string]any{
			"protocolVersion": protoVer,
			"capabilities": map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{
				"name":    "jvmdiag-mcp-server",
				"version": "0.0.1",
			},
		}
	case "ping":
		res = map[string]any{}
	case "tools/list":
		res = map[string]any{
			"tools": Tools(),
		}
	case "tools/call":
		var callParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			rpcErr = map[string]any{"code": -32602, "message": "Invalid tool call params"}
		} else {
			var output string
			var err error
			if staticHprofPath != "" || staticNative != nil {
				output = s.ExecuteOnTarget(ctx, staticHprofPath, staticNative, callParams.Name, callParams.Arguments)
			} else {
				output, err = s.ExecuteTool(ctx, workspaceID, resolvedSessionID, callParams.Name, callParams.Arguments)
			}
			isErr := false
			if strings.HasPrefix(output, "Error:") {
				isErr = true
			}
			if err != nil {
				output = "Error: " + err.Error()
				isErr = true
			}
			res = map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": output,
					},
				},
				"isError": isErr,
			}
		}
	default:
		rpcErr = map[string]any{"code": -32601, "message": "Method not found: " + req.Method}
	}

	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  res,
		Error:   rpcErr,
	}, resolvedSessionID
}

func (s *Server) handleRPCPayload(ctx context.Context, workspaceID, sessionID, staticHprofPath string, staticNative *hprof.Summary, rawReq []byte) ([]byte, string, bool) {
	trimmed := bytes.TrimSpace(rawReq)
	if len(trimmed) == 0 {
		resp, _ := json.Marshal(rpcResponse{
			JSONRPC: "2.0",
			Error:   map[string]any{"code": -32700, "message": "Empty request body"},
		})
		return resp, sessionID, true
	}

	logSessionID := sessionID
	if logSessionID == "" {
		if sess := s.store.GetActiveSession(workspaceID); sess != nil {
			logSessionID = sess.SessionID
		}
	}
	if logSessionID != "" {
		s.store.RecordMcpLog(logSessionID, "IN", string(trimmed))
	}

	// Support JSON-RPC batch arrays ([...]) per MCP Streamable HTTP specification
	if trimmed[0] == '[' {
		var batch []rpcRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
			resp, _ := json.Marshal(rpcResponse{
				JSONRPC: "2.0",
				Error:   map[string]any{"code": -32700, "message": "Invalid batch JSON"},
			})
			return resp, logSessionID, true
		}
		var responses []*rpcResponse
		activeSess := logSessionID
		for _, req := range batch {
			r, sid := s.handleSingleRPC(ctx, workspaceID, activeSess, staticHprofPath, staticNative, req)
			if sid != "" {
				activeSess = sid
			}
			if r != nil {
				responses = append(responses, r)
			}
		}
		if len(responses) == 0 {
			return nil, activeSess, false
		}
		outBytes, _ := json.Marshal(responses)
		if activeSess != "" {
			s.store.RecordMcpLog(activeSess, "OUT", string(outBytes))
		}
		return outBytes, activeSess, true
	}

	// Single JSON-RPC object
	var req rpcRequest
	if err := json.Unmarshal(trimmed, &req); err != nil {
		resp, _ := json.Marshal(rpcResponse{
			JSONRPC: "2.0",
			Error:   map[string]any{"code": -32700, "message": "Parse error"},
		})
		return resp, logSessionID, true
	}

	respObj, activeSess := s.handleSingleRPC(ctx, workspaceID, logSessionID, staticHprofPath, staticNative, req)
	if respObj == nil {
		return nil, activeSess, false
	}

	outBytes, _ := json.Marshal(respObj)
	if activeSess != "" {
		s.store.RecordMcpLog(activeSess, "OUT", string(outBytes))
	}
	return outBytes, activeSess, true
}

// RunStdio starts an MCP server over stdin/stdout for local CLI agent integration.
func (s *Server) RunStdio(ctx context.Context, hprofPath string) error {
	var nativeSum *hprof.Summary
	var absPath string
	if hprofPath != "" {
		p, err := filepath.Abs(hprofPath)
		if err != nil {
			return err
		}
		absPath = p
		_, sum, err := hprof.AnalyzeFile(absPath)
		if err != nil {
			return fmt.Errorf("failed parsing %s: %w", hprofPath, err)
		}
		nativeSum = sum
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		respBytes, _, shouldSend := s.handleRPCPayload(ctx, "default", "", absPath, nativeSum, []byte(line))
		if shouldSend && len(respBytes) > 0 {
			fmt.Fprintf(os.Stdout, "%s\n", string(respBytes))
		}
	}
	return scanner.Err()
}

// HandleStreamableHTTP implements the MCP Streamable HTTP Transport (2025-03-26) over a single HTTP endpoint.
// SSE is intentionally not used: POST returns application/json (or 202 Accepted for notifications),
// GET returns 405 Method Not Allowed, and DELETE terminates the MCP session.
func (s *Server) HandleStreamableHTTP(w http.ResponseWriter, r *http.Request, workspaceID, pathSessionID string) {

	w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id, X-Workspace-ID, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", HeaderMcpSessionID)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method == http.MethodGet {
		// Per MCP Streamable HTTP spec Section 2.2: Server MUST return 405 Method Not Allowed
		// when it does not offer a standalone GET SSE stream.
		w.Header().Set("Allow", "POST, DELETE, OPTIONS")
		http.Error(w, "Method Not Allowed: This MCP server uses Streamable HTTP (application/json over POST) without SSE.", http.StatusMethodNotAllowed)
		return
	}

	sessionID := pathSessionID
	if sessionID == "" {
		sessionID = strings.TrimSpace(r.Header.Get(HeaderMcpSessionID))
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(r.URL.Query().Get("sessionId"))
	}
	transportSessionHeader := sessionID
	if sessionID != "" && s.store.GetSession(workspaceID, sessionID) == nil {
		s.mu.Lock()
		owner, exists := s.transportSessions[sessionID]
		s.mu.Unlock()
		if !exists || owner != workspaceID {
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		sessionID = ""
	}

	if r.Method == http.MethodDelete {
		s.mu.Lock()
		delete(s.transportSessions, transportSessionHeader)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, DELETE, OPTIONS")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	respBytes, resolvedSessID, shouldSend := s.handleRPCPayload(r.Context(), workspaceID, sessionID, "", nil, body)
	if resolvedSessID != "" {
		w.Header().Set(HeaderMcpSessionID, resolvedSessID)
	} else if transportSessionHeader != "" {
		w.Header().Set(HeaderMcpSessionID, transportSessionHeader)
	}

	if !shouldSend || len(respBytes) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func intArg(args map[string]any, key string, def, max int) int {
	if args == nil {
		return def
	}
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	var n int
	switch val := v.(type) {
	case float64:
		n = int(val)
	case int:
		n = val
	}
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func strArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}
