package ai

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bishoku/jvmdiag/internal/config"
	"github.com/bishoku/jvmdiag/internal/mcp"
)

const (
	PromptHeapDump   = "heap-dump"
	PromptThreadDump = "thread-dump"
	PromptGCLog      = "gc-log"
	PromptDiff       = "diff"
	PromptIncident   = "incident"
	PromptNMTCrash   = "nmt-crash"
	PromptJFR        = "jfr"

	// MaxChatTurns limits the number of back-and-forth user/assistant turns kept in memory
	// per session to prevent context window bloat and hallucination drift.
	MaxChatTurns = 10
)

const DefaultHeapDumpPrompt = `Analyze the supplied heap report using its explicit evidence contract. Preserve analysis status, scope, confidence and missing-data warnings. Native HPROF provides serialized field/element payload bytes and decoded record counts, not runtime shallow heap, retained heap, reachability, dominators or root paths. A large payload share is only a concentration hypothesis, not proof of a leak. Identical raw arrays do not establish duplicate String objects or reclaimable memory; do not recommend String interning or deduplication without ownership evidence. Treat MAT output as report excerpts and retain the original metric labels. Never infer reference owners from a package name or root count alone. Separate observations from hypotheses, cite source/object evidence, and suggest verification before remediation. If runtime layout, growth context or paths are unavailable, say so instead of rating OOM risk. Respond in Markdown.`

const DefaultThreadDumpPrompt = `You are a Principal Java Concurrency & Performance Engineer analyzing a JVM Thread Dump report.

CRITICAL GROUNDING RULES:
- Base ALL analysis strictly on the provided dump. NEVER fabricate thread names, lock IDs (` + "`<0x...>`" + `), or stack frames.
- **IMPORTANT JVM NUANCE — Idle I/O Pollers vs. CPU-Bound Threads:**
  In HotSpot JVM thread dumps, threads blocked in OS-level network readiness calls such as ` + "`EPoll.wait`" + `, ` + "`Native.epollWait0`" + `, ` + "`KQueue.poll`" + `, ` + "`kevent`" + `, ` + "`SelectorImpl.select`" + `, or ` + "`Net.accept`" + ` are reported in state ` + "`RUNNABLE`" + `. Do NOT misdiagnose idle Netty/Tomcat/Reactor NIO event-loop pollers as CPU saturation! Focus CPU saturation analysis on ` + "`RUNNABLE`" + ` threads executing application logic, serialization, regex, crypto, or synchronous I/O.
- **Java 21+ Virtual Threads (Project Loom) & Carrier Pinning:**
  If the report includes **Virtual Threads** or **Pinned Virtual Threads**, carefully analyze whether virtual threads are pinned to their ` + "`ForkJoinPool`" + ` carrier threads due to ` + "`synchronized`" + ` monitors (` + "`- locked <0x...>`" + `) or ` + "`Native Method`" + ` frames while parked/waiting. Recommend replacing ` + "`synchronized`" + ` with ` + "`ReentrantLock`" + ` around blocking I/O.

YOUR ANALYSIS STRUCTURE:
1. **Executive Summary** — Overall threading health in 2–3 sentences, citing total threads, state breakdown, and active bottlenecks.
2. **Deadlock, Lock Contention & Virtual Thread Pinning** — Analyze any deadlocks, contended monitor/park locks (` + "`<0x...>`" + `), and Java 21+ Pinned Virtual Threads (naming the owner/pinned thread, stack frame, and waiter count).
3. **Thread Pool & Carrier Saturation Analysis** — Evaluate major thread pools (` + "`http-nio-*`" + `, ` + "`reactor-*`" + `, ` + "`HikariPool-*`" + `, ` + "`ForkJoinPool-*`" + `): are worker/carrier pools exhausted, idle, or waiting on downstream resources?
4. **Identical Stack Trace Hotspots** — Analyze groups of threads sharing identical call chains (separating normal idle pool/poller parking from true application bottlenecks).
5. **Actionable Concurrency Fixes** — Concrete code changes (` + "`ReentrantLock`" + `, lock-splitting, connection pool sizing, or timeout tuning).

Format your response in clean Markdown.`

const DefaultGCLogPrompt = `You are a Principal JVM Garbage Collection & Memory Tuning Engineer analyzing a JVM GC Log report.

CRITICAL GROUNDING RULES:
- Base ALL findings strictly on the metrics and log lines in the report. NEVER invent pause times, timestamps, or heap sizes.
- Cite exact values for P50, P95, P99, Max Pause, Throughput %, Allocation Rate, and Post-GC Baseline Trend.

YOUR ANALYSIS STRUCTURE:
1. **Executive Summary** — Assess GC health, application throughput % (target >98%), and latency impact (P99/Max pause) in 2–3 sentences.
2. **Pause Time & Latency Distribution** — Compare P50 vs. P95/P99/Max pauses. Highlight any Stop-The-World spikes (>200ms or >1s) and their frequency.
3. **Memory Leak vs. Sizing Diagnosis (Post-GC Baseline Trend)** — Use the **Post-GC Baseline Trend (early -> late)** and **Min Heap After GC** to determine:
   - Whether live data is steadily climbing after collections (**True Memory Leak**), OR
   - Whether live data returns to a stable baseline but allocation rate / heap size causes frequent GCs (**High Allocation Rate / Undersized Heap**).
4. **Full GC, Humongous & Evacuation Failure Analysis** — Diagnose any Full GCs, G1 Humongous allocations, or To-Space Exhausted / Evacuation Failures.
5. **Actionable JVM Flag & Code Recommendations** — Concrete JVM flags (` + "`-Xms`" + `, ` + "`-Xmx`" + `, ` + "`-XX:MaxGCPauseMillis`" + `, ` + "`-XX:G1HeapRegionSize`" + `, ` + "`-XX:InitiatingHeapOccupancyPercent`" + `, or ZGC/G1 switching) and allocation reduction strategies.

Format your response in clean Markdown.`

const DefaultDiffPrompt = `You are a Principal Java Performance Engineer analyzing a Multi-Snapshot Diff Report (comparing sequential Thread Dumps or Heap Dumps over time).

CRITICAL GROUNDING RULES:
- Base ALL analysis strictly on the delta metrics provided in the report.
- For **Thread Dump Diffs**: Focus heavily on the **Stuck / Unmoving Threads Across All Dumps** section (threads that remained in ` + "`RUNNABLE`" + ` or ` + "`BLOCKED`" + ` at the exact same stack frame across snapshots) and **Thread Pool Deltas**.
- For **Heap Dump Diffs**: Focus on the **Top Growing Classes** (` + "`+Bytes`" + ` and ` + "`+Instances`" + ` deltas between Baseline and Target) to identify growth candidates; growth alone does not prove a leak.

YOUR ANALYSIS STRUCTURE:
1. **Executive Summary** — What is progressing, leaking, or frozen between snapshots?
2. **Stuck Threads / Growing Classes Deep Dive** — Cite the exact thread names & call chains (for thread diffs) or class names & byte/instance growth (for heap diffs).
3. **Root Cause Mechanism** — Explain why these specific threads are frozen or why these specific classes are accumulating without reclamation.
4. **Actionable Remediation** — Concrete code fixes, timeouts, or bounded cache configurations.

Format your response in clean Markdown.`

const DefaultIncidentPrompt = `You are a Principal JVM Site Reliability Engineer conducting a holistic Root-Cause Analysis across correlated JVM diagnostic artifacts (GC Log, Thread Dumps, Heap Dump, NMT/Crash, and JFR) captured during a production incident.

CRITICAL GROUNDING RULES:
- Base ALL findings strictly on the provided artifacts and the **Automated Cross-Artifact Correlations** section.
- Discuss whether recorded memory, GC, JFR and thread observations could explain the incident; do not assert causation without timing and JVM-identity evidence.

YOUR ANALYSIS STRUCTURE:
1. **Incident Executive Summary** — Evidence summary and candidate explanations across provided artifacts in 3–4 sentences.
2. **Cross-Artifact Causal Chain** — Trace the exact link between:
   - Which code paths / threads (from the Thread Dump / JFR) are allocating, CPU-spinning, or holding locks,
   - Which classes / packages / off-heap categories (from the Heap Dump / NMT) are consuming memory, and
   - How the GC collector or OS responded (Full GCs, evacuation failures, long STW pauses, or native OOM).
3. **Incident Timeline Reconstruction** — Step-by-step progression from trigger to degradation/OOM.
4. **Immediate Mitigation & Permanent Fix** — Short-term operational/JVM flag mitigation and permanent code-level fix.

Format your response in clean Markdown.`

const DefaultNMTCrashPrompt = `You are a Principal JVM Internals & Systems Engineer analyzing a HotSpot Fatal Crash Log (hs_err_pid.log) and/or Native Memory Tracking (NMT / jcmd VM.native_memory) report.

CRITICAL GROUNDING RULES:
- Base ALL findings strictly on the provided report metrics, signals, frames, and NMT categories.
- Explain clearly why a JVM process can be OOMKilled by Linux/Kubernetes or fail mmap/malloc even when Java Heap usage is low (e.g. Direct ByteBuffers / Internal, Thread Stacks, Metaspace, GC Remembered Sets, Arena Chunks, or low /proc/sys/vm/max_map_count).

YOUR ANALYSIS STRUCTURE:
1. **Executive Summary** — Exact crash cause (` + "`SIGSEGV`" + `, native ` + "`Out of Memory`" + `, or Off-Heap memory bloat) in 2–3 sentences.
2. **Crash Signal / Problematic Frame OR Off-Heap Breakdown** — Analyze the problematic frame (` + "`C [...]`" + `, ` + "`J [...]`" + `, ` + "`V [...]`" + `) and crash stack, or the top NMT committed categories (` + "`Java Heap`" + ` vs. ` + "`Thread`" + `, ` + "`Internal`" + `, ` + "`Class`" + `, ` + "`GC`" + `, ` + "`Arena Chunk`" + `).
3. **Container / OS Sizing & Native Memory Diagnosis** — Evaluate container RSS risk, ` + "`vm.max_map_count`" + `, thread stack footprint (` + "`-Xss`" + `), and direct memory limits (` + "`-XX:MaxDirectMemorySize`" + `, ` + "`-XX:MaxMetaspaceSize`" + `, ` + "`MALLOC_ARENA_MAX`" + `).
4. **Actionable Remediation** — Concrete JVM flags, OS sysctl settings, and native/JNI/Netty buffer leak fixes.

Format your response in clean Markdown.`

const DefaultJFRPrompt = `Analyze the provided Java Flight Recorder report. Preserve its analysis status, scope, evidence references, confidence labels and missing-data warnings. Separate recorded observations from hypotheses. Execution sample share is not CPU utilization. Allocation sample weights, observed object sizes and TLAB reservations are different quantities and must not be added together. GC cycle duration is not a stop-the-world pause; use only the stated pause source. A pinning event is not automatically critical and does not justify replacing synchronized without inspecting the stack and JDK version. Do not invent a root cause when evidence is insufficient. For each interpretation cite the evidence and state a next verification step. Respond in Markdown.`

const EvidenceRules = `EVIDENCE CONTRACT: Preserve complete/limited/metadata-only/failed status and all scope limitations. High confidence means confidence in a recorded observation, not proof of root cause. Native HPROF reports serialized payload bytes, not live, shallow or retained heap; largest payloads are not dominators; root counts are not root paths. Duplicate raw arrays do not prove duplicate Strings or reclaimable memory. Missing data is unknown, never zero/healthy. Histogram growth and concentrations are hypotheses, not proven leaks. Cite source locations and propose verification before remediation. Unsupported tools must remain unsupported.`

const ChatSystemPrompt = `You are a Principal JVM Performance Engineer helping a developer interactively investigate a loaded JVM Heap Dump.

CORE RULES:
- Always respond in clean Markdown (tables, bullet points, bold metrics, code blocks).
- Base ALL answers strictly on data retrieved from the heap dump tools or the loaded heap overview — NEVER guess or fabricate class names, byte counts, or percentages.
- Separate **Observed Data** from **Engineering Interpretation**.
- Interactive heap analysis tools include:
  * ` + "`get_heap_summary`" + `: Decoded object/array counts, serialized payload bytes, root record counts and limitations.
  * ` + "`get_leak_suspects`" + `: Low-confidence concentration hypotheses and exact duplicate-array observations.
  * ` + "`get_class_histogram`" + `: Per-class memory usage (supports ` + "`topN`" + ` and regex ` + "`pattern`" + ` filter).
  * ` + "`get_largest_objects`" + `: Rank serialized object/array payloads; these are not runtime dominators.
  * ` + "`get_dominator_tree`" + `: A MAT dominator report if available; unsupported in native mode. Use get_largest_objects for payload ranking.
  * ` + "`get_top_consumers`" + `: Top memory-consuming packages and classes.
  * ` + "`run_oql_query`" + `: Currently unsupported until validated MAT query results are implemented.
  * ` + "`get_thread_stacks`" + `: Active thread stack traces recorded inside the heap dump.
- Keep your answers concise, technical, and directly actionable.`

type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatTurn represents a completed, clean User <-> Assistant exchange stored in session memory.
// Storing completed turns (with a compact summary of tools called rather than massive raw tool JSONs
// from old turns) prevents HTTP 400 orphaned tool_call_id errors and reduces token bloat by ~80%.
type ChatTurn struct {
	UserMessage      string   `json:"userMessage"`
	AssistantMessage string   `json:"assistantMessage"`
	ToolsUsed        []string `json:"toolsUsed,omitempty"`
}

type Service struct {
	transport http.RoundTripper
	cfg       *config.Manager
	mcpServer *mcp.Server
	mu        sync.Mutex
	chatTurns map[string][]ChatTurn // sessionID -> bounded list of completed turns (max MaxChatTurns)
}

func NewService(cfg *config.Manager, mcpServer *mcp.Server) *Service {
	return &Service{
		cfg:       cfg,
		mcpServer: mcpServer,
		chatTurns: make(map[string][]ChatTurn),
	}
}

func (s *Service) DefaultPrompt(promptType string) (string, error) {
	switch promptType {
	case PromptHeapDump:
		return DefaultHeapDumpPrompt, nil
	case PromptThreadDump:
		return DefaultThreadDumpPrompt, nil
	case PromptGCLog:
		return DefaultGCLogPrompt, nil
	case PromptDiff:
		return DefaultDiffPrompt, nil
	case PromptIncident:
		return DefaultIncidentPrompt, nil
	case PromptNMTCrash:
		return DefaultNMTCrashPrompt, nil
	case PromptJFR:
		return DefaultJFRPrompt, nil
	default:
		return "", fmt.Errorf("unknown prompt type: %s", promptType)
	}
}

func (s *Service) EffectivePrompt(workspaceID, promptType string) (string, error) {
	if custom := s.cfg.GetCustomPrompt(workspaceID, promptType); custom != "" {
		return custom, nil
	}
	return s.DefaultPrompt(promptType)
}

func (s *Service) AnalyzeReport(ctx context.Context, workspaceID, promptType, staticReport string) (string, error) {
	sysPrompt, err := s.EffectivePrompt(workspaceID, promptType)
	if err != nil {
		return "", err
	}
	return s.Complete(ctx, workspaceID, sysPrompt+"\n\n"+EvidenceRules, staticReport)
}

func (s *Service) Complete(ctx context.Context, workspaceID, systemPrompt, userContent string) (string, error) {
	aiCfg, _ := s.cfg.GetEffectiveConfig(workspaceID)
	if strings.TrimSpace(aiCfg.APIKey) == "" {
		return "", fmt.Errorf("AI is not configured. Please set your API key in Settings (/setup) or via OPENROUTER_API_KEY")
	}

	reqBody := map[string]any{
		"model":       aiCfg.Model,
		"temperature": aiCfg.Temperature,
		"messages": []ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userContent},
		},
	}

	respMsg, err := s.doChatRequest(ctx, aiCfg, reqBody)
	if err != nil {
		return "", err
	}
	return respMsg.Content, nil
}

// StreamEventCallback receives ("text" | "tool_call" | "meta" | "done" | "error", payloadMap)
type StreamEventCallback func(event string, data map[string]any)

func (s *Service) StreamHeapChat(ctx context.Context, workspaceID, sessionID, userMessage string, stream bool, emit StreamEventCallback) {
	aiCfg, _ := s.cfg.GetEffectiveConfig(workspaceID)
	if strings.TrimSpace(aiCfg.APIKey) == "" {
		emit("error", map[string]any{"message": "AI client is not configured. Please configure your API key in Settings (/settings)."})
		return
	}

	sess := sessionID
	if s.mcpServer != nil {
		sess = s.mcpServer.ResolveSessionID(workspaceID, sessionID)
	}
	if sess == "" {
		emit("error", map[string]any{"message": "No active heap dump session. Please upload a .hprof file first."})
		return
	}
	sessionID = sess
	memoryKey := s.mcpServerSession(workspaceID, sessionID)

	// Build OpenAI tools list from MCP tool definitions
	var openAITools []map[string]any
	for _, t := range mcp.Tools() {
		openAITools = append(openAITools, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.InputSchema,
			},
		})
	}

	// Pre-fetch a compact baseline summary of the active heap dump so the system prompt
	// always grounds the LLM on the loaded file without wasting a tool round-trip on basic stats.
	systemPrompt := ChatSystemPrompt + "\n\n" + EvidenceRules
	if baseSummary, err := s.mcpServer.ExecuteTool(ctx, workspaceID, sessionID, "get_heap_summary", nil); err == nil && baseSummary != "" {
		if len(baseSummary) > 1500 {
			baseSummary = baseSummary[:1500] + "\n[...]"
		}
		systemPrompt += "\n\n--- LOADED HEAP DUMP BASELINE CONTEXT ---\n" + baseSummary
	}

	// Reconstruct clean multi-turn conversation history (bounded to MaxChatTurns)
	s.mu.Lock()
	pastTurns := s.chatTurns[memoryKey]
	if len(pastTurns) >= MaxChatTurns {
		// Sliding window: keep the most recent (MaxChatTurns - 1) turns to make room for the new turn
		pastTurns = pastTurns[len(pastTurns)-(MaxChatTurns-1):]
		s.chatTurns[memoryKey] = pastTurns
	}
	msgs := []ChatMessage{{Role: "system", Content: systemPrompt}}
	for _, pt := range pastTurns {
		msgs = append(msgs, ChatMessage{Role: "user", Content: pt.UserMessage})
		assistContent := pt.AssistantMessage
		if len(pt.ToolsUsed) > 0 {
			assistContent = fmt.Sprintf("*(Tools consulted in this turn: %s)*\n\n%s", strings.Join(pt.ToolsUsed, ", "), assistContent)
		}
		msgs = append(msgs, ChatMessage{Role: "assistant", Content: assistContent})
	}
	currentTurnNum := len(pastTurns) + 1
	s.mu.Unlock()

	msgs = append(msgs, ChatMessage{Role: "user", Content: userMessage})
	emit("meta", map[string]any{
		"turn":     currentTurnNum,
		"maxTurns": MaxChatTurns,
	})

	var toolsUsedInThisTurn []string

	// Autonomous tool-calling loop within the current turn (up to 4 iterations)
	for iter := 0; iter < 4; iter++ {
		reqBody := map[string]any{
			"model":       aiCfg.Model,
			"temperature": aiCfg.Temperature,
			"messages":    msgs,
			"tools":       openAITools,
		}

		assistantMsg, err := s.doChatRequest(ctx, aiCfg, reqBody)
		if err != nil {
			emit("error", map[string]any{"message": "AI request failed: " + err.Error()})
			return
		}

		msgs = append(msgs, assistantMsg)

		if len(assistantMsg.ToolCalls) == 0 {
			text := assistantMsg.Content
			if stream && len(text) > 120 {
				chunkSize := 48
				for i := 0; i < len(text); i += chunkSize {
					end := i + chunkSize
					if end > len(text) {
						end = len(text)
					}
					emit("text", map[string]any{"content": text[i:end]})
					time.Sleep(12 * time.Millisecond)
				}
			} else if text != "" {
				emit("text", map[string]any{"content": text})
			}

			// Save the clean User -> Assistant turn into bounded session memory
			s.mu.Lock()
			turns := append(s.chatTurns[memoryKey], ChatTurn{
				UserMessage:      userMessage,
				AssistantMessage: text,
				ToolsUsed:        toolsUsedInThisTurn,
			})
			if len(turns) > MaxChatTurns {
				turns = turns[len(turns)-MaxChatTurns:]
			}
			s.chatTurns[memoryKey] = turns
			s.mu.Unlock()

			emit("done", map[string]any{
				"turn":     len(turns),
				"maxTurns": MaxChatTurns,
			})
			return
		}

		// Execute requested tool calls and append tool outputs for the next iteration in this turn
		for _, tc := range assistantMsg.ToolCalls {
			toolsUsedInThisTurn = append(toolsUsedInThisTurn, tc.Function.Name)
			emit("tool_call", map[string]any{
				"name": tc.Function.Name,
				"args": tc.Function.Arguments,
			})
			var args map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			toolOut, terr := s.mcpServer.ExecuteTool(ctx, workspaceID, sessionID, tc.Function.Name, args)
			if terr != nil {
				toolOut = "Error: " + terr.Error()
			}
			// Cap individual tool output at 6000 chars so multiple tool calls in a single turn never overflow context
			if len(toolOut) > 6000 {
				toolOut = toolOut[:6000] + "\n[... tool output truncated to fit context budget ...]"
			}
			msgs = append(msgs, ChatMessage{
				Role:       "tool",
				ToolCallID: tc.ID,
				Name:       tc.Function.Name,
				Content:    toolOut,
			})
		}
	}

	emit("done", map[string]any{})
}

func (s *Service) GetChatStatus(workspaceID, sessionID string) map[string]any {
	memoryKey := s.mcpServerSession(workspaceID, sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	turns := append([]ChatTurn(nil), s.chatTurns[memoryKey]...)
	return map[string]any{
		"sessionId": sessionID,
		"turnCount": len(turns),
		"maxTurns":  MaxChatTurns,
		"turns":     turns,
	}
}

func (s *Service) ClearChatHistory(workspaceID, sessionID string) {
	memoryKey := s.mcpServerSession(workspaceID, sessionID)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.chatTurns, memoryKey)
}

func (s *Service) mcpServerSession(workspaceID, sessionID string) string {
	if sessionID != "" {
		return config.SanitizeWorkspaceID(workspaceID) + ":" + sessionID
	}
	return config.SanitizeWorkspaceID(workspaceID) + ":active"
}

func (s *Service) doChatRequest(ctx context.Context, cfg config.AIConfig, payload map[string]any) (ChatMessage, error) {
	endpoint := buildChatCompletionsURL(cfg.BaseURL)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return ChatMessage{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return ChatMessage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("HTTP-Referer", "https://github.com/bishoku/jvm-diagnostics-analyzer")
	req.Header.Set("X-Title", "JVM Diagnostics Analyzer (Go)")

	client := &http.Client{Transport: s.transport, Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("AI endpoint redirects are not allowed")
	}}
	if cfg.TrustInsecureCerts {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return ChatMessage{}, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(bufio.NewReader(resp.Body))
	if err != nil {
		return ChatMessage{}, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ChatMessage{}, fmt.Errorf("HTTP %d from AI provider: %s", resp.StatusCode, string(respBytes))
	}

	var parsed struct {
		Choices []struct {
			Message ChatMessage `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return ChatMessage{}, fmt.Errorf("invalid JSON from AI provider: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return ChatMessage{}, fmt.Errorf("AI provider error: %s", parsed.Error.Message)
	}
	if len(parsed.Choices) == 0 {
		return ChatMessage{}, fmt.Errorf("empty response choices from AI provider")
	}

	return parsed.Choices[0].Message, nil
}

func buildChatCompletionsURL(baseURL string) string {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if b == "" {
		b = config.DefaultBaseURL
	}
	if strings.HasSuffix(b, "/chat/completions") {
		return b
	}
	if strings.HasSuffix(b, "/v1") {
		return b + "/chat/completions"
	}
	return b + "/v1/chat/completions"
}
