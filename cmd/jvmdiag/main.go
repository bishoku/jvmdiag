package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
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
	"github.com/bishoku/jvmdiag/v3/internal/server"
	"github.com/bishoku/jvmdiag/v3/internal/store"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		version = moduleVersion(version, info)
	}
}

func moduleVersion(current string, info *debug.BuildInfo) string {
	if current != "dev" || info == nil || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return current
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}

func main() {
	if len(os.Args) < 2 {
		runServe(nil)
		return
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "serve", "server":
		runServe(args)
	case "analyze":
		runAnalyze(args)
	case "diff":
		runDiff(args)
	case "incident":
		runIncident(args)
	case "ps":
		runPS()
	case "capture":
		runCapture(args)
	case "mcp":
		runMcpStdio(args)
	case "version", "--version", "-v":
		fmt.Printf("jvmdiag version %s (commit=%s built=%s)\n", version, commit, buildDate)
	case "help", "--help", "-h":
		printUsage()
	default:
		if _, err := os.Stat(sub); err == nil {
			runAnalyze(os.Args[1:])
			return
		}
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`🔬 JVM Diagnostics Analyzer (jvmdiag v` + version + `)

Usage:
  jvmdiag serve [flags]                      Start Web UI, REST API & Multi-User Streamable HTTP MCP Server
  jvmdiag analyze <file> [flags]             Analyze Heap (.hprof), Thread Dump (text/JSON), GC Log, Crash (hs_err), NMT, or JFR (.jfr)
  jvmdiag diff <file1> <file2> [...] [flags] Compare 2+ Thread Dumps (stuck threads) or 2 Heap Dumps (growing classes)
  jvmdiag incident [flags]                   Correlate GC Log + Thread Dump(s) + Heap + NMT/Crash + JFR together
  jvmdiag ps                                 List running local JVM processes (PID, Main Class, JVM args)
  jvmdiag capture --pid <PID> [flags]        Capture sequential Thread Dumps + NMT (+ optional Heap) from a live JVM and analyze
  jvmdiag mcp [--file <dump.hprof>]          Start Stdio MCP Server for Claude Desktop, Cursor, Windsurf, Antigravity

Examples:
  jvmdiag serve --port 8080 --multi-user
  jvmdiag analyze thread-dump.tdump --ai
  jvmdiag analyze hs_err_pid1234.log --ai
  jvmdiag analyze recording.jfr --ai
  jvmdiag ps
  jvmdiag capture --pid 12345 --count 3 --interval 2s --ai
  jvmdiag diff tdump1.txt tdump2.txt tdump3.txt
  jvmdiag incident --gc gc.log --thread thread-dump.tdump --heap app.hprof --nmt nmt.txt --jfr rec.jfr`)
}

func buildCore(baseDir string) (*config.Manager, *mat.Service, *store.Store, *mcp.Server, *ai.Service) {
	return buildCoreFromConfig(config.NewManager(baseDir))
}

func buildCoreFromConfig(cfg *config.Manager) (*config.Manager, *mat.Service, *store.Store, *mcp.Server, *ai.Service) {
	matSvc := mat.NewServiceWithOptions(cfg.MatHome(), cfg.BaseDir(), cfg.MatHeapSize(), cfg.MaxMatMemory(), mat.Options{SkipLegacy: !cfg.LegacySourcesEnabled()})
	st := store.NewStore(cfg, matSvc)
	mcpSrv := mcp.NewServer(st, matSvc)
	aiSvc := ai.NewService(cfg, mcpSrv)
	return cfg, matSvc, st, mcpSrv, aiSvc
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 8080, "HTTP server port")
	host := fs.String("host", "127.0.0.1", "HTTP bind address")
	multiUser := fs.Bool("multi-user", false, "Enable multi-user workspace isolation mode")
	maxWorkers := fs.Int("max-workers", 0, "Max concurrent heavy analysis workers")
	dataDir := fs.String("data-dir", "", "Custom data directory (defaults to ~/.jvmdiag)")
	_ = fs.Parse(args)

	if envPort := os.Getenv("SERVER_PORT"); envPort != "" && *port == 8080 {
		fmt.Sscanf(envPort, "%d", port)
	}

	cfg := config.NewManager(*dataDir)
	if *multiUser {
		cfg.SetMultiUser(true)
	}
	if *maxWorkers > 0 {
		cfg.SetMaxWorkers(*maxWorkers)
	}

	_, matSvc, st, mcpSrv, aiSvc := buildCoreFromConfig(cfg)
	srv := server.NewServer(cfg, st, matSvc, mcpSrv, aiSvc)
	addr := net.JoinHostPort(*host, strconv.Itoa(*port))

	fmt.Printf("╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║  🔬 JVM Diagnostics Analyzer (Go v%s)                     ║\n", version)
	fmt.Printf("╠══════════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║  Web UI & API : http://localhost:%-27d ║\n", *port)
	fmt.Printf("║  MCP HTTP URL : http://localhost:%d/mcp                      ║\n", *port)
	fmt.Printf("║  Multi-User   : %-44v ║\n", cfg.IsMultiUser())
	fmt.Printf("║  MAT Installed: %-44v ║\n", matSvc.IsAvailable())
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n")

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		os.Exit(1)
	}
}

func runPS() {
	procs, err := capture.ListProcesses(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed listing JVM processes: %v\n", err)
		os.Exit(1)
	}
	if len(procs) == 0 {
		fmt.Println("No running local JVM processes found.")
		return
	}
	fmt.Printf("%-10s %-42s %s\n", "PID", "MAIN CLASS / JAR", "JVM ARGUMENTS")
	fmt.Println(strings.Repeat("-", 95))
	for _, p := range procs {
		fmt.Printf("%-10d %-42s %s\n", p.PID, truncateText(p.MainClass, 40), truncateText(p.Args, 60))
	}
}

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	pid := fs.Int("pid", 0, "Target JVM PID to capture")
	count := fs.Int("count", 3, "Number of sequential thread dumps to capture")
	interval := fs.Duration("interval", 2*time.Second, "Interval between sequential thread dumps")
	withHeap := fs.Bool("with-heap", false, "Also trigger GC.heap_dump (.hprof)")
	container := fs.Bool("container", false, "Use Linux target mount namespace via /proc/PID/root")
	targetDir := fs.String("target-dir", "", "Writable absolute staging directory (container: /tmp; local: system temp)")
	jfrDuration := fs.Duration("jfr-duration", 0, "Also record JFR for this duration (max 10m)")
	timeout := fs.Duration("timeout", 3*time.Minute, "Overall capture timeout")
	commandTimeout := fs.Duration("command-timeout", 30*time.Second, "Timeout per JDK tool command; raise for large heaps")
	captureOnly := fs.Bool("capture-only", false, "Save artifacts and manifest without analysis")
	dataDir := fs.String("data-dir", "", "Configuration and analysis data directory")
	outDir := fs.String("out-dir", "", "Directory to store captured raw files")
	useAI := fs.Bool("ai", false, "Run AI root-cause diagnosis on captured bundle")
	noAI := fs.Bool("no-ai", false, "Skip AI diagnosis")
	workspace := fs.String("workspace", "default", "Workspace ID")
	outFile := fs.String("out", "", "Optional output file path to write report")
	_ = fs.Parse(reorderFlagsFirst(args))

	if *timeout <= 0 || *commandTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "Error: timeout durations must be positive")
		os.Exit(1)
	}
	if *pid <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --pid <PID> is required. Run 'jvmdiag ps' to see running JVMs.")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "🎯 Capturing %d sequential snapshots (interval=%v) from PID %d...\n", *count, *interval, *pid)
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, *timeout)
	defer cancel()
	bundle, err := capture.CaptureBundle(ctx, capture.Options{
		Container: *container, TargetDir: *targetDir, JFRDuration: *jfrDuration, CommandTimeout: *commandTimeout,
		PID:       *pid,
		Count:     *count,
		Interval:  *interval,
		WithHeap:  *withHeap,
		OutputDir: *outDir,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Live capture failed: %v\n", err)
		if bundle != nil {
			fmt.Fprintf(os.Stderr, "Partial artifacts and capture.json: %s\n", bundle.OutputDir)
		}
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "✓ Captured artifacts in %s (%s)\n", bundle.OutputDir, strings.Join(bundle.Notes, "; "))

	if *captureOnly {
		data, _ := json.MarshalIndent(bundle, "", "  ")
		outputResult(string(data), *outFile)
		return
	}
	cfg, matSvc, st, _, aiSvc := buildCore(*dataDir)
	defer st.Close()
	report, err := incident.Analyze(ctx, matSvc, incident.Input{
		ThreadDumpPaths: bundle.ThreadDumpPaths,
		NMTCrashPath:    bundle.NMTCrashPath,
		HeapDumpPath:    bundle.HeapDumpPath,
		JFRPath:         bundle.JFRPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Correlation analysis failed: %v\n", err)
		os.Exit(1)
	}

	fullOutput := report
	if len(bundle.Notes) > 0 {
		fullOutput += "\n\nCapture limitations:\n- " + strings.Join(bundle.Notes, "\n- ")
	}
	if *useAI && !*noAI && cfg.IsConfigured(*workspace) {
		fmt.Fprintln(os.Stderr, "🤖 Requesting AI (LLM) diagnosis...")
		if aiResp, aerr := aiSvc.AnalyzeReport(ctx, *workspace, ai.PromptIncident, report); aerr == nil {
			fullOutput += "\n\n" + strings.Repeat("═", 60) + "\n🤖 AI LIVE CAPTURE DIAGNOSIS\n" + strings.Repeat("═", 60) + "\n\n" + aiResp
		}
	}
	outputResult(fullOutput, *outFile)
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	explicitType := fs.String("type", "", "Explicit artifact type: heap, thread, gc, crash, nmt, jfr")
	useAI := fs.Bool("ai", true, "Send static report to configured AI provider for root-cause insights")
	noAI := fs.Bool("no-ai", false, "Skip AI diagnosis and output static report only")
	deepMat := fs.Bool("deep-mat", false, "Use Eclipse MAT in addition to Native Go HPROF parser")
	remoteServer := fs.String("server", "", "Remote jvmdiag server URL (e.g. http://localhost:8080) for remote execution")
	workspace := fs.String("workspace", "default", "Workspace ID for multi-user server isolation")
	outFile := fs.String("out", "", "Optional output file path to write report")
	_ = fs.Parse(reorderFlagsFirst(args))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing file path. Usage: jvmdiag analyze <file> [--type crash|jfr|thread|gc|heap] [--no-ai]")
		os.Exit(1)
	}
	filePath := fs.Arg(0)

	if *remoteServer != "" {
		runRemoteAnalyze(*remoteServer, *workspace, filePath, *outFile)
		return
	}

	cfg, matSvc, _, _, aiSvc := buildCore("")
	ext := strings.ToLower(filepath.Ext(filePath))
	kind := strings.ToLower(strings.TrimSpace(*explicitType))

	var (
		staticReport string
		promptType   string
		err          error
	)

	switch {
	case kind == "heap" || ext == ".hprof":
		promptType = ai.PromptHeapDump
		staticReport, _, _, err = mat.AnalyzeHeapHybrid(context.Background(), matSvc, filePath, *deepMat)
	case kind == "jfr" || ext == ".jfr" || isJFRFile(filePath):
		promptType = ai.PromptJFR
		staticReport, _, err = jfr.AnalyzeFile(filePath)
	case kind == "crash" || kind == "nmt" || isCrashOrNMTFile(filePath):
		promptType = ai.PromptNMTCrash
		staticReport, _, err = nmtcrash.AnalyzeFile(filePath)
	case kind == "thread" || isThreadDumpFile(filePath):
		promptType = ai.PromptThreadDump
		staticReport, _, err = threaddump.AnalyzeFile(filePath)
	default:
		promptType = ai.PromptGCLog
		staticReport, _, err = gclog.AnalyzeFile(filePath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis failed: %v\n", err)
		os.Exit(1)
	}

	fullOutput := staticReport
	if *useAI && !*noAI {
		if !cfg.IsConfigured(*workspace) {
			fmt.Fprintln(os.Stderr, "ℹ️  [AI] API key not configured (set OPENROUTER_API_KEY or configure in Web UI /settings). Showing static report only.")
		} else {
			fmt.Fprintln(os.Stderr, "🤖 Requesting AI (LLM) diagnosis...")
			aiResp, aerr := aiSvc.AnalyzeReport(context.Background(), *workspace, promptType, staticReport)
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "[Warning] AI request failed: %v\n", aerr)
			} else {
				fullOutput = staticReport + "\n\n" + strings.Repeat("═", 60) + "\n🤖 AI ENGINEERING DIAGNOSIS\n" + strings.Repeat("═", 60) + "\n\n" + aiResp
			}
		}
	}

	outputResult(fullOutput, *outFile)
}

func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	useAI := fs.Bool("ai", true, "Interpret diff report with AI")
	noAI := fs.Bool("no-ai", false, "Skip AI diagnosis")
	workspace := fs.String("workspace", "default", "Workspace ID")
	outFile := fs.String("out", "", "Optional output file path")
	_ = fs.Parse(reorderFlagsFirst(args))

	files := fs.Args()
	if len(files) < 2 {
		fmt.Fprintln(os.Stderr, "Error: diff requires at least 2 files. Usage: jvmdiag diff <file1> <file2> [...]")
		os.Exit(1)
	}

	cfg, _, _, _, aiSvc := buildCore("")
	var (
		report string
		err    error
	)
	if strings.HasSuffix(strings.ToLower(files[0]), ".hprof") {
		report, err = hprof.CompareFiles(files[0], files[1])
	} else {
		report, err = threaddump.CompareFiles(files)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Diff analysis failed: %v\n", err)
		os.Exit(1)
	}

	fullOutput := report
	if *useAI && !*noAI && cfg.IsConfigured(*workspace) {
		fmt.Fprintln(os.Stderr, "🤖 Requesting AI (LLM) diff diagnosis...")
		if aiResp, aerr := aiSvc.AnalyzeReport(context.Background(), *workspace, ai.PromptDiff, report); aerr == nil {
			fullOutput += "\n\n" + strings.Repeat("═", 60) + "\n🤖 AI DIFF DIAGNOSIS\n" + strings.Repeat("═", 60) + "\n\n" + aiResp
		}
	}
	outputResult(fullOutput, *outFile)
}

func runIncident(args []string) {
	fs := flag.NewFlagSet("incident", flag.ExitOnError)
	gcPath := fs.String("gc", "", "Path to GC log file")
	threadPaths := fs.String("thread", "", "Comma-separated path(s) to thread dump file(s)")
	heapPath := fs.String("heap", "", "Path to .hprof heap dump file")
	nmtPath := fs.String("nmt", "", "Path to NMT or hs_err crash log file")
	jfrPath := fs.String("jfr", "", "Path to .jfr recording file")
	deepMat := fs.Bool("deep-mat", false, "Enable Eclipse MAT deep analysis for heap dump")
	useAI := fs.Bool("ai", true, "Interpret correlated incident report with AI")
	noAI := fs.Bool("no-ai", false, "Skip AI diagnosis")
	workspace := fs.String("workspace", "default", "Workspace ID")
	outFile := fs.String("out", "", "Optional output file path")
	_ = fs.Parse(reorderFlagsFirst(args))

	var tdList []string
	if *threadPaths != "" {
		for _, p := range strings.Split(*threadPaths, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				tdList = append(tdList, trimmed)
			}
		}
	}

	cfg, matSvc, _, _, aiSvc := buildCore("")
	report, err := incident.Analyze(context.Background(), matSvc, incident.Input{
		GCLogPath:       *gcPath,
		ThreadDumpPaths: tdList,
		HeapDumpPath:    *heapPath,
		NMTCrashPath:    *nmtPath,
		JFRPath:         *jfrPath,
		UseDeepMAT:      *deepMat,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Incident analysis failed: %v\n", err)
		os.Exit(1)
	}

	fullOutput := report
	if *useAI && !*noAI && cfg.IsConfigured(*workspace) {
		fmt.Fprintln(os.Stderr, "🤖 Requesting AI (LLM) incident correlation diagnosis...")
		if aiResp, aerr := aiSvc.AnalyzeReport(context.Background(), *workspace, ai.PromptIncident, report); aerr == nil {
			fullOutput += "\n\n" + strings.Repeat("═", 60) + "\n🤖 AI INCIDENT ROOT-CAUSE CORRELATION\n" + strings.Repeat("═", 60) + "\n\n" + aiResp
		}
	}
	outputResult(fullOutput, *outFile)
}

func runMcpStdio(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	filePath := fs.String("file", "", "Optional path to .hprof file to preload for Stdio MCP")
	_ = fs.Parse(reorderFlagsFirst(args))

	_, _, _, mcpSrv, _ := buildCore("")
	if err := mcpSrv.RunStdio(context.Background(), *filePath); err != nil {
		fmt.Fprintf(os.Stderr, "MCP stdio error: %v\n", err)
		os.Exit(1)
	}
}

func runRemoteAnalyze(serverURL, workspace, filePath, outFile string) {
	base := strings.TrimRight(serverURL, "/")
	ext := strings.ToLower(filepath.Ext(filePath))
	endpoint := "/api/gc-log/upload"
	switch {
	case ext == ".hprof":
		endpoint = "/api/heap/upload"
	case ext == ".jfr" || isJFRFile(filePath):
		endpoint = "/api/jfr/upload"
	case isCrashOrNMTFile(filePath):
		endpoint = "/api/crash/upload"
	case isThreadDumpFile(filePath):
		endpoint = "/api/thread-dump/upload"
	}

	f, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed creating form: %v\n", err)
		os.Exit(1)
	}
	_, _ = io.Copy(part, f)
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, base+endpoint, &body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid server URL: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Workspace-ID", workspace)
	if token := os.Getenv("JVMDIAG_ACCESS_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	fmt.Fprintf(os.Stderr, "📤 Uploading %s to %s (workspace: %s)...\n", filepath.Base(filePath), base, workspace)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upload failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var upRes struct {
		AnalysisID string `json:"analysisId"`
		Error      string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&upRes)
	if resp.StatusCode != http.StatusOK || upRes.AnalysisID == "" {
		fmt.Fprintf(os.Stderr, "Remote server error: %s\n", upRes.Error)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "⏳ Job %s queued on remote server. Polling status...\n", upRes.AnalysisID)
	for {
		time.Sleep(1 * time.Second)
		stReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/analysis/%s/status", base, upRes.AnalysisID), nil)
		stReq.Header.Set("X-Workspace-ID", workspace)
		if token := os.Getenv("JVMDIAG_ACCESS_TOKEN"); token != "" {
			stReq.Header.Set("Authorization", "Bearer "+token)
		}
		stResp, err := http.DefaultClient.Do(stReq)
		if err != nil {
			continue
		}
		if stResp.StatusCode == http.StatusUnauthorized || stResp.StatusCode == http.StatusForbidden {
			stResp.Body.Close()
			fmt.Fprintln(os.Stderr, "Remote server denied access; check JVMDIAG_ACCESS_TOKEN and workspace")
			os.Exit(1)
		}
		var st struct {
			Status       string `json:"status"`
			StaticReport string `json:"staticReport"`
			AIResponse   string `json:"aiResponse"`
			ErrorMessage string `json:"errorMessage"`
		}
		_ = json.NewDecoder(stResp.Body).Decode(&st)
		stResp.Body.Close()

		if st.Status == "FAILED" {
			fmt.Fprintf(os.Stderr, "Remote analysis failed: %s\n", st.ErrorMessage)
			os.Exit(1)
		}
		if st.Status == "COMPLETED" {
			out := st.StaticReport
			if st.AIResponse != "" {
				out += "\n\n" + strings.Repeat("═", 60) + "\n🤖 AI DIAGNOSIS\n" + strings.Repeat("═", 60) + "\n\n" + st.AIResponse
			}
			outputResult(out, outFile)
			return
		}
	}
}

func isThreadDumpFile(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tdump") || strings.Contains(lower, "thread") {
		return true
	}
	sample := readSample(path, 4096)
	return strings.Contains(sample, "java.lang.Thread.State:") ||
		strings.Contains(sample, "Full thread dump") ||
		strings.Contains(sample, `"threadDump"`)
}

func isCrashOrNMTFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, "hs_err") || strings.Contains(base, "nmt") {
		return true
	}
	sample := readSample(path, 4096)
	return strings.Contains(sample, "A fatal error has been detected by the Java Runtime Environment") ||
		strings.Contains(sample, "Native Memory Tracking:")
}

func isJFRFile(path string) bool {
	sample := readSample(path, 512)
	return strings.HasPrefix(sample, "FLR\x00") || strings.Contains(sample, `"jdk.ExecutionSample"`)
}

func readSample(path string, maxBytes int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

func truncateText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func outputResult(content, outFile string) {
	if outFile != "" {
		if err := os.WriteFile(outFile, []byte(content), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed writing to %s: %v\n", outFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "✓ Report written to %s\n", outFile)
		return
	}
	fmt.Println(content)
}

func reorderFlagsFirst(args []string) []string {
	var flags []string
	var pos []string
	valueFlags := map[string]bool{
		"-server": true, "--server": true,
		"-workspace": true, "--workspace": true,
		"-out": true, "--out": true,
		"-out-dir": true, "--out-dir": true,
		"-type": true, "--type": true,
		"-gc": true, "--gc": true,
		"-thread": true, "--thread": true,
		"-heap": true, "--heap": true,
		"-nmt": true, "--nmt": true,
		"-jfr": true, "--jfr": true,
		"-file": true, "--file": true,
		"-pid": true, "--pid": true,
		"-count": true, "--count": true,
		"-interval": true, "--interval": true,
		"-target-dir": true, "--target-dir": true,
		"-jfr-duration": true, "--jfr-duration": true,
		"-timeout": true, "--timeout": true,
		"-command-timeout": true, "--command-timeout": true,
		"-port": true, "--port": true,
		"-max-workers": true, "--max-workers": true,
		"-data-dir": true, "--data-dir": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && valueFlags[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}
