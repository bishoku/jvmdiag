package main

import (
	"flag"
	"time"
)

type serveOptions struct {
	port       *int
	host       *string
	multiUser  *bool
	maxWorkers *int
	dataDir    *string
}

func newServeFlags() (*flag.FlagSet, *serveOptions) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	options := &serveOptions{
		port:       fs.Int("port", 8080, "HTTP server port"),
		host:       fs.String("host", "127.0.0.1", "HTTP bind address"),
		multiUser:  fs.Bool("multi-user", false, "Enable multi-user workspace isolation (MULTI_USER_MODE may also enable it)"),
		maxWorkers: fs.Int("max-workers", 0, "Max concurrent heavy analysis workers (0: use MAX_WORKERS or default 2)"),
		dataDir:    fs.String("data-dir", "", "Custom data directory (defaults to ~/.jvmdiag)"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "serve", fs) }
	return fs, options
}

type captureOptions struct {
	pid            *int
	count          *int
	interval       *time.Duration
	withHeap       *bool
	container      *bool
	targetDir      *string
	jfrDuration    *time.Duration
	timeout        *time.Duration
	commandTimeout *time.Duration
	captureOnly    *bool
	dataDir        *string
	outDir         *string
	useAI          *bool
	noAI           *bool
	workspace      *string
	outFile        *string
}

func newCaptureFlags() (*flag.FlagSet, *captureOptions) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	options := &captureOptions{
		pid:            fs.Int("pid", 0, "Target JVM PID to capture"),
		count:          fs.Int("count", 3, "Number of sequential thread dumps to capture"),
		interval:       fs.Duration("interval", 2*time.Second, "Interval between sequential thread dumps"),
		withHeap:       fs.Bool("with-heap", false, "Also trigger GC.heap_dump (.hprof)"),
		container:      fs.Bool("container", false, "Use Linux target mount namespace via /proc/PID/root"),
		targetDir:      fs.String("target-dir", "", "Writable absolute staging directory (container: /tmp; local: system temp)"),
		jfrDuration:    fs.Duration("jfr-duration", 0, "Also record JFR for this duration (max 10m)"),
		timeout:        fs.Duration("timeout", 3*time.Minute, "Overall capture timeout"),
		commandTimeout: fs.Duration("command-timeout", 30*time.Second, "Timeout per JDK tool command; raise for large heaps"),
		captureOnly:    fs.Bool("capture-only", false, "Save artifacts and manifest without analysis"),
		dataDir:        fs.String("data-dir", "", "Configuration and analysis data directory"),
		outDir:         fs.String("out-dir", "", "Directory to store captured raw files"),
		useAI:          fs.Bool("ai", false, "Run AI root-cause diagnosis on captured bundle"),
		noAI:           fs.Bool("no-ai", false, "Skip AI diagnosis"),
		workspace:      fs.String("workspace", "default", "Workspace ID"),
		outFile:        fs.String("out", "", "Optional output file path to write report"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "capture", fs) }
	return fs, options
}

type analyzeOptions struct {
	explicitType *string
	useAI        *bool
	noAI         *bool
	deepMat      *bool
	remoteServer *string
	workspace    *string
	outFile      *string
}

func newAnalyzeFlags() (*flag.FlagSet, *analyzeOptions) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	options := &analyzeOptions{
		explicitType: fs.String("type", "", "Explicit artifact type: heap, thread, gc, crash, nmt, jfr"),
		useAI:        fs.Bool("ai", true, "Send static report to configured AI provider for root-cause insights"),
		noAI:         fs.Bool("no-ai", false, "Skip AI diagnosis and output static report only"),
		deepMat:      fs.Bool("deep-mat", false, "Use Eclipse MAT in addition to Native Go HPROF parser"),
		remoteServer: fs.String("server", "", "Remote jvmdiag server URL (e.g. http://localhost:8080) for remote execution"),
		workspace:    fs.String("workspace", "default", "Workspace ID for multi-user server isolation"),
		outFile:      fs.String("out", "", "Optional output file path to write report"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "analyze", fs) }
	return fs, options
}

type diffOptions struct {
	useAI     *bool
	noAI      *bool
	workspace *string
	outFile   *string
}

func newDiffFlags() (*flag.FlagSet, *diffOptions) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	options := &diffOptions{
		useAI:     fs.Bool("ai", true, "Interpret diff report with AI"),
		noAI:      fs.Bool("no-ai", false, "Skip AI diagnosis"),
		workspace: fs.String("workspace", "default", "Workspace ID"),
		outFile:   fs.String("out", "", "Optional output file path"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "diff", fs) }
	return fs, options
}

type incidentOptions struct {
	gcPath      *string
	threadPaths *string
	heapPath    *string
	nmtPath     *string
	jfrPath     *string
	deepMat     *bool
	useAI       *bool
	noAI        *bool
	workspace   *string
	outFile     *string
}

func newIncidentFlags() (*flag.FlagSet, *incidentOptions) {
	fs := flag.NewFlagSet("incident", flag.ExitOnError)
	options := &incidentOptions{
		gcPath:      fs.String("gc", "", "Path to GC log file"),
		threadPaths: fs.String("thread", "", "Comma-separated path(s) to thread dump file(s)"),
		heapPath:    fs.String("heap", "", "Path to .hprof heap dump file"),
		nmtPath:     fs.String("nmt", "", "Path to NMT or hs_err crash log file"),
		jfrPath:     fs.String("jfr", "", "Path to .jfr recording file"),
		deepMat:     fs.Bool("deep-mat", false, "Enable Eclipse MAT deep analysis for heap dump"),
		useAI:       fs.Bool("ai", true, "Interpret correlated incident report with AI"),
		noAI:        fs.Bool("no-ai", false, "Skip AI diagnosis"),
		workspace:   fs.String("workspace", "default", "Workspace ID"),
		outFile:     fs.String("out", "", "Optional output file path"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "incident", fs) }
	return fs, options
}

type mcpOptions struct {
	filePath *string
}

func newMcpFlags() (*flag.FlagSet, *mcpOptions) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	options := &mcpOptions{
		filePath: fs.String("file", "", "Optional path to .hprof file to preload for Stdio MCP"),
	}
	fs.Usage = func() { printCommandHelp(fs.Output(), "mcp", fs) }
	return fs, options
}
