package main

import (
	"flag"
	"fmt"
	"io"
)

type commandHelp struct{ name, usage, description string }

var helpCommands = []commandHelp{
	{"serve", "serve [flags]", "Start the Web UI, REST API and HTTP MCP server (alias: server). No command starts serve with its defaults."},
	{"analyze", "analyze <file> [flags]", "Analyze HPROF, thread dumps, GC logs, crash/NMT logs or JFR. An existing file path without a command is shorthand for analyze."},
	{"diff", "diff <file1> <file2> [...] [flags]", "Compare two or more thread dumps, or two heap dumps."},
	{"incident", "incident [flags]", "Correlate GC, thread, heap, NMT/crash and JFR evidence."},
	{"ps", "ps", "List local JVM PIDs, main classes and JVM arguments. No command-specific flags."},
	{"capture", "capture --pid <PID> [flags]", "Capture thread/NMT evidence and optional heap/JFR from a running JVM."},
	{"mcp", "mcp [flags]", "Start the stdio MCP server, optionally preloading a heap dump."},
	{"version", "version", "Print version, commit and build date (aliases: --version, -v)."},
	{"help", "help [command]", "Show all command options, or help for one command (aliases: --help, -h)."},
}

func commandFlags(name string) *flag.FlagSet {
	var fs *flag.FlagSet
	switch name {
	case "serve":
		fs, _ = newServeFlags()
	case "analyze":
		fs, _ = newAnalyzeFlags()
	case "diff":
		fs, _ = newDiffFlags()
	case "incident":
		fs, _ = newIncidentFlags()
	case "capture":
		fs, _ = newCaptureFlags()
	case "mcp":
		fs, _ = newMcpFlags()
	}
	return fs
}

func printCommandHelp(w io.Writer, name string, fs *flag.FlagSet) {
	for _, c := range helpCommands {
		if c.name != name {
			continue
		}
		fmt.Fprintf(w, "Usage: jvmdiag %s\n%s\n", c.usage, c.description)
		if fs != nil {
			fmt.Fprintln(w, "Options (both -name and --name are accepted):")
			previous := fs.Output()
			fs.SetOutput(w)
			fs.PrintDefaults()
			fs.SetOutput(previous)
		}
		fmt.Fprintln(w, "  -h, --help\n        Show help for this command.")
		return
	}
}

func showCommandHelp(w io.Writer, name string) bool {
	if name == "server" {
		name = "serve"
	}
	for _, c := range helpCommands {
		if c.name == name {
			printCommandHelp(w, name, commandFlags(name))
			return true
		}
	}
	return false
}

func printAllHelp(w io.Writer) {
	fmt.Fprintf(w, "JVM Diagnostics Analyzer (jvmdiag v%s)\n\n", version)
	fmt.Fprintln(w, "Use jvmdiag help <command> or jvmdiag <command> --help for focused help.\nBoolean values use --flag=false. Duration values use units, e.g. 30s or 2m.")
	fmt.Fprintln(w)
	for _, c := range helpCommands {
		showCommandHelp(w, c.name)
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Examples:\n  jvmdiag serve --host 0.0.0.0 --port 8080 --multi-user --max-workers 1\n  jvmdiag analyze heap.hprof --deep-mat --no-ai\n  jvmdiag capture --pid 12345 --with-heap --capture-only --out-dir ./capture-001\n  jvmdiag diff thread-1.txt thread-2.txt --no-ai\n  jvmdiag incident --gc gc.log --thread thread.txt --heap heap.hprof --no-ai")
}
