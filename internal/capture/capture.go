package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type JVMProcess struct {
	PID       int    `json:"pid"`
	MainClass string `json:"mainClass"`
	Args      string `json:"args,omitempty"`
}

type Options struct {
	PID            int
	Count          int
	Interval       time.Duration
	WithHeap       bool
	Container      bool
	TargetDir      string
	JFRDuration    time.Duration
	CommandTimeout time.Duration
	OutputDir      string
}

type CapturedBundle struct {
	PID             int      `json:"pid"`
	Status          string   `json:"status"`
	JFRPath         string   `json:"jfrPath,omitempty"`
	Error           string   `json:"error,omitempty"`
	OutputDir       string   `json:"outputDir"`
	ThreadDumpPaths []string `json:"threadDumpPaths"`
	NMTCrashPath    string   `json:"nmtCrashPath,omitempty"`
	HeapDumpPath    string   `json:"heapDumpPath,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

func ListProcesses(ctx context.Context) ([]JVMProcess, error) {
	// Container JVMs may be absent from the local hsperfdata listing.
	if procs, err := listProcJVMs("/proc"); err == nil {
		return procs, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	if jcmd := findJDKTool("jcmd"); jcmd != "" {
		if out, err := exec.CommandContext(cctx, jcmd, "-l").Output(); err == nil {
			procs := parseJcmdList(string(out))
			if len(procs) > 0 {
				return procs, nil
			}
		}
	}

	if jps := findJDKTool("jps"); jps != "" {
		if out, err := exec.CommandContext(cctx, jps, "-lv").Output(); err == nil {
			procs := parseJcmdList(string(out))
			if len(procs) > 0 {
				return procs, nil
			}
		}
	}

	// Fallback to ps
	if out, err := exec.CommandContext(cctx, "ps", "-eo", "pid,args").Output(); err == nil {
		var procs []JVMProcess
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, err := strconv.Atoi(fields[0])
			if err != nil {
				continue
			}
			cmdBase := filepath.Base(fields[1])
			if cmdBase == "java" || cmdBase == "java.exe" {
				rest := strings.Join(fields[2:], " ")
				procs = append(procs, JVMProcess{
					PID:       pid,
					MainClass: rest,
				})
			}
		}
		return procs, nil
	}

	return nil, fmt.Errorf("neither jcmd, jps, nor ps could list running JVM processes")
}

func parseJcmdList(output string) []JVMProcess {
	var procs []JVMProcess
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		mainCls := "(jvm process)"
		args := ""
		if len(fields) >= 2 {
			mainCls = fields[1]
		}
		if strings.Contains(mainCls, "jdk.jcmd") || strings.Contains(mainCls, "sun.tools.jps") {
			continue
		}
		if len(fields) >= 3 {
			args = strings.Join(fields[2:], " ")
		}
		procs = append(procs, JVMProcess{
			PID:       pid,
			MainClass: mainCls,
			Args:      args,
		})
	}
	return procs
}

func findJDKTool(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		cand := filepath.Join(jh, "bin", name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}
