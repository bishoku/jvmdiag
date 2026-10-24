package capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	return listProcesses(ctx, "/proc", findJDKTool, runCommand)
}

func listProcesses(ctx context.Context, procRoot string, findTool func(string) string, run commandRunner) ([]JVMProcess, error) {
	// Procfs sees container JVMs without shared perfdata; JDK discovery also sees
	// native launchers and provides their main class. Neither source is complete.
	procs, procErr := listProcJVMs(procRoot)
	byPID := make(map[int]JVMProcess)
	merge := func(found []JVMProcess) {
		for _, proc := range found {
			if previous, ok := byPID[proc.PID]; ok {
				if proc.MainClass == "" || proc.MainClass == "(jvm process)" {
					proc.MainClass = previous.MainClass
				}
				if proc.Args == "" {
					proc.Args = previous.Args
				}
			}
			byPID[proc.PID] = proc
		}
	}
	merge(procs)
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	listed := procErr == nil
	for _, source := range []struct{ tool, flag string }{{"jcmd", "-l"}, {"jps", "-lv"}} {
		if tool := findTool(source.tool); tool != "" {
			if out, err := run(cctx, tool, source.flag); err == nil {
				listed = true
				found := parseJcmdList(string(out))
				merge(found)
				if len(found) > 0 {
					break
				}
			}
		}
	}

	// Non-procfs platforms can still discover ordinary Java processes without JDK tools.
	if procErr != nil && len(byPID) == 0 {
		if out, err := run(cctx, "ps", "-eo", "pid,args"); err == nil {
			listed = true
			for _, line := range strings.Split(string(out), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				pid, err := strconv.Atoi(fields[0])
				if err != nil || pid <= 0 {
					continue
				}
				cmdBase := filepath.Base(fields[1])
				if cmdBase == "java" || cmdBase == "java.exe" {
					rest := strings.Join(fields[2:], " ")
					merge([]JVMProcess{{PID: pid, MainClass: rest, Args: rest}})
				}
			}
		}
	}
	if !listed && len(byPID) == 0 {
		return nil, fmt.Errorf("neither procfs, jcmd, jps, nor ps could list running JVM processes")
	}
	result := make([]JVMProcess, 0, len(byPID))
	for _, proc := range byPID {
		result = append(result, proc)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
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
		if err != nil || pid <= 0 {
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
