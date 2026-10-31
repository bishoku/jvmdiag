package incident

import (
	"context"
	"fmt"
	"strings"

	"github.com/bishoku/jvmdiag/internal/analyzer/gclog"
	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/internal/analyzer/jfr"
	"github.com/bishoku/jvmdiag/internal/analyzer/mat"
	"github.com/bishoku/jvmdiag/internal/analyzer/nmtcrash"
	"github.com/bishoku/jvmdiag/internal/analyzer/threaddump"
)

type Input struct {
	GCLogPath       string
	ThreadDumpPaths []string
	HeapDumpPath    string
	NMTCrashPath    string
	JFRPath         string
	UseDeepMAT      bool
}

func Analyze(ctx context.Context, matSvc *mat.Service, in Input) (string, error) {
	if in.GCLogPath == "" && len(in.ThreadDumpPaths) == 0 && in.HeapDumpPath == "" && in.NMTCrashPath == "" && in.JFRPath == "" {
		return "", fmt.Errorf("at least one diagnostic file (GC log, Thread dump, Heap dump, NMT/Crash log, or JFR) is required for incident analysis")
	}

	var (
		gcReport     string
		gcMetrics    *gclog.Metrics
		tdReport     string
		tdDiffReport string
		tdSummary    *threaddump.DumpSummary
		heapReport   string
		heapSummary  *hprof.Summary
		nmtReport    string
		nmtSummary   *nmtcrash.Summary
		jfrReport    string
		jfrSummary   *jfr.Summary
		correlations []string
	)

	if in.GCLogPath != "" {
		r, m, err := gclog.AnalyzeFile(in.GCLogPath)
		if err != nil {
			return "", fmt.Errorf("GC log analysis failed: %w", err)
		}
		gcReport = r
		gcMetrics = m
	}

	if len(in.ThreadDumpPaths) > 0 {
		r, s, err := threaddump.AnalyzeFile(in.ThreadDumpPaths[0])
		if err != nil {
			return "", fmt.Errorf("Thread dump analysis failed: %w", err)
		}
		tdReport = r
		tdSummary = s
		if len(in.ThreadDumpPaths) >= 2 {
			diff, derr := threaddump.CompareFiles(in.ThreadDumpPaths)
			if derr != nil {
				return "", fmt.Errorf("thread snapshot comparison failed: %w", derr)
			}
			tdDiffReport = diff
		}
	}

	if in.HeapDumpPath != "" {
		r, s, _, err := mat.AnalyzeHeapHybrid(ctx, matSvc, in.HeapDumpPath, in.UseDeepMAT)
		if err != nil {
			return "", fmt.Errorf("Heap dump analysis failed: %w", err)
		}
		heapReport = r
		heapSummary = s
	}

	if in.NMTCrashPath != "" {
		r, s, err := nmtcrash.AnalyzeFile(in.NMTCrashPath)
		if err != nil {
			return "", fmt.Errorf("NMT/Crash analysis failed: %w", err)
		}
		nmtReport = r
		nmtSummary = s
	}

	if in.JFRPath != "" {
		r, s, err := jfr.AnalyzeFile(in.JFRPath)
		if err != nil {
			return "", fmt.Errorf("JFR analysis failed: %w", err)
		}
		jfrReport = r
		jfrSummary = s
	}

	// Cross-Artifact Correlation Rules
	if gcMetrics != nil && heapSummary != nil {
		if gcMetrics.LeakTrendSuspected || gcMetrics.FullGCCount > 3 {
			topCls := "unknown"
			if len(heapSummary.ClassHistogram) > 0 {
				topCls = fmt.Sprintf("%s (%s)", heapSummary.ClassHistogram[0].ClassName, hprof.FormatBytes(heapSummary.ClassHistogram[0].TotalBytes))
			}
			correlations = append(correlations, fmt.Sprintf(
				"MEMORY PRESSURE CORRELATION: GC log shows %d Full GCs (leak trend: %v, max pause %.1fms) while Heap Dump is dominated by %s (total serialized payload: %s).",
				gcMetrics.FullGCCount, gcMetrics.LeakTrendSuspected, gcMetrics.MaxPauseMs, topCls, hprof.FormatBytes(heapSummary.TotalPayloadBytes)))
		}
	}

	if tdSummary != nil && heapSummary != nil {
		for _, pkg := range heapSummary.TopPackages {
			if strings.HasPrefix(pkg.PackageName, "java.") || strings.HasPrefix(pkg.PackageName, "(") {
				continue
			}
			matchedThreads := 0
			for _, t := range tdSummary.Threads {
				for _, fr := range t.StackFrames {
					if strings.Contains(fr, pkg.PackageName) {
						matchedThreads++
						break
					}
				}
			}
			if matchedThreads > 0 {
				correlations = append(correlations, fmt.Sprintf(
					"CODE PATH <-> HEAP CORRELATION: Package %q has %s of serialized payload in the Heap Dump AND has a stack frame in %d thread(s) in the Thread Dump.",
					pkg.PackageName, hprof.FormatBytes(pkg.TotalBytes), matchedThreads))
			}
		}
	}

	if gcMetrics != nil && tdSummary != nil {
		if gcMetrics.PausesAbove1000ms > 0 && tdSummary.StateCounts["BLOCKED"]+tdSummary.StateCounts["TIMED_WAITING"] > tdSummary.TotalThreads/2 {
			correlations = append(correlations, fmt.Sprintf(
				"LATENCY / TIMEOUT CORRELATION: GC log recorded %d Stop-The-World pauses > 1s (max %.1fms), co-occurring with %d blocked/timed-waiting threads in the thread dump.",
				gcMetrics.PausesAbove1000ms, gcMetrics.MaxPauseMs, tdSummary.StateCounts["BLOCKED"]+tdSummary.StateCounts["TIMED_WAITING"]))
		}
	}

	if nmtSummary != nil && tdSummary != nil && tdSummary.TotalThreads > 200 {
		correlations = append(correlations, fmt.Sprintf(
			"OFF-HEAP <-> THREAD COUNT CORRELATION: Thread dump shows %d threads while NMT reports %.1f MB total off-heap memory.",
			tdSummary.TotalThreads, float64(nmtSummary.OffHeapCommittedKB)/1024.0))
	}

	if tdSummary != nil && jfrSummary != nil && (len(tdSummary.PinnedThreads) > 0 || len(jfrSummary.PinnedEvents) > 0) {
		correlations = append(correlations, fmt.Sprintf(
			"VIRTUAL THREAD PINNING CORRELATION: Thread dump detected %d pinned virtual threads and JFR recorded %d jdk.VirtualThreadPinned hotspot(s).",
			len(tdSummary.PinnedThreads), len(jfrSummary.PinnedEvents)))
	}

	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n")
	sb.WriteString("  UNIFIED JVM INCIDENT CORRELATION REPORT\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════\n\n")

	sb.WriteString("## Automated Cross-Artifact Correlations\n\nThese are hypotheses, not causal proof. JVM identity, workload and capture-time alignment have not been verified.\n\n")
	if len(correlations) == 0 {
		sb.WriteString("- Multiple diagnostic artifacts analyzed. See individual sections below for detailed metrics.\n\n")
	} else {
		for _, c := range correlations {
			sb.WriteString("- **[CORRELATION]** " + c + "\n")
		}
		sb.WriteString("\n")
	}

	if gcReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: GC LOG ANALYSIS\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(truncateStr(gcReport, 8000) + "\n\n")
	}

	if tdDiffReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: MULTI-SNAPSHOT THREAD DUMP DIFF\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(truncateStr(tdDiffReport, 7000) + "\n\n")
	}

	if tdReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: THREAD DUMP ANALYSIS\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(truncateStr(tdReport, 8000) + "\n\n")
	}

	if heapReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: HEAP DUMP ANALYSIS\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(heapSummary.Assessment.ContextReport() + "\n")
		sb.WriteString(truncateStr(heapReport, 9000) + "\n\n")
	}

	if nmtReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: NATIVE MEMORY (NMT) & CRASH ANALYSIS\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(truncateStr(nmtReport, 7000) + "\n\n")
	}

	if jfrReport != "" {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("  ARTIFACT: JAVA FLIGHT RECORDER (JFR) ANALYSIS\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		sb.WriteString(jfrSummary.Assessment.ContextReport() + "\n")
		sb.WriteString(truncateStr(jfrReport, 7000) + "\n\n")
	}

	return sb.String(), nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[... TRUNCATED FOR CORRELATION REPORT ...]"
}
