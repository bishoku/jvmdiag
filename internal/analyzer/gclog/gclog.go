package gclog

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MaxReportChars = 30000

var (
	unifiedPausePattern = regexp.MustCompile(`\bGC\([0-9]+\).*?\bPause\s+(.+?)\s+(\d+(?:[.,]\d+)?)\s*ms\s*$`)
	unifiedHeapPattern  = regexp.MustCompile(`(\d+)M->(\d+)M\((\d+)M\)`)
	legacyGcPattern     = regexp.MustCompile(`\[GC.*?real=(\d+[.,]\d+) secs\]`)
	legacyFullGcPattern = regexp.MustCompile(`\[Full GC.*?real=(\d+[.,]\d+) secs\]`)
	legacyHeapPattern   = regexp.MustCompile(`(\d+)K->(\d+)K\((\d+)K\)`)
	uptimePattern       = regexp.MustCompile(`\[(\d+[.,]\d+)s\]`)
)

type Metrics struct {
	Collector            string   `json:"collector"`
	TotalLines           int64    `json:"totalLines"`
	TotalEvents          int      `json:"totalEvents"`
	YoungGCCount         int      `json:"youngGcCount"`
	FullGCCount          int      `json:"fullGcCount"`
	OtherPauseCount      int      `json:"otherPauseCount"`
	MixedGCCount         int      `json:"mixedGcCount"`
	HumongousCount       int      `json:"humongousCount"`
	ToSpaceExhausted     int      `json:"toSpaceExhausted"`
	TotalPauseMs         float64  `json:"totalPauseMs"`
	AvgPauseMs           float64  `json:"avgPauseMs"`
	MinPauseMs           float64  `json:"minPauseMs"`
	MaxPauseMs           float64  `json:"maxPauseMs"`
	P50PauseMs           float64  `json:"p50PauseMs"`
	P95PauseMs           float64  `json:"p95PauseMs"`
	P99PauseMs           float64  `json:"p99PauseMs"`
	PausesAbove200ms     int      `json:"pausesAbove200ms"`
	PausesAbove1000ms    int      `json:"pausesAbove1000ms"`
	MaxHeapUsedKB        int64    `json:"maxHeapUsedKB"`
	MaxHeapCapacityKB    int64    `json:"maxHeapCapacityKB"`
	MinHeapAfterGCKB     int64    `json:"minHeapAfterGcKB"`
	TotalReclaimedKB     int64    `json:"totalReclaimedKB"`
	DurationSec          float64  `json:"durationSec"`
	ThroughputPct        float64  `json:"throughputPct"`
	LeakTrendSuspected   bool     `json:"leakTrendSuspected"`
	EarlyAfterGCBaseline int64    `json:"earlyAfterGcBaselineKB"`
	LateAfterGCBaseline  int64    `json:"lateAfterGcBaselineKB"`
	FullGCReasons        []string `json:"fullGcReasons,omitempty"`
}

func AnalyzeFile(path string) (string, *Metrics, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	var (
		pauseTimes     []float64
		afterGCHistory []int64
		logPrefix      strings.Builder
		m              = &Metrics{
			MinHeapAfterGCKB: math.MaxInt64,
		}
		firstUptime = -1.0
		lastUptime  = -1.0
		reasonsSet  = make(map[string]bool)
	)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		m.TotalLines++

		if logPrefix.Len() < MaxReportChars {
			if logPrefix.Len() > 0 {
				logPrefix.WriteByte('\n')
			}
			rem := MaxReportChars - logPrefix.Len()
			if len(line) <= rem {
				logPrefix.WriteString(line)
			} else if rem > 0 {
				logPrefix.WriteString(line[:rem])
			}
		}

		// Track uptime if available
		if up := uptimePattern.FindStringSubmatch(line); len(up) == 2 {
			if val, err := parseFloat(up[1]); err == nil {
				if firstUptime < 0 {
					firstUptime = val
				}
				if val > lastUptime {
					lastUptime = val
				}
			}
		}

		// Humongous & Evacuation failure checks
		lower := strings.ToLower(line)
		if strings.Contains(lower, "humongous") {
			m.HumongousCount++
		}
		if strings.Contains(lower, "to-space exhausted") || strings.Contains(lower, "evacuation failure") {
			m.ToSpaceExhausted++
		}

		// Unified logging pause
		if up := unifiedPausePattern.FindStringSubmatch(line); len(up) == 3 {
			gcType := up[1]
			pauseMs, err := parseFloat(up[2])
			if err == nil {
				pauseTimes = append(pauseTimes, pauseMs)
				switch {
				case strings.HasPrefix(gcType, "Mixed") || strings.HasPrefix(gcType, "Young") && strings.Contains(gcType, "(Mixed)"):
					m.MixedGCCount++
				case strings.HasPrefix(gcType, "Young"):
					m.YoungGCCount++
				case strings.HasPrefix(gcType, "Full"):
					m.FullGCCount++
					if len(m.FullGCReasons) < 5 && !reasonsSet[line] {
						reasonsSet[line] = true
						m.FullGCReasons = append(m.FullGCReasons, strings.TrimSpace(line))
					}
				default:
					m.OtherPauseCount++
				}
			}
		} else {
			// Legacy format
			if lg := legacyGcPattern.FindStringSubmatch(line); len(lg) == 2 && !strings.Contains(line, "Full GC") {
				if secs, err := parseFloat(lg[1]); err == nil {
					pauseTimes = append(pauseTimes, secs*1000.0)
					m.YoungGCCount++
				}
			}
			if lfg := legacyFullGcPattern.FindStringSubmatch(line); len(lfg) == 2 {
				if secs, err := parseFloat(lfg[1]); err == nil {
					pauseTimes = append(pauseTimes, secs*1000.0)
					m.FullGCCount++
					if len(m.FullGCReasons) < 5 && !reasonsSet[line] {
						reasonsSet[line] = true
						m.FullGCReasons = append(m.FullGCReasons, strings.TrimSpace(line))
					}
				}
			}
		}

		// Unified heap tracking
		for _, uh := range unifiedHeapPattern.FindAllStringSubmatch(line, -1) {
			if len(uh) == 4 {
				beforeMB, _ := strconv.ParseInt(uh[1], 10, 64)
				afterMB, _ := strconv.ParseInt(uh[2], 10, 64)
				capMB, _ := strconv.ParseInt(uh[3], 10, 64)
				beforeKB := beforeMB * 1024
				afterKB := afterMB * 1024
				capKB := capMB * 1024
				updateHeapMetrics(m, beforeKB, afterKB, capKB, &afterGCHistory)
			}
		}

		// Legacy heap tracking
		for _, lh := range legacyHeapPattern.FindAllStringSubmatch(line, -1) {
			if len(lh) == 4 {
				beforeKB, _ := strconv.ParseInt(lh[1], 10, 64)
				afterKB, _ := strconv.ParseInt(lh[2], 10, 64)
				capKB, _ := strconv.ParseInt(lh[3], 10, 64)
				updateHeapMetrics(m, beforeKB, afterKB, capKB, &afterGCHistory)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", nil, err
	}

	prefixStr := logPrefix.String()
	m.Collector = detectCollector(prefixStr)
	m.TotalEvents = len(pauseTimes) // recognized terminal pause records, not concurrent GC cycle count

	if len(pauseTimes) > 0 {
		sort.Float64s(pauseTimes)
		var sum float64
		m.MinPauseMs = pauseTimes[0]
		m.MaxPauseMs = pauseTimes[len(pauseTimes)-1]
		for _, p := range pauseTimes {
			sum += p
			if p > 200 {
				m.PausesAbove200ms++
			}
			if p > 1000 {
				m.PausesAbove1000ms++
			}
		}
		m.TotalPauseMs = sum
		m.AvgPauseMs = sum / float64(len(pauseTimes))
		m.P50PauseMs = pauseTimes[len(pauseTimes)/2]
		m.P95PauseMs = pauseTimes[int(float64(len(pauseTimes))*0.95)]
		m.P99PauseMs = pauseTimes[int(float64(len(pauseTimes))*0.99)]
	}

	if firstUptime >= 0 && lastUptime > firstUptime {
		m.DurationSec = lastUptime - firstUptime
		totalMs := m.DurationSec * 1000.0
		if totalMs > 0 {
			gcPct := (m.TotalPauseMs / totalMs) * 100.0
			if gcPct > 100 {
				gcPct = 100
			}
			m.ThroughputPct = 100.0 - gcPct
		}
	}

	// Check post-GC baseline growth (memory leak indicator)
	if len(afterGCHistory) >= 8 {
		q := len(afterGCHistory) / 4
		var earlySum, lateSum int64
		for i := 0; i < q; i++ {
			earlySum += afterGCHistory[i]
		}
		for i := len(afterGCHistory) - q; i < len(afterGCHistory); i++ {
			lateSum += afterGCHistory[i]
		}
		m.EarlyAfterGCBaseline = earlySum / int64(q)
		m.LateAfterGCBaseline = lateSum / int64(q)
		if m.EarlyAfterGCBaseline > 0 && float64(m.LateAfterGCBaseline) > float64(m.EarlyAfterGCBaseline)*1.35 {
			m.LeakTrendSuspected = true
		}
	}

	return buildReport(m, prefixStr), m, nil
}

func updateHeapMetrics(m *Metrics, beforeKB, afterKB, capKB int64, afterHistory *[]int64) {
	if beforeKB > m.MaxHeapUsedKB {
		m.MaxHeapUsedKB = beforeKB
	}
	if capKB > m.MaxHeapCapacityKB {
		m.MaxHeapCapacityKB = capKB
	}
	if afterKB > 0 && afterKB < m.MinHeapAfterGCKB {
		m.MinHeapAfterGCKB = afterKB
	}
	if beforeKB > afterKB {
		m.TotalReclaimedKB += (beforeKB - afterKB)
	}
	if afterKB > 0 {
		*afterHistory = append(*afterHistory, afterKB)
	}
}

func buildReport(m *Metrics, prefix string) string {
	var sb strings.Builder
	sb.WriteString("GC Log Analysis Report\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("## GC Configuration\n\n")
	sb.WriteString(fmt.Sprintf("Detected Collector: %s\n", m.Collector))
	sb.WriteString(fmt.Sprintf("Total log lines: %d\n", m.TotalLines))
	if m.DurationSec > 0 {
		sb.WriteString(fmt.Sprintf("Log Time Span: %.1f sec (%.2f min)\n", m.DurationSec, m.DurationSec/60.0))
		sb.WriteString(fmt.Sprintf("Observed pause-free log-time estimate: %.2f%% (summed pause fraction: %.2f%%)\n", m.ThroughputPct, 100.0-m.ThroughputPct))
	}
	sb.WriteString("\n")

	sb.WriteString("## GC Event Summary\n\n")
	sb.WriteString(fmt.Sprintf("Recognized GC pause records: %d\n", m.TotalEvents))
	sb.WriteString(fmt.Sprintf("  Young GC:  %d\n", m.YoungGCCount))
	sb.WriteString(fmt.Sprintf("  Full GC:   %d\n", m.FullGCCount))
	if m.OtherPauseCount > 0 {
		sb.WriteString(fmt.Sprintf("  Other named pauses: %d\n", m.OtherPauseCount))
	}
	if m.MixedGCCount > 0 {
		sb.WriteString(fmt.Sprintf("  Mixed GC:  %d\n", m.MixedGCCount))
	}
	if m.HumongousCount > 0 {
		sb.WriteString(fmt.Sprintf("  Humongous References/Allocations: %d\n", m.HumongousCount))
	}
	if m.ToSpaceExhausted > 0 {
		sb.WriteString(fmt.Sprintf("  To-Space Exhausted / Evacuation Failures: %d\n", m.ToSpaceExhausted))
	}
	sb.WriteString("\n")

	if m.TotalEvents > 0 && m.MaxPauseMs > 0 {
		sb.WriteString("## Pause Time Analysis\n\n")
		sb.WriteString(fmt.Sprintf("Total pause time: %.2f ms (%.2f sec)\n", m.TotalPauseMs, m.TotalPauseMs/1000.0))
		sb.WriteString(fmt.Sprintf("Average pause:    %.2f ms\n", m.AvgPauseMs))
		sb.WriteString(fmt.Sprintf("Min pause:        %.2f ms\n", m.MinPauseMs))
		sb.WriteString(fmt.Sprintf("Max pause:        %.2f ms\n", m.MaxPauseMs))
		sb.WriteString(fmt.Sprintf("P50 pause:        %.2f ms\n", m.P50PauseMs))
		sb.WriteString(fmt.Sprintf("P95 pause:        %.2f ms\n", m.P95PauseMs))
		sb.WriteString(fmt.Sprintf("P99 pause:        %.2f ms\n", m.P99PauseMs))
		sb.WriteString(fmt.Sprintf("Pauses > 200ms:   %d\n", m.PausesAbove200ms))
		sb.WriteString(fmt.Sprintf("Pauses > 1s:      %d\n\n", m.PausesAbove1000ms))

		if m.PausesAbove1000ms > 0 {
			sb.WriteString(fmt.Sprintf("WARNING: %d pause(s) exceeded 1 second!\n\n", m.PausesAbove1000ms))
		}
		if m.FullGCCount > 5 && float64(m.FullGCCount) > float64(m.TotalEvents)*0.1 {
			sb.WriteString(fmt.Sprintf("WARNING: High ratio of Full GC events (%.1f%%) — possible memory pressure!\n\n",
				float64(m.FullGCCount)*100.0/float64(m.TotalEvents)))
		}
		if m.ToSpaceExhausted > 0 {
			sb.WriteString(fmt.Sprintf("WARNING: %d To-Space Exhausted / Evacuation Failure events detected!\n\n", m.ToSpaceExhausted))
		}
	}

	if m.MaxHeapCapacityKB > 0 {
		sb.WriteString("## Heap Usage & Trend\n\n")
		sb.WriteString(fmt.Sprintf("Max heap used:       %s\n", formatKB(m.MaxHeapUsedKB)))
		sb.WriteString(fmt.Sprintf("Max heap capacity:   %s\n", formatKB(m.MaxHeapCapacityKB)))
		if m.MinHeapAfterGCKB < math.MaxInt64 {
			sb.WriteString(fmt.Sprintf("Min heap after GC:   %s\n", formatKB(m.MinHeapAfterGCKB)))
			livePct := (float64(m.MinHeapAfterGCKB) * 100.0) / float64(m.MaxHeapCapacityKB)
			sb.WriteString(fmt.Sprintf("Estimated live data: %.1f%% of capacity\n", livePct))
		}
		if m.TotalReclaimedKB > 0 {
			sb.WriteString(fmt.Sprintf("Total reclaimed:     %s\n", formatKB(m.TotalReclaimedKB)))
			if m.DurationSec > 0 {
				allocRateKBPerSec := float64(m.TotalReclaimedKB) / m.DurationSec
				sb.WriteString(fmt.Sprintf("Est. Allocation Rate: %s/sec\n", formatKB(int64(allocRateKBPerSec))))
			}
		}
		if m.EarlyAfterGCBaseline > 0 && m.LateAfterGCBaseline > 0 {
			sb.WriteString(fmt.Sprintf("Post-GC Baseline Trend: %s (early) -> %s (late)\n",
				formatKB(m.EarlyAfterGCBaseline), formatKB(m.LateAfterGCBaseline)))
			if m.LeakTrendSuspected {
				sb.WriteString("WARNING: Post-GC heap baseline grew by >35% over the log duration — potential memory leak!\n")
			}
		}
		sb.WriteString("\n")
	}

	if len(m.FullGCReasons) > 0 {
		sb.WriteString("## Sample Full GC Entries\n\n")
		for _, r := range m.FullGCReasons {
			sb.WriteString("- `" + r + "`\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Raw GC Log (for detailed analysis)\n\n```\n")
	remaining := MaxReportChars - sb.Len() - 100
	rawSection := prefix
	if remaining > 0 && len(rawSection) > remaining {
		rawSection = rawSection[:remaining] + "\n\n[... GC LOG TRUNCATED ...]"
	}
	sb.WriteString(rawSection)
	sb.WriteString("\n```\n")

	return sb.String()
}

func detectCollector(content string) string {
	if strings.Contains(content, "Using G1") || strings.Contains(content, "G1 Evacuation Pause") || strings.Contains(content, "Pause Young (G1") {
		return "G1 Garbage Collector (G1GC)"
	}
	if strings.Contains(content, "The Z Garbage Collector") || strings.Contains(content, "Using ZGC") || strings.Contains(content, "ZGC") {
		return "Z Garbage Collector (ZGC)"
	}
	if strings.Contains(content, "Using Shenandoah") || strings.Contains(content, "Shenandoah") {
		return "Shenandoah GC"
	}
	if strings.Contains(content, "CMS") || strings.Contains(content, "Concurrent Mark Sweep") {
		return "Concurrent Mark Sweep (CMS)"
	}
	if strings.Contains(content, "Using Parallel") || strings.Contains(content, "PSYoungGen") || strings.Contains(content, "ParOldGen") {
		return "Parallel GC"
	}
	if strings.Contains(content, "Using Serial") || strings.Contains(content, "DefNew") || strings.Contains(content, "Tenured") {
		return "Serial GC"
	}
	return "Unknown (could not auto-detect)"
}

func formatKB(kb int64) string {
	if kb >= 1048576 {
		return fmt.Sprintf("%.2f GB", float64(kb)/1048576.0)
	} else if kb >= 1024 {
		return fmt.Sprintf("%.1f MB", float64(kb)/1024.0)
	}
	return fmt.Sprintf("%d KB", kb)
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
}
