package nmtcrash

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type NMTCategory struct {
	Name        string `json:"name"`
	ReservedKB  int64  `json:"reservedKb"`
	CommittedKB int64  `json:"committedKb"`
	DeltaKB     int64  `json:"deltaKb,omitempty"`
	DetailNote  string `json:"detailNote,omitempty"`
}

type Summary struct {
	ReportType         string        `json:"reportType"` // "HS_ERR_CRASH", "NMT_REPORT", or "COMBINED"
	SignalOrError      string        `json:"signalOrError,omitempty"`
	ProblematicFrame   string        `json:"problematicFrame,omitempty"`
	CrashingThread     string        `json:"crashingThread,omitempty"`
	JVMVersion         string        `json:"jvmVersion,omitempty"`
	JVMFlags           string        `json:"jvmFlags,omitempty"`
	OSMemoryInfo       string        `json:"osMemoryInfo,omitempty"`
	MaxMapCount        int           `json:"maxMapCount,omitempty"`
	CrashStack         []string      `json:"crashStack,omitempty"`
	TotalReservedKB    int64         `json:"totalReservedKb"`
	TotalCommittedKB   int64         `json:"totalCommittedKb"`
	HeapCommittedKB    int64         `json:"heapCommittedKb"`
	OffHeapCommittedKB int64         `json:"offHeapCommittedKb"`
	ThreadCount        int           `json:"threadCount,omitempty"`
	Categories         []NMTCategory `json:"categories,omitempty"`
	Suspects           []string      `json:"suspects,omitempty"`
}

var (
	reNmtTotal = regexp.MustCompile(`(?i)Total:\s*reserved=(\d+)(KB|MB|GB|B)(?:[+-]\d+(?:KB|MB|GB|B))?,\s*committed=(\d+)(KB|MB|GB|B)`)
	reNmtCat   = regexp.MustCompile(`^\s*-\s+([A-Za-z0-9 /_-]+?)\s*\(reserved=(\d+)(KB|MB|GB|B)([+-]\d+(?:KB|MB|GB|B))?,\s*committed=(\d+)(KB|MB|GB|B)([+-]\d+(?:KB|MB|GB|B))?\)`)
	reThreadCt = regexp.MustCompile(`(?i)\(thread #(\d+)`)
	reMaxMap   = regexp.MustCompile(`/proc/sys/vm/max_map_count[:\s]+(\d+)`)
)

func AnalyzeFile(path string) (string, *Summary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return AnalyzeText(string(data))
}

func AnalyzeText(content string) (string, *Summary, error) {
	lines := strings.Split(content, "\n")
	sum := &Summary{}

	hasHsErr := false
	hasNmt := false
	inStack := false

	for i := 0; i < len(lines); i++ {
		raw := strings.TrimRight(lines[i], "\r")
		trimmed := strings.TrimSpace(raw)

		// Detect hs_err headers
		if strings.Contains(trimmed, "A fatal error has been detected by the Java Runtime Environment") ||
			strings.Contains(trimmed, "There is insufficient memory for the Java Runtime Environment to continue") {
			hasHsErr = true
		}
		if strings.HasPrefix(trimmed, "#") {
			clean := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			if strings.HasPrefix(clean, "SIG") || strings.Contains(clean, "EXCEPTION_") || strings.Contains(clean, "Out of Memory Error") || strings.Contains(clean, "Native memory allocation") {
				if sum.SignalOrError == "" {
					sum.SignalOrError = clean
					hasHsErr = true
				}
			}
			if strings.HasPrefix(clean, "Problematic frame:") {
				hasHsErr = true
				if i+1 < len(lines) {
					nextClean := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i+1]), "#"))
					sum.ProblematicFrame = nextClean
				}
			}
			if strings.HasPrefix(clean, "JRE version:") || strings.HasPrefix(clean, "Java VM:") {
				if sum.JVMVersion == "" {
					sum.JVMVersion = clean
				} else {
					sum.JVMVersion += " | " + clean
				}
			}
		}

		if strings.HasPrefix(trimmed, "Current thread (") {
			sum.CrashingThread = trimmed
			hasHsErr = true
		}

		if strings.HasPrefix(trimmed, "Native frames:") || strings.HasPrefix(trimmed, "Java frames:") {
			inStack = true
			continue
		}
		if inStack {
			if trimmed == "" || strings.HasPrefix(trimmed, "Register to memory mapping:") || strings.HasPrefix(trimmed, "Threads class SMR info:") || strings.HasPrefix(trimmed, "---------------") {
				inStack = false
			} else if len(sum.CrashStack) < 25 {
				sum.CrashStack = append(sum.CrashStack, trimmed)
			}
		}

		if strings.HasPrefix(trimmed, "jvm_args:") || strings.HasPrefix(trimmed, "VM Arguments:") {
			sum.JVMFlags = trimmed
		}
		if strings.HasPrefix(trimmed, "Memory:") && (strings.Contains(trimmed, "physical") || strings.Contains(trimmed, "page")) {
			sum.OSMemoryInfo = trimmed
		}
		if m := reMaxMap.FindStringSubmatch(trimmed); len(m) == 2 {
			sum.MaxMapCount, _ = strconv.Atoi(m[1])
		} else if strings.HasPrefix(trimmed, "/proc/sys/vm/max_map_count") && i+1 < len(lines) {
			if v, err := strconv.Atoi(strings.TrimSpace(lines[i+1])); err == nil {
				sum.MaxMapCount = v
			}
		}

		// Detect NMT Total
		if m := reNmtTotal.FindStringSubmatch(trimmed); len(m) == 5 {
			hasNmt = true
			sum.TotalReservedKB = toKB(m[1], m[2])
			sum.TotalCommittedKB = toKB(m[3], m[4])
		}

		// Detect NMT Category
		if m := reNmtCat.FindStringSubmatch(raw); len(m) >= 7 {
			hasNmt = true
			cat := NMTCategory{
				Name:        strings.TrimSpace(m[1]),
				ReservedKB:  toKB(m[2], m[3]),
				CommittedKB: toKB(m[5], m[6]),
			}
			if m[6] != "" && len(m) >= 8 && m[7] != "" {
				cat.DeltaKB = parseDeltaKB(m[7])
			}
			// Look ahead 1-3 lines for (thread #N) or (malloc=... mmap=...)
			var notes []string
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				sub := strings.TrimSpace(lines[j])
				if strings.HasPrefix(sub, "- ") || sub == "" {
					break
				}
				if strings.HasPrefix(sub, "(") {
					notes = append(notes, sub)
					if tm := reThreadCt.FindStringSubmatch(sub); len(tm) == 2 {
						sum.ThreadCount, _ = strconv.Atoi(tm[1])
					}
				}
			}
			cat.DetailNote = strings.Join(notes, " ")
			sum.Categories = append(sum.Categories, cat)

			if strings.EqualFold(cat.Name, "Java Heap") {
				sum.HeapCommittedKB = cat.CommittedKB
			}
		}
	}

	if sum.TotalCommittedKB > sum.HeapCommittedKB {
		sum.OffHeapCommittedKB = sum.TotalCommittedKB - sum.HeapCommittedKB
	}

	switch {
	case hasHsErr && hasNmt:
		sum.ReportType = "COMBINED_CRASH_AND_NMT"
	case hasHsErr:
		sum.ReportType = "HS_ERR_CRASH"
	case hasNmt:
		sum.ReportType = "NMT_REPORT"
	default:
		sum.ReportType = "UNKNOWN_NATIVE_DIAGNOSTIC"
	}

	buildSuspects(sum)
	return formatReport(sum), sum, nil
}

func buildSuspects(sum *Summary) {
	if strings.Contains(strings.ToLower(sum.SignalOrError), "insufficient memory") ||
		strings.Contains(strings.ToLower(sum.SignalOrError), "native memory allocation") ||
		strings.Contains(strings.ToLower(sum.SignalOrError), "out of memory") {
		sum.Suspects = append(sum.Suspects,
			"CRITICAL: Native OS memory allocation (mmap/malloc) failed. Either OS physical/container memory is exhausted or /proc/sys/vm/max_map_count was reached.")
	}
	if sum.MaxMapCount > 0 && sum.MaxMapCount <= 65530 {
		sum.Suspects = append(sum.Suspects,
			fmt.Sprintf("WARNING: Linux vm.max_map_count is low (%d). JVM processes with many threads, NIO buffers, or native libraries frequently hit mmap failures unless vm.max_map_count >= 262144.", sum.MaxMapCount))
	}
	if strings.HasPrefix(sum.ProblematicFrame, "C ") {
		sum.Suspects = append(sum.Suspects,
			fmt.Sprintf("CRITICAL: Native C/JNI library crash in frame %s. Inspect JNI bindings, native drivers, or direct memory access.", sum.ProblematicFrame))
	} else if strings.HasPrefix(sum.ProblematicFrame, "J ") || strings.Contains(sum.CrashingThread, "CompilerThread") {
		sum.Suspects = append(sum.Suspects,
			fmt.Sprintf("HIGH: Crash occurred inside JIT compiled code or CompilerThread (%s). Consider excluding the method via -XX:CompileCommand=exclude.", sum.ProblematicFrame))
	}

	for _, c := range sum.Categories {
		nameLower := strings.ToLower(c.Name)
		if nameLower == "thread" && (c.CommittedKB > 256*1024 || sum.ThreadCount > 300) {
			sum.Suspects = append(sum.Suspects,
				fmt.Sprintf("HIGH: Thread native stack footprint is %d MB across %d threads. Consider reducing thread pool sizes, lowering -Xss (e.g., -Xss512k), or migrating to Virtual Threads.", c.CommittedKB/1024, sum.ThreadCount))
		}
		if (nameLower == "internal" || nameLower == "other") && c.CommittedKB > 256*1024 {
			sum.Suspects = append(sum.Suspects,
				fmt.Sprintf("HIGH: Off-Heap '%s' memory is %d MB (often Direct ByteBuffers / Netty ByteBufs / unsafe allocations). Cap with -XX:MaxDirectMemorySize and check for unclosed DirectByteBuffers.", c.Name, c.CommittedKB/1024))
		}
		if nameLower == "class" && c.CommittedKB > 384*1024 {
			sum.Suspects = append(sum.Suspects,
				fmt.Sprintf("WARNING: Class / Metaspace committed memory is %d MB. Check for dynamic class generation or ClassLoader leaks and set -XX:MaxMetaspaceSize.", c.CommittedKB/1024))
		}
		if nameLower == "gc" && sum.TotalCommittedKB > 0 && float64(c.CommittedKB)/float64(sum.TotalCommittedKB) > 0.12 {
			sum.Suspects = append(sum.Suspects,
				fmt.Sprintf("WARNING: GC native overhead is %d MB (%.1f%% of total committed memory). Large G1GC Remembered Sets or ZGC page tables may require tuning (-XX:G1HeapRegionSize).",
					c.CommittedKB/1024, float64(c.CommittedKB)*100/float64(sum.TotalCommittedKB)))
		}
		if nameLower == "arena chunk" && c.CommittedKB > 128*1024 {
			sum.Suspects = append(sum.Suspects,
				fmt.Sprintf("WARNING: Native Arena Chunk memory is %d MB. In Linux containers, glibc malloc arenas can fragment native memory; consider MALLOC_ARENA_MAX=2 or jemalloc.", c.CommittedKB/1024))
		}
	}
}

func formatReport(sum *Summary) string {
	var sb strings.Builder
	sb.WriteString("==========================================================\n")
	sb.WriteString("   JVM CRASH (hs_err) & NATIVE MEMORY (NMT) REPORT\n")
	sb.WriteString("==========================================================\n")
	sb.WriteString(fmt.Sprintf("Artifact Type:          %s\n", sum.ReportType))
	if sum.JVMVersion != "" {
		sb.WriteString(fmt.Sprintf("JVM Version:            %s\n", sum.JVMVersion))
	}
	if sum.SignalOrError != "" {
		sb.WriteString(fmt.Sprintf("Signal / Fatal Error:   %s\n", sum.SignalOrError))
	}
	if sum.ProblematicFrame != "" {
		sb.WriteString(fmt.Sprintf("Problematic Frame:      %s\n", sum.ProblematicFrame))
	}
	if sum.CrashingThread != "" {
		sb.WriteString(fmt.Sprintf("Crashing Thread:        %s\n", sum.CrashingThread))
	}
	if sum.OSMemoryInfo != "" {
		sb.WriteString(fmt.Sprintf("OS Memory State:        %s\n", sum.OSMemoryInfo))
	}
	if sum.MaxMapCount > 0 {
		sb.WriteString(fmt.Sprintf("Linux vm.max_map_count: %d\n", sum.MaxMapCount))
	}
	if sum.JVMFlags != "" {
		sb.WriteString(fmt.Sprintf("JVM Flags:              %s\n", sum.JVMFlags))
	}

	if sum.TotalCommittedKB > 0 {
		offPct := 0.0
		if sum.TotalCommittedKB > 0 {
			offPct = float64(sum.OffHeapCommittedKB) * 100.0 / float64(sum.TotalCommittedKB)
		}
		sb.WriteString(fmt.Sprintf("\n--- NATIVE MEMORY (NMT) OVERVIEW ---\n"))
		sb.WriteString(fmt.Sprintf("Total Reserved:         %.1f MB (%d KB)\n", float64(sum.TotalReservedKB)/1024.0, sum.TotalReservedKB))
		sb.WriteString(fmt.Sprintf("Total Committed (RSS):  %.1f MB (%d KB)\n", float64(sum.TotalCommittedKB)/1024.0, sum.TotalCommittedKB))
		sb.WriteString(fmt.Sprintf("Java Heap Committed:    %.1f MB (%d KB)\n", float64(sum.HeapCommittedKB)/1024.0, sum.HeapCommittedKB))
		sb.WriteString(fmt.Sprintf("Off-Heap Committed:     %.1f MB (%d KB, %.1f%% of Total)\n", float64(sum.OffHeapCommittedKB)/1024.0, sum.OffHeapCommittedKB, offPct))
	}

	if len(sum.Suspects) > 0 {
		sb.WriteString("\n--- AUTOMATED DIAGNOSTIC FINDINGS ---\n")
		for i, s := range sum.Suspects {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, s))
		}
	}

	if len(sum.Categories) > 0 {
		cats := make([]NMTCategory, len(sum.Categories))
		copy(cats, sum.Categories)
		sort.Slice(cats, func(i, j int) bool {
			return cats[i].CommittedKB > cats[j].CommittedKB
		})
		sb.WriteString("\n--- NMT MEMORY BREAKDOWN BY CATEGORY (Ranked by Committed) ---\n")
		sb.WriteString(fmt.Sprintf("%-26s %14s %14s %12s  %s\n", "CATEGORY", "COMMITTED", "RESERVED", "DELTA", "DETAILS"))
		for _, c := range cats {
			deltaStr := "-"
			if c.DeltaKB != 0 {
				deltaStr = fmt.Sprintf("%+d KB", c.DeltaKB)
			}
			sb.WriteString(fmt.Sprintf("%-26s %11.1f MB %11.1f MB %12s  %s\n",
				c.Name,
				float64(c.CommittedKB)/1024.0,
				float64(c.ReservedKB)/1024.0,
				deltaStr,
				c.DetailNote,
			))
		}
	}

	if len(sum.CrashStack) > 0 {
		sb.WriteString("\n--- CRASH CALL STACK ---\n")
		for _, frame := range sum.CrashStack {
			sb.WriteString("  " + frame + "\n")
		}
	}

	return sb.String()
}

func toKB(numStr, unit string) int64 {
	v, _ := strconv.ParseInt(numStr, 10, 64)
	switch strings.ToUpper(unit) {
	case "GB":
		return v * 1024 * 1024
	case "MB":
		return v * 1024
	case "B":
		return v / 1024
	default:
		return v
	}
}

func parseDeltaKB(raw string) int64 {
	if raw == "" {
		return 0
	}
	sign := int64(1)
	if strings.HasPrefix(raw, "-") {
		sign = -1
	}
	clean := strings.TrimLeft(raw, "+-")
	for _, u := range []string{"GB", "MB", "KB", "B"} {
		if strings.HasSuffix(strings.ToUpper(clean), u) {
			numPart := clean[:len(clean)-len(u)]
			return sign * toKB(numPart, u)
		}
	}
	return 0
}
