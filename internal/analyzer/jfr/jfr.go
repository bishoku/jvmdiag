// Package jfr analyzes decoded JFR events. It never treats metadata symbols as events.
package jfr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bishoku/jvmdiag/internal/analyzer/quality"
)

type MethodHotspot struct {
	Method    string   `json:"method"`
	Samples   int      `json:"samples"`
	Pct       float64  `json:"pct"` // share of observed execution samples with resolved stacks
	Locations []string `json:"locations"`
}
type AllocationHotspot struct {
	ClassName    string   `json:"className"`
	EventType    string   `json:"eventType"`
	Metric       string   `json:"metric"`
	TopAllocator string   `json:"allocatorFrame,omitempty"`
	Count        int      `json:"count"`
	TotalBytes   int64    `json:"totalBytes"`
	Locations    []string `json:"locations"`
}
type MonitorContention struct {
	MonitorClass string   `json:"monitorClass"`
	TopFrame     string   `json:"frame,omitempty"`
	Count        int      `json:"count"`
	TimedCount   int      `json:"timedCount"`
	TotalWaitMs  float64  `json:"totalWaitMs"`
	MaxWaitMs    float64  `json:"maxWaitMs"`
	Locations    []string `json:"locations"`
}
type PinnedEvent struct {
	Frame       string   `json:"frame"`
	Count       int      `json:"count"`
	TimedCount  int      `json:"timedCount"`
	TotalWaitMs float64  `json:"totalWaitMs"`
	MaxWaitMs   float64  `json:"maxWaitMs"`
	Locations   []string `json:"locations"`
}
type Summary struct {
	GCPauseMaxLocation      string              `json:"gcPauseMaxLocation,omitempty"`
	GCPhasePauseCount       int                 `json:"gcPhasePauseCount"`
	GCWithLongestPauseCount int                 `json:"gcWithLongestPauseCount"`
	GCTimedCount            int                 `json:"gcTimedCount"`
	IOTimedCount            int                 `json:"ioTimedCount"`
	GCObservationLocations  []string            `json:"gcObservationLocations,omitempty"`
	IOObservationLocations  []string            `json:"ioObservationLocations,omitempty"`
	Assessment              quality.Assessment  `json:"assessment"`
	EngineUsed              string              `json:"engineUsed"`
	FormatVersion           string              `json:"formatVersion,omitempty"`
	ChunkCount              int                 `json:"chunkCount,omitempty"`
	DurationSeconds         float64             `json:"durationSeconds,omitempty"`
	TotalEvents             int                 `json:"totalEvents"` // decoded events in the stated scope, not whole recording count
	EventCounts             map[string]int      `json:"eventCounts"`
	CPUHotspots             []MethodHotspot     `json:"cpuHotspots,omitempty"`
	AllocationHotspots      []AllocationHotspot `json:"allocationHotspots,omitempty"`
	TLABReservedBytes       int64               `json:"tlabReservedBytes"`
	MonitorContentions      []MonitorContention `json:"monitorContentions,omitempty"`
	PinnedEvents            []PinnedEvent       `json:"pinnedEvents,omitempty"`
	GCEventCount            int                 `json:"gcEventCount"`
	MaxGCCycleMs            float64             `json:"maxGcCycleMs"`
	GCPauseCount            int                 `json:"gcPauseCount"`
	GCPauseSource           string              `json:"gcPauseSource,omitempty"`
	MaxGCPauseMs            float64             `json:"maxGcPauseMs"`
	SlowIOCount             int                 `json:"slowIoCount"`
	MaxSlowIOMs             float64             `json:"maxSlowIoMs"`
	Suspects                []string            `json:"suspects,omitempty"` // compatibility titles; see assessment.findings for evidence
}

const selectedEvents = "jdk.ExecutionSample,jdk.NativeMethodSample,jdk.ObjectAllocationInNewTLAB,jdk.ObjectAllocationOutsideTLAB,jdk.ObjectAllocationSample,jdk.JavaMonitorEnter,jdk.VirtualThreadPinned,jdk.GarbageCollection,jdk.GCPhasePause,jdk.SocketRead,jdk.FileRead"

var supportedEvents = func() map[string]bool {
	out := make(map[string]bool)
	for _, name := range strings.Split(selectedEvents, ",") {
		out[name] = true
	}
	return out
}()

type Options struct {
	ToolPath             string
	DisableToolDiscovery bool
	Environment          []string
}

func AnalyzeFile(path string) (string, *Summary, error) {
	return AnalyzeFileWithOptions(path, Options{})
}

func AnalyzeFileWithOptions(path string, opts Options) (string, *Summary, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	var magic [4]byte
	n, err := io.ReadFull(f, magic[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", nil, err
	}
	if n == 4 && string(magic[:]) == "FLR\x00" {
		metadata, err := inspectBinary(f)
		if err != nil {
			return "", nil, err
		}
		metadata.Assessment.Source = filepath.Base(path)
		tool := opts.ToolPath
		if tool == "" && !opts.DisableToolDiscovery {
			tool = findJFRBinary()
		}
		if tool == "" {
			return "", metadata, fmt.Errorf("JFR event decoding unavailable: install the JDK jfr tool or export with jfr print --json; header metadata alone cannot establish event counts or hotspots")
		}
		sum, err := analyzeWithJFRToolEnvironment(tool, path, opts.Environment)
		if err != nil {
			return "", metadata, fmt.Errorf("JFR event decoding failed (no metadata fallback): %w", err)
		}
		sum.FormatVersion = metadata.FormatVersion
		sum.ChunkCount = metadata.ChunkCount
		sum.DurationSeconds = metadata.DurationSeconds
		return formatReport(sum), sum, nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", nil, err
	}
	trimmed := bytes.TrimSpace(data)
	var sum *Summary
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		sum, err = parseJFRJSON(trimmed)
	} else {
		sum, err = parseJFRTextSummary(string(data))
	}
	if err != nil {
		return "", nil, err
	}
	sum.Assessment.Source = filepath.Base(path)
	buildFindings(sum)
	return formatReport(sum), sum, nil
}

func findJFRBinary() string {
	if p, err := exec.LookPath("jfr"); err == nil {
		return p
	}
	if home := os.Getenv("JAVA_HOME"); home != "" {
		p := filepath.Join(home, "bin", "jfr")
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func analyzeWithJFRTool(tool, path string) (*Summary, error) {
	return analyzeWithJFRToolEnvironment(tool, path, nil)
}

func analyzeWithJFRToolEnvironment(tool, path string, env []string) (*Summary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, "print", "--json", "--stack-depth", "8", "--events", selectedEvents, path)
	cmd.Env = env
	// Decode the selected event stream; summary counts are deliberately not merged into it.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jfr print: %w", err)
	}
	sum, err := parseJFRJSON(out)
	if err != nil {
		return nil, err
	}
	sum.EngineUsed = "jdk-jfr-cli"
	sum.Assessment.Source = filepath.Base(path)
	sum.Assessment.Scope = "selected events decoded by jfr print: " + selectedEvents
	sum.Assessment.Limitations = append(sum.Assessment.Limitations, "JDK export selects event types and at most 8 stack frames; counts describe this selection, not all recording events.")
	buildFindings(sum)
	return sum, nil
}

// inspectBinary validates completed chunk boundaries without decoding event metadata or payloads.
func inspectBinary(f *os.File) (*Summary, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sum := &Summary{EngineUsed: "jfr-header-only", Assessment: quality.Assessment{Status: "metadata-only", Scope: "validated completed chunk headers only", Limitations: []string{"No events decoded; event counts, hotspots and pinning are unavailable."}}}
	var offset int64
	var header [68]byte
	for offset < st.Size() {
		if st.Size()-offset < 68 {
			return nil, fmt.Errorf("truncated JFR chunk header at byte %d", offset)
		}
		if _, err := f.ReadAt(header[:], offset); err != nil {
			return nil, err
		}
		if string(header[:4]) != "FLR\x00" {
			return nil, fmt.Errorf("invalid JFR chunk magic at byte %d", offset)
		}
		major, minor := binary.BigEndian.Uint16(header[4:6]), binary.BigEndian.Uint16(header[6:8])
		if major != 2 || minor > 1 {
			return nil, fmt.Errorf("unsupported JFR version %d.%d", major, minor)
		}
		size := binary.BigEndian.Uint64(header[8:16])
		if size < 68 || size > uint64(st.Size()-offset) {
			return nil, fmt.Errorf("invalid or incomplete JFR chunk size at byte %d", offset)
		}
		// Completed recordings need metadata and constant-pool positions within this chunk.
		cp, meta := binary.BigEndian.Uint64(header[16:24]), binary.BigEndian.Uint64(header[24:32])
		if meta < 68 || meta >= size || cp != 0 && (cp < 68 || cp >= size) {
			return nil, fmt.Errorf("invalid or unfinished JFR chunk metadata at byte %d", offset)
		}
		nanos := binary.BigEndian.Uint64(header[40:48])
		sum.DurationSeconds += float64(nanos) / 1e9
		sum.FormatVersion = fmt.Sprintf("%d.%d", major, minor)
		sum.ChunkCount++
		offset += int64(size)
	}
	if sum.ChunkCount == 0 {
		return nil, fmt.Errorf("empty JFR recording")
	}
	return sum, nil
}

type eventValues struct {
	Duration       json.RawMessage `json:"duration"`
	LongestPause   json.RawMessage `json:"longestPause"`
	AllocationSize *int64          `json:"allocationSize"`
	TlabSize       *int64          `json:"tlabSize"`
	Weight         *int64          `json:"weight"`
	ObjectClass    *struct {
		Name string `json:"name"`
	} `json:"objectClass"`
	MonitorClass *struct {
		Name string `json:"name"`
	} `json:"monitorClass"`
	StackTrace *struct {
		Frames []struct {
			Method struct {
				Type struct {
					Name string `json:"name"`
				} `json:"type"`
				Name string `json:"name"`
			} `json:"method"`
			LineNumber int `json:"lineNumber"`
		} `json:"frames"`
	} `json:"stackTrace"`
}
type event struct {
	Type   string          `json:"type"`
	Values json.RawMessage `json:"values"`
}

func parseJFRJSON(raw []byte) (*Summary, error) {
	var root struct {
		Recording *struct {
			Events *[]event `json:"events"`
		} `json:"recording"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("invalid JFR JSON: %w", err)
	}
	if root.Recording == nil || root.Recording.Events == nil {
		return nil, fmt.Errorf("JFR JSON must contain recording.events as an array")
	}
	sum := &Summary{EngineUsed: "native-jfr-json", EventCounts: make(map[string]int), Assessment: quality.Assessment{Status: "complete", Scope: "events present in the supplied JSON export", Limitations: []string{"No events observed does not imply a healthy JVM; recording settings, thresholds and export filters are unknown.", "Execution sample share is not CPU utilization. Allocation events do not establish an application's total allocation rate.", "A bottleneck or root cause requires workload, timing and JVM version context."}}}
	cpu := map[string]*MethodHotspot{}
	alloc := map[string]*AllocationHotspot{}
	mon := map[string]*MonitorContention{}
	pins := map[string]*PinnedEvent{}
	samples := 0
	longestCount := 0
	maxLongest := 0.0
	longestLoc, phaseLoc := "", ""
	phaseCount := 0
	maxPhase := 0.0
	for i, ev := range *root.Recording.Events {
		loc := fmt.Sprintf("recording.events[%d] (%s)", i, ev.Type)
		if strings.TrimSpace(ev.Type) == "" || len(ev.Values) == 0 || string(ev.Values) == "null" || ev.Values[0] != '{' {
			return nil, fmt.Errorf("%s: event type and values object are required", loc)
		}
		if !supportedEvents[ev.Type] {
			sum.TotalEvents++
			sum.EventCounts[ev.Type]++
			sum.Assessment.Warn("Some event types are counted but have no supported diagnostic rules.")
			continue
		}
		var values eventValues
		if err := json.Unmarshal(ev.Values, &values); err != nil {
			return nil, fmt.Errorf("%s: invalid event fields: %w", loc, err)
		}
		v := &values
		sum.TotalEvents++
		sum.EventCounts[ev.Type]++
		frame := "(stack unavailable)"
		if v.StackTrace != nil && len(v.StackTrace.Frames) > 0 {
			f := v.StackTrace.Frames[0]
			if f.Method.Name != "" && f.Method.Type.Name != "" {
				frame = strings.ReplaceAll(f.Method.Type.Name, "/", ".") + "." + f.Method.Name + "()"
				if f.LineNumber > 0 {
					frame = fmt.Sprintf("%s:%d", frame, f.LineNumber)
				}
			}
		}
		duration, hasDuration, err := durationMs(v.Duration)
		if err != nil {
			return nil, fmt.Errorf("%s duration: %w", loc, err)
		}
		switch ev.Type {
		case "jdk.ExecutionSample", "jdk.NativeMethodSample":
			if frame == "(stack unavailable)" {
				sum.Assessment.Warn("Execution samples with missing frames are excluded from hotspot percentages.")
				continue
			}
			samples++
			h := cpu[frame]
			if h == nil {
				h = &MethodHotspot{Method: frame}
				cpu[frame] = h
			}
			h.Samples++
			h.Locations = locations(h.Locations, loc)
		case "jdk.ObjectAllocationInNewTLAB", "jdk.ObjectAllocationOutsideTLAB", "jdk.ObjectAllocationSample":
			if frame == "(stack unavailable)" {
				sum.Assessment.Warn("Some allocation events have no allocator stack.")
			}
			cls := "(class unavailable)"
			if v.ObjectClass != nil && v.ObjectClass.Name != "" {
				cls = strings.ReplaceAll(v.ObjectClass.Name, "/", ".")
			} else {
				sum.Assessment.Warn("Some allocation events have no class attribution.")
			}
			value := v.AllocationSize
			metric := "recorded-object-bytes"
			if ev.Type == "jdk.ObjectAllocationSample" {
				value = v.Weight
				metric = "sample-weight-estimate"
			}
			if ev.Type == "jdk.ObjectAllocationInNewTLAB" && v.TlabSize != nil {
				if *v.TlabSize < 0 {
					return nil, fmt.Errorf("%s: negative tlabSize", loc)
				}
				if err := addBytes(&sum.TLABReservedBytes, *v.TlabSize); err != nil {
					return nil, err
				}
			}
			if value == nil {
				sum.Assessment.Warn("Allocation events without their event-specific byte field are excluded from byte totals.")
				continue
			}
			if *value < 0 {
				return nil, fmt.Errorf("%s: negative allocation byte value", loc)
			}
			key := cls + "\x00" + ev.Type + "\x00" + frame
			a := alloc[key]
			if a == nil {
				a = &AllocationHotspot{ClassName: cls, EventType: ev.Type, Metric: metric, TopAllocator: frame}
				alloc[key] = a
			}
			a.Count++
			if err := addBytes(&a.TotalBytes, *value); err != nil {
				return nil, err
			}
			a.Locations = locations(a.Locations, loc)
		case "jdk.JavaMonitorEnter":
			if frame == "(stack unavailable)" || v.MonitorClass == nil || v.MonitorClass.Name == "" {
				sum.Assessment.Warn("Some monitor events have incomplete class or stack attribution.")
			}
			cls := "(monitor class unavailable)"
			if v.MonitorClass != nil && v.MonitorClass.Name != "" {
				cls = strings.ReplaceAll(v.MonitorClass.Name, "/", ".")
			}
			key := cls + "\x00" + frame
			m := mon[key]
			if m == nil {
				m = &MonitorContention{MonitorClass: cls, TopFrame: frame}
				mon[key] = m
			}
			m.Count++
			m.Locations = locations(m.Locations, loc)
			if hasDuration {
				m.TimedCount++
				m.TotalWaitMs += duration
				m.MaxWaitMs = math.Max(m.MaxWaitMs, duration)
			} else {
				sum.Assessment.Warn("Monitor events with missing duration are counted but excluded from wait totals.")
			}
		case "jdk.VirtualThreadPinned":
			if frame == "(stack unavailable)" {
				sum.Assessment.Warn("Some pinning events have no recorded stack; pinning cause is unknown.")
			}
			p := pins[frame]
			if p == nil {
				p = &PinnedEvent{Frame: frame}
				pins[frame] = p
			}
			p.Count++
			p.Locations = locations(p.Locations, loc)
			if hasDuration {
				p.TimedCount++
				p.TotalWaitMs += duration
				p.MaxWaitMs = math.Max(p.MaxWaitMs, duration)
			} else {
				sum.Assessment.Warn("Pinning events with missing duration are counted but excluded from wait totals.")
			}
		case "jdk.GarbageCollection":
			sum.GCEventCount++
			sum.GCObservationLocations = locations(sum.GCObservationLocations, loc)
			if hasDuration {
				sum.GCTimedCount++
				sum.MaxGCCycleMs = math.Max(sum.MaxGCCycleMs, duration)
			} else {
				sum.Assessment.Warn("GC cycle durations are unavailable for some events.")
			}
			pause, present, err := durationMs(v.LongestPause)
			if err != nil {
				return nil, fmt.Errorf("%s longestPause: %w", loc, err)
			}
			if present {
				longestCount++
				if longestLoc == "" || pause > maxLongest {
					maxLongest = pause
					longestLoc = loc
				}
			} else {
				sum.Assessment.Warn("GC events without longestPause cannot establish pause durations.")
			}
		case "jdk.GCPhasePause":
			sum.GCObservationLocations = locations(sum.GCObservationLocations, loc)
			if hasDuration {
				phaseCount++
				if phaseLoc == "" || duration > maxPhase {
					maxPhase = duration
					phaseLoc = loc
				}
			} else {
				sum.Assessment.Warn("GC pause events without duration are excluded from pause metrics.")
			}
		case "jdk.SocketRead", "jdk.FileRead":
			if hasDuration {
				sum.IOTimedCount++
			}
			if !hasDuration {
				sum.Assessment.Warn("I/O events without duration are excluded from slow-I/O counts.")
			} else if duration >= 20 {
				sum.SlowIOCount++
				sum.IOObservationLocations = locations(sum.IOObservationLocations, loc)
				sum.MaxSlowIOMs = math.Max(sum.MaxSlowIOMs, duration)
			}
		}
	}
	sum.GCPhasePauseCount = phaseCount
	sum.GCWithLongestPauseCount = longestCount
	if phaseCount > 0 && (longestCount == 0 || maxPhase >= maxLongest) {
		sum.GCPauseMaxLocation = phaseLoc
		sum.GCPauseCount = phaseCount
		sum.MaxGCPauseMs = maxPhase
		sum.GCPauseSource = "jdk.GCPhasePause.duration"
	} else if longestCount > 0 {
		sum.GCPauseMaxLocation = longestLoc
		sum.GCPauseCount = longestCount
		sum.MaxGCPauseMs = maxLongest
		sum.GCPauseSource = "jdk.GarbageCollection.longestPause (one maximum per GC event, not a count of all pauses)"
	}
	for _, h := range cpu {
		h.Pct = float64(h.Samples) * 100 / float64(samples)
		sum.CPUHotspots = append(sum.CPUHotspots, *h)
	}
	for _, a := range alloc {
		sum.AllocationHotspots = append(sum.AllocationHotspots, *a)
	}
	for _, m := range mon {
		sum.MonitorContentions = append(sum.MonitorContentions, *m)
	}
	for _, p := range pins {
		sum.PinnedEvents = append(sum.PinnedEvents, *p)
	}
	sort.Slice(sum.CPUHotspots, func(i, j int) bool {
		a, b := sum.CPUHotspots[i], sum.CPUHotspots[j]
		if a.Samples == b.Samples {
			return a.Method < b.Method
		}
		return a.Samples > b.Samples
	})
	sort.Slice(sum.AllocationHotspots, func(i, j int) bool {
		a, b := sum.AllocationHotspots[i], sum.AllocationHotspots[j]
		if a.TotalBytes == b.TotalBytes {
			return a.ClassName+a.EventType+a.TopAllocator < b.ClassName+b.EventType+b.TopAllocator
		}
		return a.TotalBytes > b.TotalBytes
	})
	sort.Slice(sum.MonitorContentions, func(i, j int) bool {
		a, b := sum.MonitorContentions[i], sum.MonitorContentions[j]
		if a.TotalWaitMs == b.TotalWaitMs {
			return a.MonitorClass+a.TopFrame < b.MonitorClass+b.TopFrame
		}
		return a.TotalWaitMs > b.TotalWaitMs
	})
	sort.Slice(sum.PinnedEvents, func(i, j int) bool {
		a, b := sum.PinnedEvents[i], sum.PinnedEvents[j]
		if a.TotalWaitMs == b.TotalWaitMs {
			return a.Frame < b.Frame
		}
		return a.TotalWaitMs > b.TotalWaitMs
	})
	if sum.TotalEvents == 0 {
		sum.Assessment.Warn("The event export is empty; no runtime conclusions can be drawn.")
	}
	return sum, nil
}

func addBytes(dst *int64, n int64) error {
	if n < 0 || *dst > math.MaxInt64-n {
		return fmt.Errorf("allocation byte total overflows int64")
	}
	*dst += n
	return nil
}
func locations(list []string, loc string) []string {
	if len(list) < 5 {
		return append(list, loc)
	}
	return list
}

// JDK JSON uses ISO-8601 strings. Numeric exports are explicitly interpreted as nanoseconds.
var isoDuration = regexp.MustCompile(`^PT(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?$`)

func durationMs(raw json.RawMessage) (float64, bool, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false, nil
	}
	var value float64
	if raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return 0, false, err
		}
		m := isoDuration.FindStringSubmatch(text)
		if m == nil || m[1]+m[2]+m[3] == "" {
			return 0, false, fmt.Errorf("expected ISO-8601 duration or numeric nanoseconds")
		}
		for i, factor := range []float64{3600000, 60000, 1000} {
			if m[i+1] != "" {
				n, err := strconv.ParseFloat(m[i+1], 64)
				if err != nil {
					return 0, false, err
				}
				value += n * factor
			}
		}
	} else {
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, false, err
		}
		value /= 1e6
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false, fmt.Errorf("duration must be finite and nonnegative")
	}
	return value, true, nil
}

var summaryEventLine = regexp.MustCompile(`^\s*([A-Za-z_$][A-Za-z0-9_.$]*)\s+(\d+)\s+(\d+)\s*$`)

func parseJFRTextSummary(content string) (*Summary, error) {
	sum := &Summary{EngineUsed: "jfr-summary-text", EventCounts: make(map[string]int), Assessment: quality.Assessment{Status: "limited", Scope: "jfr summary event-count table only", Limitations: []string{"Summary counts contain no event stacks, durations or allocation weights; hotspots and bottlenecks are unavailable.", "No events observed does not establish JVM health."}}}
	header := false
	rows := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Event Type") && strings.Contains(line, "Count") && strings.Contains(line, "Size") {
			header = true
			continue
		}
		if !header {
			continue
		}
		m := summaryEventLine.FindStringSubmatch(line)
		if m == nil {
			if strings.TrimSpace(line) != "" && strings.Trim(line, " -=\t") != "" {
				return nil, fmt.Errorf("invalid JFR summary row %q", line)
			}
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil || n > math.MaxInt-sum.TotalEvents {
			return nil, fmt.Errorf("invalid JFR event count")
		}
		if _, exists := sum.EventCounts[m[1]]; exists {
			return nil, fmt.Errorf("duplicate JFR summary event row %s", m[1])
		}
		sum.EventCounts[m[1]] = n
		sum.TotalEvents += n
		rows++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !header || rows == 0 {
		return nil, fmt.Errorf("unrecognized JFR input: provide a binary recording, recording.events JSON, or a jfr summary count table")
	}
	return sum, nil
}

func buildFindings(sum *Summary) {
	evidence := func(locs []string, metric, value, unit string) []quality.Evidence {
		return []quality.Evidence{{Source: sum.Assessment.Source, Location: "example matching event locations: " + strings.Join(locs, ", "), Metric: metric, Value: value, Unit: unit}}
	}
	for i, h := range sum.CPUHotspots {
		if i >= 15 {
			break
		}
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("jfr-execution-%d", i), Title: fmt.Sprintf("%s: %.1f%% of resolved execution samples", h.Method, h.Pct), Kind: "observation", Confidence: "medium", Evidence: evidence(h.Locations, "sample count / resolved sample share", fmt.Sprintf("%d / %.1f", h.Samples, h.Pct), "samples / percent"), Limitations: []string{"Sampling frequency and missing/unresolved stacks affect attribution; this is not CPU utilization or proof of saturation."}, NextStep: "Correlate with process CPU and recording settings before diagnosing CPU pressure."})
	}
	for i, a := range sum.AllocationHotspots {
		if i >= 15 {
			break
		}
		confidence := "high"
		if a.Metric == "sample-weight-estimate" {
			confidence = "medium"
		}
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("jfr-allocation-%d", i), Title: fmt.Sprintf("%s: %s from %s", a.ClassName, a.Metric, a.EventType), Kind: "observation", Confidence: confidence, Evidence: evidence(a.Locations, a.Metric, strconv.FormatInt(a.TotalBytes, 10), "bytes"), Limitations: []string{"Allocation event families are reported separately and must not be summed together; TLAB reservation is not allocation attributed to this class.", "These observations do not prove a leak or an allocation rate."}, NextStep: "Inspect representative allocator stacks and sampling settings over a known time window."})
	}
	for i, p := range sum.PinnedEvents {
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("jfr-pinning-%d", i), Title: fmt.Sprintf("%d observed virtual-thread pinning events at %s", p.Count, p.Frame), Kind: "observation", Confidence: "high", Evidence: evidence(p.Locations, "jdk.VirtualThreadPinned", strconv.Itoa(p.Count), "events"), Limitations: []string{"Event presence does not establish severity, cause, or which source change is appropriate; check JDK version and duration coverage."}, NextStep: "Inspect recorded stacks, valid event durations, JVM version and carrier utilization; do not replace synchronization blindly."})
	}
	for i, m := range sum.MonitorContentions {
		if i >= 15 {
			break
		}
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("jfr-monitor-%d", i), Title: fmt.Sprintf("%d recorded monitor-enter events for %s at %s", m.Count, m.MonitorClass, m.TopFrame), Kind: "observation", Confidence: "high", Evidence: evidence(m.Locations, "timed events / total wait", func() string {
			if m.TimedCount == 0 {
				return "0 / unavailable"
			}
			return fmt.Sprintf("%d / %.3f", m.TimedCount, m.TotalWaitMs)
		}(), "events / ms"), Limitations: []string{"Monitor class is not a unique lock identity; overlapping waits are not wall-clock application delay."}, NextStep: "Correlate monitor addresses, owners and request latency before inferring a bottleneck."})
	}
	if sum.GCEventCount > 0 {
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: "jfr-gc-cycle", Title: "Recorded garbage-collection cycles", Kind: "observation", Confidence: "high", Evidence: evidence(sum.GCObservationLocations, "jdk.GarbageCollection", fmt.Sprint(sum.GCEventCount), "events"), Limitations: []string{"GC cycle duration includes concurrent work and cannot establish a stop-the-world pause. Missing durations stay unavailable."}, NextStep: "Use longestPause or GCPhasePause events and timestamp alignment for latency analysis."})
	}
	if sum.GCPauseSource != "" {
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: "jfr-gc-pause", Title: "Observed GC pause duration", Kind: "observation", Confidence: "high", Evidence: evidence([]string{sum.GCPauseMaxLocation}, sum.GCPauseSource, fmt.Sprintf("%.6f", sum.MaxGCPauseMs), "ms maximum"), Limitations: []string{"Only the reported event family is counted; a GC cycle can contain concurrent work and multiple pauses. Missing events or thresholds can hide pauses."}, NextStep: "Align recorded pause timestamps with request latency before attributing an incident."})
	}
	if sum.SlowIOCount > 0 {
		sum.Assessment.Findings = append(sum.Assessment.Findings, quality.Finding{ID: "jfr-slow-io", Title: "Observed read durations at least 20ms", Kind: "observation", Confidence: "high", Evidence: evidence(sum.IOObservationLocations, "slow reads", fmt.Sprint(sum.SlowIOCount), "events"), Limitations: []string{"The 20ms threshold is a reporting heuristic, not proof of an I/O bottleneck."}, NextStep: "Inspect read stacks, expected blocking behavior and request latency."})
	}
	// Retain compatibility titles without upgrading observations into root-cause diagnoses.
	for _, f := range sum.Assessment.Findings {
		sum.Suspects = append(sum.Suspects, f.Title)
	}
}

func formatReport(sum *Summary) string {
	var b strings.Builder
	b.WriteString("JAVA FLIGHT RECORDER (JFR) ANALYSIS REPORT\n")
	fmt.Fprintf(&b, "Parser Engine: %s\n%s\n", sum.EngineUsed, sum.Assessment.Report())
	fmt.Fprintf(&b, "Events in stated scope: %d\n", sum.TotalEvents)
	if sum.FormatVersion != "" {
		fmt.Fprintf(&b, "Format: %s; completed chunks: %d; summed chunk durations: %.3fs\n", sum.FormatVersion, sum.ChunkCount, sum.DurationSeconds)
	}
	fmt.Fprintf(&b, "Recorded GC cycles: %d; valid cycle durations: %d\n", sum.GCEventCount, sum.GCTimedCount)
	if sum.GCTimedCount > 0 {
		fmt.Fprintf(&b, "Maximum observed GC cycle duration: %.3f ms (not a pause)\n", sum.MaxGCCycleMs)
	} else {
		b.WriteString("GC cycle duration: unavailable\n")
	}
	if sum.GCPauseSource != "" {
		fmt.Fprintf(&b, "Observed GC pause maximum: %.3f ms; observations: %d; source: %s\n", sum.MaxGCPauseMs, sum.GCPauseCount, sum.GCPauseSource)
	} else {
		b.WriteString("GC pause duration: unavailable\n")
	}
	fmt.Fprintf(&b, "TLAB reservation bytes observed: %d (not per-class allocation)\n", sum.TLABReservedBytes)
	for _, a := range sum.AllocationHotspots {
		fmt.Fprintf(&b, "Allocation: %s | %s | %s | %d bytes in %d events at %s\n", a.ClassName, a.EventType, a.Metric, a.TotalBytes, a.Count, a.TopAllocator)
	}
	for _, p := range sum.PinnedEvents {
		if p.TimedCount == 0 {
			fmt.Fprintf(&b, "Pinning: %s | events=%d | timing: unavailable\n", p.Frame, p.Count)
		} else {
			fmt.Fprintf(&b, "Pinning: %s | events=%d timed=%d | observed total=%.3f ms max=%.3f ms\n", p.Frame, p.Count, p.TimedCount, p.TotalWaitMs, p.MaxWaitMs)
		}
	}
	if sum.IOTimedCount > 0 {
		fmt.Fprintf(&b, "Observed I/O events >=20ms: %d / %d timed events; max slow duration %.3f ms\n", sum.SlowIOCount, sum.IOTimedCount, sum.MaxSlowIOMs)
	} else {
		b.WriteString("I/O timing: unavailable\n")
	}
	names := make([]string, 0, len(sum.EventCounts))
	for name := range sum.EventCounts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "Event count: %s = %d\n", name, sum.EventCounts[name])
	}
	return b.String()
}
