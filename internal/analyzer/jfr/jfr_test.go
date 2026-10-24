package jfr

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func analyzeJSON(t *testing.T, events string) *Summary {
	t.Helper()
	sum, err := parseJFRJSON([]byte(`{"recording":{"events":` + events + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	return sum
}
func binaryFixture() []byte {
	data := make([]byte, 72)
	copy(data, "FLR\x00")
	binary.BigEndian.PutUint16(data[4:6], 2)
	binary.BigEndian.PutUint64(data[8:16], uint64(len(data)))
	binary.BigEndian.PutUint64(data[24:32], 68)
	return data
}
func writeFixture(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "recording.jfr")
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBinarySymbolsCannotBecomeEvents(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("JAVA_HOME", t.TempDir())
	data := append(binaryFixture(), []byte("jdk.VirtualThreadPinned jdk.ExecutionSample com/acme/Busy.work")...)
	binary.BigEndian.PutUint64(data[8:16], uint64(len(data)))
	report, sum, err := AnalyzeFile(writeFixture(t, data))
	if err == nil || report != "" || sum == nil || sum.Assessment.Status != "metadata-only" {
		t.Fatalf("header-only input presented as analysis: %s %+v %v", report, sum, err)
	}
	if sum.TotalEvents != 0 || len(sum.PinnedEvents) != 0 || len(sum.CPUHotspots) != 0 || len(sum.Assessment.Findings) != 0 {
		t.Fatal("symbols became runtime evidence")
	}
}

func TestBinaryDecoderFailureCannotFallbackToSuccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake POSIX executable")
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "jfr"), []byte("#!/bin/sh\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("JAVA_HOME", "")
	report, _, err := AnalyzeFile(writeFixture(t, binaryFixture()))
	if err == nil || report != "" || !strings.Contains(err.Error(), "no metadata fallback") {
		t.Fatalf("decoder failure hidden: %q %v", report, err)
	}
}

func TestBinaryChunkValidation(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("JAVA_HOME", "")
	base := binaryFixture()
	tests := map[string][]byte{"short header": base[:20], "unfinished chunk": append([]byte(nil), base...), "trailing bytes": append(append([]byte(nil), base...), 1), "unsupported version": append([]byte(nil), base...)}
	binary.BigEndian.PutUint64(tests["unfinished chunk"][24:32], 0)
	binary.BigEndian.PutUint16(tests["unsupported version"][4:6], 9)
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			report, sum, err := AnalyzeFile(writeFixture(t, data))
			if err == nil || report != "" || sum != nil {
				t.Fatalf("invalid chunk accepted: %+v %v", sum, err)
			}
		})
	}
}

func TestStrictJSONAndTextRecognition(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"recording":{}}`, `{"recording":{"events":null}}`, `{"recording":{"events":[null]}}`, `{"recording":{"events":[{"type":"jdk.ExecutionSample"}]}}`, `{"recording":{"events":[]}} trailing`, `not a JFR recording`, `jdk.VirtualThreadPinned 4 12`} {
		report, _, err := AnalyzeFile(writeFixture(t, []byte(raw)))
		if err == nil || report != "" {
			t.Fatalf("unrecognized input accepted: %q", raw)
		}
	}
	sum := analyzeJSON(t, `[]`)
	if sum.Assessment.Status != "limited" || len(sum.Assessment.Findings) != 0 {
		t.Fatal("empty export implied health")
	}
	sum, err := parseJFRTextSummary("Version: 2.0\n Event Type Count Size (bytes)\n----------------------\n jdk.ExecutionSample 3 30\n jdk.VirtualThreadPinned 0 0\n com.example.Custom 2 20\n")
	if err != nil || sum.TotalEvents != 5 || sum.Assessment.Status != "limited" || len(sum.CPUHotspots) != 0 || len(sum.PinnedEvents) != 0 {
		t.Fatalf("summary counts promoted into findings: %+v %v", sum, err)
	}
	if _, err := parseJFRTextSummary("Event Type Count Size\njdk.ExecutionSample 3 3\njdk.ExecutionSample 3 3\n"); err == nil {
		t.Fatal("duplicate summary rows accepted")
	}
}

func TestDurationUnitsAreExplicit(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want float64
	}{{`50000`, .05}, {`100000`, .1}, {`100001`, .100001}, {`1000000`, 1}, {`"PT0.15S"`, 150}, {`"PT1H2M3.5S"`, 3723500}, {`"PT0S"`, 0}} {
		got, present, err := durationMs(json.RawMessage(tc.raw))
		if err != nil || !present || math.Abs(got-tc.want) > 1e-8 {
			t.Fatalf("%s: %v %v %v", tc.raw, got, present, err)
		}
	}
	for _, raw := range []string{`-1`, `"PT"`, `"garbage"`, `{}`, `1e999`} {
		if _, _, err := durationMs(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid duration accepted: %s", raw)
		}
	}
	for _, raw := range []json.RawMessage{nil, json.RawMessage(`null`)} {
		_, present, err := durationMs(raw)
		if err != nil || present {
			t.Fatal("missing duration treated as zero observation")
		}
	}
}

func TestGCUsesPauseEvidenceNotCycleDuration(t *testing.T) {
	sum := analyzeJSON(t, `[{"type":"jdk.GarbageCollection","values":{"duration":"PT2S","longestPause":"PT0.003S"}}]`)
	if sum.MaxGCCycleMs != 2000 || sum.MaxGCPauseMs != 3 || sum.GCPauseCount != 1 {
		t.Fatalf("cycle mislabeled pause: %+v", sum)
	}
	sum = analyzeJSON(t, `[{"type":"jdk.GarbageCollection","values":{"duration":"PT2S"}}]`)
	if sum.MaxGCPauseMs != 0 || sum.GCPauseSource != "" || sum.Assessment.Status != "limited" || !strings.Contains(formatReport(sum), "GC pause duration: unavailable") {
		t.Fatal("missing pause replaced by cycle duration")
	}
	sum = analyzeJSON(t, `[{"type":"jdk.GarbageCollection","values":{"duration":"PT2S","longestPause":"PT0.003S"}},{"type":"jdk.GCPhasePause","values":{"duration":"PT0.004S"}}]`)
	if sum.GCPauseCount != 1 || sum.MaxGCPauseMs != 4 || sum.GCPauseSource != "jdk.GCPhasePause.duration" {
		t.Fatal("GC event families double counted")
	}
}

func TestAllocationFamiliesAreNotMixed(t *testing.T) {
	sum := analyzeJSON(t, `[
 {"type":"jdk.ObjectAllocationInNewTLAB","values":{"allocationSize":32,"tlabSize":1048576,"objectClass":{"name":"A"}}},
 {"type":"jdk.ObjectAllocationOutsideTLAB","values":{"allocationSize":100,"objectClass":{"name":"A"}}},
 {"type":"jdk.ObjectAllocationSample","values":{"weight":2000,"allocationSize":9999,"objectClass":{"name":"A"}}}
 ]`)
	if len(sum.AllocationHotspots) != 3 || sum.TLABReservedBytes != 1048576 {
		t.Fatalf("allocation families merged: %+v", sum)
	}
	values := map[string]int64{}
	for _, a := range sum.AllocationHotspots {
		values[a.EventType] = a.TotalBytes
	}
	if values["jdk.ObjectAllocationInNewTLAB"] != 32 || values["jdk.ObjectAllocationOutsideTLAB"] != 100 || values["jdk.ObjectAllocationSample"] != 2000 {
		t.Fatal("wrong per-event byte semantics")
	}
	sum = analyzeJSON(t, `[{"type":"jdk.ObjectAllocationInNewTLAB","values":{"tlabSize":1048576,"objectClass":{"name":"A"}}}]`)
	if len(sum.AllocationHotspots) != 0 || sum.Assessment.Status != "limited" {
		t.Fatal("TLAB reservation attributed to class allocation")
	}
}

func TestMissingTimingAndStacksRemainUnknown(t *testing.T) {
	sum := analyzeJSON(t, `[{"type":"jdk.ExecutionSample","values":{}},{"type":"jdk.VirtualThreadPinned","values":{}},{"type":"jdk.JavaMonitorEnter","values":{}}]`)
	if sum.Assessment.Status != "limited" || len(sum.CPUHotspots) != 0 || len(sum.PinnedEvents) != 1 || sum.PinnedEvents[0].TimedCount != 0 || sum.MonitorContentions[0].TimedCount != 0 {
		t.Fatalf("missing fields treated as measurements: %+v", sum)
	}
	sum.Assessment.Source = "fixture.json"
	buildFindings(sum)
	report := formatReport(sum)
	if strings.Contains(report, "CRITICAL") || strings.Contains(report, "Replace synchronized") {
		t.Fatal("pinning observation upgraded to a critical diagnosis")
	}
	for _, f := range sum.Assessment.Findings {
		if len(f.Evidence) == 0 || f.Evidence[0].Source != "fixture.json" || !strings.Contains(f.Evidence[0].Location, "recording.events[") || f.Confidence == "" || f.NextStep == "" {
			t.Fatalf("missing evidence contract: %+v", f)
		}
	}
}

func TestJDKSelectedEventCountsAreNotDoubled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake POSIX executable")
	}
	bin := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" != print ]; then exit 99; fi\nprintf '%s' '{\"recording\":{\"events\":[{\"type\":\"jdk.ExecutionSample\",\"values\":{}}]}}'\n"
	path := filepath.Join(bin, "jfr")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	sum, err := analyzeWithJFRTool(path, "ignored.jfr")
	if err != nil || sum.TotalEvents != 1 || sum.EventCounts["jdk.ExecutionSample"] != 1 || !strings.Contains(sum.Assessment.Scope, "selected events") {
		t.Fatalf("selected counts changed: %+v %v", sum, err)
	}
}

func FuzzJSONEvents(f *testing.F) {
	f.Add([]byte(`{"recording":{"events":[]}}`))
	f.Add([]byte(`{"recording":{"events":[{"type":"jdk.GarbageCollection","values":{"duration":50000}}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		sum, err := parseJFRJSON(raw)
		if err == nil && (sum == nil || sum.TotalEvents < 0 || math.IsNaN(sum.MaxGCPauseMs)) {
			t.Fatal("invalid successful parse")
		}
	})
}

func TestUnknownCustomSchemaIsCountedWithoutInventedMetrics(t *testing.T) {
	sum := analyzeJSON(t, `[{"type":"com.example.Custom","values":{"duration":"application label","objectClass":"custom text"}}]`)
	if sum.TotalEvents != 1 || sum.Assessment.Status != "limited" || len(sum.CPUHotspots) != 0 {
		t.Fatal("unknown custom event misinterpreted")
	}
}

func TestGCMaximumDoesNotDiscardLongerIndependentPauseEvidence(t *testing.T) {
	sum := analyzeJSON(t, `[{"type":"jdk.GarbageCollection","values":{"duration":"PT2S","longestPause":"PT0.01S"}},{"type":"jdk.GCPhasePause","values":{"duration":"PT0.004S"}}]`)
	if sum.MaxGCPauseMs != 10 || !strings.Contains(sum.GCPauseSource, "longestPause") || !strings.Contains(sum.GCPauseMaxLocation, "events[0]") || sum.GCPhasePauseCount != 1 || sum.GCWithLongestPauseCount != 1 {
		t.Fatalf("longer observed pause discarded: %+v", sum)
	}
}
