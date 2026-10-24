package analyzer_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bishoku/jvmdiag/v3/internal/analyzer/gclog"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/jfr"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/nmtcrash"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/threaddump"
)

type corpusArtifact struct {
	File, SHA256, CompressedSHA256 string
	Bytes                          int64
}
type corpusEntry struct {
	ID, JDK, Vendor, Platform, GC string
	ActualCollectors              []string
	Artifacts                     map[string]corpusArtifact
	Expected                      struct {
		Heap struct {
			PayloadBytes, Records, MarkerArrays int64
			RootTags                            map[string]int64
			IdentifierBytes                     int
		}
		JFR struct {
			Counts                 map[string]int
			Total                  int
			MaxPauseMs, MaxCycleMs float64
			AllocationBytesByEvent map[string]int64
			TLABReservedBytes      int64
		}
		GC struct {
			PauseCount               int
			TotalPauseMs, MaxPauseMs float64
		}
		Threads struct {
			Total       int
			States      map[string]int
			BlockedName string
		}
	}
}
type corpusManifest struct {
	SchemaVersion int
	Entries       []corpusEntry
}

func corpus(t testing.TB) (string, corpusManifest) {
	t.Helper()
	root := filepath.Join("..", "..", "tests", "corpus", "jvm-v1")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m corpusManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.SchemaVersion != 1 || len(m.Entries) == 0 {
		t.Fatal("missing corpus matrix")
	}
	return root, m
}
func artifact(t testing.TB, root string, e corpusEntry, name string) []byte {
	t.Helper()
	a, ok := e.Artifacts[name]
	if !ok {
		t.Fatalf("missing artifact %s", name)
	}
	if filepath.Base(a.File) != a.File || a.Bytes < 0 || a.Bytes > 128<<20 {
		t.Fatal("invalid corpus artifact bounds")
	}
	raw, err := os.ReadFile(filepath.Join(root, e.ID, a.File))
	if err != nil {
		t.Fatal(err)
	}
	compressed := sha256.Sum256(raw)
	if hex.EncodeToString(compressed[:]) != a.CompressedSHA256 {
		t.Fatalf("compressed fixture digest mismatch: %s", name)
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, a.Bytes+1))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if int64(len(data)) != a.Bytes || hex.EncodeToString(hash[:]) != a.SHA256 {
		t.Fatalf("fixture size/digest mismatch: %s", name)
	}
	return data
}
func writeArtifact(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func closeFloat(t testing.TB, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-7 {
		t.Errorf("%s: got %.12f want %.12f", name, got, want)
	}
}

func TestCapturedJVMRegressionCorpus(t *testing.T) {
	root, m := corpus(t)
	for _, entry := range m.Entries {
		entry := entry
		t.Run(entry.ID, func(t *testing.T) { t.Parallel(); checkCorpusEntry(t, root, entry) })
	}
}

func checkCorpusEntry(t *testing.T, root string, e corpusEntry) {
	t.Helper()
	dir := t.TempDir()
	files := make(map[string][]byte)
	for name := range e.Artifacts {
		files[name] = artifact(t, root, e, name)
		writeArtifact(t, dir, name, files[name])
	}
	if e.JDK == "" || e.Vendor == "" || len(e.ActualCollectors) == 0 {
		t.Fatal("fixture lacks producer/collector provenance")
	}
	heapReport, heap, err := hprof.AnalyzeFile(filepath.Join(dir, "heap.hprof"))
	if err != nil {
		t.Fatal(err)
	}
	if heap.TotalPayloadBytes != e.Expected.Heap.PayloadBytes || heap.TotalInstances != e.Expected.Heap.Records || heap.IdentifierSize != e.Expected.Heap.IdentifierBytes {
		t.Errorf("heap differs from independent format audit: bytes=%d records=%d", heap.TotalPayloadBytes, heap.TotalInstances)
	}
	roots := map[string]string{"255": "ROOT_UNKNOWN", "1": "ROOT_JNI_GLOBAL", "2": "ROOT_JNI_LOCAL", "3": "ROOT_JAVA_FRAME", "4": "ROOT_NATIVE_STACK", "5": "ROOT_STICKY_CLASS", "6": "ROOT_THREAD_BLOCK", "7": "ROOT_MONITOR_USED", "8": "ROOT_THREAD_OBJECT"}
	for tag, count := range e.Expected.Heap.RootTags {
		if heap.GCRootCounts[roots[tag]] != count {
			t.Errorf("root count %s differs", tag)
		}
	}
	found := false
	for _, group := range heap.DuplicateArrays {
		if group.Preview == "jvmdiag-fixture-array-content-2026" {
			found = true
			if group.Count != e.Expected.Heap.MarkerArrays {
				t.Errorf("duplicate marker count: %d != %d", group.Count, e.Expected.Heap.MarkerArrays)
			}
		}
	}
	if !found {
		t.Error("known live marker arrays missing")
	}
	for i := 0; i < 4; i++ {
		if got := hprof.BuildStructuredReport(heap); got != heapReport {
			t.Error("heap report order is nondeterministic")
			break
		}
	}
	jfrReport, events, err := jfr.AnalyzeFile(filepath.Join(dir, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	if events.TotalEvents != e.Expected.JFR.Total || !reflect.DeepEqual(events.EventCounts, e.Expected.JFR.Counts) {
		t.Errorf("event counts differ from JDK JSON export: got=%v expected=%v", events.EventCounts, e.Expected.JFR.Counts)
	}
	closeFloat(t, "JFR max pause", events.MaxGCPauseMs, e.Expected.JFR.MaxPauseMs)
	closeFloat(t, "JFR cycle", events.MaxGCCycleMs, e.Expected.JFR.MaxCycleMs)
	allocations := map[string]int64{}
	for _, a := range events.AllocationHotspots {
		allocations[a.EventType] += a.TotalBytes
	}
	if !reflect.DeepEqual(allocations, e.Expected.JFR.AllocationBytesByEvent) || events.TLABReservedBytes != e.Expected.JFR.TLABReservedBytes {
		t.Error("allocation byte semantics differ from reference fields")
	}
	for i := 0; i < 3; i++ {
		report, _, err := jfr.AnalyzeFile(filepath.Join(dir, "events.json"))
		if err != nil || report != jfrReport {
			t.Error("JFR report is nondeterministic")
			break
		}
	}
	_, summary, err := jfr.AnalyzeFile(filepath.Join(dir, "summary.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for name, count := range events.EventCounts {
		if summary.EventCounts[name] != count {
			t.Errorf("JDK summary/export count mismatch: %s", name)
		}
	}
	gcReport, gc, err := gclog.AnalyzeFile(filepath.Join(dir, "gc.log"))
	if err != nil {
		t.Fatal(err)
	}
	if gc.TotalEvents != e.Expected.GC.PauseCount {
		t.Errorf("GC pause records got %d want %d", gc.TotalEvents, e.Expected.GC.PauseCount)
	}
	closeFloat(t, "GC pause sum", gc.TotalPauseMs, e.Expected.GC.TotalPauseMs)
	closeFloat(t, "GC max pause", gc.MaxPauseMs, e.Expected.GC.MaxPauseMs)
	collector := map[string]string{"g1": "G1", "parallel": "Parallel", "serial": "Serial", "zgc": "ZGC"}[e.GC]
	if !strings.Contains(gc.Collector, collector) {
		t.Errorf("collector detection got %q for %s", gc.Collector, e.GC)
	}
	threadReport, threads, err := threaddump.AnalyzeFile(filepath.Join(dir, "threads.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if threads.TotalThreads != e.Expected.Threads.Total {
		t.Errorf("thread count %d != %d", threads.TotalThreads, e.Expected.Threads.Total)
	}
	for state, count := range e.Expected.Threads.States {
		if threads.StateCounts[state] != count {
			t.Errorf("thread state %s count mismatch", state)
		}
	}
	blocked := false
	for _, thread := range threads.Threads {
		if thread.Name == e.Expected.Threads.BlockedName {
			blocked = thread.State == "BLOCKED"
		}
	}
	if !blocked {
		t.Error("known blocked platform thread missing")
	}
	for i := 0; i < 10; i++ {
		report := threaddump.BuildReport(threaddump.ParseContent("threads.txt", string(files["threads.txt"])), string(files["threads.txt"]))
		if report != threadReport {
			t.Error("thread report order is nondeterministic")
			break
		}
	}
	_, nmt, err := nmtcrash.AnalyzeText(string(files["nmt.txt"]))
	if err != nil || nmt.ReportType != "NMT_REPORT" || nmt.TotalCommittedKB <= 0 {
		t.Fatalf("real NMT output not recognized: %v", err)
	}
	for name, report := range map[string]string{"gc": gcReport, "threads": threadReport, "heap": heapReport, "jfr": jfrReport} {
		if strings.Contains(report, "NaN") {
			t.Errorf("%s report contains invalid numeric output", name)
		}
	}
}

func TestCorpusCoversDeclaredJDKAndGCFamilies(t *testing.T) {
	_, m := corpus(t)
	seen := map[string]map[string]bool{}
	for _, e := range m.Entries {
		major := strings.Split(e.JDK, ".")[0]
		if seen[major] == nil {
			seen[major] = map[string]bool{}
		}
		seen[major][e.GC] = true
	}
	for _, major := range []string{"17", "25"} {
		for _, gc := range []string{"g1", "parallel", "serial", "zgc"} {
			if !seen[major][gc] {
				t.Errorf("missing JDK %s / %s reference", major, gc)
			}
		}
	}
}

func TestCorpusSourceProvenance(t *testing.T) {
	root, _ := corpus(t)
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct{ GeneratorSha256, WorkloadSha256 string }
	if err := json.Unmarshal(raw, &provenance); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]string{"capture.py": provenance.GeneratorSha256, "GenerateDiagnostics.java": provenance.WorkloadSha256} {
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != expected {
			t.Errorf("archived source digest mismatch: %s", name)
		}
	}
}
