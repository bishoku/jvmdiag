package analyzer_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bishoku/jvmdiag/v3/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/v3/internal/analyzer/jfr"
)

// Opt in with JVMDIAG_TEST_JDK=/path/to/jdk. All artifacts belong to a fresh synthetic JVM.
func TestRealJDKArtifacts(t *testing.T) {
	home := os.Getenv("JVMDIAG_TEST_JDK")
	if home == "" {
		t.Skip("set JVMDIAG_TEST_JDK for real JVM reference artifacts")
	}
	dir := t.TempDir()
	src := filepath.Join("..", "..", "tests", "fixtures", "GenerateDiagnostics.java")
	for _, args := range [][]string{{"javac", "-d", dir, src}, {"java", "-Xmx64m", "-cp", dir, "GenerateDiagnostics", dir}} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(home, "bin", args[0]), args[1:]...)
		cmd.Env = fixtureEnvironment(home, dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture generation: %v\n%s", err, out)
		}
	}

	_, heap, err := hprof.AnalyzeFile(filepath.Join(dir, "heap.hprof"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, dup := range heap.DuplicateArrays {
		if dup.Preview == "jvmdiag-fixture-array-content-2026" && dup.Count >= 10 {
			found = true
		}
	}
	if !found {
		t.Fatal("real JVM duplicate-array payload not recovered")
	}
	_, recording, err := jfr.AnalyzeFileWithOptions(filepath.Join(dir, "recording.jfr"), jfr.Options{ToolPath: filepath.Join(home, "bin", "jfr"), DisableToolDiscovery: true, Environment: fixtureEnvironment(home, dir)})
	if err != nil {
		t.Fatal(err)
	}
	if recording.TotalEvents == 0 || recording.EngineUsed != "jdk-jfr-cli" {
		t.Fatal("real recording was not decoded")
	}
	// Independently count the exact selected JSON export to catch summary double-counting and synthetic events.
	command := exec.Command(filepath.Join(home, "bin", "jfr"), "print", "--json", "--stack-depth", "8", "--events", "jdk.ExecutionSample,jdk.NativeMethodSample,jdk.ObjectAllocationInNewTLAB,jdk.ObjectAllocationOutsideTLAB,jdk.ObjectAllocationSample,jdk.JavaMonitorEnter,jdk.VirtualThreadPinned,jdk.GarbageCollection,jdk.GCPhasePause,jdk.SocketRead,jdk.FileRead", filepath.Join(dir, "recording.jfr"))
	command.Env = fixtureEnvironment(home, dir)
	out, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Recording struct {
			Events []struct {
				Type string `json:"type"`
			} `json:"events"`
		} `json:"recording"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, ev := range decoded.Recording.Events {
		counts[ev.Type]++
	}
	if recording.TotalEvents != len(decoded.Recording.Events) {
		t.Fatalf("event total %d != JDK export %d", recording.TotalEvents, len(decoded.Recording.Events))
	}
	for name, count := range counts {
		if recording.EventCounts[name] != count {
			t.Fatalf("%s count mismatch", name)
		}
	}
	if recording.GCEventCount == 0 || recording.GCPauseSource == "" {
		t.Fatal("real GC pause evidence missing")
	}
	t.Logf("JDK reference: %d HPROF object/array records; %d selected JFR events; %d GC events", heap.TotalInstances, recording.TotalEvents, recording.GCEventCount)
}
