package analyzer_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bishoku/jvmdiag/v3/internal/analyzer/jfr"
)

func jdkMatrix(t *testing.T) map[string]string {
	t.Helper()
	raw := os.Getenv("JVMDIAG_TEST_JDKS")
	if raw == "" {
		t.Skip("set JVMDIAG_TEST_JDKS to a JSON object mapping corpus labels to JDK homes")
	}
	var homes map[string]string
	if err := json.Unmarshal([]byte(raw), &homes); err != nil || len(homes) == 0 {
		t.Fatal("invalid JVMDIAG_TEST_JDKS")
	}
	return homes
}

func TestCapturedBinaryJFRWithMatchingJDKs(t *testing.T) {
	homes := jdkMatrix(t)
	root, m := corpus(t)
	for _, e := range m.Entries {
		e := e
		label := strings.TrimSuffix(e.ID, "-"+e.GC)
		home, ok := homes[label]
		if !ok {
			t.Fatalf("missing matching JDK for %s", label)
		}
		t.Run(e.ID, func(t *testing.T) {
			path := writeArtifact(t, t.TempDir(), "recording.jfr", artifact(t, root, e, "recording.jfr"))
			_, sum, err := jfr.AnalyzeFileWithOptions(path, jfr.Options{ToolPath: filepath.Join(home, "bin", "jfr"), DisableToolDiscovery: true, Environment: fixtureEnvironment(home, t.TempDir())})
			if err != nil {
				t.Fatal(err)
			}
			if sum.TotalEvents != e.Expected.JFR.Total {
				t.Fatalf("binary/export total mismatch: %d != %d", sum.TotalEvents, e.Expected.JFR.Total)
			}
			for name, count := range e.Expected.JFR.Counts {
				if sum.EventCounts[name] != count {
					t.Errorf("binary/export mismatch: %s", name)
				}
			}
		})
	}
}

// A bounded opt-in generation test. Captures go only to a temp directory; committed data is never overwritten.
func TestLiveJDKGCMatrix(t *testing.T) {
	homes := jdkMatrix(t)
	if os.Getenv("JVMDIAG_GENERATE_MATRIX") != "1" {
		t.Skip("set JVMDIAG_GENERATE_MATRIX=1 to start synthetic JVMs")
	}
	python := os.Getenv("JVMDIAG_TEST_PYTHON")
	if python == "" {
		var err error
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Fatal("Python 3 is required for explicit live generation")
		}
	}
	labels := make([]string, 0, len(homes))
	for label := range homes {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	out := filepath.Join(t.TempDir(), "corpus")
	args := []string{filepath.Join("..", "..", "tests", "fixtures", "capture.py"), "--out", out}
	for _, label := range labels {
		args = append(args, "--jdk", label+"="+homes[label])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, python, args...)
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("matrix generation: %v\n%s", err, data)
	}
	raw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m corpusManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Entries) != len(homes)*4 {
		t.Fatalf("live matrix silently omitted combinations: %d", len(m.Entries))
	}
	for _, e := range m.Entries {
		e := e
		t.Run(e.ID, func(t *testing.T) { checkCorpusEntry(t, out, e) })
	}
}

func fixtureEnvironment(home, temp string) []string {
	return []string{"PATH=" + filepath.Join(home, "bin"), "HOME=" + temp, "TMPDIR=" + temp, "TZ=UTC", "LANG=C", "LC_ALL=C"}
}
