package threaddump

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzeAndCompareRejectInvalidThreadEvidence(t *testing.T) {
	valid := "\"worker\" #1 tid=0x01 runnable\n   java.lang.Thread.State: RUNNABLE\n\tat Fixture.main(Fixture.java:1)\n"
	dir := t.TempDir()
	good := filepath.Join(dir, "valid.tdump")
	if err := os.WriteFile(good, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, content string }{
		{"empty", ""}, {"arbitrary", "this is not JVM diagnostic data"},
		{"quoted text", "\"hello\" world\n"},
		{"broken json", `{"threadDump":{"threadContainers":[`},
		{"empty json threads", `{"threadDump":{"threadContainers":[]}}`},
		{"header only", "Full thread dump OpenJDK 64-Bit Server VM:\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "invalid.tdump")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			report, sum, err := AnalyzeFile(path)
			if err == nil || report != "" || sum != nil {
				t.Fatalf("invalid data accepted: err=%v summary=%+v report=%q", err, sum, report)
			}
			if report, err := CompareFiles([]string{good, path}); err == nil || report != "" {
				t.Fatalf("invalid comparison accepted: err=%v report=%q", err, report)
			}
		})
	}
	for _, content := range []string{valid, `{"threadDump":{"threadContainers":[{"threads":[{"tid":"1","name":"worker","stack":["Fixture.main(Fixture.java:1)"]}]}]}}`} {
		if err := os.WriteFile(good, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		report, sum, err := AnalyzeFile(good)
		if err != nil || sum == nil || sum.TotalThreads != 1 || !strings.Contains(report, "worker") {
			t.Fatalf("valid dump rejected: %v %+v", err, sum)
		}
	}
}
