package incident

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestedThreadSnapshotsMustAllBeAnalyzed(t *testing.T) {
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.tdump")
	invalid := filepath.Join(dir, "invalid.tdump")
	if err := os.WriteFile(valid, []byte("\"worker\" #1 tid=0x01 runnable\n   java.lang.Thread.State: RUNNABLE\n\tat Fixture.main(Fixture.java:1)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalid, []byte("not a thread dump"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		paths []string
		bad   string
	}{
		{"missing second", []string{valid, filepath.Join(dir, "missing.tdump")}, "missing.tdump"},
		{"unreadable third", []string{valid, valid, dir}, filepath.Base(dir)},
		{"invalid second", []string{valid, invalid}, "invalid.tdump"},
		{"invalid third", []string{valid, valid, invalid}, "invalid.tdump"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := Analyze(context.Background(), nil, Input{ThreadDumpPaths: tc.paths})
			if err == nil || report != "" {
				t.Fatalf("requested snapshot failure was hidden: err=%v report=%q", err, report)
			}
			if !strings.Contains(err.Error(), tc.bad) {
				t.Fatalf("error must identify failing input: %v", err)
			}
		})
	}
	report, err := Analyze(context.Background(), nil, Input{ThreadDumpPaths: []string{valid, valid, valid}})
	if err != nil || !strings.Contains(report, "Snapshots compared: 3") {
		t.Fatalf("valid snapshots: %v\n%s", err, report)
	}
}
