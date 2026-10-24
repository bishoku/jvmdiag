package gclog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZGCStatsAndConcurrentPhasesAreNotPauseEvents(t *testing.T) {
	text := `[0.1s][info][gc,phases] GC(0) Y: Pause Mark Start (Major) 0.003ms
[0.2s][info][gc,phases] GC(0) Y: Concurrent Mark 300.000ms
[0.3s][info][gc,phases] GC(0) O: Pause Mark End 0.001ms
[0.4s][info][gc,stats] Old Pause: Pause Mark End 0.000 / 0.000 0.000 / 0.000 ms
[0.5s][info][gc] GC(1) Pause Young (Mixed) (G1 Evacuation Pause) 20M->10M(64M) 1.000ms
`
	p := filepath.Join(t.TempDir(), "gc.log")
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	_, m, err := AnalyzeFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.TotalEvents != 3 || m.OtherPauseCount != 2 || m.MixedGCCount != 1 || m.YoungGCCount != 0 || m.MaxPauseMs != 1 || m.TotalPauseMs != 1.004 {
		t.Fatalf("phase/stats double counting: %+v", m)
	}
}
