package model

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestConcurrentAnalysisSnapshots(t *testing.T) {
	state := NewAnalysisState("job", "alpha", "test", AnalysisHeapDump, 1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				state.SetStatus(StatusAnalyzing)
				state.SetStaticReport("report", "native")
				state.SetAIResponse("ai")
				snap := state.Snapshot()
				rec := RecordFromState(snap)
				if rec.ID != "job" {
					t.Error("snapshot identity changed")
				}
			}
		}()
	}
	wg.Wait()
}

func TestWaitCompletionAndRerun(t *testing.T) {
	state := NewAnalysisState("job", "alpha", "test", AnalysisHeapDump, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := state.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unfinished job: %v", err)
	}
	state.SetStatus(StatusCompleted)
	if err := state.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	state.SetStatus(StatusAnalyzing)
	if err := state.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("rerun reused completed signal: %v", err)
	}
	state.SetError("failed")
	if err := state.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}
