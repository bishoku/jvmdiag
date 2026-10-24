package main

import (
	"github.com/bishoku/jvmdiag/internal/config"
	"runtime/debug"
	"testing"
)

func TestCoreUsesConfiguredWorkerLimit(t *testing.T) {
	for _, limit := range []int{1, 4} {
		cfg := config.NewManagerWithOptions(t.TempDir(), config.Options{SkipDotEnv: true, SkipLegacy: true, IgnoreEnvironment: true})
		cfg.SetMaxWorkers(limit)
		_, _, st, _, _ := buildCoreFromConfig(cfg)
		t.Cleanup(st.Close)
		for i := 0; i < limit; i++ {
			if !st.TryAcquireWorker() {
				t.Fatalf("worker capacity below %d", limit)
			}
		}
		if st.TryAcquireWorker() {
			t.Fatalf("worker capacity exceeds %d", limit)
		}
		st.ReleaseWorker()
		if !st.TryAcquireWorker() {
			t.Fatal("released slot unavailable")
		}
		for i := 0; i < limit; i++ {
			st.ReleaseWorker()
		}
	}
}

func TestCaptureValueFlagsStayWithTheirArguments(t *testing.T) {
	args := []string{"--pid", "1", "--container", "--target-dir", "/target/tmp", "--jfr-duration", "2s", "--timeout", "90s", "--command-timeout", "20s", "--out-dir", "/tmp/new", "--capture-only"}
	got := reorderFlagsFirst(args)
	if len(got) != len(args) {
		t.Fatalf("flag values lost: %v", got)
	}
	for i := range args {
		if args[i] != got[i] {
			t.Fatalf("capture flag reordering changed meaning: %v", got)
		}
	}
}

func TestGoInstalledModuleVersionAndReleaseOverride(t *testing.T) {
	info := &debug.BuildInfo{Main: debug.Module{Version: "v3.0.0"}}
	if got := moduleVersion("dev", info); got != "3.0.0" {
		t.Fatalf("Go install version lost: %s", got)
	}
	if got := moduleVersion("3.0.1", info); got != "3.0.1" {
		t.Fatalf("release ldflags overridden: %s", got)
	}
	info.Main.Version = "(devel)"
	if got := moduleVersion("dev", info); got != "dev" {
		t.Fatalf("source build claimed a release: %s", got)
	}
}
