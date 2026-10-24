package capture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fakeTools(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"jcmd", "jstack"} {
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("JAVA_HOME", "")
}
func fakeCommand(_ context.Context, _ string, args ...string) ([]byte, error) {
	switch args[1] {
	case "Thread.print":
		return []byte("Full thread dump\n\"fixture\"\n java.lang.Thread.State: RUNNABLE\n"), nil
	case "VM.native_memory":
		return []byte("Native memory tracking is not enabled"), nil
	case "GC.heap_dump":
		return []byte("created"), os.WriteFile(args[2], []byte("JAVA PROFILE 1.0.2\x00test"), 0600)
	case "JFR.start":
		return []byte("Started recording 1."), nil
	case "JFR.dump":
		return []byte("Dumped recording"), os.WriteFile(strings.TrimPrefix(args[3], "filename="), []byte("FLR\x00test"), 0600)
	case "JFR.stop":
		return []byte("Stopped recording"), nil
	}
	return nil, errors.New("unexpected command")
}
func TestCaptureStagesTargetFilesAndCleansUp(t *testing.T) {
	fakeTools(t)
	parent := t.TempDir()
	out := filepath.Join(t.TempDir(), "capture")
	b, err := captureBundle(context.Background(), Options{PID: 42, Count: 1, WithHeap: true, JFRDuration: time.Nanosecond, TargetDir: parent, OutputDir: out}, fakeCommand)
	if err != nil {
		t.Fatal(err)
	}
	if b.Status != "complete" || b.HeapDumpPath == "" || b.JFRPath == "" || len(b.ThreadDumpPaths) != 1 || len(b.Notes) != 1 {
		t.Fatalf("incomplete bundle: %+v", b)
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 0 {
		t.Fatal("target staging files leaked")
	}
	for _, path := range []string{out, b.HeapDumpPath, b.JFRPath, b.ThreadDumpPaths[0], filepath.Join(out, "capture.json")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			t.Errorf("artifact is accessible to other identities: %s %v", path, info.Mode())
		}
	}
	raw, _ := os.ReadFile(filepath.Join(out, "capture.json"))
	var saved CapturedBundle
	if err = json.Unmarshal(raw, &saved); err != nil || saved.Status != "complete" {
		t.Fatal("manifest missing completion")
	}
}
func TestRequestedArtifactFailureIsPartial(t *testing.T) {
	fakeTools(t)
	run := func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		if args[1] == "GC.heap_dump" {
			return []byte("failed creating dump"), nil
		}
		return fakeCommand(ctx, tool, args...)
	}
	b, err := captureBundle(context.Background(), Options{PID: 42, Count: 1, WithHeap: true, TargetDir: t.TempDir(), OutputDir: filepath.Join(t.TempDir(), "out")}, run)
	if err == nil || b == nil || b.Status != "partial" || b.HeapDumpPath != "" {
		t.Fatalf("missing heap presented as success: %+v %v", b, err)
	}
	raw, _ := os.ReadFile(filepath.Join(b.OutputDir, "capture.json"))
	if !strings.Contains(string(raw), `"error"`) {
		t.Fatal("failure absent from manifest")
	}
}
func TestCanceledJFRStopsOnlyOwnedRecording(t *testing.T) {
	fakeTools(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := false
	run := func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		if args[1] == "JFR.start" {
			cancel()
		}
		if args[1] == "JFR.stop" {
			if ctx.Err() != nil {
				t.Fatal("cleanup reused canceled context")
			}
			if !strings.HasPrefix(args[2], "name=jvmdiag_") {
				t.Fatal("cleanup targeted unrelated recording")
			}
			stopped = true
		}
		return fakeCommand(ctx, tool, args...)
	}
	b, err := captureBundle(ctx, Options{PID: 42, Count: 1, JFRDuration: time.Minute, TargetDir: t.TempDir()}, run)
	if !errors.Is(err, context.Canceled) || !stopped || b.Status != "partial" {
		t.Fatalf("cancellation cleanup failed: %+v %v %v", b, err, stopped)
	}
}
func TestCommandDeadlineAndInvalidInput(t *testing.T) {
	fakeTools(t)
	run := func(ctx context.Context, _ string, _ ...string) ([]byte, error) { <-ctx.Done(); return nil, ctx.Err() }
	_, err := captureBundle(context.Background(), Options{PID: 42, Count: 1, CommandTimeout: time.Millisecond}, run)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline not enforced: %v", err)
	}
	for _, opts := range []Options{{PID: 0}, {PID: -1}, {PID: 42, JFRDuration: -1}, {PID: 42, JFRDuration: 11 * time.Minute}} {
		if _, err = captureBundle(context.Background(), opts, run); err == nil {
			t.Fatalf("accepted invalid options: %+v", opts)
		}
	}
}
func TestNoOverwriteOrSymlinkArtifacts(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	os.WriteFile(original, []byte("keep"), 0600)
	link := filepath.Join(dir, "link")
	if runtime.GOOS != "windows" {
		if err := os.Symlink(original, link); err != nil {
			t.Fatal(err)
		}
		if err := writePrivate(link, []byte("replace")); err == nil {
			t.Fatal("followed output symlink")
		}
		if err := copyArtifact(link, filepath.Join(dir, "copy"), "keep"); err == nil {
			t.Fatal("followed input symlink")
		}
	}
	fakeTools(t)
	if _, err := captureBundle(context.Background(), Options{PID: 42, OutputDir: dir}, fakeCommand); err == nil {
		t.Fatal("reused existing output directory")
	}
}
func TestContainerIdentityUsesEffectiveIDs(t *testing.T) {
	status := "Uid:\t0\t10001\t0\t0\nGid:\t0\t10002\t0\t0\n"
	if err := checkIdentity(status, 10001, 10002); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][2]int{{0, 0}, {10001, 0}, {0, 10002}} {
		if err := checkIdentity(status, ids[0], ids[1]); err == nil {
			t.Fatal("accepted mismatching effective identity")
		}
	}
	if err := checkIdentity("Uid: 0 invalid\n", 0, 0); err == nil {
		t.Fatal("accepted unknown identity")
	}
}
func TestProcDiscoveryDoesNotNeedSharedPerfdata(t *testing.T) {
	root := t.TempDir()
	for _, id := range []string{"20", "3", "1"} {
		dir := filepath.Join(root, id)
		os.Mkdir(dir, 0700)
		name := "/opt/java/bin/java"
		if id == "1" {
			name = "/bin/sh"
		}
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(name+"\x00-jar\x00app.jar\x00"), 0600)
	}
	p, err := listProcJVMs(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for _, proc := range p {
		ids = append(ids, proc.PID)
	}
	if !reflect.DeepEqual(ids, []int{3, 20}) {
		t.Fatalf("discovery: %+v", p)
	}
}

func TestAttachBridgeSamePIDSeparateMounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux attach bridge requires Unix symlinks")
	}
	base := t.TempDir()
	root := filepath.Join(base, "1", "root")
	targetTmp := filepath.Join(root, "tmp")
	os.MkdirAll(targetTmp, 0700)
	local := t.TempDir()
	cleanup, err := prepareAttachBridge(root, local, "NSpid:\t1\n")
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(local, ".java_pid1")
	target, err := os.Readlink(alias)
	if err != nil || target != filepath.Join(targetTmp, ".java_pid1") {
		t.Fatalf("incorrect socket bridge: %s %v", target, err)
	}
	if _, err = os.Stat(filepath.Join(targetTmp, ".attach_pid1")); err != nil {
		t.Fatal("target trigger missing")
	}
	if _, err = prepareAttachBridge(root, local, "NSpid:\t1\n"); err == nil {
		t.Fatal("overwrote existing socket bridge")
	}
	cleanup()
	for _, path := range []string{alias, filepath.Join(targetTmp, ".attach_pid1")} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("bridge leaked: %s", path)
		}
	}
	// Shared temporary directories need no bridge.
	cleanup, err = prepareAttachBridge(root, targetTmp, "NSpid:\t1\n")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	// Preserve an attach trigger created by another tool.
	trigger := filepath.Join(targetTmp, ".attach_pid1")
	os.WriteFile(trigger, []byte("existing"), 0600)
	cleanup, err = prepareAttachBridge(root, local, "NSpid:\t1\n")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if raw, _ := os.ReadFile(trigger); string(raw) != "existing" {
		t.Fatal("removed another client's trigger")
	}
	// Different PID namespaces are already supported by the JDK.
	cleanup, err = prepareAttachBridge(root, local, "NSpid:\t1 2\n")
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if entries, _ := os.ReadDir(local); len(entries) != 0 {
		t.Fatal("unnecessary attach bridge")
	}
}

func TestJFRStopFailureIsNotComplete(t *testing.T) {
	fakeTools(t)
	run := func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		if args[1] == "JFR.stop" {
			return []byte("cleanup denied"), errors.New("denied")
		}
		return fakeCommand(ctx, tool, args...)
	}
	b, err := captureBundle(context.Background(), Options{PID: 42, Count: 1, JFRDuration: time.Nanosecond, TargetDir: t.TempDir()}, run)
	if err == nil || b.Status != "partial" || !strings.Contains(b.Error, "cleanup failed") {
		t.Fatalf("cleanup failure hidden: %+v %v", b, err)
	}
}
func TestJavaMainDisplayHints(t *testing.T) {
	for _, tc := range []struct {
		args []string
		main string
	}{
		{[]string{"-Xmx64m", "-cp", "/fixture", "Fixture"}, "Fixture"},
		{[]string{"-jar", "app.jar", "argument"}, "app.jar"},
		{[]string{"--module-path", "/modules", "--module", "app/Main"}, "app/Main"},
		{[]string{"-classpath"}, "(java)"},
	} {
		if got := javaMain(tc.args); got != tc.main {
			t.Errorf("%v: %s != %s", tc.args, got, tc.main)
		}
	}
}
