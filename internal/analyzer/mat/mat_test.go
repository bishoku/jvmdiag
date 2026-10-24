package mat_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bishoku/jvmdiag/internal/analyzer/mat"
)

func TestDownloadURLForAllPlatforms(t *testing.T) {
	cases := []struct {
		goos, goarch string
		wantSuffix   string
	}{
		{"windows", "amd64", "-win32.win32.x86_64.zip"},
		{"linux", "amd64", "-linux.gtk.x86_64.zip"},
		{"linux", "arm64", "-linux.gtk.aarch64.zip"},
		{"darwin", "amd64", "-macosx.cocoa.x86_64.zip"},
		{"darwin", "arm64", "-macosx.cocoa.aarch64.zip"},
	}

	for _, tc := range cases {
		got := mat.DownloadURLForPlatform(tc.goos, tc.goarch)
		if !strings.HasSuffix(got, tc.wantSuffix) {
			t.Errorf("DownloadURLForPlatform(%q, %q) = %q, want suffix %q", tc.goos, tc.goarch, got, tc.wantSuffix)
		}
	}
}

func TestResolveParseScriptAcrossOSLayouts(t *testing.T) {
	// 1. Linux layout: <base>/mat/mat/ParseHeapDump.sh
	linuxBase := t.TempDir()
	linuxMatDir := filepath.Join(linuxBase, "mat", "mat")
	_ = os.MkdirAll(linuxMatDir, 0o755)
	_ = os.WriteFile(filepath.Join(linuxMatDir, "ParseHeapDump.sh"), []byte("#!/bin/sh\n"), 0o644)
	_ = os.WriteFile(filepath.Join(linuxMatDir, "MemoryAnalyzer"), []byte("bin"), 0o644)

	svcLinux := mat.NewServiceWithOptions("", linuxBase, "", "4g", mat.Options{SkipLegacy: true})
	if got := svcLinux.ResolveParseScript(); got == "" {
		t.Errorf("expected Linux ParseHeapDump.sh to be resolved")
	}

	// 2. Windows layout: <base>/mat/mat/ParseHeapDump.bat
	winBase := t.TempDir()
	winMatDir := filepath.Join(winBase, "mat", "mat")
	_ = os.MkdirAll(winMatDir, 0o755)
	_ = os.WriteFile(filepath.Join(winMatDir, "ParseHeapDump.bat"), []byte("@echo off\r\n"), 0o644)
	_ = os.WriteFile(filepath.Join(winMatDir, "MemoryAnalyzer.exe"), []byte("exe"), 0o644)

	svcWin := mat.NewServiceWithOptions("", winBase, "", "4g", mat.Options{SkipLegacy: true})
	if got := svcWin.ResolveParseScript(); got == "" {
		t.Errorf("expected Windows ParseHeapDump.bat to be resolved")
	}

	// 3. macOS .app bundle layout: <base>/mat/mat/MemoryAnalyzer.app/Contents/Eclipse/ParseHeapDump.sh
	macBase := t.TempDir()
	eclipseDir := filepath.Join(macBase, "mat", "mat", "MemoryAnalyzer.app", "Contents", "Eclipse")
	macOSDir := filepath.Join(macBase, "mat", "mat", "MemoryAnalyzer.app", "Contents", "MacOS")
	_ = os.MkdirAll(eclipseDir, 0o755)
	_ = os.MkdirAll(macOSDir, 0o755)
	_ = os.WriteFile(filepath.Join(eclipseDir, "ParseHeapDump.sh"), []byte("#!/bin/sh\n"), 0o644)
	_ = os.WriteFile(filepath.Join(macOSDir, "MemoryAnalyzer"), []byte("macho"), 0o644)

	svcMac := mat.NewServiceWithOptions("", macBase, "", "4g", mat.Options{SkipLegacy: true})
	if got := svcMac.ResolveParseScript(); got == "" {
		t.Errorf("expected macOS ParseHeapDump.sh to be resolved")
	}
}

func TestEmptyMATReportIsNotSuccess(t *testing.T) {
	if report, err := mat.BuildReportFromDir(t.TempDir()); err == nil || report != "" {
		t.Fatal("banner-only MAT result reported as deep analysis")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken_System_Overview.zip"), []byte("not a zip"), 0600); err != nil {
		t.Fatal(err)
	}
	if report, err := mat.BuildReportFromDir(dir); err == nil || report != "" {
		t.Fatal("unreadable MAT report treated as success")
	}
}

func TestNativeOQLAndDominatorsAreUnsupported(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	svc := mat.NewServiceWithOptions("", t.TempDir(), "", "4g", mat.Options{SkipLegacy: true})
	for _, query := range []string{"SELECT * FROM A", "SELECT a.x FROM A a WHERE a.x > 1", "SELECT count(*) FROM A", "SELECT * FROM INSTANCEOF A"} {
		if out := svc.RunOQLQuery(context.Background(), "", query, &hprof.Summary{}); !strings.HasPrefix(out, "Error: unsupported capability") {
			t.Fatalf("unsupported query simulated: %s", out)
		}
	}
	if out := svc.QueryDominatorTree("missing.hprof", 10, &hprof.Summary{}); !strings.HasPrefix(out, "Error: unsupported capability") {
		t.Fatal("payload ranking presented as a dominator tree")
	}
}

func TestRequestedMATFailureIsExplicitlyLimited(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var data bytes.Buffer
	data.WriteString("JAVA PROFILE 1.0.1\x00")
	_ = binary.Write(&data, binary.BigEndian, uint32(8))
	_ = binary.Write(&data, binary.BigEndian, uint64(0))
	data.WriteByte(0x0c)
	_ = binary.Write(&data, binary.BigEndian, uint32(0))
	_ = binary.Write(&data, binary.BigEndian, uint32(0))
	path := filepath.Join(t.TempDir(), "heap.hprof")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	report, sum, engine, err := mat.AnalyzeHeapHybrid(context.Background(), nil, path, true)
	if err != nil || engine != "native-hprof" || sum.Assessment.Status != "limited" || !strings.Contains(report, "MAT is unavailable") {
		t.Fatalf("missing MAT request was hidden: %s %s %v", engine, report, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	tool := t.TempDir()
	if err := os.WriteFile(filepath.Join(tool, "ParseHeapDump.sh"), []byte("#!/bin/sh\nexit 9\n"), 0700); err != nil {
		t.Fatal(err)
	}
	svc := mat.NewServiceWithOptions(tool, t.TempDir(), "", "4g", mat.Options{SkipLegacy: true})
	report, sum, engine, err = mat.AnalyzeHeapHybrid(context.Background(), svc, path, true)
	if err != nil || engine != "native-hprof" || sum.Assessment.Status != "limited" || !strings.Contains(report, "Requested MAT analysis failed") {
		t.Fatalf("MAT failure promoted to success: %s %s %v", engine, report, err)
	}
}

func TestIsolatedMATDoesNotDiscoverOperatorInstallation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	legacy := filepath.Join(home, ".jvm-diagnostics", "mat")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "ParseHeapDump.sh"), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	svc := mat.NewServiceWithOptions("", t.TempDir(), "", "4g", mat.Options{SkipLegacy: true})
	if svc.IsAvailable() {
		t.Fatal("test discovered the operator's MAT")
	}
}
