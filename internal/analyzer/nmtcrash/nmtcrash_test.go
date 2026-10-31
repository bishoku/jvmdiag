package nmtcrash

import (
	"strings"
	"testing"
)

func TestRejectUnrecognizedNativeDiagnostics(t *testing.T) {
	for _, text := range []string{"", "this is not JVM diagnostic data", "Native Memory Tracking:\n", "Total: reserved=invalid, committed=invalid"} {
		report, sum, err := AnalyzeText(text)
		if err == nil || report != "" || sum != nil {
			t.Fatalf("unrecognized input accepted: err=%v sum=%+v report=%q", err, sum, report)
		}
	}
}

func TestNMTCommittedIsNotReportedAsRSS(t *testing.T) {
	report, sum, err := AnalyzeText("Native Memory Tracking:\nTotal: reserved=100MB, committed=50MB\n- Java Heap (reserved=64MB, committed=32MB)\n")
	if err != nil || sum == nil {
		t.Fatalf("valid NMT rejected: %v", err)
	}
	if sum.TotalCommittedKB != 50*1024 || sum.OffHeapCommittedKB != 18*1024 {
		t.Fatalf("incorrect NMT values: %+v", sum)
	}
	if !strings.Contains(report, "NMT Total Committed:") || strings.Contains(report, "Total Committed (RSS)") || !strings.Contains(report, "not process RSS") || !strings.Contains(report, "NMT total committed minus Java heap committed") {
		t.Fatalf("NMT metric scope missing:\n%s", report)
	}
}

func TestRecognizedCrashWithoutNMTIsSupported(t *testing.T) {
	report, sum, err := AnalyzeText("# A fatal error has been detected by the Java Runtime Environment:\n# SIGSEGV (0xb) at pc=0x123\n")
	if err != nil || sum == nil || sum.ReportType != "HS_ERR_CRASH" || !strings.Contains(report, "SIGSEGV") {
		t.Fatalf("valid crash rejected: %v %+v", err, sum)
	}
}
