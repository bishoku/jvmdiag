package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestInlineDiagnosticToolsRejectInvalidEvidence(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct{ name, content string }{
		{"analyze_thread_dump", "this is not JVM diagnostic data"},
		{"analyze_thread_dump", `{"threadDump":`},
		{"analyze_crash_or_nmt", "this is not JVM diagnostic data"},
	} {
		report, handled, err := s.executeStandaloneTool(context.Background(), tc.name, map[string]any{"content": tc.content})
		if !handled || err == nil || report != "" {
			t.Fatalf("%s accepted invalid evidence: handled=%v err=%v report=%q", tc.name, handled, err, report)
		}
	}
	report, handled, err := s.executeStandaloneTool(context.Background(), "analyze_thread_dump", map[string]any{"content": "\"worker\" #1 tid=0x01 runnable\n   java.lang.Thread.State: RUNNABLE\n\tat Fixture.main(Fixture.java:1)\n"})
	if !handled || err != nil || !strings.Contains(report, "worker") {
		t.Fatalf("valid inline dump rejected: handled=%v err=%v report=%q", handled, err, report)
	}
}
