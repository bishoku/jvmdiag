package analyzer_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bishoku/jvmdiag/internal/analyzer/gclog"
	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
	"github.com/bishoku/jvmdiag/internal/analyzer/incident"
	"github.com/bishoku/jvmdiag/internal/analyzer/jfr"
	"github.com/bishoku/jvmdiag/internal/analyzer/nmtcrash"
	"github.com/bishoku/jvmdiag/internal/analyzer/threaddump"
)

func buildSyntheticHprof(t *testing.T, cacheInstances int, dupStrings int) []byte {
	t.Helper()
	var buf bytes.Buffer

	// Header: "JAVA PROFILE 1.0.2\x00" + idSize (8) + timestamp
	buf.WriteString("JAVA PROFILE 1.0.2\x00")
	_ = binary.Write(&buf, binary.BigEndian, uint32(8))
	_ = binary.Write(&buf, binary.BigEndian, uint64(1700000000000))

	writeRecord := func(tag byte, payload []byte) {
		buf.WriteByte(tag)
		_ = binary.Write(&buf, binary.BigEndian, uint32(0)) // time offset
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(payload)))
		buf.Write(payload)
	}

	writeUTF8 := func(id uint64, s string) {
		var p bytes.Buffer
		_ = binary.Write(&p, binary.BigEndian, id)
		p.WriteString(s)
		writeRecord(0x01, p.Bytes())
	}

	writeLoadClass := func(serial uint32, classObjID uint64, nameID uint64) {
		var p bytes.Buffer
		_ = binary.Write(&p, binary.BigEndian, serial)
		_ = binary.Write(&p, binary.BigEndian, classObjID)
		_ = binary.Write(&p, binary.BigEndian, uint32(1)) // trace serial
		_ = binary.Write(&p, binary.BigEndian, nameID)
		writeRecord(0x02, p.Bytes())
	}

	writeUTF8(1, "com/acme/cache/OrderCacheEntry")
	writeUTF8(2, "java/lang/String")
	writeUTF8(3, "processOrders")
	writeUTF8(4, "OrderService.java")

	writeLoadClass(1, 0x100, 1)
	writeLoadClass(2, 0x200, 2)

	// Add a stack frame (0x04) and trace (0x05)
	{
		var fp bytes.Buffer
		_ = binary.Write(&fp, binary.BigEndian, uint64(10)) // frameID
		_ = binary.Write(&fp, binary.BigEndian, uint64(3))  // methodNameID
		_ = binary.Write(&fp, binary.BigEndian, uint64(0))  // methodSigID
		_ = binary.Write(&fp, binary.BigEndian, uint64(4))  // sourceFileID
		_ = binary.Write(&fp, binary.BigEndian, uint32(1))  // classSerial
		_ = binary.Write(&fp, binary.BigEndian, int32(88))  // lineNum
		writeRecord(0x04, fp.Bytes())

		var tp bytes.Buffer
		_ = binary.Write(&tp, binary.BigEndian, uint32(1))  // traceSerial
		_ = binary.Write(&tp, binary.BigEndian, uint32(1))  // threadSerial
		_ = binary.Write(&tp, binary.BigEndian, uint32(1))  // numFrames
		_ = binary.Write(&tp, binary.BigEndian, uint64(10)) // frameID
		writeRecord(0x05, tp.Bytes())
	}

	// Build Heap Dump Segment (0x1C)
	var seg bytes.Buffer
	// Thread root (0x08)
	seg.WriteByte(0x08)
	_ = binary.Write(&seg, binary.BigEndian, uint64(0x9000)) // threadObjID
	_ = binary.Write(&seg, binary.BigEndian, uint32(1))      // threadSerial
	_ = binary.Write(&seg, binary.BigEndian, uint32(1))      // traceSerial

	// Instances of com.acme.cache.OrderCacheEntry (0x21)
	for i := 0; i < cacheInstances; i++ {
		seg.WriteByte(0x21)
		_ = binary.Write(&seg, binary.BigEndian, uint64(0x10000+i)) // objID
		_ = binary.Write(&seg, binary.BigEndian, uint32(1))         // traceSerial
		_ = binary.Write(&seg, binary.BigEndian, uint64(0x100))     // classObjID
		payload := make([]byte, 256)
		_ = binary.Write(&seg, binary.BigEndian, uint32(len(payload)))
		seg.Write(payload)
	}

	// Duplicate byte[] arrays (0x23)
	dupContent := []byte("SELECT * FROM orders WHERE customer_session_token = 'repeated-token-12345'")
	for i := 0; i < dupStrings; i++ {
		seg.WriteByte(0x23)
		_ = binary.Write(&seg, binary.BigEndian, uint64(0x50000+i)) // arrID
		_ = binary.Write(&seg, binary.BigEndian, uint32(1))         // traceSerial
		_ = binary.Write(&seg, binary.BigEndian, uint32(len(dupContent)))
		seg.WriteByte(8) // typeByte = 8
		seg.Write(dupContent)
	}

	writeRecord(0x1C, seg.Bytes())
	writeRecord(0x2C, nil)
	return buf.Bytes()
}

func TestNativeHprofParserAndDiff(t *testing.T) {
	tmp := t.TempDir()
	hprof1 := filepath.Join(tmp, "dump1.hprof")
	hprof2 := filepath.Join(tmp, "dump2.hprof")

	if err := os.WriteFile(hprof1, buildSyntheticHprof(t, 20, 10), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hprof2, buildSyntheticHprof(t, 80, 25), 0o644); err != nil {
		t.Fatal(err)
	}

	report, summary, err := hprof.AnalyzeFile(hprof2)
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}
	if !strings.Contains(report, "com.acme.cache.OrderCacheEntry") {
		t.Errorf("expected report to contain OrderCacheEntry, got:\n%s", report)
	}
	if len(summary.DuplicateArrays) == 0 {
		t.Errorf("expected duplicate strings to be detected")
	}
	if len(summary.ThreadStacks) == 0 {
		t.Errorf("expected thread stacks to be extracted from heap dump")
	}

	diffReport, err := hprof.CompareFiles(hprof1, hprof2)
	if err != nil {
		t.Fatalf("CompareFiles failed: %v", err)
	}
	if !strings.Contains(diffReport, "+60") {
		t.Errorf("expected +60 instance growth in diff report, got:\n%s", diffReport)
	}
}

func TestThreadDumpAndMultiSnapshotDiff(t *testing.T) {
	tmp := t.TempDir()
	td1 := filepath.Join(tmp, "td1.tdump")
	td2 := filepath.Join(tmp, "td2.tdump")

	dump1Content := `2026-10-22 20:00:00
Full thread dump OpenJDK 64-Bit Server VM:

"http-nio-8080-exec-1" #11 daemon prio=5 tid=0x00000001 nid=0x11 runnable
   java.lang.Thread.State: RUNNABLE
	at com.acme.payment.XmlParser.parseLoop(XmlParser.java:142)
	- locked <0x0000000777> (a java.lang.Object)

"http-nio-8080-exec-2" #12 daemon prio=5 tid=0x00000002 nid=0x12 waiting for monitor entry
   java.lang.Thread.State: BLOCKED (on object monitor)
	at com.acme.payment.XmlParser.acquire(XmlParser.java:99)
	- waiting to lock <0x0000000777> (a java.lang.Object)
`
	dump2Content := dump1Content // Both threads remain stuck in exact same frames!

	_ = os.WriteFile(td1, []byte(dump1Content), 0o644)
	_ = os.WriteFile(td2, []byte(dump2Content), 0o644)

	rep, sum, err := threaddump.AnalyzeFile(td1)
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Contentions) != 1 || sum.Contentions[0].OwnerThread != "http-nio-8080-exec-1" {
		t.Errorf("expected lock contention owned by http-nio-8080-exec-1, got: %+v", sum.Contentions)
	}
	if !strings.Contains(rep, "Lock Contention Bottlenecks") {
		t.Errorf("expected contention section in report")
	}

	diffRep, err := threaddump.CompareFiles([]string{td1, td2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(diffRep, "http-nio-8080-exec-1") || !strings.Contains(diffRep, "XmlParser.parseLoop") {
		t.Errorf("expected stuck thread http-nio-8080-exec-1 in diff report, got:\n%s", diffRep)
	}
}

func TestGCLogAndIncidentCorrelation(t *testing.T) {
	tmp := t.TempDir()
	gcFile := filepath.Join(tmp, "gc.log")
	tdFile := filepath.Join(tmp, "td.txt")
	heapFile := filepath.Join(tmp, "heap.hprof")

	gcContent := `[0.100s][info][gc] Using G1
[1.000s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 512M->128M(1024M) 25.40ms
[5.000s][info][gc] GC(1) Pause Full (G1 Compaction Pause) 950M->820M(1024M) 1250.50ms
`
	tdContent := `"worker-1" #21 prio=5 tid=0x01 runnable
   java.lang.Thread.State: RUNNABLE
	at com.acme.cache.OrderCacheEntry.put(OrderCacheEntry.java:55)
`
	_ = os.WriteFile(gcFile, []byte(gcContent), 0o644)
	_ = os.WriteFile(tdFile, []byte(tdContent), 0o644)
	_ = os.WriteFile(heapFile, buildSyntheticHprof(t, 50, 10), 0o644)

	incRep, err := incident.Analyze(context.Background(), nil, incident.Input{
		GCLogPath:       gcFile,
		ThreadDumpPaths: []string{tdFile},
		HeapDumpPath:    heapFile,
	})
	if err != nil {
		t.Fatalf("Incident Analyze failed: %v", err)
	}
	if !strings.Contains(incRep, "CODE PATH <-> HEAP CORRELATION") {
		t.Errorf("expected cross-artifact correlation in incident report, got:\n%s", incRep)
	}

	_, metrics, err := gclog.AnalyzeFile(gcFile)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.PausesAbove1000ms != 1 || metrics.FullGCCount != 1 {
		t.Errorf("unexpected GC metrics: %+v", metrics)
	}
}

func TestNMTCrashAnalyzer(t *testing.T) {
	sample := `#
# There is insufficient memory for the Java Runtime Environment to continue.
# Native memory allocation (mmap) failed to map 16777216 bytes for committing reserved memory.
# Problematic frame:
# C  [libc.so.6+0x89abc]  malloc+0x5c
# JRE version: OpenJDK Runtime Environment (21.0.2+13)
Current thread (0x00007f9a00123000):  JavaThread "netty-nio-1" [_thread_in_native, id=4567]

Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
C  [libc.so.6+0x89abc]  malloc+0x5c
J 1234  io.netty.buffer.PoolArena.allocate(I)V (45 bytes)

/proc/sys/vm/max_map_count: 65530

Native Memory Tracking:

Total: reserved=6144MB, committed=4096MB
-                 Java Heap (reserved=2048MB, committed=1536MB)
                            (mmap: reserved=2048MB, committed=1536MB)
-                    Thread (reserved=1024MB, committed=1024MB)
                            (thread #950)
-                  Internal (reserved=800MB, committed=800MB)
`
	rep, sum, err := nmtcrash.AnalyzeText(sample)
	if err != nil {
		t.Fatalf("AnalyzeText failed: %v", err)
	}
	if sum.ReportType != "COMBINED_CRASH_AND_NMT" {
		t.Errorf("expected COMBINED_CRASH_AND_NMT, got %s", sum.ReportType)
	}
	if sum.OffHeapCommittedKB != (4096-1536)*1024 {
		t.Errorf("expected off-heap committed %d KB, got %d KB", (4096-1536)*1024, sum.OffHeapCommittedKB)
	}
	if sum.ThreadCount != 950 {
		t.Errorf("expected 950 threads in NMT, got %d", sum.ThreadCount)
	}
	if len(sum.Suspects) < 3 || !strings.Contains(rep, "max_map_count") {
		t.Errorf("expected automated NMT/crash suspects in report, got:\n%s", rep)
	}
}

func TestJava21VirtualThreadPinningJSONAndText(t *testing.T) {
	jsonDump := `{
  "threadDump": {
    "processId": "9999",
    "runtimeVersion": "21.0.3",
    "threadContainers": [
      {
        "container": "<root>",
        "threads": [
          {
            "tid": "101",
            "name": "vthread-order-1",
            "state": "WAITING",
            "virtual": true,
            "carrier": "ForkJoinPool-1-worker-1",
            "stack": [
              "jdk.internal.misc.Unsafe.park(Native Method)",
              "com.acme.db.JdbcClient.query(JdbcClient.java:88)"
            ],
            "monitorsOwned": [
              { "depth": 1, "locks": ["0x0000000abc"] }
            ]
          },
          {
            "tid": "20",
            "name": "ForkJoinPool-1-worker-1",
            "state": "RUNNABLE",
            "virtual": false,
            "stack": ["java.util.concurrent.ForkJoinPool.runWorker(ForkJoinPool.java:1800)"]
          }
        ]
      }
    ]
  }
}`
	sum := threaddump.ParseContent("loom.json", jsonDump)
	rep := threaddump.BuildReport(sum, jsonDump)
	if sum.VirtualThreadCount != 1 || len(sum.PinnedThreads) != 1 {
		t.Fatalf("expected 1 virtual thread and 1 pinned thread, got virtual=%d pinned=%d", sum.VirtualThreadCount, len(sum.PinnedThreads))
	}
	if !strings.Contains(rep, "PINNED") || !strings.Contains(rep, "vthread-order-1") {
		t.Errorf("expected PINNED virtual thread in report, got:\n%s", rep)
	}
}

func TestJFRAnalyzerJSONAndBinary(t *testing.T) {
	tmp := t.TempDir()
	jfrJSONPath := filepath.Join(tmp, "recording.json")
	jfrJSON := `{
  "recording": {
    "events": [
      {
        "type": "jdk.ExecutionSample",
        "values": {
          "stackTrace": {
            "frames": [
              { "method": { "type": { "name": "com/acme/crypto/HashEngine" }, "name": "computeSha512" }, "lineNumber": 77 }
            ]
          }
        }
      },
      {
        "type": "jdk.ObjectAllocationInNewTLAB",
        "values": {
          "tlabSize": 104857600,
          "allocationSize": 64,
          "objectClass": { "name": "byte[]" },
          "stackTrace": {
            "frames": [
              { "method": { "type": { "name": "com/acme/xml/PayloadBuilder" }, "name": "serialize" }, "lineNumber": 42 }
            ]
          }
        }
      },
      {
        "type": "jdk.VirtualThreadPinned",
        "values": {
          "duration": "PT0.150S",
          "stackTrace": {
            "frames": [
              { "method": { "type": { "name": "com/acme/legacy/SyncCache" }, "name": "getOrLoad" }, "lineNumber": 19 }
            ]
          }
        }
      }
    ]
  }
}`
	if err := os.WriteFile(jfrJSONPath, []byte(jfrJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, sum, err := jfr.AnalyzeFile(jfrJSONPath)
	if err != nil {
		t.Fatalf("jfr.AnalyzeFile failed: %v", err)
	}
	if len(sum.CPUHotspots) == 0 || !strings.Contains(sum.CPUHotspots[0].Method, "HashEngine.computeSha512") {
		t.Errorf("expected CPU hotspot HashEngine.computeSha512, got %+v", sum.CPUHotspots)
	}
	if len(sum.AllocationHotspots) == 0 || sum.AllocationHotspots[0].TotalBytes != 64 || sum.TLABReservedBytes != 104857600 {
		t.Errorf("expected 64 recorded object bytes and separate 100MB TLAB reservation, got %+v", sum.AllocationHotspots)
	}
	if len(sum.PinnedEvents) != 1 || !strings.Contains(rep, "SyncCache.getOrLoad") {
		t.Errorf("expected VirtualThreadPinned event in JFR report, got:\n%s", rep)
	}
}
