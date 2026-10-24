package hprof

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/bishoku/jvmdiag/internal/analyzer/quality"
)

// HPROF Top-Level Tags
const (
	tagUTF8            = 0x01
	tagLoadClass       = 0x02
	tagUnloadClass     = 0x03
	tagFrame           = 0x04
	tagTrace           = 0x05
	tagAllocSites      = 0x06
	tagHeapSummary     = 0x07
	tagStartThread     = 0x0A
	tagEndThread       = 0x0B
	tagHeapDump        = 0x0C
	tagHeapDumpSegment = 0x1C
	tagHeapDumpEnd     = 0x2C
)

// HPROF Heap Dump Sub-record Tags
const (
	subRootUnknown      = 0xFF
	subRootJNIGlobal    = 0x01
	subRootJNILocal     = 0x02
	subRootJavaFrame    = 0x03
	subRootNativeStack  = 0x04
	subRootStickyClass  = 0x05
	subRootThreadBlock  = 0x06
	subRootMonitorUsed  = 0x07
	subRootThreadObject = 0x08
	subClassDump        = 0x20
	subInstanceDump     = 0x21
	subObjArrayDump     = 0x22
	subPrimArrayDump    = 0x23
)

// Basic types in HPROF
const (
	typeObject  = 2
	typeBoolean = 4
	typeChar    = 5
	typeFloat   = 6
	typeDouble  = 7
	typeByte    = 8
	typeShort   = 9
	typeInt     = 10
	typeLong    = 11
)

type ClassStat struct {
	SampleObjectIDs     []uint64 `json:"sampleObjectIds"`
	ClassID             uint64   `json:"classId"`
	ClassName           string   `json:"className"`
	PackageName         string   `json:"packageName"`
	InstanceCount       int64    `json:"instanceCount"`
	TotalBytes          int64    `json:"payloadBytes"`
	LargestPayloadBytes int64    `json:"largestPayloadBytes"`
}

type PackageStat struct {
	PackageName   string `json:"packageName"`
	InstanceCount int64  `json:"instanceCount"`
	TotalBytes    int64  `json:"payloadBytes"`
}

type LargestObject struct {
	ClassID   uint64 `json:"classId,omitempty"`
	ObjectID  uint64 `json:"objectId"`
	ClassName string `json:"className"`
	SizeBytes int64  `json:"payloadBytes"`
	TraceID   uint32 `json:"traceId,omitempty"`
}

type DuplicateArrayStat struct {
	ArrayType             string   `json:"arrayType"`
	SampleObjectIDs       []uint64 `json:"sampleObjectIds"`
	Preview               string   `json:"preview"`
	Count                 int64    `json:"count"`
	UnitPayloadBytes      int64    `json:"unitPayloadBytes"`
	DuplicatePayloadBytes int64    `json:"duplicatePayloadBytes"`
}

type ThreadStack struct {
	ThreadSerial uint32   `json:"threadSerial"`
	ThreadObject uint64   `json:"threadObjectId"`
	TraceSerial  uint32   `json:"traceSerial"`
	Frames       []string `json:"frames"`
}

type LeakSuspect struct {
	Confidence  string  `json:"confidence"`
	Evidence    string  `json:"evidence"`
	Title       string  `json:"title"`
	ClassName   string  `json:"className"`
	Bytes       int64   `json:"bytes"`
	Percentage  float64 `json:"percentage"`
	Instances   int64   `json:"instances"`
	Description string  `json:"description"`
}

type Summary struct {
	Assessment        quality.Assessment   `json:"assessment"`
	FileName          string               `json:"fileName"`
	FileSize          int64                `json:"fileSizeBytes"`
	FormatVersion     string               `json:"formatVersion"`
	IdentifierSize    int                  `json:"identifierSize"`
	CaptureTime       time.Time            `json:"captureTime"`
	TotalPayloadBytes int64                `json:"totalPayloadBytes"`
	TotalInstances    int64                `json:"totalInstances"`
	TotalClasses      int                  `json:"totalClasses"`
	GCRootCounts      map[string]int64     `json:"gcRootCounts"`
	ClassHistogram    []ClassStat          `json:"classHistogram"`
	TopPackages       []PackageStat        `json:"topPackages"`
	LargestObjects    []LargestObject      `json:"largestObjects"`
	DuplicateArrays   []DuplicateArrayStat `json:"duplicateArrays,omitempty"`
	ThreadStacks      []ThreadStack        `json:"threadStacks,omitempty"`
	LeakSuspects      []LeakSuspect        `json:"leakSuspects,omitempty"`
	SystemPropHints   []string             `json:"systemPropHints,omitempty"`
}

type frameRecord struct {
	methodNameID uint64
	methodSigID  uint64
	sourceFileID uint64
	classSerial  uint32
	lineNum      int32
}

type traceRecord struct {
	threadSerial uint32
	frameIDs     []uint64
}

type stringDupTracker struct {
	arrayType string
	objectIDs []uint64
	preview   string
	count     int64
	unitBytes int64
}

// AnalyzeFile streams a binary .hprof file and builds a comprehensive Summary and LLM report
// without requiring Java or Eclipse MAT.
func AnalyzeFile(path string) (string, *Summary, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()

	summary, err := ParseStream(bufio.NewReaderSize(f, 4*1024*1024), filepath.Base(path), st.Size())
	if err != nil {
		return "", nil, err
	}

	return BuildStructuredReport(summary), summary, nil
}

func ParseStream(r *bufio.Reader, fileName string, fileSize int64) (*Summary, error) {
	// 1. Read null-terminated header string, e.g. "JAVA PROFILE 1.0.2\x00"
	var headerBytes []byte
	for len(headerBytes) < 64 {
		b, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("invalid hprof header: %w", err)
		}
		if b == 0 {
			break
		}
		headerBytes = append(headerBytes, b)
	}
	formatVer := string(headerBytes)
	if formatVer != "JAVA PROFILE 1.0.1" && formatVer != "JAVA PROFILE 1.0.2" {
		return nil, fmt.Errorf("unsupported hprof format %q", formatVer)
	}

	var idSizeU32 uint32
	if err := binary.Read(r, binary.BigEndian, &idSizeU32); err != nil {
		return nil, fmt.Errorf("failed reading identifier size: %w", err)
	}
	idSize := int(idSizeU32)
	if idSize != 4 && idSize != 8 {
		return nil, fmt.Errorf("unsupported identifier size: %d", idSize)
	}

	var tsMillis uint64
	if err := binary.Read(r, binary.BigEndian, &tsMillis); err != nil {
		return nil, fmt.Errorf("failed reading header timestamp: %w", err)
	}

	summary := &Summary{
		FileName:       fileName,
		FileSize:       fileSize,
		FormatVersion:  formatVer,
		IdentifierSize: idSize,
		CaptureTime:    time.UnixMilli(int64(tsMillis)).UTC(),
		GCRootCounts:   make(map[string]int64),
		Assessment: quality.Assessment{Status: "complete", Scope: "serialized object/array payload histogram and GC root record counts", Source: fileName,
			Limitations: []string{"Payload bytes are serialized HPROF field/element bytes, not runtime shallow heap, retained heap or live heap. Identifier width does not determine JVM object layout or compressed references.", "No reference graph, dominator tree, paths to GC roots, or proof of a memory leak is computed.", "Duplicate-array detection covers identical raw byte[]/char[] payloads of 16–256 bytes, up to 25000 distinct payloads; it does not identify String owners or reclaimable memory. Only the top 20 duplicate groups and top 25 payloads are reported."}},
	}

	// Internal lookup maps (bounded to stay memory-friendly even on multi-GB dumps)
	utf8Strings := make(map[uint64]string)
	classNameByID := make(map[uint64]string)
	classNameBySerial := make(map[uint32]string)
	classNameIDByClassID := make(map[uint64]uint64)
	classIDBySerial := make(map[uint32]uint64)
	classStats := make(map[string]*ClassStat)
	frames := make(map[uint64]frameRecord)
	traces := make(map[uint32]traceRecord)
	var threadObjects []ThreadStack
	dupStrings := make(map[string]*stringDupTracker)
	var propHints []string

	const maxTrackedStrings = 350000
	const maxLargestObjects = 25

	var largest []LargestObject
	recordLargest := func(objID uint64, className string, size int64, traceID uint32, classID uint64) {
		if len(largest) < maxLargestObjects {
			largest = append(largest, LargestObject{ClassID: classID, ObjectID: objID, ClassName: className, SizeBytes: size, TraceID: traceID})
			sort.Slice(largest, func(i, j int) bool {
				if largest[i].SizeBytes == largest[j].SizeBytes {
					return largest[i].ObjectID < largest[j].ObjectID
				}
				return largest[i].SizeBytes > largest[j].SizeBytes
			})
			return
		}
		if size > largest[len(largest)-1].SizeBytes {
			largest[len(largest)-1] = LargestObject{ClassID: classID, ObjectID: objID, ClassName: className, SizeBytes: size, TraceID: traceID}
			sort.Slice(largest, func(i, j int) bool {
				if largest[i].SizeBytes == largest[j].SizeBytes {
					return largest[i].ObjectID < largest[j].ObjectID
				}
				return largest[i].SizeBytes > largest[j].SizeBytes
			})
		}
	}

	addStat := func(classID uint64, fallbackName string, bytes int64, objectID uint64) string {
		key := fmt.Sprintf("class:%x", classID)
		if classID == 0 {
			key = "primitive:" + fallbackName
		}
		st, ok := classStats[key]
		if !ok {
			name := classNameByID[classID]
			if name == "" {
				name = fallbackName
			}
			st = &ClassStat{
				ClassID:     classID,
				ClassName:   name,
				PackageName: extractPackage(name),
			}
			classStats[key] = st
		}
		if len(st.SampleObjectIDs) < 3 {
			st.SampleObjectIDs = append(st.SampleObjectIDs, objectID)
		}
		st.InstanceCount++
		st.TotalBytes += bytes
		if bytes > st.LargestPayloadBytes {
			st.LargestPayloadBytes = bytes
		}
		summary.TotalInstances++
		summary.TotalPayloadBytes += bytes
		return st.ClassName
	}

	// Every record is bounded and all reads are checked before results are published.
	offset := int64(len(headerBytes) + 1 + 12)
	heapSeen, segmented, ended := false, false, false
	var recHeader [9]byte
	for {
		n, err := io.ReadFull(r, recHeader[:])
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("record header at byte %d: %w", offset, err)
		}
		tag := recHeader[0]
		length := int64(binary.BigEndian.Uint32(recHeader[5:9]))
		lr := &io.LimitedReader{R: r, N: length}
		cr := &checkedReader{r: lr}
		fail := func(err error) (*Summary, error) {
			return nil, fmt.Errorf("HPROF record 0x%02x at byte %d: %w", tag, offset, err)
		}
		switch tag {
		case tagUTF8:
			if length < int64(idSize) {
				return fail(fmt.Errorf("UTF8 record shorter than identifier"))
			}
			strID := cr.id(idSize)
			strLen := length - int64(idSize)
			if strLen <= 512 && len(utf8Strings) < maxTrackedStrings {
				value := string(cr.data(strLen))
				utf8Strings[strID] = value
				if len(propHints) < 20 && isInterestingJVMString(value) {
					propHints = append(propHints, value)
				}
			} else {
				cr.skip(strLen)
				summary.Assessment.Warn("String metadata exceeded tracking limits; class names or frame names may be unresolved.")
			}
		case tagLoadClass:
			if length != int64(8+2*idSize) {
				return fail(fmt.Errorf("invalid LOAD_CLASS length"))
			}
			serial := cr.u4()
			id := cr.id(idSize)
			cr.u4()
			nameID := cr.id(idSize)
			name := formatJavaClassName(utf8Strings[nameID])
			if name == "" {
				name = fmt.Sprintf("Class@0x%x", id)
			}
			classNameByID[id] = name
			classNameIDByClassID[id] = nameID
			classIDBySerial[serial] = id
			classNameBySerial[serial] = name
		case tagFrame:
			if length != int64(4*idSize+8) {
				return fail(fmt.Errorf("invalid FRAME length"))
			}
			id := cr.id(idSize)
			fr := frameRecord{methodNameID: cr.id(idSize), methodSigID: cr.id(idSize), sourceFileID: cr.id(idSize), classSerial: cr.u4(), lineNum: int32(cr.u4())}
			if len(frames) < 100000 {
				frames[id] = fr
			} else {
				summary.Assessment.Warn("Frame tracking limit reached; thread stacks are incomplete.")
			}
		case tagTrace:
			if length < 12 {
				return fail(fmt.Errorf("invalid TRACE length"))
			}
			trace, thread, count := cr.u4(), cr.u4(), cr.u4()
			if int64(count)*int64(idSize) != lr.N {
				return fail(fmt.Errorf("TRACE frame count does not match record length"))
			}
			ids := make([]uint64, 0, 25)
			for i := uint32(0); i < count && i < 25; i++ {
				ids = append(ids, cr.id(idSize))
			}
			cr.skip(lr.N)
			if count > 25 {
				summary.Assessment.Warn("Thread stacks are truncated to 25 frames.")
			}
			if len(traces) < 50000 {
				traces[trace] = traceRecord{threadSerial: thread, frameIDs: ids}
			} else {
				summary.Assessment.Warn("Trace tracking limit reached; thread stacks are incomplete.")
			}
		case tagHeapDump, tagHeapDumpSegment:
			if ended || tag == tagHeapDump && heapSeen || tag == tagHeapDumpSegment && heapSeen && !segmented {
				return fail(fmt.Errorf("multiple heap snapshots are not supported in one file"))
			}
			heapSeen = true
			segmented = tag == tagHeapDumpSegment
			if segmented && formatVer != "JAVA PROFILE 1.0.2" {
				return fail(fmt.Errorf("segmented heaps require HPROF 1.0.2"))
			}
			if err := parseHeapSegment(lr, length, idSize, summary, classNameByID, addStat, recordLargest, &threadObjects, dupStrings); err != nil {
				return fail(err)
			}
		case tagHeapDumpEnd:
			if !segmented || ended || length != 0 {
				return fail(fmt.Errorf("unexpected HEAP_DUMP_END"))
			}
			ended = true
		default:
			cr.skip(length)
			switch tag {
			case tagUnloadClass, tagAllocSites, tagHeapSummary, tagStartThread, tagEndThread:
			default:
				summary.Assessment.Warn(fmt.Sprintf("Top-level record 0x%02x was skipped; its content is outside the supported scope.", tag))
			}
		}
		if cr.err != nil {
			return fail(cr.err)
		}
		if lr.N != 0 {
			return fail(fmt.Errorf("record has %d unconsumed bytes", lr.N))
		}
		offset += 9 + length
	}
	if !heapSeen {
		return nil, fmt.Errorf("no heap dump records found")
	}
	if segmented && !ended {
		return nil, fmt.Errorf("incomplete segmented heap dump: HEAP_DUMP_END is missing")
	}

	// Resolve metadata after all records, without assuming UTF8 precedes LOAD_CLASS.
	for classID, nameID := range classNameIDByClassID {
		name := formatJavaClassName(utf8Strings[nameID])
		if name == "" {
			summary.Assessment.Warn("Some class names could not be resolved.")
			name = fmt.Sprintf("Class@0x%x", classID)
		}
		classNameByID[classID] = name
	}
	for serial, classID := range classIDBySerial {
		classNameBySerial[serial] = classNameByID[classID]
	}
	// Finalize class histogram
	summary.TotalClasses = len(classNameByID)
	pkgMap := make(map[string]*PackageStat)
	for _, st := range classStats {
		if st.ClassID != 0 {
			if resolved := classNameByID[st.ClassID]; resolved != "" {
				st.ClassName = resolved
				st.PackageName = extractPackage(resolved)
			}
			if classNameByID[st.ClassID] == "" {
				summary.Assessment.Warn("Some object classes have no LOAD_CLASS metadata; class attribution is incomplete.")
			}
		}
		summary.ClassHistogram = append(summary.ClassHistogram, *st)
		if st.PackageName != "" {
			ps, ok := pkgMap[st.PackageName]
			if !ok {
				ps = &PackageStat{PackageName: st.PackageName}
				pkgMap[st.PackageName] = ps
			}
			ps.InstanceCount += st.InstanceCount
			ps.TotalBytes += st.TotalBytes
		}
	}

	sort.Slice(summary.ClassHistogram, func(i, j int) bool {
		a, b := summary.ClassHistogram[i], summary.ClassHistogram[j]
		if a.TotalBytes == b.TotalBytes {
			if a.ClassName == b.ClassName {
				return a.ClassID < b.ClassID
			}
			return a.ClassName < b.ClassName
		}
		return a.TotalBytes > b.TotalBytes
	})

	for _, ps := range pkgMap {
		summary.TopPackages = append(summary.TopPackages, *ps)
	}
	sort.Slice(summary.TopPackages, func(i, j int) bool {
		a, b := summary.TopPackages[i], summary.TopPackages[j]
		if a.TotalBytes == b.TotalBytes {
			return a.PackageName < b.PackageName
		}
		return a.TotalBytes > b.TotalBytes
	})

	for i := range largest {
		if name := classNameByID[largest[i].ClassID]; name != "" {
			largest[i].ClassName = name
		}
	}
	summary.LargestObjects = largest
	summary.SystemPropHints = propHints

	// Finalize duplicate strings
	for _, ds := range dupStrings {
		if ds.count >= 2 {
			repeatedPayload := (ds.count - 1) * ds.unitBytes
			if repeatedPayload > 0 {
				summary.DuplicateArrays = append(summary.DuplicateArrays, DuplicateArrayStat{
					Preview:          ds.preview,
					Count:            ds.count,
					UnitPayloadBytes: ds.unitBytes,
					ArrayType:        ds.arrayType, SampleObjectIDs: ds.objectIDs,
					DuplicatePayloadBytes: repeatedPayload,
				})
			}
		}
	}
	sort.Slice(summary.DuplicateArrays, func(i, j int) bool {
		a, b := summary.DuplicateArrays[i], summary.DuplicateArrays[j]
		if a.DuplicatePayloadBytes == b.DuplicatePayloadBytes {
			return a.SampleObjectIDs[0] < b.SampleObjectIDs[0]
		}
		return a.DuplicatePayloadBytes > b.DuplicatePayloadBytes
	})
	if len(summary.DuplicateArrays) > 20 {
		summary.DuplicateArrays = summary.DuplicateArrays[:20]
	}

	// Resolve thread stacks
	for _, to := range threadObjects {
		tr, ok := traces[to.TraceSerial]
		if !ok || len(tr.frameIDs) == 0 {
			summary.Assessment.Warn("Some thread root records have no resolvable trace; thread stacks are incomplete.")
			continue
		}
		var resolvedFrames []string
		for _, fid := range tr.frameIDs {
			fr, ok := frames[fid]
			if !ok {
				summary.Assessment.Warn("Some trace frames could not be resolved.")
				continue
			}
			cls := classNameBySerial[fr.classSerial]
			if cls == "" {
				cls = "UnknownClass"
			}
			method := utf8Strings[fr.methodNameID]
			if method == "" {
				method = "unknownMethod"
			}
			src := utf8Strings[fr.sourceFileID]
			if src != "" && fr.lineNum > 0 {
				resolvedFrames = append(resolvedFrames, fmt.Sprintf("%s.%s(%s:%d)", cls, method, src, fr.lineNum))
			} else {
				resolvedFrames = append(resolvedFrames, fmt.Sprintf("%s.%s()", cls, method))
			}
		}
		if len(resolvedFrames) > 0 {
			to.Frames = resolvedFrames
			summary.ThreadStacks = append(summary.ThreadStacks, to)
		}
	}

	// Build heuristic leak suspects
	if summary.TotalInstances == 0 {
		summary.Assessment.Warn("No object or array records were decoded; no runtime memory conclusion is available.")
	}
	summary.LeakSuspects = computeLeakSuspects(summary)
	summary.Assessment.Findings = append(summary.Assessment.Findings, quality.Finding{ID: "hprof-payload", Title: "Decoded object and array payload totals", Kind: "observation", Confidence: "high", Evidence: []quality.Evidence{{Source: fileName, Location: "validated heap dump records", Metric: "serialized payload", Value: fmt.Sprint(summary.TotalPayloadBytes), Unit: "bytes"}, {Source: fileName, Location: "validated INSTANCE_DUMP / OBJECT_ARRAY / PRIMITIVE_ARRAY records", Metric: "decoded records", Value: fmt.Sprint(summary.TotalInstances), Unit: "objects/arrays"}}, Limitations: []string{"Counts exclude class objects; dumped objects are not necessarily reachable/live. Payload size is not runtime heap size."}, NextStep: "Use a validated runtime layout or MAT for shallow/retained heap and reachability analysis."})
	for i, ls := range summary.LeakSuspects {
		summary.Assessment.Findings = append(summary.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("hprof-concentration-%d", i), Title: ls.Title, Kind: "hypothesis", Confidence: ls.Confidence, Evidence: []quality.Evidence{{Source: fileName, Location: ls.Evidence, Metric: "serialized payload concentration", Value: fmt.Sprintf("%d bytes / %.1f percent / %d records", ls.Bytes, ls.Percentage, ls.Instances)}}, Limitations: []string{"A concentration threshold is not a memory leak test; caches, workload and snapshot timing can explain it."}, NextStep: "Verify boundedness, compare equivalent workloads and inspect retained paths using MAT."})
	}
	for i, ds := range summary.DuplicateArrays {
		summary.Assessment.Findings = append(summary.Assessment.Findings, quality.Finding{ID: fmt.Sprintf("hprof-duplicate-%d", i), Title: fmt.Sprintf("%d identical %s payloads", ds.Count, ds.ArrayType), Kind: "observation", Confidence: "high", Evidence: []quality.Evidence{{Source: fileName, Location: fmt.Sprintf("sample object IDs: %x", ds.SampleObjectIDs), Metric: "identical raw payload copies", Value: fmt.Sprint(ds.Count), Unit: "arrays"}, {Source: fileName, Location: "exact raw-byte equality within one primitive type", Metric: "repeated serialized payload beyond first copy", Value: fmt.Sprint(ds.DuplicatePayloadBytes), Unit: "bytes"}}, Limitations: []string{"This is not String equality or guaranteed reclaimable memory; ownership, mutability and deduplication safety are unknown."}, NextStep: "Identify array owners before recommending deduplication."})
	}

	return summary, nil
}

// checkedReader retains the first I/O error; no partially decoded record is accepted.
type checkedReader struct {
	r   io.Reader
	err error
}

func (c *checkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.r.Read(p)
	if err != nil {
		c.err = err
	}
	return n, err
}
func (c *checkedReader) read(v any) {
	if c.err == nil {
		c.err = binary.Read(c.r, binary.BigEndian, v)
	}
}
func (c *checkedReader) u1() byte   { var v byte; c.read(&v); return v }
func (c *checkedReader) u2() uint16 { var v uint16; c.read(&v); return v }
func (c *checkedReader) u4() uint32 { var v uint32; c.read(&v); return v }
func (c *checkedReader) id(size int) uint64 {
	if size == 4 {
		return uint64(c.u4())
	}
	var v uint64
	c.read(&v)
	return v
}
func (c *checkedReader) skip(n int64) {
	if c.err == nil {
		_, c.err = io.CopyN(io.Discard, c.r, n)
	}
}
func (c *checkedReader) data(n int64) []byte {
	if c.err != nil {
		return nil
	}
	b := make([]byte, int(n))
	_, c.err = io.ReadFull(c.r, b)
	return b
}
func (c *checkedReader) value(t byte, idSize int) {
	size := typeSize(t, idSize)
	if size == 0 {
		c.err = fmt.Errorf("invalid field type %d", t)
		return
	}
	c.skip(int64(size))
}

func parseHeapSegment(r io.Reader, segBytes int64, idSize int, summary *Summary, classNameByID map[uint64]string,
	addStat func(uint64, string, int64, uint64) string, recordLargest func(uint64, string, int64, uint32, uint64), threadObjects *[]ThreadStack, dupStrings map[string]*stringDupTracker) error {
	lr := &io.LimitedReader{R: r, N: segBytes}
	c := &checkedReader{r: lr}
	for lr.N > 0 && c.err == nil {
		start := segBytes - lr.N
		tag := c.u1()
		switch tag {
		case subRootUnknown, subRootStickyClass, subRootMonitorUsed:
			c.id(idSize)
			names := map[byte]string{subRootUnknown: "ROOT_UNKNOWN", subRootStickyClass: "ROOT_STICKY_CLASS", subRootMonitorUsed: "ROOT_MONITOR_USED"}
			summary.GCRootCounts[names[tag]]++
		case subRootJNIGlobal:
			c.id(idSize)
			c.id(idSize)
			summary.GCRootCounts["ROOT_JNI_GLOBAL"]++
		case subRootJNILocal, subRootJavaFrame:
			c.id(idSize)
			c.skip(8)
			name := "ROOT_JNI_LOCAL"
			if tag == subRootJavaFrame {
				name = "ROOT_JAVA_FRAME"
			}
			summary.GCRootCounts[name]++
		case subRootNativeStack, subRootThreadBlock:
			c.id(idSize)
			c.skip(4)
			name := "ROOT_NATIVE_STACK"
			if tag == subRootThreadBlock {
				name = "ROOT_THREAD_BLOCK"
			}
			summary.GCRootCounts[name]++
		case subRootThreadObject:
			obj, thread, trace := c.id(idSize), c.u4(), c.u4()
			summary.GCRootCounts["ROOT_THREAD_OBJECT"]++
			if len(*threadObjects) < 500 {
				*threadObjects = append(*threadObjects, ThreadStack{ThreadSerial: thread, ThreadObject: obj, TraceSerial: trace})
			} else {
				summary.Assessment.Warn("Thread object tracking limit reached; thread stacks are incomplete.")
			}
		case subClassDump:
			c.id(idSize)
			c.skip(int64(4 + 6*idSize + 4))
			cp := int(c.u2())
			for i := 0; i < cp && c.err == nil; i++ {
				c.u2()
				c.value(c.u1(), idSize)
			}
			statics := int(c.u2())
			for i := 0; i < statics && c.err == nil; i++ {
				c.id(idSize)
				c.value(c.u1(), idSize)
			}
			fields := int(c.u2())
			for i := 0; i < fields && c.err == nil; i++ {
				c.id(idSize)
				if typeSize(c.u1(), idSize) == 0 {
					c.err = fmt.Errorf("invalid instance field type")
				}
			}
		case subInstanceDump:
			obj, trace, class := c.id(idSize), c.u4(), c.id(idSize)
			n := int64(c.u4())
			c.skip(n)
			if c.err == nil {
				name := addStat(class, fmt.Sprintf("Class@0x%x", class), n, obj)
				recordLargest(obj, name, n, trace, class)
			}
		case subObjArrayDump:
			obj, trace, n, class := c.id(idSize), c.u4(), c.u4(), c.id(idSize)
			payload := int64(n) * int64(idSize)
			c.skip(payload)
			if c.err == nil {
				name := addStat(class, "Object[]", payload, obj)
				recordLargest(obj, name, payload, trace, class)
			}
		case subPrimArrayDump:
			obj, trace, n := c.id(idSize), c.u4(), c.u4()
			t := c.u1()
			size := typeSize(t, idSize)
			if size == 0 || t == typeObject {
				return fmt.Errorf("invalid primitive array type %d at segment byte %d", t, start)
			}
			payload := int64(n) * int64(size)
			if (t == typeByte || t == typeChar) && payload >= 16 && payload <= 256 {
				raw := c.data(payload)
				key := string(append([]byte{t}, raw...))
				if c.err == nil {
					tracker, exists := dupStrings[key]
					if !exists && len(dupStrings) < 25000 {
						preview, _ := extractPrintableSample(raw, t)
						tracker = &stringDupTracker{preview: preview, unitBytes: payload, arrayType: primArrayTypeName(t)}
						dupStrings[key] = tracker
					}
					if tracker != nil {
						tracker.count++
						if len(tracker.objectIDs) < 3 {
							tracker.objectIDs = append(tracker.objectIDs, obj)
						}
					} else {
						summary.Assessment.Warn("Duplicate-array tracking limit reached; duplicate counts cover tracked payloads only.")
					}
				}
			} else {
				c.skip(payload)
			}
			if c.err == nil {
				name := primArrayTypeName(t)
				addStat(0, name, payload, obj)
				recordLargest(obj, name, payload, trace, 0)
			}
		default:
			return fmt.Errorf("unsupported heap sub-record 0x%02x at segment byte %d; refusing an incomplete histogram", tag, start)
		}
		if c.err != nil {
			return fmt.Errorf("heap sub-record 0x%02x at segment byte %d: %w", tag, start, c.err)
		}
	}
	return c.err
}

func computeLeakSuspects(s *Summary) []LeakSuspect {
	if s.TotalPayloadBytes <= 0 || len(s.ClassHistogram) == 0 {
		return nil
	}
	var suspects []LeakSuspect

	// 1. Check application/non-JDK classes or classes exceeding 12% of serialized payload
	for _, c := range s.ClassHistogram {
		pct := float64(c.TotalBytes) * 100.0 / float64(s.TotalPayloadBytes)
		if pct >= 12.0 && len(suspects) < 4 {
			desc := fmt.Sprintf("Class %q accounts for %.1f%% of serialized payload (%s across %d instances).",
				c.ClassName, pct, FormatBytes(c.TotalBytes), c.InstanceCount)
			if c.ClassName == "byte[]" || c.ClassName == "char[]" {
				desc += " Primitive arrays have many possible owners; no reference ownership was decoded."
			}
			suspects = append(suspects, LeakSuspect{
				Confidence: "low", Evidence: fmt.Sprintf("class ID 0x%x; sample object IDs %x", c.ClassID, c.SampleObjectIDs),
				Title:       fmt.Sprintf("High Payload Concentration in %s", c.ClassName),
				ClassName:   c.ClassName,
				Bytes:       c.TotalBytes,
				Percentage:  pct,
				Instances:   c.InstanceCount,
				Description: desc,
			})
		}
	}

	// 2. Check top non-JDK package concentration
	for _, p := range s.TopPackages {
		if isStandardJDKPackage(p.PackageName) {
			continue
		}
		pct := float64(p.TotalBytes) * 100.0 / float64(s.TotalPayloadBytes)
		if pct >= 10.0 && len(suspects) < 5 {
			suspects = append(suspects, LeakSuspect{
				Confidence: "low", Evidence: "class histogram aggregated by package " + p.PackageName,
				Title:       fmt.Sprintf("Application Package Payload Concentration: %s", p.PackageName),
				ClassName:   p.PackageName + ".*",
				Bytes:       p.TotalBytes,
				Percentage:  pct,
				Instances:   p.InstanceCount,
				Description: fmt.Sprintf("Application package %q holds %s (%.1f%% of serialized payload) across %d instances.", p.PackageName, FormatBytes(p.TotalBytes), pct, p.InstanceCount),
			})
		}
	}

	return suspects
}

// BuildStructuredReport generates an LLM-ready structured report matching the 6-section MAT format
// plus Duplicate Strings and Largest Objects.
func BuildStructuredReport(s *Summary) string {
	var sb strings.Builder

	sb.WriteString("═══════════════════════════════════════════════════════════\n")
	sb.WriteString("  NATIVE GO HPROF — STRUCTURED HEAP DUMP ANALYSIS\n")
	sb.WriteString("═══════════════════════════════════════════════════════════\n\n")

	sb.WriteString(s.Assessment.Report() + "\n")
	sb.WriteString(fmt.Sprintf("File: %s (%s)\n", s.FileName, FormatBytes(s.FileSize)))
	sb.WriteString(fmt.Sprintf("Format: %s (%d-bit identifiers)\n", s.FormatVersion, s.IdentifierSize*8))
	sb.WriteString(fmt.Sprintf("Total Serialized Payload: %s across %d instances (%d classes)\n\n",
		FormatBytes(s.TotalPayloadBytes), s.TotalInstances, s.TotalClasses))

	// Section 1: Leak Suspects
	sb.WriteString("━━━ SECTION 1: CONCENTRATION HYPOTHESES ━━━\n")
	if len(s.LeakSuspects) == 0 {
		sb.WriteString("No single class exceeded the payload concentration threshold (no leak verdict).\n\n")
	} else {
		for i, ls := range s.LeakSuspects {
			sb.WriteString(fmt.Sprintf("Suspect #%d: %s — %s (%.1f%% of serialized payload, %d objects)\n",
				i+1, ls.Title, FormatBytes(ls.Bytes), ls.Percentage, ls.Instances))
			sb.WriteString("  " + ls.Description + "\n\n")
		}
	}

	// Section 2: Largest Individual Objects & Duplicate Strings
	sb.WriteString("━━━ SECTION 2: LARGEST PAYLOADS & DUPLICATE ARRAYS ━━━\n")
	if len(s.LargestObjects) > 0 {
		sb.WriteString("Largest decoded object / array payloads:\n")
		for i, lo := range s.LargestObjects {
			if i >= 12 {
				break
			}
			sb.WriteString(fmt.Sprintf("  #%d  0x%x  %-38s  %s\n", i+1, lo.ObjectID, lo.ClassName, FormatBytes(lo.SizeBytes)))
		}
		sb.WriteString("\n")
	}
	if len(s.DuplicateArrays) > 0 {
		sb.WriteString("Identical raw primitive-array payloads:\n")
		for i, ds := range s.DuplicateArrays {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  #%d  %d copies (repeated payload %s; savings unknown): %q\n",
				i+1, ds.Count, FormatBytes(ds.DuplicatePayloadBytes), ds.Preview))
		}
		sb.WriteString("\n")
	}

	// Section 3: Class Histogram
	sb.WriteString("━━━ SECTION 3: TOP CLASSES BY SERIALIZED PAYLOAD ━━━\n")
	sb.WriteString(fmt.Sprintf("%-4s %-45s %12s %8s %12s\n", "#", "Class Name", "Payload Bytes", "Share", "Instances"))
	for i, c := range s.ClassHistogram {
		if i >= 25 {
			break
		}
		pct := 0.0
		if s.TotalPayloadBytes > 0 {
			pct = float64(c.TotalBytes) * 100.0 / float64(s.TotalPayloadBytes)
		}
		sb.WriteString(fmt.Sprintf("#%-3d %-45s %12s %7.1f%% %12d\n",
			i+1, c.ClassName, FormatBytes(c.TotalBytes), pct, c.InstanceCount))
	}
	sb.WriteString("\n")

	// Section 4: Top Packages
	sb.WriteString("━━━ SECTION 4: TOP PACKAGES BY SERIALIZED PAYLOAD ━━━\n")
	for i, p := range s.TopPackages {
		if i >= 15 {
			break
		}
		pct := 0.0
		if s.TotalPayloadBytes > 0 {
			pct = float64(p.TotalBytes) * 100.0 / float64(s.TotalPayloadBytes)
		}
		sb.WriteString(fmt.Sprintf("#%-3d %-40s %12s (%5.1f%%) — %d objects\n",
			i+1, p.PackageName, FormatBytes(p.TotalBytes), pct, p.InstanceCount))
	}
	sb.WriteString("\n")

	// Section 5: GC Roots & JVM Hints
	sb.WriteString("━━━ SECTION 5: GC ROOT RECORD COUNTS & UNVERIFIED STRING HINTS ━━━\n")
	rootNames := make([]string, 0, len(s.GCRootCounts))
	for name := range s.GCRootCounts {
		rootNames = append(rootNames, name)
	}
	sort.Strings(rootNames)
	for _, k := range rootNames {
		v := s.GCRootCounts[k]
		sb.WriteString(fmt.Sprintf("  %-24s %d\n", k+":", v))
	}
	if len(s.SystemPropHints) > 0 {
		sb.WriteString("Strings resembling JVM flags (not verified runtime properties):\n")
		for i, h := range s.SystemPropHints {
			if i >= 10 {
				break
			}
			sb.WriteString("  " + h + "\n")
		}
	}
	sb.WriteString("\n")

	// Section 6: Thread Overview
	sb.WriteString("━━━ SECTION 6: THREAD STACKS IN HEAP DUMP ━━━\n")
	sb.WriteString(fmt.Sprintf("Resolved thread root records with stack traces: %d\n", len(s.ThreadStacks)))
	for i, ts := range s.ThreadStacks {
		if i >= 10 {
			break
		}
		sb.WriteString(fmt.Sprintf("  Thread #%d (0x%x):\n", ts.ThreadSerial, ts.ThreadObject))
		for j, fr := range ts.Frames {
			if j >= 6 {
				break
			}
			sb.WriteString("    at " + fr + "\n")
		}
	}

	return sb.String()
}

// Query helpers used by MCP tools when operating in Native HPROF mode (or combined with MAT)
func (s *Summary) QueryClassHistogram(topN int, pattern string) string {
	if topN <= 0 {
		topN = 30
	}
	var re *regexp.Regexp
	if pattern != "" {
		var err error
		re, err = regexp.Compile("(?i)" + pattern)
		if err != nil {
			return "Error: invalid class histogram regex: " + err.Error()
		}
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== CLASS HISTOGRAM: SERIALIZED PAYLOAD (Top %d) ===\n", topN))
	sb.WriteString(s.Assessment.ContextReport() + "\n")
	sb.WriteString(fmt.Sprintf("%-45s %14s %8s %12s\n", "Class Name", "Payload Bytes", "Share", "Instances"))
	sb.WriteString(strings.Repeat("-", 84) + "\n")
	count := 0
	for _, c := range s.ClassHistogram {
		if re != nil && !re.MatchString(c.ClassName) {
			continue
		}
		pct := 0.0
		if s.TotalPayloadBytes > 0 {
			pct = float64(c.TotalBytes) * 100.0 / float64(s.TotalPayloadBytes)
		}
		sb.WriteString(fmt.Sprintf("%-45s %14s %7.1f%% %12d\n",
			c.ClassName, FormatBytes(c.TotalBytes), pct, c.InstanceCount))
		count++
		if count >= topN {
			break
		}
	}
	if count == 0 {
		sb.WriteString("No matching classes found.\n")
	}
	return sb.String()
}

func (s *Summary) QueryLargestObjects(topN int) string {
	if topN <= 0 {
		topN = 20
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== LARGEST SERIALIZED PAYLOADS (Top %d); RETAINED HEAP UNAVAILABLE ===\n\n", topN))
	for i, lo := range s.LargestObjects {
		if i >= topN {
			break
		}
		sb.WriteString(fmt.Sprintf("#%-2d Object 0x%x (%s) — %s\n",
			i+1, lo.ObjectID, lo.ClassName, FormatBytes(lo.SizeBytes)))
	}
	if len(s.DuplicateArrays) > 0 {
		sb.WriteString("\n--- Top Duplicated Strings/Arrays ---\n")
		for i, ds := range s.DuplicateArrays {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("#%-2d %d copies (repeated payload %s; savings unknown): %q\n",
				i+1, ds.Count, FormatBytes(ds.DuplicatePayloadBytes), ds.Preview))
		}
	}
	return sb.String()
}

// CompareFiles compares two .hprof heap dump files and highlights classes whose instance count
// and byte footprint grew the most between snapshot 1 and snapshot 2.
func CompareFiles(path1, path2 string) (string, error) {
	_, s1, err := AnalyzeFile(path1)
	if err != nil {
		return "", fmt.Errorf("failed parsing first heap dump %s: %w", filepath.Base(path1), err)
	}
	_, s2, err := AnalyzeFile(path2)
	if err != nil {
		return "", fmt.Errorf("failed parsing second heap dump %s: %w", filepath.Base(path2), err)
	}
	return CompareSummaries(s1, s2), nil
}

func CompareSummaries(s1, s2 *Summary) string {
	var sb strings.Builder
	sb.WriteString("Heap Dump Histogram Diff Report\n")
	sb.WriteString("Confidence: medium for observed payload/count deltas; low for leak hypotheses. Snapshots must represent the same JVM/workload and comparable collection conditions.\n")
	sb.WriteString("Baseline assessment:\n" + s1.Assessment.Report() + "\nTarget assessment:\n" + s2.Assessment.Report() + "\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("Baseline (#1): %s — %s (%d instances, %d classes)\n",
		s1.FileName, FormatBytes(s1.TotalPayloadBytes), s1.TotalInstances, s1.TotalClasses))
	sb.WriteString(fmt.Sprintf("Target   (#2): %s — %s (%d instances, %d classes)\n",
		s2.FileName, FormatBytes(s2.TotalPayloadBytes), s2.TotalInstances, s2.TotalClasses))
	deltaBytes := s2.TotalPayloadBytes - s1.TotalPayloadBytes
	deltaInst := s2.TotalInstances - s1.TotalInstances
	sb.WriteString(fmt.Sprintf("Net Serialized Payload Delta: %s (%+d instances)\n\n", FormatSignedBytes(deltaBytes), deltaInst))

	aggregate := func(rows []ClassStat) map[string]ClassStat {
		out := make(map[string]ClassStat)
		for _, c := range rows {
			v := out[c.ClassName]
			v.ClassName = c.ClassName
			v.TotalBytes += c.TotalBytes
			v.InstanceCount += c.InstanceCount
			out[c.ClassName] = v
		}
		return out
	}
	m1 := aggregate(s1.ClassHistogram)
	m2 := aggregate(s2.ClassHistogram)

	type classDiff struct {
		ClassName  string
		Bytes1     int64
		Bytes2     int64
		DeltaBytes int64
		Inst1      int64
		Inst2      int64
		DeltaInst  int64
	}
	var diffs []classDiff
	seen := make(map[string]bool)

	for _, c2 := range m2 {
		c1 := m1[c2.ClassName]
		seen[c2.ClassName] = true
		diffs = append(diffs, classDiff{
			ClassName:  c2.ClassName,
			Bytes1:     c1.TotalBytes,
			Bytes2:     c2.TotalBytes,
			DeltaBytes: c2.TotalBytes - c1.TotalBytes,
			Inst1:      c1.InstanceCount,
			Inst2:      c2.InstanceCount,
			DeltaInst:  c2.InstanceCount - c1.InstanceCount,
		})
	}
	for name, c1 := range m1 {
		if !seen[name] {
			diffs = append(diffs, classDiff{
				ClassName:  name,
				Bytes1:     c1.TotalBytes,
				Bytes2:     0,
				DeltaBytes: -c1.TotalBytes,
				Inst1:      c1.InstanceCount,
				Inst2:      0,
				DeltaInst:  -c1.InstanceCount,
			})
		}
	}

	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].DeltaBytes == diffs[j].DeltaBytes {
			return diffs[i].ClassName < diffs[j].ClassName
		}
		return diffs[i].DeltaBytes > diffs[j].DeltaBytes
	})

	sb.WriteString("## Classes with Growing Serialized Payload (growth is not proof of a leak)\n\n")
	sb.WriteString(fmt.Sprintf("%-42s %12s %12s %14s %12s\n", "Class Name", "Baseline", "Target", "Delta Bytes", "Delta Objs"))
	sb.WriteString(strings.Repeat("-", 96) + "\n")
	shown := 0
	for _, d := range diffs {
		if d.DeltaBytes <= 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("%-42s %12s %12s %14s %+12d\n",
			d.ClassName, FormatBytes(d.Bytes1), FormatBytes(d.Bytes2), FormatSignedBytes(d.DeltaBytes), d.DeltaInst))
		shown++
		if shown >= 25 {
			break
		}
	}
	if shown == 0 {
		sb.WriteString("No classes increased in size between baseline and target.\n")
	}
	sb.WriteString("\n")

	return sb.String()
}

// Helpers
func typeSize(t byte, idSize int) int {
	switch t {
	case typeObject:
		return idSize
	case typeBoolean, typeByte:
		return 1
	case typeChar, typeShort:
		return 2
	case typeFloat, typeInt:
		return 4
	case typeDouble, typeLong:
		return 8
	default:
		return 0
	}
}

func primArrayTypeName(t byte) string {
	switch t {
	case typeBoolean:
		return "boolean[]"
	case typeChar:
		return "char[]"
	case typeFloat:
		return "float[]"
	case typeDouble:
		return "double[]"
	case typeByte:
		return "byte[]"
	case typeShort:
		return "short[]"
	case typeInt:
		return "int[]"
	case typeLong:
		return "long[]"
	default:
		return "primitive[]"
	}
}

func formatJavaClassName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	dims := 0
	for strings.HasPrefix(raw, "[") {
		dims++
		raw = raw[1:]
	}
	if dims > 0 {
		switch raw {
		case "B":
			raw = "byte"
		case "C":
			raw = "char"
		case "Z":
			raw = "boolean"
		case "S":
			raw = "short"
		case "I":
			raw = "int"
		case "J":
			raw = "long"
		case "F":
			raw = "float"
		case "D":
			raw = "double"
		default:
			if strings.HasPrefix(raw, "L") && strings.HasSuffix(raw, ";") {
				raw = raw[1 : len(raw)-1]
			}
		}
	}
	raw = strings.ReplaceAll(raw, "/", ".")
	for i := 0; i < dims; i++ {
		raw += "[]"
	}
	return raw
}

func extractPackage(className string) string {
	base := strings.TrimSuffix(className, "[]")
	idx := strings.LastIndex(base, ".")
	if idx <= 0 {
		return "(default / primitive)"
	}
	return base[:idx]
}

func isStandardJDKPackage(pkg string) bool {
	return pkg == "(default / primitive)" ||
		strings.HasPrefix(pkg, "java.") ||
		strings.HasPrefix(pkg, "javax.") ||
		strings.HasPrefix(pkg, "jdk.") ||
		strings.HasPrefix(pkg, "sun.") ||
		strings.HasPrefix(pkg, "com.sun.")
}

func isInterestingJVMString(s string) bool {
	return strings.HasPrefix(s, "-Xmx") ||
		strings.HasPrefix(s, "-Xms") ||
		strings.HasPrefix(s, "-XX:+Use") ||
		strings.HasPrefix(s, "-XX:Max")
}

func extractPrintableSample(buf []byte, elemType byte) (string, bool) {
	value := string(buf)
	if elemType == typeChar {
		units := make([]uint16, len(buf)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(buf[i*2:])
		}
		value = string(utf16.Decode(units))
	}
	if len(value) > 80 {
		value = value[:80] + "..."
	}
	return value, true
}

func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func FormatSignedBytes(b int64) string {
	if b >= 0 {
		return "+" + FormatBytes(b)
	}
	return "-" + FormatBytes(-b)
}

// QueryDominators never substitutes shallow/payload ranking for a dominator tree.
func (s *Summary) QueryDominators(topN int) string {
	return "Error: unsupported capability: native HPROF does not compute a reference graph, dominators or retained heap. Use get_largest_objects for serialized payload ranking, or a validated MAT dominator report."
}
