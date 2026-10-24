package hprof

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

type fixtureBuilder struct {
	bytes.Buffer
	idSize int
}

func fixture(size int) *fixtureBuilder {
	b := &fixtureBuilder{idSize: size}
	b.WriteString("JAVA PROFILE 1.0.2\x00")
	b.u4(uint32(size))
	b.u8(1700000000000)
	return b
}
func (b *fixtureBuilder) u4(n uint32) { _ = binary.Write(&b.Buffer, binary.BigEndian, n) }
func (b *fixtureBuilder) u8(n uint64) { _ = binary.Write(&b.Buffer, binary.BigEndian, n) }
func (b *fixtureBuilder) id(n uint64) {
	if b.idSize == 4 {
		b.u4(uint32(n))
	} else {
		b.u8(n)
	}
}
func (b *fixtureBuilder) record(tag byte, p []byte) {
	b.WriteByte(tag)
	b.u4(0)
	b.u4(uint32(len(p)))
	b.Write(p)
}
func (b *fixtureBuilder) primitive(id uint64, kind byte, raw []byte) {
	b.WriteByte(subPrimArrayDump)
	b.id(id)
	b.u4(0)
	b.u4(uint32(len(raw) / typeSize(kind, b.idSize)))
	b.WriteByte(kind)
	b.Write(raw)
}
func (b *fixtureBuilder) instance(id, class uint64, raw []byte) {
	b.WriteByte(subInstanceDump)
	b.id(id)
	b.u4(0)
	b.id(class)
	b.u4(uint32(len(raw)))
	b.Write(raw)
}
func validPrimitiveFixture(size int) []byte {
	b := fixture(size)
	seg := &fixtureBuilder{idSize: size}
	seg.primitive(0x10, typeByte, bytes.Repeat([]byte("a"), 32))
	b.record(tagHeapDumpSegment, seg.Bytes())
	b.record(tagHeapDumpEnd, nil)
	return b.Bytes()
}
func parse(raw []byte) (*Summary, error) {
	return ParseStream(bufio.NewReader(bytes.NewReader(raw)), "fixture.hprof", int64(len(raw)))
}

func TestEveryTruncationFailsWithoutPartialSummary(t *testing.T) {
	for _, size := range []int{4, 8} {
		raw := validPrimitiveFixture(size)
		for n := 0; n < len(raw); n++ {
			sum, err := parse(raw[:n])
			if err == nil || sum != nil {
				t.Fatalf("identifier=%d truncation at %d accepted", size, n)
			}
		}
	}
}

func TestPayloadIsNotRuntimeHeapSize(t *testing.T) {
	for _, size := range []int{4, 8} {
		sum, err := parse(validPrimitiveFixture(size))
		if err != nil {
			t.Fatal(err)
		}
		if sum.TotalPayloadBytes != 32 || sum.TotalInstances != 1 || sum.LargestObjects[0].SizeBytes != 32 {
			t.Fatalf("identifier width inflated payload: %+v", sum)
		}
		report := BuildStructuredReport(sum)
		if !strings.Contains(report, "not runtime shallow heap") || strings.Contains(report, "Total Live Heap") {
			t.Fatal("runtime heap precision was implied")
		}
		if len(sum.Assessment.Findings) == 0 || sum.Assessment.Findings[0].Kind != "observation" || len(sum.Assessment.Findings[0].Evidence) == 0 {
			t.Fatal("missing measurement evidence")
		}
		if !strings.HasPrefix(sum.QueryDominators(10), "Error: unsupported capability") {
			t.Fatal("largest payload masqueraded as dominator")
		}
	}
}

func TestRejectMalformedAndUnsupportedRecords(t *testing.T) {
	tests := map[string]func(*fixtureBuilder){
		"unknown subtag": func(b *fixtureBuilder) { b.record(tagHeapDumpSegment, []byte{0x99}); b.record(tagHeapDumpEnd, nil) },
		"invalid array type": func(b *fixtureBuilder) {
			seg := &fixtureBuilder{idSize: b.idSize}
			seg.WriteByte(subPrimArrayDump)
			seg.id(1)
			seg.u4(0)
			seg.u4(0)
			seg.WriteByte(3)
			b.record(tagHeapDumpSegment, seg.Bytes())
			b.record(tagHeapDumpEnd, nil)
		},
		"invalid instance field type": func(b *fixtureBuilder) {
			seg := &fixtureBuilder{idSize: b.idSize}
			seg.WriteByte(subClassDump)
			seg.Write(make([]byte, b.idSize+4+6*b.idSize+4))
			seg.Write([]byte{0, 0, 0, 0, 0, 1})
			seg.id(0)
			seg.WriteByte(3)
			b.record(tagHeapDumpSegment, seg.Bytes())
			b.record(tagHeapDumpEnd, nil)
		},
		"huge trace count": func(b *fixtureBuilder) {
			p := &fixtureBuilder{idSize: b.idSize}
			p.u4(1)
			p.u4(1)
			p.u4(^uint32(0))
			b.record(tagTrace, p.Bytes())
		},
		"short load class":       func(b *fixtureBuilder) { b.record(tagLoadClass, []byte{1}) },
		"extra load class bytes": func(b *fixtureBuilder) { b.record(tagLoadClass, make([]byte, 8+2*b.idSize+1)) },
		"missing heap":           func(b *fixtureBuilder) { b.record(tagUTF8, make([]byte, b.idSize)) },
		"missing end":            func(b *fixtureBuilder) { b.record(tagHeapDumpSegment, nil) },
		"extra end": func(b *fixtureBuilder) {
			b.record(tagHeapDumpSegment, nil)
			b.record(tagHeapDumpEnd, nil)
			b.record(tagHeapDumpEnd, nil)
		},
		"multiple snapshots": func(b *fixtureBuilder) {
			b.record(tagHeapDumpSegment, nil)
			b.record(tagHeapDumpEnd, nil)
			b.record(tagHeapDumpSegment, nil)
		},
		"truncated unknown top record": func(b *fixtureBuilder) { b.WriteByte(0x88); b.u4(0); b.u4(100); b.WriteByte(0) },
		"record boundary crossing": func(b *fixtureBuilder) {
			seg := &fixtureBuilder{idSize: b.idSize}
			seg.instance(1, 2, make([]byte, 32))
			payload := seg.Bytes()
			b.record(tagHeapDumpSegment, payload[:len(payload)-1])
			b.record(tagHeapDumpEnd, nil)
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			b := fixture(8)
			build(b)
			sum, err := parse(b.Bytes())
			if err == nil || sum != nil {
				t.Fatalf("malformed input accepted: %+v", sum)
			}
		})
	}
}

func TestDuplicateArraysUseFullRawIdentityAndType(t *testing.T) {
	b := fixture(8)
	seg := &fixtureBuilder{idSize: 8}
	prefix := strings.Repeat("a", 100)
	for i := 0; i < 5; i++ {
		seg.primitive(uint64(i+1), typeByte, []byte(prefix+"x"))
		seg.primitive(uint64(i+11), typeByte, []byte(prefix+"y"))
	}
	// Identical bytes under char[] and byte[] must remain separate; leading/trailing spaces must not be trimmed for equality.
	chars := bytes.Repeat([]byte{0, 'A'}, 16)
	for i := 0; i < 2; i++ {
		seg.primitive(uint64(30+i), typeChar, chars)
		seg.primitive(uint64(40+i), typeByte, chars)
	}
	seg.primitive(50, typeByte, []byte("  aaaaaaaaaaaaaaaa"))
	seg.primitive(51, typeByte, []byte("aaaaaaaaaaaaaaaa  "))
	b.record(tagHeapDumpSegment, seg.Bytes())
	b.record(tagHeapDumpEnd, nil)
	sum, err := parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.DuplicateArrays) != 4 {
		t.Fatalf("preview truncation or array type conflated duplicates: %+v", sum.DuplicateArrays)
	}
	for _, d := range sum.DuplicateArrays {
		if d.Count != 5 && d.Count != 2 {
			t.Fatalf("wrong duplicate count: %+v", d)
		}
		if d.DuplicatePayloadBytes != (d.Count-1)*d.UnitPayloadBytes || len(d.SampleObjectIDs) == 0 || d.ArrayType == "" {
			t.Fatal("invalid duplicate evidence")
		}
	}
	if strings.Contains(BuildStructuredReport(sum), "wasted ") {
		t.Fatal("duplicates claimed reclaimable memory")
	}
}

func TestMetadataLimitsProduceLimitedAssessment(t *testing.T) {
	b := fixture(8)
	str := &fixtureBuilder{idSize: 8}
	str.id(1)
	str.WriteString(strings.Repeat("x", 513))
	b.record(tagUTF8, str.Bytes())
	b.record(tagHeapDumpSegment, nil)
	b.record(tagHeapDumpEnd, nil)
	sum, err := parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Assessment.Status != "limited" || len(sum.Assessment.Warnings) == 0 {
		t.Fatal("metadata truncation was hidden")
	}
}

func TestTraceCapsAndPrimitiveIDsCannotCollide(t *testing.T) {
	b := fixture(8)
	trace := &fixtureBuilder{idSize: 8}
	trace.u4(1)
	trace.u4(1)
	trace.u4(26)
	for i := 0; i < 26; i++ {
		trace.id(uint64(i + 1))
	}
	b.record(tagTrace, trace.Bytes())
	seg := &fixtureBuilder{idSize: 8}
	seg.instance(1, 0xFFFFFF08, make([]byte, 5))
	seg.primitive(2, typeByte, make([]byte, 32))
	b.record(tagHeapDumpSegment, seg.Bytes())
	b.record(tagHeapDumpEnd, nil)
	sum, err := parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.ClassHistogram) != 2 || sum.TotalPayloadBytes != 37 || sum.Assessment.Status != "limited" {
		t.Fatalf("class collision or lost limit: %+v", sum)
	}
}

func TestDiffAggregatesSameNameAcrossClassLoaders(t *testing.T) {
	a := &Summary{ClassHistogram: []ClassStat{{ClassName: "A", InstanceCount: 2, TotalBytes: 10}, {ClassName: "A", InstanceCount: 3, TotalBytes: 20}}}
	b := &Summary{ClassHistogram: []ClassStat{{ClassName: "A", InstanceCount: 10, TotalBytes: 100}}}
	report := CompareSummaries(a, b)
	if !strings.Contains(report, "+70 B") || !strings.Contains(report, "+5") {
		t.Fatalf("class loader rows overwritten: %s", report)
	}
}

func FuzzParseStream(f *testing.F) {
	f.Add(validPrimitiveFixture(4))
	f.Add(validPrimitiveFixture(8))
	f.Add([]byte("JAVA PROFILE"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		sum, err := parse(raw)
		if err != nil {
			if sum != nil {
				t.Fatal("partial summary returned on error")
			}
			return
		}
		if sum == nil || sum.Assessment.Status == "" || sum.TotalPayloadBytes < 0 {
			t.Fatal(fmt.Sprintf("invalid accepted summary: %+v", sum))
		}
	})
}

func TestClassNamesResolveWithoutRecordOrderingAssumptions(t *testing.T) {
	b := fixture(8)
	load := &fixtureBuilder{idSize: 8}
	load.u4(1)
	load.id(0x100)
	load.u4(0)
	load.id(0x200)
	b.record(tagLoadClass, load.Bytes())
	seg := &fixtureBuilder{idSize: 8}
	seg.instance(1, 0x100, make([]byte, 5))
	b.record(tagHeapDumpSegment, seg.Bytes())
	b.record(tagHeapDumpEnd, nil)
	name := &fixtureBuilder{idSize: 8}
	name.id(0x200)
	name.WriteString("com/example/LateName")
	b.record(tagUTF8, name.Bytes())
	sum, err := parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if sum.ClassHistogram[0].ClassName != "com.example.LateName" || sum.LargestObjects[0].ClassName != "com.example.LateName" || sum.Assessment.Status != "complete" {
		t.Fatalf("late class metadata lost: %+v", sum)
	}
}
