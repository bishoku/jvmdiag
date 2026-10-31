# Diagnostic evidence and limitations

JFR and HPROF summaries expose an `assessment` with `status`, `scope`, `source`, `warnings`, `limitations` and structured `findings`. Findings distinguish `observation` from `hypothesis`; each carries `confidence`, evidence references and a next verification step. Confidence describes the stated observation or hypothesis, not a probability that a root cause is correct or that an input is authentic.

- `complete` means parsing completed **within the stated scope**. It does not mean every JVM feature was analyzed or that the JVM is healthy.
- `limited` means usable scoped data exists but metadata, timings, event coverage or a requested engine is unavailable. Reports, API responses, saved history, MCP session status and the UI retain this distinction. A job can finish processing (`COMPLETED`) while its assessment remains `limited`.
- `metadata-only` means binary JFR headers were readable but events were not decoded. This is returned with an analysis error; it is not a successful runtime diagnosis.
- Malformed/truncated supported records, unsupported heap sub-records, missing segmented-heap termination, invalid event fields and failed binary JFR decoding produce errors. Upload jobs become `FAILED` and no AI diagnosis is generated from a failed parser. Empty JSON event exports remain explicitly limited; the server skips AI interpretation when no supported runtime findings exist.

**HPROF:** `totalPayloadBytes`, class/package `payloadBytes` and largest-object `payloadBytes` count serialized fields/elements. They exclude runtime headers, alignment and compressed-reference layout effects, as well as class-object storage. Dumped objects are not assumed live. Native mode does not build an object reference graph, compute retained heap/dominators or find paths to roots. `get_largest_objects` ranks payloads; `get_dominator_tree` fails explicitly without a MAT dominator report. `run_oql_query` returns an unsupported-capability error instead of emulating queries with histogram filters. Native class filtering uses `get_class_histogram`; invalid regular expressions are errors.

Duplicate detection compares full raw `byte[]`/`char[]` payloads and primitive type, independently of preview truncation. It covers arrays of 16–256 payload bytes and at most 25,000 distinct payloads; only the top 20 duplicate groups are reported. Repeated payload bytes are not guaranteed memory savings, duplicate Strings or safe deduplication opportunities. Tracking limits are visible as warnings. Heap histogram diffs aggregate same-name classes across class loaders; equivalence of snapshots and leak causality remain unverified.

**JFR:** Binary analysis requires the JDK `jfr` tool. Metadata text inside a binary is never counted as events, pinning or CPU samples. `jfr print --json` exports and recognized `jfr summary` event-count tables can be analyzed without Java; summary tables provide counts only. Filtered JDK export counts are not mixed with recording-wide summary counts. Export filters, thresholds and recording settings remain limitations even when the supplied export parses completely.

Execution sample percentages describe resolved observed samples, not CPU utilization. `ObjectAllocationInNewTLAB.allocationSize`, `ObjectAllocationOutsideTLAB.allocationSize`, `ObjectAllocationSample.weight` and TLAB reservation are kept distinct. Allocation observations do not establish total allocation rate. GC cycle `duration` is kept separate from `longestPause`/`GCPhasePause.duration`; their overlapping observations are not added together. Numeric duration exports are interpreted as nanoseconds; ISO-8601 strings are decoded explicitly. Missing timing is unavailable, not a measured zero. Pinning events are observations; severity and synchronization changes require stacks, timing and JDK-version context.

These semantics change the earlier experimental summary schema: `totalLiveBytes` is replaced by `totalPayloadBytes`, `duplicateStrings` by `duplicateArrays`, and duplicate byte fields describe repeated serialized payload rather than wasted heap. Historical reports written by older builds retain their original wording and are not revalidated by loading them.

Metric references: [OpenJDK JFR event metadata](https://github.com/openjdk/jdk/blob/jdk-21-ga/src/hotspot/share/jfr/metadata/metadata.xml) and [HPROF binary format](https://cr.openjdk.org/~rpatil/webrev.01/raw_files/new/src/share/demo/jvmti/hprof/manual.html). Native parsing validates supported record boundaries and selected field types; it does not validate the entire object graph or authenticate an artifact.

## Thread, NMT and incident input validation

Thread analysis requires recognizable thread records. Empty/unrecognized text, malformed thread JSON and JSON exports without recognizable threads are rejected with an error. File analysis, snapshot diffs and inline MCP analysis use the same validation. This validates supported structure, not artifact authenticity or completeness; a parsed dump does not prove JVM health.

Native diagnostics require recognizable JVM crash records or NMT metrics. Unrecognized content is rejected instead of returning an unknown-type successful report. Upload failures produce no static report or AI diagnosis.

Incident analysis fails if any requested thread snapshot is unreadable or invalid; the error identifies the failing file. A missing later snapshot is not silently excluded from the comparison. MCP live capture also propagates artifact-analysis errors.

`NMT Total Committed` is the NMT committed value, not process RSS or cgroup usage. `Off-Heap Committed` is NMT total committed minus Java heap committed. NMT does not cover every native allocation. No RSS or cgroup measurement is inferred from these numbers.
