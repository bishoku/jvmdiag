# go-jvmdiag

Single-binary **CLI + Web UI + Multi-User Server + MCP Server** for JVM diagnostics with optional AI interpretation. Static analysis works without an AI credential. Binary JFR and live JVM capture require compatible JDK tools.

[![CI](https://github.com/bishoku/jvmdiag/actions/workflows/ci.yml/badge.svg)](https://github.com/bishoku/jvmdiag/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

[Install](docs/INSTALL.md) · [Kubernetes](deploy/kubernetes/README.md) · [Contribute](CONTRIBUTING.md) · [Release process](docs/RELEASING.md) · [Security](SECURITY.md)


## Features

1. **Single Binary with Optional JDK/MAT Tools:**
   - HTML templates and CSS are embedded directly into the Go binary via `//go:embed`.
   - No JVM or Maven required for native HPROF, text/JSON analysis or the UI. Binary JFR event decoding and live capture require JDK tools; MAT requires its own runtime.
2. **2-Tier Hybrid Heap Dump Engine (`.hprof`):**
   - **Tier 1 — Native Go Streaming `.hprof` Parser:** Validates supported HPROF 1.0.1/1.0.2 records with 4/8-byte identifiers. Extracts serialized payload histograms, package totals, largest payloads, exact duplicate primitive-array payloads, GC root record counts and available thread stacks. Native payload bytes are not runtime shallow/retained/live heap.
   - **Tier 2 — Optional Eclipse MAT Integration:** When installed (or downloaded from Settings), adds readable MAT report excerpts with their original metric labels. The OQL tool is unsupported until a validated query-result adapter is implemented.
3. **Dual-Mode Architecture (Personal PC + Shared Multi-User Server):**
   - **Workspace Isolation:** Shared mode requires workspace-scoped Bearer tokens. The Workspace Switcher, query parameter and header select a workspace; they do not grant access. Jobs, history, MCP sessions, chat and logs are checked against the authenticated workspace.
   - **Central AI Key + User Override:** Configure a default server-wide OpenRouter/OpenAI key, while allowing any workspace to override with its own API key or model.
   - **Worker Pool Semaphore:** Limits simultaneous heavy jobs; it does not provide a memory budget or guarantee against OOM.
4. **New Diagnostic Capabilities:**
   - **Multi-Snapshot Diff (`jvmdiag diff` & `/diff`):** Compare 2+ Thread Dumps to catch **stuck `RUNNABLE` threads** (threads whose top stack frame never moves across snapshots) or 2 `.hprof` Heap Dumps to identify **growing payload/count candidates**; growth alone does not prove a leak.
   - **Incident Correlation (`jvmdiag incident` & `/incident`):** Combine a GC Log + Thread Dump(s) + Heap Dump from the same incident for automated cross-artifact correlation.
   - **MCP Server (Streamable HTTP + Local Stdio):** Connect clients to `/mcp` using Streamable HTTP (JSON responses; no SSE), or locally via stdio (`jvmdiag mcp --file dump.hprof`). Shared HTTP clients must send a Bearer token.

---

## 🚀 Quick Start

### 1. Install or build

Download a verified binary from [GitHub Releases](https://github.com/bishoku/jvmdiag/releases), or build with the Go version in `.go-version`:

```bash
git clone https://github.com/bishoku/jvmdiag.git
cd jvmdiag
go build -trimpath -o jvmdiag ./cmd/jvmdiag
```

See [installation and upgrades](docs/INSTALL.md) for Linux/macOS/Windows packages, checksums, provenance verification and containers. A direct source build reports `dev`; tagged releases inject the exact version and revision.

### 2. Start Web UI & Multi-User Server

```bash
# Personal / Local mode
./jvmdiag serve --port 8080

# Shared mode: generate separate secrets for administrator and workspace access.
export JVMDIAG_ADMIN_TOKEN="$(openssl rand -hex 32)"
export JVMDIAG_WORKSPACE_TOKENS="{\"payments-team\":\"$(openssl rand -hex 32)\"}"
./jvmdiag serve --port 8080 --multi-user --max-workers 4
```

Open **http://localhost:8080**.

### 3. CLI Usage (Local & Remote Server Execution)

```bash
# Analyze a thread dump, GC log, or .hprof file locally
./jvmdiag analyze ../thread-dump.tdump --no-ai

# Analyze with AI root-cause diagnosis
./jvmdiag analyze app.hprof --ai

# Send a local file to a shared server (set JVMDIAG_ACCESS_TOKEN to your workspace token first)
./jvmdiag analyze app.hprof --server http://diag.internal:8080 --workspace payments-team

# Compare multiple thread dumps (catches stuck RUNNABLE threads) or 2 heap dumps
./jvmdiag diff dump1.tdump dump2.tdump dump3.tdump --ai
./jvmdiag diff baseline.hprof after-load.hprof --ai

# Correlate GC Log + Thread Dump + Heap Dump for a single production incident
./jvmdiag incident --gc gc.log --thread dump1.tdump,dump2.tdump --heap app.hprof --ai

# Run as a local Stdio MCP Server for Claude Desktop / Cursor / Windsurf / Antigravity
./jvmdiag mcp --file app.hprof
```


## Access and settings security

Local mode binds to `127.0.0.1` and requires no access token. Use it only for a trusted local user. To listen on an external interface, explicitly pass `--host 0.0.0.0`; use `--multi-user` for a shared deployment. The container image explicitly binds to all interfaces and runs in shared mode.

Shared mode reads these settings at server startup:

- `JVMDIAG_WORKSPACE_TOKENS`: a JSON object mapping workspace names to unique random tokens, each at least 32 bytes. Workspace names must already be canonical (letters, digits, `_`, `-`, up to 64 characters). `default` is reserved for administrators.
- `JVMDIAG_ADMIN_TOKEN`: a separate random token of at least 32 bytes. Administrators can select workspaces and manage global settings, MAT installation and host JVM access.
- `JVMDIAG_PUBLIC_ORIGIN`: optional exact public origin, such as `https://diag.example.com`, when a reverse proxy terminates TLS. Do not include a trailing slash. Proxy headers alone are not trusted for origin validation.

Without valid credentials configured, shared API/MCP requests fail closed. Keep tokens in a secret manager and distribute each workspace's token only to its members; restart the server after rotating them. This is workspace-level access control, not per-person identity or an SSO implementation. Use HTTPS at the reverse proxy for remote access.

In the Web UI, enter your workspace name, then use **Server access token → Connect**. The token stays in page memory and is cleared by a reload. API and MCP HTTP clients must send `Authorization: Bearer <token>`. Remote CLI analysis reads that token from `JVMDIAG_ACCESS_TOKEN`. MCP configuration shown in the UI contains a placeholder; replace it with the appropriate access token in your client.

Workspace tokens cannot select another workspace, change global settings or the AI endpoint/TLS policy, install MAT, or access arbitrary host files and JVMs through MCP. Inline diagnostic content and uploaded artifacts remain available. Administrator access is required for host operations. Global setting updates require `applyGlobal: "true"`; the local default workspace retains its local settings workflow.

Changing an AI endpoint requires an explicitly supplied API key when retaining a saved workspace/global key would otherwise send it to a different provider. Workspace overrides never inherit the global key for a different endpoint or a less secure TLS policy. AI HTTP redirects are rejected. Browser requests from other origins are rejected.

The Markdown renderer is bundled locally (Marked 17.0.5, MIT; license in `internal/server/assets/js/LICENSE.marked.txt`). Rendered content is copied into an allowlist of HTML elements and HTTP(S) links; scripts, event handlers, images, embedded documents and arbitrary attributes are discarded. Other dynamic UI fields are encoded or inserted as text.

## Verification

```bash
go test -race -shuffle=on -count=5 -cpu=1,4 -timeout=120s ./...
go vet ./...
go build -o jvmdiag ./cmd/jvmdiag
```

The Go tests cover cross-workspace reads, writes and deletions, authentication and selector spoofing, global settings protection, key preservation across restarts, provider redirect rejection, concurrent snapshots, and worker limits. Server tests use an isolated home directory and do not depend on an installed MAT or live AI provider.

For the browser XSS regression, use Node 24 with the locked test dependencies: `npm ci --prefix tests --ignore-scripts`, `npx --prefix tests playwright install chromium`, then `node tests/ui-security.cjs`. Alternatively set `CHROME_PATH` to a compatible Chrome executable. The test uses an isolated browser profile and mocked HTTP. Node/Playwright are test-only dependencies, not runtime requirements.


## Diagnostic evidence and limitations

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

Additional verification:

```bash
# Parser robustness (bounded randomized runs)
go test -run '^$' -fuzz FuzzParseStream -fuzztime=10s -parallel=2 ./internal/analyzer/hprof
go test -run '^$' -fuzz FuzzJSONEvents -fuzztime=10s -parallel=2 ./internal/analyzer/jfr

# Optional real JDK reference: generates a fresh synthetic JVM's HPROF/JFR in a temp directory
JVMDIAG_TEST_JDK=/path/to/jdk go test -v -run TestRealJDKArtifacts -timeout=60s ./internal/analyzer
```

The real-JDK tests start their own synthetic JVMs and compare parsed results with independent references. They never attach to an application JVM.

## JVM regression dataset

`tests/corpus/jvm-v1/manifest.json` pins 84 compressed artifacts from 12 actual JVM/collector combinations:

| JVM | Version | Collectors captured |
| --- | --- | --- |
| Eclipse Temurin | 17.0.20+8 | G1, Parallel, Serial, ZGC |
| Oracle JDK | 25.0.3+9-LTS-195 | G1, Parallel, Serial, ZGC |
| Oracle GraalVM | 25.0.3+9-LTS-jvmci-b01 | G1, Parallel, Serial, ZGC |

Each combination contains HPROF, binary JFR, selected JFR JSON events, JFR summary, GC log, thread dump and NMT summary. The manifest records the runtime, actual collector names, capture flags, original/redacted/compressed SHA-256 digests and independent expected values. The approximately 21 MiB dataset comes from a synthetic allocation and lock-contention workload. Operator home/identity bytes are replaced without changing binary field widths; this is a normalized capture rather than the original byte stream. The exact generating Python and Java sources are archived beside the manifest and their digests are tested.

The Python reference reader computes HPROF record/root counts and array payloads directly from the binary format, and derives event counts, allocation categories, GC pauses and thread states from the JDK exports. It does not call the Go analyzers. Regression tests compare those references, verify artifact hashes and repeat report generation to detect unstable ordering. The ordinary Go suite reads these fixed captures offline and needs no JVM, Python, MAT or AI service. Configuration tests explicitly isolate environment variables, dotenv files and legacy installations; asynchronous tests wait for completion signals rather than fixed sleeps.

```bash
# Offline captured-data regression
go test -v -run 'TestCapturedJVMRegressionCorpus|TestCorpus' ./internal/analyzer

# Decode the captured binary recordings with their corresponding JDKs
export JVMDIAG_TEST_JDKS='{"temurin17":"/path/to/temurin17","oracle25":"/path/to/oracle25","graal25":"/path/to/graal25"}'
go test -v -run TestCapturedBinaryJFRWithMatchingJDKs -timeout=120s ./internal/analyzer

# Generate all four collectors for each supplied JDK in a fresh temporary directory,
# then compare every fresh capture with its independently calculated reference.
JVMDIAG_GENERATE_MATRIX=1 go test -v -run TestLiveJDKGCMatrix -timeout=300s ./internal/analyzer

# Create a candidate dataset for manual review; refuses to overwrite existing entries.
python3 tests/fixtures/capture.py --jdk temurin17=/path/to/temurin17 --out /tmp/jvm-corpus-candidate
```

Live generation requires Python 3, full JDK tools (`javac`, `java`, `jcmd`, `jfr`) and permission to attach to the test's own JVM. Unsupported collector combinations fail instead of silently disappearing. `JVMDIAG_TEST_PYTHON` can select a Python executable. Fresh recordings naturally differ in timestamps, addresses, scheduling and counts; determinism means fixed-input regression results and explicit synchronization, not identical future JVM captures. Dataset updates require reviewing provenance, independent expected values and binary changes before replacing the pinned corpus. These tests cover the versions above; the archived corpus does not include JDK 8/21 or Shenandoah. The CI workflow additionally generates fresh Temurin 21 captures; it does not add an archived JDK 21 reference. Production workloads remain outside this synthetic matrix.


Metric semantics were checked against the [OpenJDK JFR event metadata](https://github.com/openjdk/jdk/blob/jdk-21-ga/src/hotspot/share/jfr/metadata/metadata.xml) and the [OpenJDK HPROF binary-format description](https://cr.openjdk.org/~rpatil/webrev.01/raw_files/new/src/share/demo/jvmti/hprof/manual.html). Native parsing validates supported record boundaries and selected field types; it does not validate the entire object graph or authenticate an artifact.

## Kubernetes live diagnostics

Use the dedicated full-JDK diagnostic image as an ephemeral container to inspect a running Linux HotSpot JVM. See [the Kubernetes guide](deploy/kubernetes/README.md) for image builds, matching UID/GID profiles, operator RBAC, thread/NMT/heap/JFR examples, artifact extraction and real kind integration tests. The target Java image does not need a shell or JDK tools. AI is opt-in for live capture.

## License and community

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE) and [third-party notices](THIRD_PARTY_NOTICES.md). Contributions follow [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Follow [SECURITY.md](SECURITY.md) for private vulnerability reporting. Repository governance, tested release gates and maintainer setup are described in [the release guide](docs/RELEASING.md).
