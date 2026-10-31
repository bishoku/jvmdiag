# Testing and regression data

```bash
go test -race -shuffle=on -count=5 -cpu=1,4 -timeout=120s ./...
go vet ./...
go build -o jvmdiag ./cmd/jvmdiag
```

The Go tests cover cross-workspace reads, writes and deletions, authentication and selector spoofing, global settings protection, key preservation across restarts, provider redirect rejection, concurrent snapshots, and worker limits. Server tests use an isolated home directory and do not depend on an installed MAT or live AI provider.

For the browser XSS regression, use Node 24 with the locked test dependencies: `npm ci --prefix tests --ignore-scripts`, `npx --prefix tests playwright install chromium`, then `node tests/ui-security.cjs`. Alternatively set `CHROME_PATH` to a compatible Chrome executable. The test uses an isolated browser profile and mocked HTTP. Node/Playwright are test-only dependencies, not runtime requirements.

## Parser and live-JDK checks

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

For local kind and MicroK8s integration tests, see the [Kubernetes guide](../deploy/kubernetes/README.md#repeatable-integration-test).
