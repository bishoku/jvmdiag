# jvmdiag

A single-binary tool for investigating JVM performance and memory problems. Analyze existing diagnostic files or collect evidence from a running JVM, then inspect the results through the CLI, Web UI or MCP. AI interpretation is optional; local static analysis works without an API key.

[![CI](https://github.com/bishoku/jvmdiag/actions/workflows/ci.yml/badge.svg)](https://github.com/bishoku/jvmdiag/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## What can I investigate?

| Situation | Workflow |
| --- | --- |
| Slow responses, lock contention or suspected stuck threads | Analyze thread dumps and compare successive snapshots. |
| Growing heap or suspected memory leaks | Inspect HPROF payload histograms and compare dumps; use optional Eclipse MAT for retained-heap analysis. |
| GC pressure, allocation hotspots or JVM pauses | Analyze GC logs and JFR recordings. |
| Native memory growth or JVM crashes | Analyze NMT summaries and crash logs. |
| Several artifacts from the same incident | Combine thread, heap, GC, NMT and JFR evidence in an incident report. |
| A Java application running in Kubernetes | Add a temporary diagnostic container, discover the JVM and capture evidence without rebuilding the application image. |
| Team or assistant access | Run the shared Web/API server or connect an MCP client. |

Native HPROF analysis does not compute retained heap or prove a memory leak. Live capture and binary JFR decoding need compatible JDK tools. See [diagnostic scope and limitations](docs/DIAGNOSTIC-SEMANTICS.md).

## Get started

Download a verified binary using the [installation guide](docs/INSTALL.md), or build from source using the Go version in `.go-version`:

```sh
git clone https://github.com/bishoku/jvmdiag.git
cd jvmdiag
go build -trimpath -o jvmdiag ./cmd/jvmdiag
./jvmdiag serve --port 8080
```

Open `http://localhost:8080` to upload diagnostic files and view reports. The local server binds to loopback by default. For team access, follow [shared-server configuration](docs/SECURITY-AND-CONFIGURATION.md).

## Usage examples

### Analyze existing files

```sh
./jvmdiag analyze thread-dump.tdump --no-ai
./jvmdiag analyze gc.log --type gc --no-ai
./jvmdiag analyze app.hprof --no-ai
./jvmdiag analyze recording.jfr --no-ai
```

### Compare snapshots and correlate an incident

```sh
./jvmdiag diff before.tdump during.tdump after.tdump --no-ai
./jvmdiag diff baseline.hprof after-load.hprof --no-ai
./jvmdiag incident --gc gc.log --thread before.tdump,during.tdump --heap app.hprof --no-ai
```

### Capture a local JVM

```sh
./jvmdiag ps
# Replace 12345 with the discovered JVM PID.
./jvmdiag capture --pid 12345 --count 3 --interval 2s \
  --out-dir /tmp/jvm-case-001 --out /tmp/jvm-case-001/report.md --no-ai
```

Thread dumps and available NMT data are collected by default. Heap dumps and JFR are opt-in. Use a new output directory for each capture.

### Investigate a Kubernetes Pod

Build the [diagnostic image](deploy/kubernetes/README.md#build-an-image-matching-the-jvm), make it available to the cluster, and set the custom profile's UID/GID to match the target JVM. Replace the namespace, Pod, target container and image below:

```sh
kubectl debug -n YOUR_NAMESPACE YOUR_POD -it \
  --container=jvmdiag-001 --target=java \
  --image=YOUR_REGISTRY/jvmdiag:diagnostic-jdk17 \
  --profile=restricted --custom=deploy/kubernetes/profile-restricted.json \
  -- /bin/sh
```

Inside the temporary container:

```sh
jvmdiag ps
# Use the discovered PID; this example assumes PID 1.
jvmdiag capture --pid 1 --container --count 3 --interval 2s \
  --out-dir /tmp/case-001 --out /tmp/case-001/report.md --no-ai
cat /tmp/case-001/report.md
```

Keep the debug shell open while copying results from another terminal:

```sh
kubectl cp -n YOUR_NAMESPACE -c jvmdiag-001 YOUR_POD:/tmp/case-001 ./case-001
```

The target image needs no shell or JDK tools. The [Kubernetes guide](deploy/kubernetes/README.md) covers permissions, compatible JVMs, heap/JFR capture, cleanup, troubleshooting and repeatable kind/MicroK8s tests. Heap capture may pause the application; diagnostics share Pod/node resources.

### Use AI, a shared server or MCP

```sh
# Configure your AI provider in Settings first.
./jvmdiag analyze app.hprof --ai

# JVMDIAG_ACCESS_TOKEN must contain your workspace access token.
./jvmdiag analyze app.hprof --server https://diag.example.com --workspace payments-team

# Local stdio MCP server; binary JFR/live operations still need JDK tools.
./jvmdiag mcp --file app.hprof
```

## Documentation

- [Installation, containers and upgrades](docs/INSTALL.md)
- [Kubernetes live diagnostics](deploy/kubernetes/README.md)
- [Architecture and capabilities](docs/ARCHITECTURE.md)
- [Shared-server security and configuration](docs/SECURITY-AND-CONFIGURATION.md)
- [Diagnostic metrics, evidence and limitations](docs/DIAGNOSTIC-SEMANTICS.md)
- [Testing and JVM regression dataset](docs/TESTING.md)
- [Release process](docs/RELEASING.md)
- [Product review and MicroK8s validation, 2026-10-24](docs/REVIEW-2026-10-24.md)

Licensed under [Apache-2.0](LICENSE). See [contributing](CONTRIBUTING.md), the [code of conduct](CODE_OF_CONDUCT.md), [security policy](SECURITY.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
