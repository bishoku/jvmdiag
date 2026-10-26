# Large memory dumps: limits, sizing and alternatives

Applies to the current implementation (v0.0.3). There is **no tested maximum dump-file size** and no guarantee that a dump of a particular byte size fits a particular amount of RAM. Archived regressions and small live fixtures are not multi-GB capacity benchmarks.

## Actual implementation limits

| Layer | Current behavior | Operational consequence |
| --- | --- | --- |
| Web uploads | Multipart file parts stream to disk through a 256KiB copy buffer; no application-wide file/request byte limit is configured | Upload size is bounded by disk, intermediaries and connection limits. Streaming upload does not imply constant-memory analysis. There is no resumable/chunked upload protocol or quota enforcement. |
| Worker pool | Default 2; `--max-workers`, or `MAX_WORKERS`; deployment examples set 1 | Controls simultaneous analysis jobs, not RAM budgets, admission by file size or upload concurrency. Queued uploads still occupy disk. |
| Native HPROF | Sequential records, no full object graph; retains metadata/maps, class statistics, frames/traces and bounded duplicate-array tracking | Memory depends on input structure and metadata, not only file bytes. No retained-size/dominator/path-to-root analysis. No hard process memory budget. |
| MAT heap | Explicit `MAT_HEAP_SIZE` wins; otherwise approximately 1.2 × file bytes, capped by `DYNAMIC_MAX_MAT_MEMORY` (default `8g`), then floored at 2GiB | The cap is a heuristic for MAT's `-Xmx`, not Go RSS or total container memory. A cap below 2GiB still produces the 2GiB floor. Explicit heap size bypasses the dynamic cap. |
| Hybrid MAT analysis | Native parsing always runs first; MAT child execution gets at most 25 minutes, shortened by any parent deadline | Not a configurable CLI/UI timeout. MAT failure can produce native-only output with a `limited` assessment; verify engine and warnings. |
| MCP heap sessions | 20-minute analysis context; idle expiry 120 minutes, checked every 5 minutes | Native parsing itself does not accept context cancellation, so the context is not a hard wall-clock kill of native parsing. Idle expiry is not general upload/history retention. |
| Web incident/capture | Three-minute context; capture command limits also apply | Larger heap collection/analysis can exceed these. The native parser is not interruptible through context. Prefer offline CLI workflows when these fixed server paths do not fit. |
| Other artifacts | Thread/NMT/text and JFR paths can materialize complete inputs or decoded output in memory | Do not extrapolate HPROF streaming behavior to every format. Avoid enormous JFR JSON exports. |
| HTTP server | No explicit server ReadTimeout/WriteTimeout/body limit on `http.ListenAndServe` | Ingress, OpenShift router, browser and proxy limits still apply. No built-in upload safety ceiling. |

HPROF uses 32-bit per-record length fields; segmented dumps may be much larger than 4GiB in total. That is a format detail, not a supported-size promise. The parser bounds duplicate primitive-array tracking (16–256 payload bytes, 25,000 distinct entries, top 20 groups); hitting tracking bounds is reported as a limitation. See [metric semantics](DIAGNOSTIC-SEMANTICS.md).

## Memory and storage planning

For MAT, reserve room for **Go memory + MAT `-Xmx` + Java native/thread overhead + other container overhead**, with headroom under the Pod limit. With several workers, simultaneous MAT processes can each allocate their configured heap. `MAT_HEAP_SIZE` does not constrain the Go parser. A 4GiB container and an 8GiB MAT heap are not a viable configuration. The example 4GiB Pod / dynamic 2GiB MAT cap is only a conservative starting configuration for small workloads; measure realistic files before accepting larger dumps.

Provision disk for concurrent uploaded dumps, queued files, MAT index/report files, retained MCP files, configuration/history and temporary exports. Ephemeral-container collection temporarily stores JVM-created artifacts in both the target and diagnostic filesystems; copying them to another machine adds another copy. MAT index sizes and native memory cannot be predicted from HPROF file bytes alone.

The Go upload handlers normally remove job artifact directories after processing, while reports/history and active MCP artifacts have different lifecycles. Failed/interrupted uploads and process crashes are not a guaranteed cleanup mechanism. Monitor free bytes/inodes and establish retention/cleanup procedures after confirming that files are not in use. Do not rely on session idle expiry to clean every upload or history file.

Upstream MAT [configuration guidance](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/configure_mat.html) explains object-count-dependent memory and implementation limits. Its large-file examples are MAT results, not jvmdiag benchmarks. Experimental object-discard modes change the analyzed population and are not exposed as jvmdiag options.

## Choose an execution path

1. **Local/offline first pass:** copy the HPROF securely to a sufficiently sized host and run `jvmdiag analyze /data/app.hprof --no-ai`. This avoids browser, ingress and upload copies. Inspect payload histograms before deciding whether MAT is needed.
2. **Deep analysis:** on a full-JDK host with MAT installed, set `APP_MAT_HOME=/opt/mat` and optionally `MAT_HEAP_SIZE=12g`, then run `jvmdiag analyze /data/app.hprof --deep-mat --no-ai`. The host needs more than the MAT heap alone; the built-in MAT child deadline still applies. For longer analysis, run MAT directly using its [batch workflow](https://help.eclipse.org/latest/topic/org.eclipse.mat.ui.help/tasks/batch.html), preserving its output/metric labels. jvmdiag has no arbitrary precomputed-MAT-report import adapter.
3. **Mounted analysis storage:** use an approved PVC/object-storage download workflow and CLI/Job to analyze a file already on disk. The UI has no general server-path import control; merely mounting a dump does not submit it to the UI. An admin MCP path tool is a separate privileged host operation.
4. **Dedicated larger instance:** one worker, an adequately sized Pod and PVC, explicit MAT heap, monitored CPU/RAM/storage. Validate OOM/eviction behavior; Kubernetes memory limits kill a process rather than gracefully reducing parser memory.
5. **Reduce evidence scope:** start with thread snapshots, NMT or a bounded JFR capture if these answer the question. Do not truncate an HPROF file or split it with generic file tools; record/graph consistency would be lost.

For remote uploads, configure ingress body limits and buffering/temp storage explicitly. For [ingress-nginx](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/), controller-version-specific options include `nginx.ingress.kubernetes.io/proxy-body-size`, read/send timeouts and request buffering; these are not portable Kubernetes fields. For OpenShift, `haproxy.router.openshift.io/timeout` controls router timing, not an application byte-size limit. Confirm limits with your controller/router documentation and infrastructure owner. Port-forward can isolate ingress/router problems but does not remove application/disk/memory limits.

There is no automatic distributed analysis, horizontal job coordination, memory-aware scheduling, disk quota, or proven multi-GB SLA today. Record file size, object/metadata counts where available, engine, peak RSS, elapsed time and index/temp disk growth in a representative capacity test before setting an organization-wide supported limit.
