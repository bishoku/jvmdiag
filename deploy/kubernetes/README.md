# Analyze a running Java Pod with an ephemeral container

For the persistent Web UI/API/MCP server deployment, see [Kubernetes and OpenShift server examples](../README.md).

The diagnostic image includes a native `jvmdiag` binary and a full Temurin HotSpot JDK (`jcmd`, `jstack`, `jfr`). It runs as UID/GID 10001 by default and starts with CLI help, without opening a server port. The small web-server `Dockerfile` remains separate. No Kubernetes client or API credentials are required inside the diagnostic container.

## Build an image matching the JVM

```sh
docker build -f Dockerfile.diagnostic -t YOUR_REGISTRY/jvmdiag:diagnostic-jdk17 .
docker build -f Dockerfile.diagnostic \
  --build-arg JDK_IMAGE=eclipse-temurin:25-jdk-jammy \
  -t YOUR_REGISTRY/jvmdiag:diagnostic-jdk25 .
# Push using your normal registry/release procedure; no public image is published by this repository yet.
```

Use a maintained HotSpot JDK with the same major version as the target, preferably the same vendor/update, and the correct node architecture. `JDK_IMAGE` and `GO_IMAGE` accept digest-pinned references for reproducible releases. The full JDK makes the image larger than the native-only server. Multi-architecture publication can use `docker buildx build --platform linux/amd64,linux/arm64 ...`; the Go binary is built inside the selected platform's builder. This implementation targets Linux HotSpot; Windows containers, OpenJ9, GraalVM native-image and older JDK 8 attach behavior are not covered.

## Prerequisites and permissions

- Ephemeral containers must be enabled/supported (stable since Kubernetes 1.25), and the container runtime must support `kubectl debug --target` process namespace targeting. The existing Pod need not have `shareProcessNamespace: true`. Separate mount namespaces are expected; no shared `/tmp` volume is required.
- Use `kubectl` 1.32+ for the custom profile workflow below, within the supported client/server version skew. Get the target's **effective** numeric UID and GID from its deployment/image/runtime configuration; a startup script may change them. Copy `profile-restricted.json` and set both `runAsUser` and `runAsGroup` to those values. The tool checks these identities before attaching. The sample assumes a non-root target, UID/GID 10001; a root JVM needs an explicitly approved root profile and cannot use a Restricted policy namespace.
- HotSpot attach must be enabled (`-XX:+DisableAttachMechanism` blocks it). The target must be running and responsive, with a writable `/tmp` for the attach socket. `/proc/PID/root` and the target staging directory must be accessible to that same identity. Read-only roots work only when required temporary paths have writable mounts already present in the Pod. An ephemeral container cannot add a new Pod volume; a custom `volumeMounts` profile can mount an **existing** volume when needed.
- Start with `--profile=restricted` and the supplied custom security context: non-root, no privilege escalation, all capabilities dropped, RuntimeDefault seccomp. No privileged mode, host PID, `nsenter`, `SYS_ADMIN` or `SYS_PTRACE` is requested. Kernel procfs settings, non-dumpable processes, user namespaces, AppArmor or SELinux can still prevent cross-container access. Diagnose the denial with your platform team; the tool does not broaden permissions. If your policy requires `SYS_PTRACE`, that needs a separately reviewed profile outside Restricted policy; it does not replace matching JVM credentials or fix disabled attach.
- The operator needs namespace-scoped Pod get/list/watch (including interactive attach startup), ephemeral-container update/patch, attach/exec and logs permissions. [`rbac.yaml`](rbac.yaml) provides a Role and example Group binding in `jvmdiag-demo`; change the namespace and group before applying it. It grants no workload deletion, secrets, nodes, or cluster-wide permissions. Grant it to the human operator, not the application ServiceAccount. Existing admission policies and registry credentials still apply.

```sh
kubectl auth can-i patch pods --subresource=ephemeralcontainers -n YOUR_NAMESPACE
kubectl auth can-i create pods --subresource=attach -n YOUR_NAMESPACE
kubectl auth can-i create pods --subresource=exec -n YOUR_NAMESPACE
# Administrator: edit namespace/group in this file before applying it.
kubectl apply -f deploy/kubernetes/rbac.yaml
```

## Interactive capture and analysis

Use a unique debug container name for each session. Set `--target` to the **container name**, not the Pod name. Replace the Pod, namespace, image and identity placeholders for your deployment.

```sh
kubectl debug -n YOUR_NAMESPACE YOUR_POD -it \
  --container=jvmdiag-001 --target=java \
  --image=YOUR_REGISTRY/jvmdiag:diagnostic-jdk17 \
  --profile=restricted --custom=deploy/kubernetes/profile-restricted.json \
  -- /bin/sh
```

Inside the diagnostic shell:

```sh
jvmdiag ps
# Use the PID shown here; it is not necessarily 1.
jvmdiag capture --pid 1 --container --count 3 --interval 2s \
  --out-dir /tmp/case-001 --out /tmp/case-001/report.md \
  --data-dir /tmp/jvmdiag-config --no-ai
cat /tmp/case-001/report.md

# Explicitly request a heap and a short JFR recording. Use a NEW output directory.
jvmdiag capture --pid 1 --container --count 3 --interval 2s \
  --with-heap --jfr-duration 10s --command-timeout 90s --timeout 3m \
  --out-dir /tmp/case-002 --out /tmp/case-002/report.md --no-ai
```

`--container` uses `/proc/PID/root` for JVM-created artifacts. The tool creates a private staging directory under the target's `/tmp` (override with `--target-dir /existing/writable/path`), sends that **target-visible** path to `jcmd`, copies validated HPROF/JFR files into the diagnostic container's private output directory, then removes its staging directory. It never passes the debugger's private output path to the target JVM. For JDK attach clients that use their own `/tmp` when namespace PIDs match, the tool creates a temporary `.java_pidPID` symlink to the target socket and an attach trigger in the target `/tmp`. Existing local paths are never replaced; only files created by this invocation are removed. A conflicting local socket requires a fresh diagnostic container. `jvmdiag ps` scans procfs because local `jcmd -l`/perfdata discovery can miss JVMs in another mount namespace.

Thread snapshots and available NMT are captured by default. NMT requires `-XX:NativeMemoryTracking=summary` or `detail` at target JVM startup; adding the diagnostic container cannot enable it retroactively. Its absence is included as a limitation. Other NMT command failures are reported as unavailable, rather than assumed disabled. Historical GC logs are not reconstructed: analyze an existing target log explicitly, for example `jvmdiag analyze /proc/1/root/var/log/app/gc.log --type gc --no-ai`.

Heap dumping may trigger full GC and a substantial pause. Heap/JFR are opt-in; check disk capacity in **both** containers and Pod/node headroom before requesting them. Artifact copying temporarily needs storage in both filesystems, and native heap analysis consumes additional memory. Ephemeral containers cannot request their own resource allocations; diagnostics compete for the Pod/node's resources and can contribute to OOM/eviction. `--command-timeout` bounds each JDK client command; `--timeout` bounds collection. A timed-out client does not guarantee that an operation already accepted by the target JVM has stopped. SIGINT/SIGTERM attempts to stop only the JFR recording created by this invocation, using a bounded independent cleanup context; forced termination or failed cleanup can require `jcmd PID JFR.stop name=<reported-name>`.

Output directories must be new: existing directories/files are not overwritten. Directories use mode 0700, copied artifacts and capture manifests 0600. `capture.json` records available paths, notes and `complete`/`partial` collection status; `complete` describes the requested collection, not a healthy JVM or complete diagnostic evidence. Missing requested heap/JFR, invalid output or attach errors produce a non-zero exit with a partial manifest when collection has begun. `--capture-only` saves artifacts without analysis. Live capture sends nothing to AI unless `--ai` is explicitly supplied and a provider is configured; examples use `--no-ai`.

From another terminal, **while the debug shell is still running**:

```sh
kubectl cp -n YOUR_NAMESPACE -c jvmdiag-001 YOUR_POD:/tmp/case-001 ./case-001
# Optional local re-analysis:
jvmdiag incident --thread ./case-001/threaddump_1.txt,./case-001/threaddump_2.txt --no-ai
```

The JDK base includes `tar`, which `kubectl cp` requires. Dumps and reports may contain secrets or personal data; store the copied directory with appropriate access control. Remove the files you created when done, then exit the shell. A terminated ephemeral container cannot be restarted, exec'd into, or individually removed from the Pod specification; its entry remains until Pod replacement. Exiting does not restart the Java container. One-shot `kubectl debug ... -- jvmdiag capture ...` is also possible, but use stdout/`kubectl logs` for the report or an already mounted persistent volume: private files in a terminated debugger cannot be retrieved using `kubectl cp`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `jvmdiag ps` finds no Java / PID inaccessible | Correct `--target`, live JVM, runtime process namespace support; choose the visible PID rather than assuming 1. |
| Effective UID/GID mismatch | Set both numeric IDs in the custom profile; root is not used as an attach workaround. |
| `/proc/PID/root` inaccessible | Procfs/dumpability, user namespaces and AppArmor/SELinux; matching UID alone may not be sufficient. |
| Cannot open attach socket / timeout | Compatible JDK, attach enabled, target `/tmp` writable, JVM responsive, access policy. |
| Heap/JFR requested but missing | Check target-visible staging path, free disk, command output and partial `capture.json`; failure is not a successful capture. |
| NMT unavailable | Startup flag absent or command failed; see the exact capture note. |
| Profile/admission rejection | Namespace Pod Security, custom UID/GID, seccomp/capability policies and image registry access. |
| `kubectl cp` fails after one-shot capture | Use a live interactive shell, report logs, or a pre-existing volume. |

## Repeatable integration test

Unit tests are offline: `go test -race ./internal/capture ./cmd/jvmdiag`. Real tests require Docker, kind, kubectl 1.32+ and Python 3. They operate on their own namespace in an explicitly selected kind context. The test script rejects other context names unless the exact `microk8s` context is explicitly enabled with `--allow-microk8s` and deletes its namespace in `finally`; the commands below use a separate kubeconfig and leave the user's current context unchanged.

```sh
docker build -f Dockerfile.diagnostic -t jvmdiag-diagnostic:k8s-test .
docker build -f tests/kubernetes/Dockerfile.fixture -t jvmdiag-fixture:k8s-test .
kind create cluster --name jvmdiag-e2e --image kindest/node:v1.32.2 \
  --kubeconfig /tmp/jvmdiag-e2e.kubeconfig
kind load docker-image jvmdiag-diagnostic:k8s-test jvmdiag-fixture:k8s-test --name jvmdiag-e2e
python3 tests/kubernetes/e2e.py --kubeconfig /tmp/jvmdiag-e2e.kubeconfig --context kind-jvmdiag-e2e
kind delete cluster --name jvmdiag-e2e --kubeconfig /tmp/jvmdiag-e2e.kubeconfig
```

### Run on an existing local MicroK8s cluster

This creates synthetic Java Pods and a Role/RoleBinding in a unique `jvmdiag-test-*` namespace, then deletes that namespace and waits for cleanup. It does not change existing workloads, the current kubectl context, cluster authorization or addons. Images remain in the local image stores for reuse.

Use MicroK8s' matching kubectl instead of an older system client. The script accepts a kubectl executable, so a small wrapper supplies the `microk8s kubectl` subcommand:

```sh
docker build -f Dockerfile.diagnostic -t jvmdiag-diagnostic:k8s-test .
docker build -f tests/kubernetes/Dockerfile.fixture -t jvmdiag-fixture:k8s-test .
TEST_DIR=$(mktemp -d /tmp/jvmdiag-microk8s.XXXXXX)
chmod 700 "$TEST_DIR"
printf '#!/bin/sh\nexec microk8s kubectl "$@"\n' > "$TEST_DIR/kubectl"
chmod 700 "$TEST_DIR/kubectl"
(umask 077; microk8s config > "$TEST_DIR/kubeconfig")
docker save -o "$TEST_DIR/images.tar" jvmdiag-diagnostic:k8s-test jvmdiag-fixture:k8s-test
microk8s ctr image import "$TEST_DIR/images.tar"
python3 tests/kubernetes/e2e.py --kubectl "$TEST_DIR/kubectl" \
  --kubeconfig "$TEST_DIR/kubeconfig" --context microk8s --allow-microk8s \
  --results-dir "$TEST_DIR/results"
```

On installations where `microk8s ctr` asks for sudo but the current user already has access through the `microk8s` group, the equivalent import is:

```sh
/snap/microk8s/current/bin/ctr \
  --address /var/snap/microk8s/common/run/containerd.sock --namespace k8s.io \
  images import "$TEST_DIR/images.tar"
```

If RBAC is disabled, the script fails rather than claiming denial enforcement. To validate capture on such a development cluster without changing its authorization, add `--allow-unrestricted-rbac`. It prints `SKIP` for RBAC denial checks; allowed operator actions and all capture tests still run. A pass with this option is **not** proof of least-privilege enforcement.

`--results-dir` must be new and retains synthetic debugger logs, Pod snapshots and exported thread/NMT/heap/JFR/report files. Store it privately; Pod snapshots include environment/runtime metadata. After reviewing results, remove the temporary test directory (including the kubeconfig) when no longer needed. If a run is force-killed before cleanup, inspect and remove only its reported `jvmdiag-test-*` namespace.

The integration test uses a Java JRE target without `jcmd`, separate mount namespaces, no shared `/tmp`, a Restricted-policy namespace and operator RBAC. It checks discovery, actual thread/heap/JFR/NMT capture and analysis, target restart count, non-init PIDs in a shared process namespace, operator artifact extraction with `kubectl cp`, private output permissions, staging/socket-bridge/JFR cleanup, denied UID/GID/PID/attach cases and explicit NMT absence. It does not certify every CRI runtime, security policy, JDK or architecture.

References: [Kubernetes ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/), [debug profiles and process targeting](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/), [jcmd identity and discovery requirements](https://docs.oracle.com/en/java/javase/21/docs/specs/man/jcmd.html), [OpenJDK Linux attach implementation](https://github.com/openjdk/jdk17u/blob/master/src/jdk.attach/linux/classes/sun/tools/attach/VirtualMachineImpl.java).

Validated on 2026-10-24: Linux arm64, kind Kubernetes 1.32.2, containerd 2.0.3, matching kubectl 1.32.2, Temurin HotSpot JDK/JRE 17.0.20.1+1. AMD64 builds compile, but runtime validation here used ARM64.

Validated on 2026-10-24 on local MicroK8s: Linux amd64, Kubernetes/kubectl 1.35.6, containerd 2.1.6, matching Temurin JDK/JRE 17.0.20.1+1. Capture, analysis, extraction, cleanup and failure scenarios passed; RBAC denial checks were explicitly skipped because cluster authorization was unrestricted. See the [review and validation report](../../docs/REVIEW-2026-10-24.md) for evidence and scope.

The same MicroK8s matrix was rerun successfully after the diagnostic-input fixes, including invalid thread/NMT rejection, missing incident snapshots and the corrected NMT committed label. The review report records the second run separately.
