# Web UI image with Eclipse MAT included

The published minimal server image contains neither Java nor MAT. Diagnostic images contain a JDK, but do not bundle MAT. The optional [Dockerfile.mat](../Dockerfile.mat) builds a Web UI image with the complete Eclipse MAT 1.16.1.20250109 Linux distribution and Eclipse Temurin 17 JDK on Ubuntu Jammy. It supports native analysis and deep MAT analysis without downloading MAT at runtime.

The release workflow builds this variant as `X.Y.Z-mat-jdk17` (stable alias `mat-jdk17`) in both `ghcr.io/bishoku/jvmdiag` and `docker.io/barishoku/jvmdiag`, for Linux AMD64 and ARM64. These variants are introduced in v0.0.4; older releases are unchanged. The examples below also support local builds.

## Single-user Web UI

The image defaults to **multi-user mode**. To run locally without access tokens, replace its complete default command by putting `serve` and its arguments **after the image name**:

```sh
docker volume create jvmdiag-personal
docker run --rm --name jvmdiag-mat \
  -p 127.0.0.1:8080:8080 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 -v jvmdiag-personal:/data \
  -e MULTI_USER_MODE=false -e DYNAMIC_MAX_MAT_MEMORY=2g \
  barishoku/jvmdiag:0.0.5-mat-jdk17 \
  serve --host 0.0.0.0 --port 8080 --data-dir /data --max-workers 1
```

Open `http://localhost:8080/settings`. Single-user mode has no access-token gate and grants local administrative access, so keep the published host port on `127.0.0.1`. `--host 0.0.0.0` binds inside the container; `-p 127.0.0.1:...` limits access on the host. `MULTI_USER_MODE=false` prevents an inherited environment setting from enabling shared mode. Omitting `--multi-user` replaces the image default; simply adding an environment variable to the unchanged default command does not disable its explicit `--multi-user` flag.

Docker options (`-p`, `-v`, `-e`, `--memory`) go before the image; jvmdiag arguments go after it. Do not append a second `jvmdiag` executable name: the image already supplies that entrypoint.

## Multi-user Web UI

Create a private `access.env` as described in [the installation guide](INSTALL.md), containing `JVMDIAG_ADMIN_TOKEN` and `JVMDIAG_WORKSPACE_TOKENS`. Then use the default command:

```sh
docker volume create jvmdiag-shared
docker run --rm --name jvmdiag-mat \
  -p 127.0.0.1:8080:8080 --env-file ./access.env \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 -v jvmdiag-shared:/data \
  -e DYNAMIC_MAX_MAT_MEMORY=2g \
  barishoku/jvmdiag:0.0.5-mat-jdk17
```

Connect in the UI using a workspace token and matching workspace name, or use the administrator token for global settings and installation. MAT is already installed; no Download action is needed. Before connecting, protected status requests return 401. Version 0.0.4 could leave the initial download button visible when this happened (fixed in 0.0.5); it does not mean the bundled MAT files are missing. With a valid token, Settings shows `Installed & Ready` and `/opt/mat/ParseHeapDump.sh`.

Protect each persistent volume: it stores uploaded dumps, configuration and analysis results. Use different volumes for personal and shared servers to keep their settings separate.

## Other arguments and CLI analysis

To publish a different host port and use two workers, replace the command explicitly:

```sh
docker run --rm -p 127.0.0.1:9090:8080 \
  -v jvmdiag-personal:/data -e MULTI_USER_MODE=false \
  -e MAT_HEAP_SIZE=2g \
  barishoku/jvmdiag:0.0.5-mat-jdk17 \
  serve --host 0.0.0.0 --port 8080 --data-dir /data --max-workers 2
```

Each worker can start a MAT process; two 2g heaps require additional server/JVM overhead and sufficient container memory. Change the container port consistently in both `-p` and `--port` if needed. `--data-dir` must point at writable storage. Run `docker run --rm barishoku/jvmdiag:0.0.5-mat-jdk17 serve --help` for server flags.

For an offline CLI analysis, use a writable dump directory because MAT writes indexes beside the heap file:

```sh
# Ensure /absolute/path/dumps is writable by container UID/GID 10001:10001.
docker run --rm --network none \
  -v jvmdiag-personal:/data -v /absolute/path/dumps:/dumps \
  -e MAT_HEAP_SIZE=2g \
  barishoku/jvmdiag:0.0.5-mat-jdk17 \
  analyze /dumps/heap.hprof --deep-mat --no-ai
```

`--deep-mat` requests retained-heap analysis; bundling MAT does not enable it for every analysis automatically. `--no-ai` avoids provider requests.

## Local build

```sh
docker build -f Dockerfile.mat -t jvmdiag:mat-local .
```

Use `jvmdiag:mat-local` instead of the published image in any example above. GHCR offers the same published variant as `ghcr.io/bishoku/jvmdiag:0.0.5-mat-jdk17`.

`APP_MAT_HOME=/opt/mat` selects the bundled installation. `HOME=/data` and `JAVA_TOOL_OPTIONS=-Duser.home=/data` keep Java/Eclipse user configuration writable when the image filesystem is read-only or the UID has no passwd entry. Preserve that Java property if adding other `JAVA_TOOL_OPTIONS`. Keep both `/data` and `/tmp` writable.

MAT memory is additional to the Go server and other runtime overhead. A 2g MAT heap is not a 2 GiB container memory guarantee. The automatic heap calculation has a 2 GiB floor; use [large-dump sizing and limits](LARGE-DUMPS.md) to choose container resources, disk capacity and timeouts. One worker limits analysis concurrency, not simultaneous uploads. Full JDK availability does not guarantee compatibility with every target JVM or JFR version.

## Corporate proxy and disconnected runtime

The build still needs access to base images, Go dependencies, Alpine packages and the Eclipse archive. Build on an approved connected builder, then push to your internal registry or transfer the image:

```sh
docker save -o jvmdiag-mat.tar jvmdiag:mat-local
# On the destination Docker host:
docker load -i jvmdiag-mat.tar
```

A Docker load does not import into Kubernetes containerd automatically. Use your cluster's image import workflow or an accessible internal registry. Once installed, MAT analysis of local files requires no internet access. AI-enabled analysis can still require an external provider; use `--no-ai` for offline CLI analysis.

An internal mirror can serve the exact pinned archives:

```sh
docker build -f Dockerfile.mat \
  --build-arg MAT_BASE_URL=https://artifacts.example.com/eclipse/mat/1.16.1/rcp \
  -t jvmdiag:mat-local .
```

The build verifies fixed SHA-256 hashes for AMD64 and ARM64. These pins were calculated from the official Eclipse HTTPS downloads; they are not a separate signature verification. Mirrors must preserve the archive filenames and bytes. Do not put proxy passwords in build arguments or disable TLS verification. For an existing desktop installation, [manual browser download](MAT-PROXY.md#manual-installation-with-a-browser-download) remains an alternative.

## Kubernetes and OpenShift

Build and push the image to your approved registry. In the [server manifests](../deploy/README.md), replace the image while keeping server arguments, access secrets, PVC and writable `/tmp` mount. For an existing deployment:

```sh
kubectl -n jvmdiag set image deployment/jvmdiag \
  jvmdiag=registry.example.com/tools/jvmdiag:mat-validated
kubectl -n jvmdiag rollout status deployment/jvmdiag
```

Use `oc` on OpenShift. Record the same image change in your maintained manifest/overlay. OpenShift should assign its own UID and volume group permissions; do not add a fixed UID to bypass SCC. The example memory settings are starting points; size them for your dumps.

## Verification

```sh
python3 scripts/mat_image_smoke.py --image jvmdiag:mat-local
python3 scripts/container_smoke.py --image jvmdiag:mat-local --kind server --version dev
```

The MAT smoke test analyzes a real small HPROF with networking disabled, a read-only root filesystem and writable data/tmp, using both `10001:10001` and arbitrary `1000710000:0` identities. It requires actual MAT report sections and rejects native-only fallback. Its explicit 512m MAT heap is for the small fixture, not production sizing. The server smoke test checks Web UI access and API authentication.

Both tests passed for AMD64 and ARM64 on native GitHub runners for v0.0.4. Actual OpenShift SCC/Route admission was not tested. The full upstream MAT distribution and its component license notices remain in `/opt/mat`; see [third-party notices](../THIRD_PARTY_NOTICES.md).
