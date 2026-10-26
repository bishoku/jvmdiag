# Web UI image with Eclipse MAT included

The published minimal server image contains neither Java nor MAT. Diagnostic images contain a JDK, but do not bundle MAT. The optional [Dockerfile.mat](../Dockerfile.mat) builds a Web UI image with the complete Eclipse MAT 1.16.1.20250109 Linux distribution and Eclipse Temurin 17 JDK on Ubuntu Jammy. It supports native analysis and deep MAT analysis without downloading MAT at runtime.

The release workflow builds this variant as `X.Y.Z-mat-jdk17` (stable alias `mat-jdk17`) in both `ghcr.io/bishoku/jvmdiag` and `docker.io/barishoku/jvmdiag`, for Linux AMD64 and ARM64. These variants are introduced in v0.0.4; older releases are unchanged. The examples below also support local builds.

## Build and run

```sh
docker build -f Dockerfile.mat -t jvmdiag:mat-local .
docker volume create jvmdiag-data
# Create a private access.env using the token variables in INSTALL.md.
docker run --rm --name jvmdiag-mat \
  -p 127.0.0.1:8080:8080 --env-file ./access.env \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,mode=1777 \
  -v jvmdiag-data:/data \
  -e DYNAMIC_MAX_MAT_MEMORY=2g \
  jvmdiag:mat-local
```

See [container access-token setup](INSTALL.md) for `JVMDIAG_ADMIN_TOKEN` and `JVMDIAG_WORKSPACE_TOKENS`. The default command starts shared-server mode on port 8080 with one analysis worker. Protect the persistent volume: it stores uploaded dumps, configuration and analysis results.

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

Both tests passed on this machine for AMD64. ARM64 archive checksums were verified, but ARM64 execution and actual OpenShift SCC/Route admission were not tested. The full upstream MAT distribution and its component license notices remain in `/opt/mat`; see [third-party notices](../THIRD_PARTY_NOTICES.md).
