# Installation

Releases are published at [bishoku/jvmdiag Releases](https://github.com/bishoku/jvmdiag/releases). A workflow in the repository does not mean a release already exists; use source builds until the first tagged workflow completes.

## Choose an installation

| Use | Install | Additional runtime tools |
| --- | --- | --- |
| CLI, local UI, native HPROF/text/JSON analysis | Release archive or source build | None |
| Decode binary JFR or capture a local JVM | Same executable | Compatible full HotSpot JDK: `jcmd`, `jstack`, `jfr` |
| Shared UI/API/MCP server | Native binary or server image | Access tokens; HTTPS at a reverse proxy |
| Analyze Java in Kubernetes | JDK diagnostic image | Matching effective UID/GID and Pod/runtime permissions |
| Retained heap/dominators with MAT | Binary plus separate MAT installation | MAT's compatible Java runtime and enough memory |

Release archives cover Linux AMD64/ARM64, macOS Intel/Apple Silicon and Windows AMD64. Windows ARM64 and 32-bit systems have no native release package. Containers cover Linux AMD64/ARM64. Windows ACLs and macOS Gatekeeper are platform-specific; Unix mode bits alone are not an access-control guarantee on Windows.

## Linux and macOS binary

Choose the OS/architecture in the release asset name. `x86_64` means `amd64`; `aarch64`/Apple Silicon mean `arm64`. Replace the example version with an existing release.

```sh
VERSION=3.0.0
# Linux ARM64: PLATFORM=linux_arm64; Intel Mac: darwin_amd64; Apple Silicon: darwin_arm64
PLATFORM=linux_amd64
ASSET="jvmdiag_${VERSION}_${PLATFORM}.tar.gz"
BASE="https://github.com/bishoku/jvmdiag/releases/download/v${VERSION}"
mkdir -p jvmdiag-download
cd jvmdiag-download
curl --fail --location --output "$ASSET" "$BASE/$ASSET"
curl --fail --location --output SHA256SUMS "$BASE/SHA256SUMS"
# Linux:
sha256sum --ignore-missing --check SHA256SUMS
# macOS alternative: calculate and compare the exact asset's line in SHA256SUMS
# shasum -a 256 "$ASSET"
tar -xzf "$ASSET"
mkdir -p "$HOME/.local/bin"
install -m 0755 jvmdiag "$HOME/.local/bin/jvmdiag"
export PATH="$HOME/.local/bin:$PATH"
jvmdiag version
```

Check that checksum verification succeeds for the **downloaded asset**, not merely another listed file. On macOS, compare `shasum -a 256` with that exact asset's line before extracting. Put the PATH addition in your shell configuration if desired. Archives include Apache-2.0 `LICENSE`, `NOTICE`, third-party notices/licenses and `buildinfo.json`. Keep notices when redistributing. The binaries are not Apple notarized or Windows Authenticode signed; validate provenance and follow your organization's execution policy instead of broadly disabling OS protections.

With GitHub CLI, verify provenance in addition to checksums:

```sh
gh attestation verify "$ASSET" --repo bishoku/jvmdiag \
  --signer-workflow bishoku/jvmdiag/.github/workflows/release.yml
```

Checksums detect corruption; downloading a checksum beside an asset is not an independent proof of publisher identity. Provenance verification checks GitHub's signed record of the expected repository/workflow. Inspect the returned source revision and compare it with the release tag. See [GitHub's verification documentation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Windows AMD64

Download `jvmdiag_VERSION_windows_amd64.zip` and `SHA256SUMS` from the same release. In PowerShell:

```powershell
$Version = '3.0.0'
$Asset = "jvmdiag_${Version}_windows_amd64.zip"
$Base = "https://github.com/bishoku/jvmdiag/releases/download/v$Version"
Invoke-WebRequest "$Base/$Asset" -OutFile $Asset
Invoke-WebRequest "$Base/SHA256SUMS" -OutFile SHA256SUMS
$Lines = @(Get-Content SHA256SUMS | Where-Object { ($_ -split '\s+')[1] -eq $Asset })
if ($Lines.Count -ne 1) { throw 'Missing or ambiguous asset checksum' }
$Expected = ($Lines[0] -split '\s+')[0]
if ((Get-FileHash $Asset -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected) { throw 'Checksum mismatch' }
Expand-Archive $Asset -DestinationPath .\jvmdiag
.\jvmdiag\jvmdiag.exe version
.\jvmdiag\jvmdiag.exe serve
```

Keep the extracted executable in a user-owned directory and add that directory to your user PATH if needed. This does not install a Windows service. Kubernetes diagnostic images require Linux nodes even when kubectl runs on Windows.

## Build from source

Install the Go version in `.go-version` (currently 1.27.3) and Git. No Maven, Java or Node is needed for a basic native build.

```sh
git clone https://github.com/bishoku/jvmdiag.git
cd jvmdiag
go test ./...
go build -trimpath -o jvmdiag ./cmd/jvmdiag
./jvmdiag version
./jvmdiag serve
```

After a tagged release exists, Go users can alternatively install from source with:

```sh
go install github.com/bishoku/jvmdiag/v3/cmd/jvmdiag@v3.0.0
```

This compiles locally and reports the module version. Its executable bytes differ from the GitHub archive and do not carry that archive's provenance attestation. Add `$(go env GOPATH)/bin` to PATH if needed. Go's `/v3` module suffix matches the v3 release tags.

A direct `go build` reports `dev`/unknown revision metadata. The release workflow injects the validated version, commit and commit timestamp. For a locally versioned package, run `scripts/release.py build` as described in [RELEASING.md](RELEASING.md). The public module path is `github.com/bishoku/jvmdiag/v3`; previous experimental monorepo imports have been migrated. There is no Homebrew, apt, Chocolatey or Winget publication in this workflow.

## Container server

Use an existing stable version tag. The default container starts a shared server, runs as UID/GID 10001 and stores data under `/data`. Use a named volume or set matching ownership on bind mounts. Generate separate administrator/workspace tokens and pass them through your orchestrator's secret mechanism. For a local Docker example, put the following keys in a private file named `server.env`:

```dotenv
JVMDIAG_ADMIN_TOKEN=REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES
JVMDIAG_WORKSPACE_TOKENS={"payments-team":"REPLACE_WITH_A_DIFFERENT_RANDOM_SECRET_AT_LEAST_32_BYTES"}
```

Replace the placeholders; on Unix set `chmod 600 server.env`. Do not commit it or embed it in images.

```sh
docker volume create jvmdiag-data
docker run --rm --name jvmdiag -p 127.0.0.1:8080:8080 \
  --env-file server.env --mount source=jvmdiag-data,target=/data \
  ghcr.io/bishoku/jvmdiag:3.0.0
```

Open `http://localhost:8080` and connect using your workspace name/token. Keep the host port bound to loopback for this example. For remote deployment, configure TLS at the reverse proxy and `JVMDIAG_PUBLIC_ORIGIN`; see the README security section. The server image has no JDK or MAT runtime. Add a compatible runtime yourself or use a diagnostic image for CLI/JVM work. Builds do not publish ports or credentials automatically.

Versioned diagnostic images are `ghcr.io/bishoku/jvmdiag:3.0.0-diagnostic-jdk17` and `:3.0.0-diagnostic-jdk25`. Stable aliases are `latest`, `diagnostic-jdk17` and `diagnostic-jdk25`; prereleases never update them. Prefer versioned tags or, for immutable deployments, verified image digests. For example:

```sh
gh attestation verify oci://ghcr.io/bishoku/jvmdiag:3.0.0 --repo bishoku/jvmdiag \
  --signer-workflow bishoku/jvmdiag/.github/workflows/release.yml
# Use the verified digest from the attestation/registry for deployment:
# docker pull ghcr.io/bishoku/jvmdiag@sha256:VERIFIED_DIGEST
```

Follow [the Kubernetes guide](../deploy/kubernetes/README.md) for ephemeral-container permissions and capture examples. Use the JDK image matching the Java target, not the native-only server image.

## Upgrade, rollback and removal

Back up the configured data directory/volume before an upgrade. Stop the old process, verify the new package, replace the executable or pinned image and restart it using the same data directory and configuration. Keep the previous verified version for rollback. Diagnostic schema changes are described in the changelog; historical saved reports are not automatically re-analyzed. Do not assume a future data migration is reversible.

To remove the binary, stop its process and delete the executable from your installation directory. Configuration/history defaults to `~/.jvmdiag`, or `--data-dir` for servers; delete it only when you intend to discard saved data. Stopping/removing a container does not delete a named volume. There is no telemetry or AI-provider credential required for static local analysis; disable AI explicitly with `--no-ai` in scripted analysis.
