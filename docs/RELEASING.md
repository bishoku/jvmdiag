# Maintainer and release guide

The repository is `bishoku/jvmdiag`, licensed Apache-2.0. Version metadata lives in `VERSION`; direct source builds default to `dev`. The Go module is `github.com/bishoku/jvmdiag`.

## One-time GitHub configuration

These are repository settings, not settings that a committed workflow file can enforce:

1. Enable Actions and GHCR publishing for `GITHUB_TOKEN`. Enable private vulnerability reporting under Security. The repository is public; verify that the GHCR package is also public after its first push (new packages may require a visibility change). Preserve the OCI source label so package/repository permissions remain linked.
2. Protect `main` with a ruleset: require pull requests, review, the `Required checks` result from the CI/Verification workflow, conversation resolution, and no force pushes/deletion. Enable CODEOWNERS review when there is an independent reviewer; one maintainer cannot approve their own PR. Restrict workflow edits and review changes to `.github`, scripts, containers and dependency pins carefully.
3. Protect `v*` tags against update/deletion and restrict creation to release maintainers. Tags must point to a commit already merged into the default branch. Consider signed annotated tags. Configure immutable GitHub Releases if available; the workflow prepares assets in a draft before publishing, so immutability takes effect only once complete.
4. Keep default workflow permissions read-only and fork approval policies enabled. CI uses `pull_request`, never `pull_request_target`, and receives no publishing secrets. Only tag-release image/publish jobs request write/OIDC permissions. No PAT, registry password or long-lived signing key is required.
5. Ensure your account/organization permits the pinned Actions and public ARM64/macOS runners. CI is intentionally comprehensive and may use billable minutes in private repositories. Dependabot proposes Actions SHA, npm, Go module and Docker updates; review and test them. The `.go-version`, tool versions inside workflows and Dockerfile build-argument defaults also need coordinated maintenance.

Branch/tag rules, package visibility and private reporting must be verified in GitHub; their existence is not implied by YAML in this checkout.

## Required verification

`ci.yml` calls the same `verify.yml` used by releases. It runs:

- Go race/regression tests with shuffled order, three repetitions and CPU settings 1/4, on native Linux AMD64/ARM64, macOS Intel/ARM64 and Windows AMD64 runners.
- Actual per-platform archive packaging, extraction, metadata/checksum validation and native execution against captured JVM data.
- Format/vet, release-script policy tests and pinned actionlint validation.
- Locked Playwright browser security tests.
- Fresh Temurin 17/21/25 captures, each with G1, Parallel, Serial and ZGC, using independently calculated references. Fixed Oracle/GraalVM/Temurin captures continue to run offline in the Go suite. These are coverage statements, not universal JVM certification.
- Native server/JDK17/JDK25 image smoke tests on Linux AMD64/ARM64. Diagnostic tests decode real binary JFR and parse actual HPROF/thread captures with their bundled tools; server tests check unauthenticated rejection and authenticated access.
- Actual kind ephemeral-container tests against the pinned Kubernetes baseline, with restricted security contexts, RBAC, separate mount namespaces, artifact extraction and failure scenarios.

The final `Required checks` job fails if any prerequisite fails, is cancelled or is skipped. Protect that check in branch rules. Release jobs depend on the whole reusable verification workflow. There is no `continue-on-error` release bypass and no manual dispatch that publishes arbitrary refs.

## Prepare a version

1. Merge all intended changes into the default branch. Update `VERSION`, add the exact `## [X.Y.Z]` (or prerelease) section to `CHANGELOG.md`, and update compatibility/installation documentation as needed. `Unreleased` is not a substitute for a release section.
2. Wait for CI, inspect its logs and open a release preparation PR if needed.
3. Validate, then push an annotated tag:

```sh
python3 scripts/release.py validate v0.0.1
git tag -a v0.0.1 -m 'Release v0.0.1'
git push origin v0.0.1
```

The example version is not an instruction to overwrite an existing tag. SemVer tags must be `vMAJOR.MINOR.PATCH`, optionally followed by a valid prerelease such as `-rc.1`. Numeric identifiers cannot have leading zeros. Build metadata (`+...`) and other tag formats are rejected. The tag must exactly match `VERSION`; the workflow also checks that HEAD belongs to the default branch's history.

## What the tag workflow publishes

1. Validate the tag, version/changelog, source ancestry and absence of an already published release.
2. Re-run the full verification suite **on that tag**. Preserve the exact five native archive byte streams that were installed/executed in those jobs.
3. Build each native image once, test that candidate, then push those exact Docker images under unique `build-RUN-ATTEMPT-VARIANT-ARCH` staging tags. Staging images are individually tested; no version/stable image aliases are promoted until all candidates and verification succeed.
4. Check completeness, shared version/revision and checksums of all binaries and image descriptors. Upload archives, `SHA256SUMS` and `release.json` into a draft GitHub Release. Generate GitHub build provenance attestations for those exact bytes.
5. Create versioned multi-architecture manifests from the six tested child digests, without rebuilding. Attest the three versioned image indexes. Existing version tags with different content/revision are rejected.
6. The publication job is serialized across all release versions, preventing competing stable-alias updates. GitHub concurrency queues are not FIFO and can cancel older pending jobs when multiple releases queue up; inspect and re-run such a job rather than moving tags. For stable releases, update `latest`/diagnostic aliases only when doing so does not downgrade an existing higher version. Prereleases leave them unchanged. Finally publish the prepared GitHub Release; a maintenance/prerelease release is not marked Latest when inappropriate.

Tags are `:X.Y.Z`, `:X.Y.Z-diagnostic-jdk17` and `:X.Y.Z-diagnostic-jdk25`. All images share `ghcr.io/bishoku/jvmdiag`; package visibility is a separate GitHub setting. Staging tags can be pruned after retention requirements are met, but do not delete digests still referenced by published indexes.

There is no atomic transaction spanning GitHub Releases and GHCR: versioned images/aliases may become visible shortly before the draft is published. A failure can leave tested staging images or a draft behind; the workflow does not claim an all-or-nothing rollback. Checksums/provenance do not replace independent security review or dependency/SBOM scanning. These binaries are not Apple notarized or Authenticode signed.

## Failure recovery

Before retrying, inspect the failing check and artifacts. Never repoint a released tag or manually waive tests. Before publication, rerunning the failed workflow is supported when the source tag and artifact contents remain identical; drafts can be refreshed, and identical existing image indexes are reused. Changed version-tag contents are refused, including when a mutable base-image update changes a rebuilt candidate. In that case inspect and remove only the **unpublished draft/versioned candidates** you intentionally created, or prepare a new version; never replace a published release's digest to hide a fix.

If publication succeeded but the client lost its final response, confirm the release and attestations in GitHub rather than overwriting it. The workflow refuses to replace an already published release. Roll back deployments by pinning the previous verified digest/version, and publish a new patch for corrections. Do not force-update tags.

## Local package rehearsal

Requires Go and Python 3. Use a fresh output directory and your actual source commit/timestamp. No GitHub token or publishing is involved:

```sh
python3 scripts/release.py build --version v0.0.1 --platform darwin_arm64 \
  --out /tmp/jvmdiag-dist --commit FULL_40_CHARACTER_COMMIT \
  --date 2026-10-24T00:00:00Z
python3 scripts/release.py smoke /tmp/jvmdiag-dist/jvmdiag_0.0.1_darwin_arm64.tar.gz
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Use the native platform for `smoke`; cross-compilation alone never counts as execution validation. `release.py collect` requires exactly the five complete archives, verifies their sidecar/binary digests and prevents mixed-version/revision releases. Stable archive timestamps come from the source commit rather than the wall clock. Reproducibility also requires the same Go toolchain, Python/compression tools and source tree; container base references and package repositories may change unless digest/snapshot pinned. Binary/runtime notices are included in every archive/image.
