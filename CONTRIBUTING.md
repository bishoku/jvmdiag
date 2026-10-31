# Contributing

Read the [code of conduct](CODE_OF_CONDUCT.md), [diagnostic limitations](docs/DIAGNOSTIC-SEMANTICS.md) and [security policy](SECURITY.md). Discuss larger changes in an issue before implementing them. Small fixes can go directly to a pull request.

Use the Go version in `.go-version`, Python 3 and Git. Browser tests additionally use Node 24 and `npm ci --prefix tests`; live JVM tests need full JDK tools. Run:

```sh
go test -race -shuffle=on -timeout=180s ./...
go vet ./...
python3 -m unittest discover -s tests -p 'test_*.py' -v
npm ci --prefix tests --ignore-scripts
npx --prefix tests playwright install chromium
node tests/ui-security.cjs
```

Format Go changes with `gofmt`. Work on a branch and explain the problem, resulting behavior and checks actually executed in the PR template. Native release packaging runs on five OS/architecture combinations in CI; a local cross-compilation is not a runtime test.

Parser changes should include a minimal failing regression. Validate metric meanings against primary JVM documentation or independently read real outputs. Preserve `limited`/`metadata-only` and observation-versus-hypothesis distinctions. Do not change goldens just to make a failing test pass. See `tests/fixtures/capture.py` and the corpus manifest for independent references, redaction and immutable artifact digests. Fresh JVM captures are not byte-for-byte deterministic; compare their independent references instead.

Do not contribute production diagnostic data. Use synthetic workloads, remove operator identity and confirm provenance and redistribution rights. Retain original third-party license notices. Existing source is Apache-2.0 licensed; by submitting contributions you agree to distribute your contribution under that project license and confirm you have the right to do so. No CLA or DCO automation is currently required.

The [Kubernetes guide](deploy/kubernetes/README.md) describes opt-in local kind and MicroK8s tests. The [release guide](docs/RELEASING.md) describes the protected publication workflow. Never add publication credentials or `pull_request_target` code execution to PR checks.
