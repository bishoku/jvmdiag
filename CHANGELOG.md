# Changelog

Changes follow [Semantic Versioning](https://semver.org/). Dates are recorded when releases are prepared. A section here does not imply that a release has already been published.

## [Unreleased]

## [0.0.2] - 2026-10-24

- Fail incident and MCP capture analysis when a requested thread snapshot cannot be read or analyzed.
- Reject unrecognized thread/NMT input and malformed thread JSON across CLI, uploads, diffs and inline MCP analysis.
- Label NMT committed memory separately from RSS/cgroup usage and explain the derived off-heap metric.
- Add regression coverage and explicit local MicroK8s integration testing; reorganize user documentation.

## [0.0.1]

- Native JVM diagnostics with workspace authorization, protected configuration and browser output sanitization.
- Scoped JFR/HPROF evidence, confidence and explicit limitations; unavailable data is not reported as successful diagnosis.
- Deterministic regressions and independently audited captures across JDK/GC families.
- Ephemeral-container Linux HotSpot diagnostics with matching identities, separate mount namespaces and bounded capture cleanup.
- Verified release archives, non-root server and JDK diagnostic images, and GitHub Actions publication gates.
