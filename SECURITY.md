# Security policy

Do not post credentials, API keys, production HPROF/JFR dumps, customer data or exploitation details in public issues or pull requests.

Use this repository's **Security → Report a vulnerability** private reporting feature. If it is not enabled, ask the maintainer for a private contact channel without posting vulnerability details. Reporting should include the affected version, safe reproduction, impact and any proposed mitigation. Response and remediation are best effort; no response-time guarantee is offered.

Security fixes target the latest stable release. Older releases and snapshots may not receive backports. A release is supported only after it appears in GitHub Releases; an unreleased changelog section is not a support promise.

Run shared servers with separate administrator/workspace credentials, HTTPS at the ingress and controlled data-directory access. Diagnostics can disclose application secrets and consume significant memory or disk. Follow the Kubernetes guide before enabling heap capture. AI requests transmit report content to the configured provider; assess that provider and your data-handling requirements before enabling them.

See `docs/RELEASING.md` for protected tag and workflow configuration, dependency update policy and release recovery. A checksum detects corruption; provenance verification additionally links artifacts to the expected repository workflow and source revision.
