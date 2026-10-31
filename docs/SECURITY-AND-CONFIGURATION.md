# Access and settings security

Local mode binds to `127.0.0.1` and requires no access token. Use it only for a trusted local user. To listen on an external interface, explicitly pass `--host 0.0.0.0`; use `--multi-user` for a shared deployment. The container image explicitly binds to all interfaces and runs in shared mode.

Shared mode reads these settings at server startup:

- `JVMDIAG_WORKSPACE_TOKENS`: a JSON object mapping workspace names to unique random tokens, each at least 32 bytes. Workspace names must already be canonical (letters, digits, `_`, `-`, up to 64 characters). `default` is reserved for administrators.
- `JVMDIAG_ADMIN_TOKEN`: a separate random token of at least 32 bytes. Administrators can select workspaces and manage global settings, MAT installation and host JVM access.
- `JVMDIAG_PUBLIC_ORIGIN`: optional exact public origin, such as `https://diag.example.com`, when a reverse proxy terminates TLS. Do not include a trailing slash. Proxy headers alone are not trusted for origin validation.

Without valid credentials configured, shared API/MCP requests fail closed. Keep tokens in a secret manager and distribute each workspace's token only to its members; restart the server after rotating them. This is workspace-level access control, not per-person identity or an SSO implementation. Use HTTPS at the reverse proxy for remote access.

In the Web UI, enter your workspace name, then use **Server access token → Connect**. The token stays in page memory and is cleared by a reload. API and MCP HTTP clients must send `Authorization: Bearer <token>`. Remote CLI analysis reads that token from `JVMDIAG_ACCESS_TOKEN`. MCP configuration shown in the UI contains a placeholder; replace it with the appropriate access token in your client.

Workspace tokens cannot select another workspace, change global settings or the AI endpoint/TLS policy, install MAT, or access arbitrary host files and JVMs through MCP. Inline diagnostic content and uploaded artifacts remain available. Administrator access is required for host operations. Global setting updates require `applyGlobal: "true"`; the local default workspace retains its local settings workflow.

Changing an AI endpoint requires an explicitly supplied API key when retaining a saved workspace/global key would otherwise send it to a different provider. Workspace overrides never inherit the global key for a different endpoint or a less secure TLS policy. AI HTTP redirects are rejected. Browser requests from other origins are rejected.

The Markdown renderer is bundled locally (Marked 17.0.5, MIT; license in `internal/server/assets/js/LICENSE.marked.txt`). Rendered content is copied into an allowlist of HTML elements and HTTP(S) links; scripts, event handlers, images, embedded documents and arbitrary attributes are discarded. Other dynamic UI fields are encoded or inserted as text.
