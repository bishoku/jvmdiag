# Architecture and capabilities

1. **Single Binary with Optional JDK/MAT Tools:**
   - HTML templates and CSS are embedded directly into the Go binary via `//go:embed`.
   - No JVM or Maven required for native HPROF, text/JSON analysis or the UI. Binary JFR event decoding and live capture require JDK tools; MAT requires its own runtime.
2. **2-Tier Hybrid Heap Dump Engine (`.hprof`):**
   - **Tier 1 — Native Go Streaming `.hprof` Parser:** Validates supported HPROF 1.0.1/1.0.2 records with 4/8-byte identifiers. Extracts serialized payload histograms, package totals, largest payloads, exact duplicate primitive-array payloads, GC root record counts and available thread stacks. Native payload bytes are not runtime shallow/retained/live heap.
   - **Tier 2 — Optional Eclipse MAT Integration:** When installed (or downloaded from Settings), adds readable MAT report excerpts with their original metric labels. The OQL tool is unsupported until a validated query-result adapter is implemented.
3. **Dual-Mode Architecture (Personal PC + Shared Multi-User Server):**
   - **Workspace Isolation:** Shared mode requires workspace-scoped Bearer tokens. The Workspace Switcher, query parameter and header select a workspace; they do not grant access. Jobs, history, MCP sessions, chat and logs are checked against the authenticated workspace.
   - **Central AI Key + User Override:** Configure a default server-wide OpenRouter/OpenAI key, while allowing any workspace to override with its own API key or model.
   - **Worker Pool Semaphore:** Limits simultaneous heavy jobs; it does not provide a memory budget or guarantee against OOM.
4. **New Diagnostic Capabilities:**
   - **Multi-Snapshot Diff (`jvmdiag diff` & `/diff`):** Compare 2+ Thread Dumps to catch **stuck `RUNNABLE` threads** (threads whose top stack frame never moves across snapshots) or 2 `.hprof` Heap Dumps to identify **growing payload/count candidates**; growth alone does not prove a leak.
   - **Incident Correlation (`jvmdiag incident` & `/incident`):** Combine a GC Log + Thread Dump(s) + Heap Dump from the same incident for automated cross-artifact correlation.
   - **MCP Server (Streamable HTTP + Local Stdio):** Connect clients to `/mcp` using Streamable HTTP (JSON responses; no SSE), or locally via stdio (`jvmdiag mcp --file dump.hprof`). Shared HTTP clients must send a Bearer token.

See [diagnostic semantics](DIAGNOSTIC-SEMANTICS.md) for metric definitions and unsupported capabilities, and [security and configuration](SECURITY-AND-CONFIGURATION.md) for workspace authorization and settings.
