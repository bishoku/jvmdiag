# Run the jvmdiag Web UI on Kubernetes or OpenShift

These examples run a persistent shared Web UI/API/MCP server. For temporary capture inside an application Pod, use the separate [ephemeral-container guide](kubernetes/README.md).

| Platform | Manifests | Identity and access |
| --- | --- | --- |
| Kubernetes | [kubernetes/server](kubernetes/server) | UID/GID/fsGroup 10001, ClusterIP Service; initially use port-forward |
| OpenShift | [openshift/server](openshift/server) | No fixed UID/GID/fsGroup; admission assigns namespace-compatible values; edge TLS Route |

Both examples use one replica, `Recreate`, a 50Gi RWO PVC, a writable disk-backed `/tmp`, a read-only image filesystem, dropped capabilities, no privilege escalation and no mounted ServiceAccount credentials. They need no Pod/ephemeral-container RBAC: uploaded-file analysis does not access application Pods. The existing `kubernetes/rbac.yaml` is for human ephemeral-container operators, not this server.

## Configure secrets, then deploy

The examples use the versioned server image `ghcr.io/bishoku/jvmdiag:0.0.4`. Prefer a verified digest for production. Resource values are a starting point, not capacity guarantees. Review [large dump limits and options](../docs/LARGE-DUMPS.md) before sizing storage and memory.

```sh
kubectl create namespace jvmdiag
# Generate DIFFERENT random tokens without putting literal secrets in shell history.
python3 - <<'PY' | kubectl -n jvmdiag apply -f -
import json, secrets
print(json.dumps({"apiVersion":"v1","kind":"Secret","metadata":{"name":"jvmdiag-access"},
 "type":"Opaque","stringData":{"JVMDIAG_ADMIN_TOKEN":secrets.token_hex(32),
 "JVMDIAG_WORKSPACE_TOKENS":json.dumps({"payments-team":secrets.token_hex(32)})}}))
PY
kubectl -n jvmdiag apply -k deploy/kubernetes/server
kubectl -n jvmdiag rollout status deployment/jvmdiag
kubectl -n jvmdiag port-forward service/jvmdiag 8080:8080
```

Open `http://localhost:8080`. Retrieve the workspace token through your approved secret-management workflow and enter `payments-team` and its token using **Server access token → Connect**. The administrator token is for global settings and MAT installation; do not distribute it as a workspace token. [The Secret template](server-examples/access-secret.example.yaml) is an alternative for an existing secret manager; replace its placeholders before applying. Never commit populated secrets.

For OpenShift, use `oc new-project jvmdiag` instead of creating the namespace above, create the same secret in that project, then:

```sh
# First replace jvmdiag.apps.example.com in BOTH files:
# deploy/openshift/server/route.yaml
# deploy/openshift/server/deployment.yaml (JVMDIAG_PUBLIC_ORIGIN)
oc -n jvmdiag apply -k deploy/openshift/server
oc -n jvmdiag rollout status deployment/jvmdiag
oc -n jvmdiag get route jvmdiag
```

Use the HTTPS Route URL. Edge TLS encrypts browser-to-router traffic; router-to-Service traffic is HTTP. Use an organization-approved re-encrypt/mesh design if that hop must also be encrypted. The Route's 30-minute timeout is an example inactivity timeout, not an application processing-time guarantee. The public origin must match the browser origin exactly, with no trailing slash. For Kubernetes ingress, configure TLS, that same origin, upload limits and timeouts for your installed controller; no controller-specific ingress is enabled by default.

The OpenShift example relies on `restricted-v2` admission and a storage driver honoring the assigned supplemental/fsGroup permissions on the mounted PVC. It does not require `anyuid`, privileged SCC or a root init container. If storage does not support those permissions, provision suitable storage with the platform administrator. Do not copy the Kubernetes fixed IDs into a namespace whose SCC rejects them. TCP probes check that the socket is listening, not credentials, disk capacity, Java availability or successful analysis.

## Persistence and scaling

`/data` contains configuration, history, uploads, MCP artifact/session files and downloaded MAT. Back up the PVC; do not delete it to restart or upgrade the application. Analyze jobs and active sessions are process-local. A Pod restart interrupts active work; queued work is not a durable distributed queue. A shared PVC and more replicas do not make jobs highly available. Keep one replica until coordination/session routing is implemented. `Recreate` causes upgrade downtime and avoids simultaneous writers and RWO multi-attach conflicts.

## Binary JFR and Eclipse MAT

The default Alpine server image has no JDK or MAT. Native HPROF/text analysis works, but downloading MAT alone does not provide its Java runtime. For Java-dependent features, change the container image to the versioned `ghcr.io/bishoku/jvmdiag:0.0.4-diagnostic-jdk25` (or your validated full-JDK server build) and keep the **server args and both volume mounts** from these manifests. The diagnostic image normally starts CLI help; the explicit `serve` args here make it run the UI. Its numeric default user is overridden by OpenShift admission. Validate the JDK/MAT combination on your architecture; a diagnostic image running the server does not grant access to JVMs in other Pods.

For preinstalled MAT and a full JDK, build the [optional MAT image](../docs/MAT-IMAGE.md) and use it from your internal registry. It avoids runtime MAT downloads, including in Kerberos-only proxy environments.

MAT downloads under `/data/mat`; alternatively mount a preinstalled distribution read-only and set `APP_MAT_HOME` to its installation directory. Use writable dump/index storage, and do not mount the MAT runtime over `/data` itself. For Kerberos-only proxy environments, download/extract MAT in an authenticated browser and preinstall it for the backend; environment proxy variables alone do not provide Kerberos negotiation. See [manual MAT installation](../docs/MAT-PROXY.md#manual-installation-with-a-browser-download).

## Proxy and corporate CA

Optionally create the [proxy Secret](server-examples/proxy-secret.example.yaml). Both deployments read it at startup. For a corporate HTTPS inspection CA on Linux:

```sh
kubectl -n jvmdiag create configmap jvmdiag-corporate-ca --from-file=corporate-ca.crt=/path/to/approved-corporate-ca.crt
kubectl -n jvmdiag patch deployment jvmdiag --type=strategic --patch-file deploy/server-examples/proxy-ca.patch.yaml
kubectl -n jvmdiag rollout restart deployment/jvmdiag
```

Use `oc` for the same operations on OpenShift. The patch adds the approved CA directory without hiding system certificates. It configures the Go downloader's trust; Java/MAT trust stores are separate. Restart after changing proxy/CA settings. Do not add TLS bypass settings. Make the patch part of your maintained overlay so reapplying the base manifests does not undo deployment configuration.

## Validation scope

Both Kustomizations were rendered and checked for selector/security/route consistency; the Kubernetes resources passed server-side dry-run on local MicroK8s. The published server image was also smoke-tested with arbitrary UID/GID 0, writable data/tmp and read-only root. The manifests are examples, not an installed cluster change. Validate against your cluster's admission/storage/router configuration with server-side dry-run before deployment. OpenShift SCC and Route behavior require a real OpenShift cluster; Kubernetes schema validation alone does not verify them. See [security configuration](../docs/SECURITY-AND-CONFIGURATION.md) and [large dumps](../docs/LARGE-DUMPS.md) for operational boundaries.
