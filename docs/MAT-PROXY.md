# Eclipse MAT download behind a corporate proxy

## Why a browser download can work while Settings fails

The browser sends an authenticated request to `POST /api/mat/download`; the **jvmdiag backend** downloads MAT. It does not use the browser's proxy/PAC settings, proxy login session or browser-specific certificate store. A successful browser download therefore does not prove that the server/Pod can fetch the same URL.

Current code uses Go's default HTTP transport with a **45-minute total download timeout**. It already supports `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and lowercase equivalents through [Go's ProxyFromEnvironment](https://pkg.go.dev/net/http#ProxyFromEnvironment). It does not interpret browser/system PAC or WPAD configuration. Proxy configuration is process environment, not a MAT Web UI setting. Environment-based proxy selection is cached by Go; restart the process/Pod after changing it. AI provider TLS settings do not configure the MAT downloader.

### Reported environment: Kerberos proxy and blocked direct egress

The reported PC gets a **connection timeout**, direct internet access is blocked by the firewall, and the browser authenticates to the proxy using **Kerberos**. This is consistent with the backend lacking a working authenticated proxy path; the exact connection attempt has not been traced. jvmdiag's default Go transport does not negotiate Kerberos/SPNEGO proxy authentication or reuse the browser's authenticated session. Setting `HTTPS_PROXY` alone does not supply that capability, and adding a CA does not solve Kerberos authentication.

For this environment, the recommended supported workflow is **download in the authenticated browser, extract MAT, configure `APP_MAT_HOME`, then run analysis locally**. No downloader change, browser-cookie transfer, Kerberos credential export or TLS bypass is required. Follow [the manual installation steps below](#manual-installation-with-a-browser-download).

The CONNECT-proxy regression checks environment-proxy routing and 407 error reporting only; it is not a Kerberos implementation or a reproduction of this organization's firewall.

## Get the real backend error first

Use **Settings → Eclipse MAT** status, server logs, or (as administrator in shared mode):

```sh
# JVMDIAG_ACCESS_TOKEN must be the ADMIN token for these host/global operations.
curl --fail --silent --show-error \
  -H "Authorization: Bearer $JVMDIAG_ACCESS_TOKEN" \
  http://127.0.0.1:8080/api/mat/status
```

Inspect `error`, `status`, `downloading`, `downloadedBytes` and `totalBytes`. The initial download API response only means background work started; it does not mean the archive was downloaded or installed. Redact credentials, user names and internal hostnames before sharing logs.

| Error / symptom | Check or remedy |
| --- | --- |
| Connection refused, DNS error or timeout | Process/Pod proxy environment, proxy reachability and NetworkPolicy/egress rules. Browser configuration is separate. |
| HTTP 407 / Proxy Authentication Required | Provide the proxy's supported authentication. Browser-integrated NTLM/Kerberos/SSO is not automatically available to Go. Use an approved local gateway/forwarder or offline installation if required by IT. |
| `x509: certificate signed by unknown authority` | Install the approved corporate CA in the **backend's** trust store; browser trust may differ. |
| TLS name/expiry errors | Correct the proxy/certificate chain or hostname; do not disable verification. |
| 403, HTML login/block page or ZIP extraction error | Verify policy for the final download/redirect host and whether an actual ZIP was returned. |
| Download succeeds but MAT cannot run | Full compatible Java runtime, executable permissions, correct OS/architecture and libc dependencies; the minimal Alpine server image has no JDK and is not a generic glibc MAT runtime. |
| Permission/disk errors | Writable `/data/mat`, enough archive + extracted-runtime space, and PVC ownership for the Pod identity. |

The configured source is currently MAT **1.16.1**, build **20250109**:

```text
https://download.eclipse.org/mat/1.16.1/rcp/MemoryAnalyzer-1.16.1.20250109-linux.gtk.x86_64.zip
```

ARM64 uses `linux.gtk.aarch64.zip`; Windows/macOS use their platform archive. Check the URL for the installed jvmdiag version rather than assuming today's latest MAT. Allow required redirect destinations through the proxy; Go follows ordinary download redirects. The downloader has no custom-mirror URL setting or separately configured proxy credentials UI today.

## Supply proxy settings to the backend

For a local process launched from a shell:

```sh
HTTPS_PROXY=http://proxy.corp.example:3128 \
HTTP_PROXY=http://proxy.corp.example:3128 \
NO_PROXY=localhost,127.0.0.1,.svc,.cluster.local \
jvmdiag serve --port 8080
```

`HTTPS_PROXY=http://...` is normal for an HTTP CONNECT proxy carrying HTTPS traffic. Use the explicit proxy endpoint provided by IT. A desktop launcher, Windows service or systemd service needs its own environment configuration; setting variables in an unrelated terminal is insufficient. Docker does not automatically pass every host proxy setting to a running container; set the container environment explicitly.

For Basic proxy authentication, a URL may include percent-encoded credentials. Keep that URL in a private service environment/Secret, not source control, command-line literals, screenshots or logs. Go's default transport does not reproduce a browser's interactive proxy-authentication flow. Proxy settings may also affect other Go HTTP clients using the default transport; this is not a MAT-only network configuration.

For Kubernetes/OpenShift, use the optional [proxy Secret](../deploy/server-examples/proxy-secret.example.yaml) and [deployment guide](../deploy/README.md), then restart the Deployment. Include internal destinations in `NO_PROXY` according to your network; do not bypass the proxy for Eclipse when direct internet access is unavailable.

## Trust a corporate inspection CA

On Linux, Go supports `SSL_CERT_FILE` and `SSL_CERT_DIR`; see [SystemCertPool](https://pkg.go.dev/crypto/x509#SystemCertPool). A custom CA bundle must retain the public roots needed by other destinations. Mounting only a corporate root over the image's system bundle can break unrelated HTTPS requests.

The provided [CA patch](../deploy/server-examples/proxy-ca.patch.yaml) mounts an additional ConfigMap directory and uses `SSL_CERT_DIR=/etc/ssl/certs:/etc/jvmdiag-ca`. Obtain the CA from your organization's approved source. Do not download an unverified certificate from an arbitrary error page. On Windows/macOS, use the appropriate backend service/account system trust configuration; Linux certificate-file variables are not a portable substitute for OS trust setup. MAT/Java trust stores are separate from the Go downloader.

The downloader does **not** offer an insecure TLS bypass. The AI provider's skip-TLS option is unrelated and should not be used to solve MAT download problems.

## Manual installation with a browser download

1. On a machine/browser with approved Kerberos proxy access, open the exact Eclipse MAT download URL for the **backend's OS and CPU architecture**. For the current jvmdiag version, the Linux AMD64 URL is shown above; choose the Windows ZIP or appropriate macOS/ARM64 archive when needed. If downloading on a different PC, select the destination server's platform, not the browser PC's platform.
2. Download the complete archive and verify its source/integrity through Eclipse's published verification procedure. Transfer it to the backend host through your approved file-transfer process if necessary.
3. Extract the **whole archive**, preserving the launcher, `plugins`, configuration and other dependencies. Do not copy only `ParseHeapDump.sh`/`.bat`. A ZIP may contain an extra `mat` subdirectory; use the actual installation directory in the examples below.
4. Install a compatible full JDK on the backend and make `java` available in PATH or `JAVA_HOME`. Downloading MAT does not install Java. Check the chosen MAT distribution's Java requirements.
5. Set `APP_MAT_HOME` in the environment of the process that starts jvmdiag, and restart it. A setting in a separate terminal does not update a running process or service.

### Linux

For example, if the extracted installation is `/opt/tools/mat`:

```sh
# These checks must succeed before starting the application.
java -version
test -f /opt/tools/mat/ParseHeapDump.sh
# Preserve/set executable permissions on the trusted extracted Linux launchers.
chmod u+x /opt/tools/mat/ParseHeapDump.sh /opt/tools/mat/MemoryAnalyzer
APP_MAT_HOME=/opt/tools/mat jvmdiag serve --port 8080
```

Use an installation location readable/executable by the jvmdiag service identity. A service deployment must set the variable in its service environment and restart through its service manager. On macOS, point to the extracted MAT installation/app bundle; the resolver searches subdirectories for the parse script. Use the macOS archive rather than Linux binaries.

### Windows PowerShell

For example, if the ZIP was extracted under `C:\Tools` and the parse script is in `C:\Tools\mat`:

```powershell
java -version
Test-Path 'C:\Tools\mat\ParseHeapDump.bat'  # Must return True.
$env:APP_MAT_HOME = 'C:\Tools\mat'
.\jvmdiag.exe serve --port 8080
```

The variable above applies to the current PowerShell and child process. If a Windows service or desktop launcher starts jvmdiag, configure its environment instead and restart it. Do not use Linux `export` syntax in PowerShell. Use the Windows archive and keep the accompanying executable/dependencies together.

### Verify and use it

Open **Settings → Eclipse MAT** and confirm that MAT is installed and the detected `scriptPath` points to your extracted installation. If it is detected, there is no need to click Download. `APP_MAT_HOME` takes precedence over the automatic download directory. The status endpoint shown above can also confirm the detected script.

Then request **deep MAT analysis** in the UI, or test a small trusted HPROF through the CLI using the same environment:

```sh
APP_MAT_HOME=/opt/tools/mat jvmdiag analyze /data/test.hprof --deep-mat --no-ai
```

In PowerShell, keep `$env:APP_MAT_HOME` set and run `.\jvmdiag.exe analyze C:\Dumps\test.hprof --deep-mat --no-ai`. Check that the report includes actual MAT output/engine `native-hprof+eclipse-mat`; a `limited` report saying MAT failed or was unavailable is native-only analysis. Script discovery alone does not validate Java, executable dependencies, heap sizing or a successful MAT run.

Once installed, analysis of local files does not require downloading MAT again. `--no-ai` also avoids AI provider requests during this verification. See [large dump sizing](LARGE-DUMPS.md) before using a large production dump.

### Containers, Kubernetes and OpenShift

The [optional MAT image](MAT-IMAGE.md) bundles MAT and a full JDK at build time, avoiding downloads from running Pods.

Downloading in your laptop browser does not install MAT in a remote Pod. Put the verified extracted distribution into an approved compatible full-JDK image, or mount/copy it into storage visible to the server. Configure `APP_MAT_HOME` inside the container and restart the Deployment. Preserve writable storage for dump files, MAT indexes and any runtime configuration the chosen distribution needs. Test read-only runtime mounts with that distribution before adopting them.

The default Alpine server image has no JDK and is not a generic glibc MAT runtime. Use the full-JDK image option from the [deployment guide](../deploy/README.md). Mounting the ZIP or the laptop's Windows MAT directory into a Linux Pod will not provide a working Linux installation. There is no Web UI archive-upload installer today.

The automatic installer currently has no separate checksum/signature verification step. A preverified, versioned runtime is appropriate for controlled environments; keep its version and redistribution notices with your installation.

## Reproduce from the same environment

Run a request from the same host/container identity and network as the backend. For example, where curl is installed, `curl --fail --location --output /dev/null 'THE_EXACT_PLATFORM_URL'` can test reachability while honoring its own proxy environment. Curl/browser success alone still does not validate the Go trust store or authentication behavior. The minimal server image does not include curl; use an approved diagnostic environment instead of installing tools into a running production Pod.

If troubleshooting beyond manual installation is needed, collect the jvmdiag version/OS, launch method and redacted MAT error. Do not share proxy passwords, browser cookies or Kerberos tickets.
