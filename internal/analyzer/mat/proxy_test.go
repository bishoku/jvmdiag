package mat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bishoku/jvmdiag/internal/analyzer/mat"
)

func TestMATDownloadUsesEnvironmentProxy(t *testing.T) {
	// Go caches environment proxy configuration; isolate the actual downloader
	// in a child process so other tests and the operator's proxy cannot affect it.
	if os.Getenv("JVMDIAG_PROXY_TEST_CHILD") == "1" {
		svc := mat.NewServiceWithOptions("", t.TempDir(), "", "", mat.Options{SkipLegacy: true})
		err := svc.DownloadAndInstall()
		if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Fatalf("expected proxy rejection, got %v", err)
		}
		status := svc.Status()
		if status["downloading"] != false || !strings.Contains(status["error"].(string), "Proxy Authentication Required") {
			t.Fatalf("download failure missing from status: %+v", status)
		}
		return
	}
	requests := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- r.Method + " " + r.Host:
		default:
		}
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMATDownloadUsesEnvironmentProxy$", "-test.count=1")
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD", "JVMDIAG_PROXY_TEST_CHILD":
			continue
		}
		cmd.Env = append(cmd.Env, entry)
	}
	cmd.Env = append(cmd.Env, "JVMDIAG_PROXY_TEST_CHILD=1", "HTTPS_PROXY="+proxy.URL, "NO_PROXY=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("downloader proxy regression: %v\n%s", err, out)
	}
	select {
	case request := <-requests:
		if request != "CONNECT download.eclipse.org:443" {
			t.Fatalf("unexpected proxy request: %s", request)
		}
	default:
		t.Fatal("MAT downloader did not use the environment proxy")
	}
}
