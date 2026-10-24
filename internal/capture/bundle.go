package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type commandRunner func(context.Context, string, ...string) ([]byte, error)

func runCommand(ctx context.Context, tool string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, tool, args...).CombinedOutput()
}

func CaptureBundle(ctx context.Context, opts Options) (*CapturedBundle, error) {
	return captureBundle(ctx, opts, runCommand)
}

func captureBundle(ctx context.Context, opts Options, run commandRunner) (bundle *CapturedBundle, resultErr error) {
	if opts.PID <= 0 {
		return nil, fmt.Errorf("valid --pid is required; PID 0 (all JVMs) is forbidden")
	}
	if opts.JFRDuration < 0 || opts.JFRDuration > 10*time.Minute {
		return nil, fmt.Errorf("JFR duration must be between 0 and 10m")
	}
	if opts.Count <= 0 {
		opts.Count = 3
	}
	if opts.Count > 10 {
		opts.Count = 10
	}
	if opts.Interval <= 0 {
		opts.Interval = 2 * time.Second
	}
	if opts.CommandTimeout <= 0 {
		opts.CommandTimeout = 30 * time.Second
	}
	root := ""
	if opts.Container {
		var err error
		root, err = targetRoot(opts.PID)
		if err != nil {
			return nil, err
		}
	}
	jcmd, jstack := findJDKTool("jcmd"), findJDKTool("jstack")
	if jcmd == "" && jstack == "" {
		return nil, fmt.Errorf("neither jcmd nor jstack found in PATH or $JAVA_HOME/bin; use the diagnostic JDK image")
	}
	if (opts.WithHeap || opts.JFRDuration > 0) && jcmd == "" {
		return nil, fmt.Errorf("requested heap/JFR capture requires jcmd")
	}
	if root != "" {
		status, err := os.ReadFile(filepath.Join(filepath.Dir(root), "status"))
		if err != nil {
			return nil, err
		}
		cleanup, err := prepareAttachBridge(root, "/tmp", string(status))
		if err != nil {
			return nil, err
		}
		defer cleanup()
	}

	outDir := opts.OutputDir
	var err error
	if outDir == "" {
		outDir, err = os.MkdirTemp("", fmt.Sprintf("jvmdiag-capture-%d-", opts.PID))
	} else {
		err = os.Mkdir(outDir, 0700)
	}
	if err != nil {
		return nil, fmt.Errorf("capture output directory must be new (existing paths are not overwritten): %w", err)
	}
	outDir, err = filepath.Abs(outDir)
	if err != nil {
		return nil, err
	}
	bundle = &CapturedBundle{PID: opts.PID, OutputDir: outDir, Status: "partial"}
	defer func() {
		if resultErr != nil {
			bundle.Error = resultErr.Error()
		} else {
			bundle.Status = "complete"
		}
		data, e := json.MarshalIndent(bundle, "", "  ")
		if e == nil {
			e = writePrivate(filepath.Join(outDir, "capture.json"), data)
		}
		if e != nil && resultErr == nil {
			bundle.Status = "partial"
			resultErr = fmt.Errorf("write capture manifest: %w", e)
		}
	}()
	call := func(tool string, args ...string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, opts.CommandTimeout)
		defer cancel()
		out, e := run(cctx, tool, args...)
		if cctx.Err() != nil {
			return out, cctx.Err()
		}
		return out, e
	}
	pid := strconv.Itoa(opts.PID)
	for i := 1; i <= opts.Count; i++ {
		if i > 1 {
			if err = wait(ctx, opts.Interval); err != nil {
				return bundle, err
			}
		}
		var data []byte
		var e error
		if jcmd != "" {
			data, e = call(jcmd, pid, "Thread.print", "-l")
		}
		if (e != nil || len(data) == 0) && jstack != "" {
			data, e = call(jstack, "-l", pid)
		}
		if e != nil {
			return bundle, fmt.Errorf("thread capture #%d: %w (%s); check matching JDK, attach enabled, target /tmp writable, PID namespace and UID/GID", i, e, strings.TrimSpace(string(data)))
		}
		if !strings.Contains(string(data), "Full thread dump") && !strings.Contains(string(data), "java.lang.Thread.State:") {
			return bundle, fmt.Errorf("thread command returned no recognizable thread dump: %s", strings.TrimSpace(string(data)))
		}
		path := filepath.Join(outDir, fmt.Sprintf("threaddump_%d.txt", i))
		if err = writePrivate(path, data); err != nil {
			return bundle, err
		}
		bundle.ThreadDumpPaths = append(bundle.ThreadDumpPaths, path)
	}
	if jcmd != "" {
		nmt, e := call(jcmd, pid, "VM.native_memory", "summary")
		if e == nil && strings.Contains(string(nmt), "Total:") {
			path := filepath.Join(outDir, "nmt_summary.txt")
			if err = writePrivate(path, nmt); err != nil {
				return bundle, err
			}
			bundle.NMTCrashPath = path
		} else if e == nil && strings.Contains(string(nmt), "Native memory tracking is not enabled") {
			bundle.Notes = append(bundle.Notes, "NMT unavailable: target was not started with -XX:NativeMemoryTracking=summary")
		} else {
			bundle.Notes = append(bundle.Notes, fmt.Sprintf("NMT unavailable (not assumed disabled): %v %s", e, strings.TrimSpace(string(nmt))))
		}
	} else {
		bundle.Notes = append(bundle.Notes, "NMT unavailable: jcmd is absent")
	}
	if err := ctx.Err(); err != nil {
		return bundle, err
	}
	if !opts.WithHeap && opts.JFRDuration == 0 {
		return bundle, nil
	}
	// JVM-created files use the target mount namespace. Stage in a private directory
	// there and copy through /proc/PID/root; a shared /tmp volume is not required.
	parent := opts.TargetDir
	if parent == "" {
		parent = os.TempDir()
		if root != "" {
			parent = "/tmp"
		}
	}
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent || strings.ContainsAny(parent, "\x00\r\n\t \"'") {
		return bundle, fmt.Errorf("target directory must be a clean absolute path without whitespace or quotes")
	}
	visibleParent := parent
	if root != "" {
		visibleParent = filepath.Join(root, parent)
	}
	staging, err := os.MkdirTemp(visibleParent, "jvmdiag-stage-")
	if err != nil {
		return bundle, fmt.Errorf("target staging directory must be writable by the JVM and accessible to the debugger: %w", err)
	}
	defer os.RemoveAll(staging)
	targetStaging := filepath.Join(parent, filepath.Base(staging))
	if opts.WithHeap {
		name := "heap.hprof"
		out, e := call(jcmd, pid, "GC.heap_dump", filepath.Join(targetStaging, name))
		if e != nil {
			return bundle, fmt.Errorf("requested heap dump failed: %w (%s)", e, strings.TrimSpace(string(out)))
		}
		path := filepath.Join(outDir, name)
		if err = copyArtifact(filepath.Join(staging, name), path, "JAVA PROFILE "); err != nil {
			return bundle, fmt.Errorf("requested heap dump unavailable: %w", err)
		}
		bundle.HeapDumpPath = path
	}
	if opts.JFRDuration > 0 {
		name := "jvmdiag_" + filepath.Base(staging)
		defer func() {
			// Cancellation must not leave our named recording running indefinitely.
			stopCtx, cancel := context.WithTimeout(context.Background(), opts.CommandTimeout)
			defer cancel()
			out, e := run(stopCtx, jcmd, pid, "JFR.stop", "name="+name)
			if e != nil || !strings.Contains(string(out), "Stopped recording") {
				bundle.Notes = append(bundle.Notes, "Could not confirm JFR cleanup; stop recording "+name+": "+strings.TrimSpace(string(out)))
				if resultErr == nil {
					resultErr = fmt.Errorf("JFR recording cleanup failed: %s", name)
				}
			}
		}()
		out, e := call(jcmd, pid, "JFR.start", "name="+name, "settings=profile")
		if e != nil || !strings.Contains(string(out), "Started recording") {
			if e != nil {
				return bundle, fmt.Errorf("requested JFR start failed: %w (%s)", e, strings.TrimSpace(string(out)))
			}
			return bundle, fmt.Errorf("requested JFR start failed: %s", strings.TrimSpace(string(out)))
		}

		if err = wait(ctx, opts.JFRDuration); err != nil {
			return bundle, err
		}
		out, e = call(jcmd, pid, "JFR.dump", "name="+name, "filename="+filepath.Join(targetStaging, "recording.jfr"))
		if e != nil {
			return bundle, fmt.Errorf("requested JFR dump failed: %w (%s)", e, strings.TrimSpace(string(out)))
		}
		path := filepath.Join(outDir, "recording.jfr")
		if err = copyArtifact(filepath.Join(staging, "recording.jfr"), path, "FLR\x00"); err != nil {
			return bundle, fmt.Errorf("requested JFR unavailable: %w", err)
		}
		bundle.JFRPath = path
	}
	return bundle, nil
}

func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func copyArtifact(src, dst, magic string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source is not a regular file")
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	header := make([]byte, len(magic))
	if _, err = io.ReadFull(f, header); err != nil {
		return err
	}
	if string(header) != magic {
		return fmt.Errorf("artifact has invalid header")
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, f)
	closeErr := out.Close()
	if err != nil {
		os.Remove(dst)
		return err
	}
	return closeErr
}
