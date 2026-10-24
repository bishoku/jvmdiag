package mat

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bishoku/jvmdiag/internal/analyzer/hprof"
)

const (
	matVersion   = "1.16.1"
	matDate      = "20250109"
	downloadBase = "https://download.eclipse.org/mat/" + matVersion + "/rcp/MemoryAnalyzer-" + matVersion + "." + matDate
)

var (
	scriptRe   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	styleRe    = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	commentRe  = regexp.MustCompile(`(?is)<!--.*?-->`)
	thSepRe    = regexp.MustCompile(`(?i)</th>\s*<th`)
	tdSepRe    = regexp.MustCompile(`(?i)</td>\s*<td`)
	brRe       = regexp.MustCompile(`(?i)<br\s*/?>`)
	blockEndRe = regexp.MustCompile(`(?i)</(p|tr|li|h[1-6])>`)
	tagRe      = regexp.MustCompile(`<[^>]+>`)
	spacesRe   = regexp.MustCompile(`[ \t]+`)
	nlSpaceRe  = regexp.MustCompile(`\n[ \t]+`)
	multiNlRe  = regexp.MustCompile(`\n{3,}`)
	detailRe   = regexp.MustCompile(`^(?:pages/)?\d+\.html$`)
)

type Options struct{ SkipLegacy bool }

type Service struct {
	mu                sync.RWMutex
	configuredHome    string
	autoDownloadDir   string
	legacyDownloadDir string
	matHeapSize       string
	maxMatMemory      string
	downloading       bool
	downloadStatus    string
	downloadError     string
	downloadProgress  int
	downloadedBytes   int64
	totalBytes        int64
}

func NewService(configuredHome, baseDir, matHeapSize, maxMatMemory string) *Service {
	return NewServiceWithOptions(configuredHome, baseDir, matHeapSize, maxMatMemory, Options{})
}

func NewServiceWithOptions(configuredHome, baseDir, matHeapSize, maxMatMemory string, opts Options) *Service {
	home, _ := os.UserHomeDir()
	legacy := ""
	if !opts.SkipLegacy {
		legacy = filepath.Join(home, ".jvm-diagnostics", "mat")
	}
	svc := &Service{
		configuredHome:    configuredHome,
		autoDownloadDir:   filepath.Join(baseDir, "mat"),
		legacyDownloadDir: legacy,
		matHeapSize:       matHeapSize,
		maxMatMemory:      maxMatMemory,
	}
	if script := svc.ResolveParseScript(); script != "" {
		svc.downloadStatus = "Installed at " + script
		svc.downloadProgress = 100
	}
	return svc
}

// ResolveParseScript searches configured and auto-download directories (including macOS .app bundles,
// Linux mat/ directories, and Windows mat/ directories) for ParseHeapDump.sh or ParseHeapDump.bat.
func (s *Service) ResolveParseScript() string {
	candidates := []string{
		s.configuredHome,
		s.autoDownloadDir,
		s.legacyDownloadDir,
	}
	scriptNames := []string{"ParseHeapDump.sh", "ParseHeapDump.bat"}
	if runtime.GOOS == "windows" {
		scriptNames = []string{"ParseHeapDump.bat", "ParseHeapDump.sh"}
	}

	for _, root := range candidates {
		if root == "" {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		var found string
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			for _, target := range scriptNames {
				if strings.EqualFold(d.Name(), target) {
					found = path
					return fs.SkipAll
				}
			}
			return nil
		})
		if found != "" {
			ensurePlatformExecutables(found)
			return found
		}
	}
	return ""
}

func (s *Service) IsAvailable() bool {
	return s.ResolveParseScript() != ""
}

func (s *Service) Status() map[string]any {
	scriptPath := s.ResolveParseScript()
	avail := scriptPath != ""

	s.mu.RLock()
	defer s.mu.RUnlock()

	statusText := s.downloadStatus
	prog := s.downloadProgress
	if avail && !s.downloading {
		if statusText == "" {
			statusText = "Installed at " + scriptPath
		}
		prog = 100
	}

	return map[string]any{
		"available":       avail,
		"scriptPath":      scriptPath,
		"downloading":     s.downloading,
		"status":          statusText,
		"error":           s.downloadError,
		"progress":        prog,
		"downloadedBytes": s.downloadedBytes,
		"totalBytes":      s.totalBytes,
		"nativeFallback":  true,
	}
}

func (s *Service) CalculateMatHeap(fileSizeBytes int64) string {
	if strings.TrimSpace(s.matHeapSize) != "" {
		return strings.TrimSpace(s.matHeapSize)
	}
	target := int64(float64(fileSizeBytes) * 1.2)
	maxBytes := parseMemString(s.maxMatMemory)
	if maxBytes > 0 && target > maxBytes {
		target = maxBytes
	}
	minBytes := int64(2 * 1024 * 1024 * 1024)
	if target < minBytes {
		target = minBytes
	}
	return fmt.Sprintf("%dm", target/(1024*1024))
}

func (s *Service) DownloadAndInstall() error {
	if script := s.ResolveParseScript(); script != "" {
		s.setProgress(fmt.Sprintf("Eclipse MAT is already installed (%s)", script), 100, 0, 0, "")
		return nil
	}

	s.mu.Lock()
	if s.downloading {
		s.mu.Unlock()
		return nil
	}
	s.downloading = true
	s.downloadError = ""
	s.downloadStatus = "Connecting to Eclipse MAT mirror..."
	s.downloadProgress = 2
	s.downloadedBytes = 0
	s.totalBytes = 0
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.downloading = false
		s.mu.Unlock()
	}()

	url := downloadURL()
	log.Printf("[MAT] Starting Eclipse MAT download from %s", url)
	s.setProgress(fmt.Sprintf("Connecting to %s...", url), 3, 0, 0, "")

	if err := os.MkdirAll(s.autoDownloadDir, 0o755); err != nil {
		s.failDownload("Failed creating directory: " + err.Error())
		return err
	}

	zipPath := filepath.Join(s.autoDownloadDir, "mat-download.zip")
	client := &http.Client{
		Timeout: 45 * time.Minute,
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		s.failDownload("Invalid download URL: " + err.Error())
		return err
	}
	req.Header.Set("User-Agent", "jvmdiag/3.0")

	resp, err := client.Do(req)
	if err != nil {
		s.failDownload("Network error while downloading MAT: " + err.Error())
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("HTTP %d from Eclipse mirror (%s)", resp.StatusCode, url)
		s.failDownload(err.Error())
		return err
	}

	out, err := os.Create(zipPath)
	if err != nil {
		s.failDownload("Cannot create zip file: " + err.Error())
		return err
	}

	contentLen := resp.ContentLength
	if contentLen <= 0 {
		// Standard MAT zip is ~100-150 MB; use 110 MB as estimated denominator if header omitted
		contentLen = 110 * 1024 * 1024
	}

	buf := make([]byte, 64*1024)
	var totalRead int64
	lastUpdate := time.Now()
	startTime := time.Now()

	s.setProgress("Downloading Eclipse MAT...", 5, 0, contentLen, "")

	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				s.failDownload("Disk write error: " + werr.Error())
				return werr
			}
			totalRead += int64(n)

			if time.Since(lastUpdate) >= 250*time.Millisecond {
				lastUpdate = time.Now()
				prog := 5 + int(80.0*float64(totalRead)/float64(contentLen))
				if prog > 85 {
					prog = 85
				}
				elapsedSec := time.Since(startTime).Seconds()
				speedMB := 0.0
				if elapsedSec > 0 {
					speedMB = (float64(totalRead) / (1024 * 1024)) / elapsedSec
				}
				msg := fmt.Sprintf("Downloading Eclipse MAT... %.1f MB / %.1f MB (%.1f MB/s)",
					float64(totalRead)/(1024*1024),
					float64(contentLen)/(1024*1024),
					speedMB)
				s.setProgress(msg, prog, totalRead, contentLen, "")
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			s.failDownload("Download stream interrupted: " + rerr.Error())
			return rerr
		}
	}
	out.Close()

	log.Printf("[MAT] Download finished (%.1f MB). Extracting archive to %s...", float64(totalRead)/(1024*1024), s.autoDownloadDir)
	s.setProgress("Extracting Eclipse MAT archive...", 90, totalRead, totalRead, "")

	if err := extractZip(zipPath, s.autoDownloadDir); err != nil {
		s.failDownload("Extraction failed: " + err.Error())
		return err
	}
	_ = os.Remove(zipPath)

	script := s.ResolveParseScript()
	if script == "" {
		err := fmt.Errorf("archive extracted to %s, but ParseHeapDump script was not found inside", s.autoDownloadDir)
		s.failDownload(err.Error())
		return err
	}

	log.Printf("[MAT] Eclipse MAT installed successfully! Script: %s", script)
	s.setProgress("Eclipse MAT installed successfully at "+script, 100, totalRead, totalRead, "")
	return nil
}

func (s *Service) setProgress(msg string, progress int, downloaded, total int64, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadStatus = msg
	s.downloadProgress = progress
	s.downloadedBytes = downloaded
	s.totalBytes = total
	s.downloadError = errMsg
}

func (s *Service) failDownload(errMsg string) {
	log.Printf("[MAT] ERROR: %s", errMsg)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadError = errMsg
	s.downloadStatus = "Download failed: " + errMsg
	s.downloadProgress = 0
}

// ensurePlatformExecutables fixes executable permissions on Linux/macOS and links
// the macOS MemoryAnalyzer.app bundle binary when needed.
func ensurePlatformExecutables(parseScriptPath string) {
	if runtime.GOOS == "windows" {
		return
	}
	_ = os.Chmod(parseScriptPath, 0o755)
	eclipseDir := filepath.Dir(parseScriptPath)
	expectedBin := filepath.Join(eclipseDir, "MemoryAnalyzer")
	if _, err := os.Stat(expectedBin); err == nil {
		_ = os.Chmod(expectedBin, 0o755)
		return
	}
	macOSBin := filepath.Clean(filepath.Join(eclipseDir, "..", "MacOS", "MemoryAnalyzer"))
	if _, err := os.Stat(macOSBin); err == nil {
		_ = os.Chmod(macOSBin, 0o755)
		_ = os.Symlink(macOSBin, expectedBin)
	}
}

// buildMatCommand constructs a cross-platform *exec.Cmd for Windows, Linux, and macOS.
// On Windows, if MemoryAnalyzer.exe is present alongside ParseHeapDump.bat, it invokes
// MemoryAnalyzer.exe directly with -consolelog -nosplash -application org.eclipse.mat.api.parse
// to avoid cmd.exe batch argument splitting issues on '=' and quotes.
func (s *Service) buildMatCommand(ctx context.Context, script string, hprofPath string, extraArgs ...string) *exec.Cmd {
	dir := filepath.Dir(script)
	xmx := "-Xmx" + s.CalculateMatHeap(fileSizeOrZero(hprofPath))

	// Check if MemoryAnalyzer.exe (Windows) or MemoryAnalyzer (Linux/macOS) can be invoked directly
	var directBin string
	if runtime.GOOS == "windows" {
		cand := filepath.Join(dir, "MemoryAnalyzer.exe")
		if _, err := os.Stat(cand); err == nil {
			directBin = cand
		}
	} else {
		cand := filepath.Join(dir, "MemoryAnalyzer")
		if _, err := os.Stat(cand); err == nil {
			directBin = cand
		}
	}

	var cmd *exec.Cmd
	if directBin != "" {
		args := []string{
			"-consolelog",
			"-nosplash",
			"-application", "org.eclipse.mat.api.parse",
			hprofPath,
		}
		if javaBin := resolveJavaBinary(); javaBin != "" {
			args = append([]string{"-vm", javaBin}, args...)
		}
		args = append(args, extraArgs...)
		args = append(args, "-vmargs", xmx, "-Djava.awt.headless=true")
		cmd = exec.CommandContext(ctx, directBin, args...)
	} else {
		args := []string{hprofPath}
		args = append(args, extraArgs...)
		args = append(args, "-vmargs", xmx, "-Djava.awt.headless=true")
		cmd = exec.CommandContext(ctx, script, args...)
	}

	cmd.Dir = filepath.Dir(hprofPath)
	return cmd
}

func resolveJavaBinary() string {
	javaName := "java"
	if runtime.GOOS == "windows" {
		javaName = "java.exe"
	}
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		cand := filepath.Join(jh, "bin", javaName)
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if p, err := exec.LookPath(javaName); err == nil {
		return p
	}
	return ""
}

func fileSizeOrZero(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

// RunHeadless executes Eclipse MAT on hprofPath and extracts its structured report.
func (s *Service) RunHeadless(ctx context.Context, hprofPath string) (string, error) {
	script := s.ResolveParseScript()
	if script == "" {
		return "", fmt.Errorf("Eclipse MAT is not installed")
	}

	if _, err := os.Stat(hprofPath); err != nil {
		return "", err
	}

	cmd := s.buildMatCommand(ctx, script, hprofPath,
		"org.eclipse.mat.api:suspects",
		"org.eclipse.mat.api:overview",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("MAT exited with error: %v\n%s", err, string(out))
	}

	return BuildReportFromDir(filepath.Dir(hprofPath))
}

func BuildReportFromDir(dir string) (string, error) {
	sections := 0
	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════\n")
	sb.WriteString("  ECLIPSE MAT — DEEP HEAP DUMP ANALYSIS\n")
	sb.WriteString("═══════════════════════════════════════════════════════════\n\n")

	suspectsZip := findZip(dir, "*_Leak_Suspects.zip")
	overviewZip := findZip(dir, "*_System_Overview.zip")

	if suspectsZip != "" {
		if sum := extractZipEntryText(suspectsZip, "index.html"); sum != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 1: LEAK SUSPECTS (RETAINED HEAP & GC ROOTS) ━━━\n")
			sb.WriteString(truncate(sum, 4000) + "\n\n")
		}
		if det := extractSuspectDetails(suspectsZip, 3); det != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 2: SUSPECT DETAILS (SHORTEST PATHS TO GC ROOTS) ━━━\n")
			sb.WriteString(truncate(det, 3000) + "\n\n")
		}
	}

	if overviewZip != "" {
		if hist := extractZipKeywordText(overviewZip, "histogram", "class_statistics", "index"); hist != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 3: CLASS REPORT EXCERPT (ORIGINAL METRIC LABELS) ━━━\n")
			sb.WriteString(truncate(filterTopLines(hist, 25), 2000) + "\n\n")
		}
		if pkgs := extractZipKeywordText(overviewZip, "top_component", "package", "biggest_objects"); pkgs != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 4: PACKAGE REPORT EXCERPT (ORIGINAL METRIC LABELS) ━━━\n")
			sb.WriteString(truncate(filterTopLines(pkgs, 15), 1500) + "\n\n")
		}
		if props := extractZipKeywordText(overviewZip, "system_properties", "environment"); props != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 5: JVM SYSTEM PROPERTIES ━━━\n")
			sb.WriteString(truncate(props, 800) + "\n\n")
		}
		if th := extractZipKeywordText(overviewZip, "thread"); th != "" {
			sections++
			sb.WriteString("━━━ MAT SECTION 6: THREAD OVERVIEW ━━━\n")
			sb.WriteString(truncate(filterTopLines(th, 20), 800) + "\n")
		}
	}

	if sections == 0 {
		return "", fmt.Errorf("no readable MAT report sections found in %s", dir)
	}
	return sb.String(), nil
}

// Hybrid Query Methods (use MAT ZIP/CLI if available on the parsed session, else Native Go HPROF summary!)

func (s *Service) QueryHeapSummary(hprofPath string, native *hprof.Summary) string {
	dir := filepath.Dir(hprofPath)
	overviewZip := findZip(dir, "*_System_Overview.zip")
	if overviewZip != "" {
		var sb strings.Builder
		sb.WriteString("=== MAT HEAP REPORT EXCERPT (original metric labels preserved) ===\n\n")
		if native != nil {
			sb.WriteString(native.Assessment.ContextReport() + "\n")
		}
		if idx := extractZipEntryText(overviewZip, "index.html"); idx != "" {
			sb.WriteString(idx + "\n\n")
		}
		if props := extractZipKeywordText(overviewZip, "system_properties", "environment"); props != "" {
			sb.WriteString("--- JVM System Properties ---\n")
			sb.WriteString(truncate(props, 1500) + "\n")
		}
		return truncate(sb.String(), 8000)
	}

	if native != nil {
		var sb strings.Builder
		sb.WriteString("=== HEAP DUMP SUMMARY (Native HPROF Engine) ===\n\n")
		sb.WriteString(native.Assessment.ContextReport() + "\n")
		sb.WriteString(fmt.Sprintf("File: %s (%s)\n", native.FileName, hprof.FormatBytes(native.FileSize)))
		sb.WriteString(fmt.Sprintf("Format: %s (%d-bit)\n", native.FormatVersion, native.IdentifierSize*8))
		sb.WriteString(fmt.Sprintf("Total Serialized Payload: %s\n", hprof.FormatBytes(native.TotalPayloadBytes)))
		sb.WriteString(fmt.Sprintf("Decoded object/array records (liveness unknown): %d\n", native.TotalInstances))
		sb.WriteString(fmt.Sprintf("Total Loaded Classes: %d\n\n", native.TotalClasses))
		sb.WriteString("GC Roots Breakdown:\n")
		for k, v := range native.GCRootCounts {
			sb.WriteString(fmt.Sprintf("  %-24s %d\n", k+":", v))
		}
		return sb.String()
	}
	return "No heap summary available."
}

func (s *Service) QueryLeakSuspects(hprofPath string, native *hprof.Summary) string {
	dir := filepath.Dir(hprofPath)
	suspectsZip := findZip(dir, "*_Leak_Suspects.zip")
	if suspectsZip != "" {
		var sb strings.Builder
		sb.WriteString("=== LEAK SUSPECTS (Eclipse MAT) ===\n\n")
		if idx := extractZipEntryText(suspectsZip, "index.html"); idx != "" {
			sb.WriteString(idx + "\n\n")
		}
		if det := extractSuspectDetails(suspectsZip, 5); det != "" {
			sb.WriteString(det + "\n")
		}
		return truncate(sb.String(), 12000)
	}

	if native != nil {
		var sb strings.Builder
		sb.WriteString("=== CONCENTRATION HYPOTHESES (Native HPROF Engine) ===\n\n")
		sb.WriteString(native.Assessment.Report() + "\n")
		if len(native.LeakSuspects) == 0 {
			sb.WriteString("No class crossed the payload concentration threshold; this is not a leak verdict.\n")
		} else {
			for i, ls := range native.LeakSuspects {
				sb.WriteString(fmt.Sprintf("Suspect #%d: %s\n", i+1, ls.Title))
				sb.WriteString(fmt.Sprintf("  Class/Pkg: %s\n", ls.ClassName))
				sb.WriteString(fmt.Sprintf("  Size:      %s (%.1f%% of serialized payload, %d instances)\n",
					hprof.FormatBytes(ls.Bytes), ls.Percentage, ls.Instances))
				sb.WriteString(fmt.Sprintf("  Analysis:  %s\n\n", ls.Description))
			}
		}
		if len(native.DuplicateArrays) > 0 {
			sb.WriteString("--- Identical Primitive-array Payloads ---\n")
			for i, ds := range native.DuplicateArrays {
				if i >= 10 {
					break
				}
				sb.WriteString(fmt.Sprintf("  #%d: %d identical array payload copies; repeated payload %s (savings unknown) -> %q\n",
					i+1, ds.Count, hprof.FormatBytes(ds.DuplicatePayloadBytes), ds.Preview))
			}
		}
		return sb.String()
	}
	return "No leak suspects report available."
}

func (s *Service) QueryClassHistogram(hprofPath string, topN int, pattern string, native *hprof.Summary) string {
	if native != nil {
		return native.QueryClassHistogram(topN, pattern)
	}
	dir := filepath.Dir(hprofPath)
	overviewZip := findZip(dir, "*_System_Overview.zip")
	if overviewZip != "" {
		raw := extractZipKeywordText(overviewZip, "histogram", "class_statistics", "index")
		return filterTopLines(raw, topN+5)
	}
	return "No class histogram available."
}

func (s *Service) QueryDominatorTree(hprofPath string, topN int, native *hprof.Summary) string {
	dir := filepath.Dir(hprofPath)
	overviewZip := findZip(dir, "*_System_Overview.zip")
	if overviewZip != "" {
		if raw := extractZipKeywordText(overviewZip, "dominator"); raw != "" {
			return fmt.Sprintf("=== MAT DOMINATOR REPORT EXCERPT (up to %d lines; original metric labels preserved) ===\n\n%s", topN, filterTopLines(raw, topN+5))
		}
	}
	if native != nil {
		return native.QueryDominators(topN)
	}
	return "Error: unsupported capability: no validated MAT dominator report is available."
}

func (s *Service) QueryTopConsumers(hprofPath string, native *hprof.Summary) string {
	dir := filepath.Dir(hprofPath)
	overviewZip := findZip(dir, "*_System_Overview.zip")
	if overviewZip != "" {
		if raw := extractZipKeywordText(overviewZip, "top_component", "biggest_objects", "package"); raw != "" {
			return truncate("=== TOP MEMORY CONSUMERS ===\n\n"+raw, 8000)
		}
	}
	if native != nil {
		var sb strings.Builder
		sb.WriteString("=== TOP SERIALIZED PAYLOAD CONSUMERS (Packages & Classes) ===\n\n")
		sb.WriteString(native.Assessment.ContextReport() + "\n")
		sb.WriteString("--- Top Packages ---\n")
		for i, p := range native.TopPackages {
			if i >= 15 {
				break
			}
			pct := 0.0
			if native.TotalPayloadBytes > 0 {
				pct = float64(p.TotalBytes) * 100.0 / float64(native.TotalPayloadBytes)
			}
			sb.WriteString(fmt.Sprintf("#%-2d %-40s %12s (%.1f%%) — %d objects\n",
				i+1, p.PackageName, hprof.FormatBytes(p.TotalBytes), pct, p.InstanceCount))
		}
		sb.WriteString("\n")
		sb.WriteString(native.QueryClassHistogram(15, ""))
		return sb.String()
	}
	return "No top consumer data available."
}

func (s *Service) QueryThreadStacks(hprofPath string, native *hprof.Summary) string {
	dir := filepath.Dir(hprofPath)
	overviewZip := findZip(dir, "*_System_Overview.zip")
	if overviewZip != "" {
		if raw := extractZipKeywordText(overviewZip, "thread"); raw != "" {
			return truncate("=== THREAD STACKS ===\n\n"+raw, 10000)
		}
	}
	if native != nil {
		var sb strings.Builder
		sb.WriteString("=== THREAD STACKS (Native HPROF Engine) ===\n\n")
		sb.WriteString(native.Assessment.ContextReport() + "\n")
		if len(native.ThreadStacks) == 0 {
			sb.WriteString("No resolvable traces in available metadata; absence of active threads is not established.\n")
		} else {
			for _, ts := range native.ThreadStacks {
				sb.WriteString(fmt.Sprintf("Thread #%d (Object 0x%x, Trace #%d):\n",
					ts.ThreadSerial, ts.ThreadObject, ts.TraceSerial))
				for _, fr := range ts.Frames {
					sb.WriteString("  at " + fr + "\n")
				}
				sb.WriteString("\n")
			}
		}
		return truncate(sb.String(), 10000)
	}
	return "No thread stack data available."
}

// RunOQLQuery intentionally fails closed until a typed MAT OQL result adapter is available.
// A histogram filter is not OQL, and successful MAT process output is not proof of query execution.
func (s *Service) RunOQLQuery(ctx context.Context, hprofPath, query string, native *hprof.Summary) string {
	return "Error: unsupported capability: OQL execution is not implemented with validated results. Use get_class_histogram with a regex filter, or run OQL directly in Eclipse MAT."
}

// Helpers

func findZip(dir, pattern string) string {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func extractZipEntryText(zipPath, name string) string {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return ""
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if f.Name == name || strings.HasSuffix(f.Name, "/"+name) {
			rc, err := f.Open()
			if err != nil {
				return ""
			}
			data, _ := io.ReadAll(rc)
			rc.Close()
			return htmlToText(string(data))
		}
	}
	return ""
}

func extractZipKeywordText(zipPath string, keywords ...string) string {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return ""
	}
	defer zr.Close()

	for _, kw := range keywords {
		kwLower := strings.ToLower(kw)
		for _, f := range zr.File {
			if !f.FileInfo().IsDir() && strings.HasSuffix(f.Name, ".html") && strings.Contains(strings.ToLower(f.Name), kwLower) {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				data, _ := io.ReadAll(rc)
				rc.Close()
				return htmlToText(string(data))
			}
		}
	}
	return ""
}

func extractSuspectDetails(zipPath string, maxSuspects int) string {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return ""
	}
	defer zr.Close()

	var pages []*zip.File
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && detailRe.MatchString(f.Name) {
			pages = append(pages, f)
		}
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].Name < pages[j].Name })

	var sb strings.Builder
	for i, p := range pages {
		if i >= maxSuspects {
			break
		}
		rc, err := p.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		sb.WriteString(fmt.Sprintf("--- Suspect #%d Detail ---\n", i+1))
		sb.WriteString(htmlToText(string(data)) + "\n\n")
	}
	return sb.String()
}

func htmlToText(html string) string {
	s := scriptRe.ReplaceAllString(html, "")
	s = styleRe.ReplaceAllString(s, "")
	s = commentRe.ReplaceAllString(s, "")
	s = thSepRe.ReplaceAllString(s, "  |  </th><th")
	s = tdSepRe.ReplaceAllString(s, "  |  </td><td")
	s = brRe.ReplaceAllString(s, "\n")
	s = blockEndRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = spacesRe.ReplaceAllString(s, " ")
	s = nlSpaceRe.ReplaceAllString(s, "\n")
	s = multiNlRe.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

func filterTopLines(text string, maxLines int) string {
	var sb strings.Builder
	count := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			sb.WriteString(trimmed + "\n")
			count++
			if count >= maxLines {
				break
			}
		}
	}
	return sb.String()
}

func truncate(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + fmt.Sprintf("\n[... truncated at %d chars ...]", maxChars)
}

func parseMemString(mem string) int64 {
	val := strings.ToLower(strings.TrimSpace(mem))
	if val == "" {
		return 0
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(val, "gb") || strings.HasSuffix(val, "g"):
		mult = 1024 * 1024 * 1024
	case strings.HasSuffix(val, "mb") || strings.HasSuffix(val, "m"):
		mult = 1024 * 1024
	case strings.HasSuffix(val, "kb") || strings.HasSuffix(val, "k"):
		mult = 1024
	}
	digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(val, "")
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

func downloadURL() string {
	return DownloadURLForPlatform(runtime.GOOS, runtime.GOARCH)
}

func DownloadURLForPlatform(goos, goarch string) string {
	switch goos {
	case "windows":
		return downloadBase + "-win32.win32.x86_64.zip"
	case "darwin":
		if goarch == "arm64" {
			return downloadBase + "-macosx.cocoa.aarch64.zip"
		}
		return downloadBase + "-macosx.cocoa.x86_64.zip"
	default: // linux, etc.
		if goarch == "arm64" {
			return downloadBase + "-linux.gtk.aarch64.zip"
		}
		return downloadBase + "-linux.gtk.x86_64.zip"
	}
}

func extractZip(zipFile, targetDir string) error {
	zr, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer zr.Close()

	cleanTarget := filepath.Clean(targetDir) + string(os.PathSeparator)
	for _, f := range zr.File {
		dest := filepath.Join(targetDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(dest)+string(os.PathSeparator), cleanTarget) {
			return fmt.Errorf("zip slip attempt: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(dest, 0o755)
			continue
		}
		_ = os.MkdirAll(filepath.Dir(dest), 0o755)
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := f.Mode()
		if strings.HasSuffix(f.Name, ".sh") || strings.HasSuffix(f.Name, "MemoryAnalyzer") || strings.HasSuffix(f.Name, "ParseHeapDump") {
			mode |= 0o755
		}
		out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			rc.Close()
			return err
		}
		_, _ = io.Copy(out, rc)
		out.Close()
		rc.Close()
	}
	return nil
}

// Helper for building a composite report (Native HPROF + Optional MAT)
func AnalyzeHeapHybrid(ctx context.Context, matSvc *Service, hprofPath string, useDeepMat bool) (string, *hprof.Summary, string, error) {
	// Step 1: Always run fast Native Go HPROF analysis first (takes seconds)
	nativeReport, summary, err := hprof.AnalyzeFile(hprofPath)
	if err != nil {
		return "", nil, "", err
	}

	engine := "native-hprof"
	if useDeepMat {
		if matSvc == nil || !matSvc.IsAvailable() {
			summary.Assessment.Warn("Requested MAT analysis was not performed: MAT is unavailable.")
		} else {
			ctxTimeout, cancel := context.WithTimeout(ctx, 25*time.Minute)
			defer cancel()
			matReport, err := matSvc.RunHeadless(ctxTimeout, hprofPath)
			if err == nil && matReport != "" {
				return nativeReport + "\n\n" + matReport, summary, "native-hprof+eclipse-mat", nil
			}
			if ctx.Err() != nil {
				return "", nil, "", ctx.Err()
			}
			summary.Assessment.Warn(fmt.Sprintf("Requested MAT analysis failed; only native payload analysis is available: %v", err))
		}
	}
	return hprof.BuildStructuredReport(summary), summary, engine, nil
}
