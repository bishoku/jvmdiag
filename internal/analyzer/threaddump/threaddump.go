package threaddump

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const MaxReportChars = 30000

var (
	threadHeaderPattern = regexp.MustCompile(`^"([^"]*)"(.*)$`)
	threadIDPattern     = regexp.MustCompile(`tid=(0x[0-9a-fA-F]+|\d+)`)
	threadStatePattern  = regexp.MustCompile(`^\s*java\.lang\.Thread\.State:\s+(\S+)`)
	deadlockPattern     = regexp.MustCompile(`(?i)Found (one|\d+) Java-level deadlock`)
	waitingLockPattern  = regexp.MustCompile(`-\s+(?:waiting to lock|parking to wait for|waiting on)\s+<([0-9a-fA-Fx]+)>\s*(?:\(a\s+([^\)]+)\))?`)
	heldLockPattern     = regexp.MustCompile(`-\s+locked\s+<([0-9a-fA-Fx]+)>\s*(?:\(a\s+([^\)]+)\))?`)
	poolNormPattern     = regexp.MustCompile(`[-_#:]?\d+(?:[-_#:]\d+)*$`)
)

type ThreadInfo struct {
	Name          string   `json:"name"`
	Pool          string   `json:"pool"`
	TID           string   `json:"tid,omitempty"`
	State         string   `json:"state"`
	Virtual       bool     `json:"virtual,omitempty"`
	CarrierThread string   `json:"carrierThread,omitempty"`
	Pinned        bool     `json:"pinned,omitempty"`
	PinReason     string   `json:"pinReason,omitempty"`
	StackFrames   []string `json:"stackFrames,omitempty"`
	WaitingOnLock string   `json:"waitingOnLock,omitempty"`
	WaitingClass  string   `json:"waitingClass,omitempty"`
	HeldLocks     []string `json:"heldLocks,omitempty"`
}

func (t ThreadInfo) TopFrame() string {
	if len(t.StackFrames) > 0 {
		return t.StackFrames[0]
	}
	return "(no stack frame)"
}

func (t ThreadInfo) Signature(depth int) string {
	if len(t.StackFrames) == 0 {
		return ""
	}
	if depth > len(t.StackFrames) {
		depth = len(t.StackFrames)
	}
	return strings.Join(t.StackFrames[:depth], " <- ")
}

type LockContention struct {
	LockID        string   `json:"lockId"`
	ClassName     string   `json:"className"`
	OwnerThread   string   `json:"ownerThread"`
	OwnerState    string   `json:"ownerState"`
	OwnerTopFrame string   `json:"ownerTopFrame"`
	WaiterCount   int      `json:"waiterCount"`
	Waiters       []string `json:"waiters"`
}

type DumpSummary struct {
	FileName           string           `json:"fileName"`
	TotalThreads       int              `json:"totalThreads"`
	VirtualThreadCount int              `json:"virtualThreadCount,omitempty"`
	CarrierThreadCount int              `json:"carrierThreadCount,omitempty"`
	ActiveCarrierCount int              `json:"activeCarrierCount,omitempty"`
	PinnedThreads      []ThreadInfo     `json:"pinnedThreads,omitempty"`
	StateCounts        map[string]int   `json:"stateCounts"`
	PoolCounts         map[string]int   `json:"poolCounts"`
	Threads            []ThreadInfo     `json:"threads"`
	Contentions        []LockContention `json:"contentions,omitempty"`
	HasDeadlock        bool             `json:"hasDeadlock"`
	DeadlockDetails    string           `json:"deadlockDetails,omitempty"`
}

func AnalyzeFile(path string) (string, *DumpSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	content := string(data)
	summary := ParseContent(filepath.Base(path), content)
	report := BuildReport(summary, content)
	return report, summary, nil
}

// jcmd Thread.dump_to_file -format=json schema (Java 21+)
type jsonThreadDumpRoot struct {
	ThreadDump struct {
		ProcessID        string `json:"processId"`
		Time             string `json:"time"`
		RuntimeVersion   string `json:"runtimeVersion"`
		ThreadContainers []struct {
			Container string `json:"container"`
			Parent    string `json:"parent"`
			Threads   []struct {
				TID           string   `json:"tid"`
				Name          string   `json:"name"`
				State         string   `json:"state"`
				Virtual       bool     `json:"virtual"`
				Carrier       string   `json:"carrier"`
				Stack         []string `json:"stack"`
				MonitorsOwned []struct {
					Depth int      `json:"depth"`
					Locks []string `json:"locks"`
				} `json:"monitorsOwned"`
				BlockedOn   string `json:"blockedOn"`
				WaitingOn   string `json:"waitingOn"`
				ParkBlocker string `json:"parkBlocker"`
			} `json:"threads"`
		} `json:"threadContainers"`
	} `json:"threadDump"`
}

func ParseContent(fileName, content string) *DumpSummary {
	summary := &DumpSummary{
		FileName: fileName,
		StateCounts: map[string]int{
			"RUNNABLE":      0,
			"WAITING":       0,
			"TIMED_WAITING": 0,
			"BLOCKED":       0,
			"NEW":           0,
			"TERMINATED":    0,
		},
		PoolCounts: make(map[string]int),
	}

	trimmedContent := strings.TrimSpace(content)
	if strings.HasPrefix(trimmedContent, "{") && strings.Contains(trimmedContent, `"threadDump"`) {
		if parseJSONThreadDump(trimmedContent, summary) {
			finalizeContentionAndLoom(summary, "")
			return summary
		}
	}

	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	var current *ThreadInfo
	var deadlockSection strings.Builder
	inDeadlock := false

	flushThread := func() {
		if current != nil {
			if current.State == "" {
				current.State = "JVM_INTERNAL"
				summary.StateCounts["JVM_INTERNAL"]++
			}
			evaluateVirtualThreadPinning(current)
			if current.Virtual {
				summary.VirtualThreadCount++
			}
			if current.Pinned {
				summary.PinnedThreads = append(summary.PinnedThreads, *current)
			}
			summary.Threads = append(summary.Threads, *current)
			current = nil
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		if deadlockPattern.MatchString(line) {
			flushThread()
			summary.HasDeadlock = true
			inDeadlock = true
			deadlockSection.WriteString(line + "\n")
			continue
		}

		if inDeadlock {
			deadlockSection.WriteString(line + "\n")
			if strings.TrimSpace(line) == "" && i+1 < len(lines) &&
				!strings.HasPrefix(strings.TrimSpace(lines[i+1]), `"`) &&
				!strings.Contains(lines[i+1], "waiting to lock") &&
				!strings.Contains(lines[i+1], "which is held by") {
				inDeadlock = false
			}
			continue
		}

		if m := threadHeaderPattern.FindStringSubmatch(line); len(m) == 3 {
			flushThread()
			name := m[1]
			rest := m[2]
			tid := ""
			if tm := threadIDPattern.FindStringSubmatch(rest); len(tm) == 2 {
				tid = tm[1]
			}
			isVirtual := strings.Contains(strings.ToLower(rest), " virtual") ||
				strings.HasPrefix(strings.ToLower(name), "virtualthread") ||
				(name == "" && strings.Contains(strings.ToLower(rest), "virtual"))
			if name == "" && isVirtual {
				name = "VirtualThread-" + tid
			}
			pool := normalizePoolName(name)
			if isVirtual && pool == name {
				pool = "VirtualThreads"
			}
			summary.PoolCounts[pool]++
			summary.TotalThreads++

			carrier := ""
			if idx := strings.Index(rest, "carrier="); idx >= 0 {
				carrier = strings.Fields(rest[idx+len("carrier="):])[0]
			}
			current = &ThreadInfo{
				Name:          name,
				Pool:          pool,
				TID:           tid,
				Virtual:       isVirtual,
				CarrierThread: carrier,
			}
			continue
		}

		if current == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Carrying virtual thread") {
			summary.CarrierThreadCount++
			summary.ActiveCarrierCount++
			continue
		}

		if sm := threadStatePattern.FindStringSubmatch(line); len(sm) == 2 {
			state := sm[1]
			current.State = state
			summary.StateCounts[state]++
			continue
		}

		if strings.HasPrefix(trimmed, "at ") {
			frame := strings.TrimPrefix(trimmed, "at ")
			if len(current.StackFrames) < 25 {
				current.StackFrames = append(current.StackFrames, frame)
			}
			continue
		}

		if wm := waitingLockPattern.FindStringSubmatch(trimmed); len(wm) >= 2 {
			if current.WaitingOnLock == "" {
				current.WaitingOnLock = wm[1]
				if len(wm) >= 3 {
					current.WaitingClass = wm[2]
				}
			}
			continue
		}

		if hm := heldLockPattern.FindStringSubmatch(trimmed); len(hm) >= 2 {
			lockID := hm[1]
			already := false
			for _, h := range current.HeldLocks {
				if h == lockID {
					already = true
					break
				}
			}
			if !already {
				current.HeldLocks = append(current.HeldLocks, lockID)
			}
		}
	}
	flushThread()

	finalizeContentionAndLoom(summary, deadlockSection.String())
	return summary
}

func parseJSONThreadDump(content string, summary *DumpSummary) bool {
	var root jsonThreadDumpRoot
	if err := json.Unmarshal([]byte(content), &root); err != nil {
		return false
	}
	for _, container := range root.ThreadDump.ThreadContainers {
		for _, jt := range container.Threads {
			name := jt.Name
			if name == "" {
				if jt.Virtual {
					name = "VirtualThread-#" + jt.TID
				} else {
					name = "Thread-#" + jt.TID
				}
			}
			state := strings.ToUpper(strings.TrimSpace(jt.State))
			if state == "" {
				state = "WAITING"
			}
			if strings.Contains(state, "PARK") || state == "PARKED" {
				state = "WAITING"
			}
			pool := normalizePoolName(name)
			if jt.Virtual && strings.HasPrefix(name, "VirtualThread-") {
				pool = "VirtualThreads"
			}
			summary.TotalThreads++
			summary.StateCounts[state]++
			summary.PoolCounts[pool]++

			var held []string
			for _, mo := range jt.MonitorsOwned {
				held = append(held, mo.Locks...)
			}
			frames := jt.Stack
			if len(frames) > 25 {
				frames = frames[:25]
			}
			ti := ThreadInfo{
				Name:          name,
				Pool:          pool,
				TID:           jt.TID,
				State:         state,
				Virtual:       jt.Virtual,
				CarrierThread: jt.Carrier,
				StackFrames:   frames,
				WaitingOnLock: jt.BlockedOn,
				HeldLocks:     held,
			}
			evaluateVirtualThreadPinning(&ti)
			if ti.Virtual {
				summary.VirtualThreadCount++
			}
			if ti.Pinned {
				summary.PinnedThreads = append(summary.PinnedThreads, ti)
			}
			summary.Threads = append(summary.Threads, ti)
		}
	}
	return summary.TotalThreads > 0
}

func evaluateVirtualThreadPinning(t *ThreadInfo) {
	if !t.Virtual {
		// Check if stack frames show VirtualThread continuation mounted on a carrier
		for _, f := range t.StackFrames {
			if strings.Contains(f, "java.lang.VirtualThread") {
				t.Virtual = true
				break
			}
		}
	}
	if !t.Virtual {
		return
	}

	isParkedOrWaiting := t.State == "WAITING" || t.State == "TIMED_WAITING" || t.State == "BLOCKED"
	if !isParkedOrWaiting {
		return
	}

	// Reason 1: Holding an object monitor (synchronized block/method) while parked/waiting
	if len(t.HeldLocks) > 0 {
		t.Pinned = true
		t.PinReason = fmt.Sprintf("Holding synchronized monitor (%s) while in %s state", strings.Join(t.HeldLocks, ", "), t.State)
		return
	}

	// Reason 2: Native method on call stack (excluding standard Unsafe.park / Continuation.yield0)
	for idx, f := range t.StackFrames {
		if idx > 0 && strings.Contains(f, "(Native Method)") &&
			!strings.Contains(f, "Unsafe.park") &&
			!strings.Contains(f, "Continuation.run") &&
			!strings.Contains(f, "Continuation.yield") {
			t.Pinned = true
			t.PinReason = fmt.Sprintf("Parked inside native frame: %s", f)
			return
		}
	}

	// Reason 3: Explicitly still mounted on a carrier thread while in WAITING/TIMED_WAITING state
	if t.CarrierThread != "" {
		t.Pinned = true
		t.PinReason = fmt.Sprintf("Remained mounted on carrier %s while in %s state", t.CarrierThread, t.State)
	}
}

func finalizeContentionAndLoom(summary *DumpSummary, deadlockText string) {
	// Count ForkJoinPool carrier threads if not already counted
	for _, t := range summary.Threads {
		if !t.Virtual && (strings.Contains(t.Name, "ForkJoinPool") && strings.Contains(t.Name, "worker")) {
			summary.CarrierThreadCount++
			if t.State == "RUNNABLE" || t.State == "BLOCKED" {
				summary.ActiveCarrierCount++
			}
		}
	}

	// Build lock contention map
	lockOwners := make(map[string]ThreadInfo)
	lockWaiters := make(map[string][]string)
	lockClasses := make(map[string]string)

	for _, t := range summary.Threads {
		for _, held := range t.HeldLocks {
			if t.WaitingOnLock != held {
				lockOwners[held] = t
			}
		}
		if t.WaitingOnLock != "" && t.State == "BLOCKED" {
			lockWaiters[t.WaitingOnLock] = append(lockWaiters[t.WaitingOnLock], t.Name)
			if t.WaitingClass != "" {
				lockClasses[t.WaitingOnLock] = t.WaitingClass
			}
		}
	}

	for lockID, waiters := range lockWaiters {
		owner := lockOwners[lockID]
		summary.Contentions = append(summary.Contentions, LockContention{
			LockID:        lockID,
			ClassName:     lockClasses[lockID],
			OwnerThread:   owner.Name,
			OwnerState:    owner.State,
			OwnerTopFrame: owner.TopFrame(),
			WaiterCount:   len(waiters),
			Waiters:       waiters,
		})
	}
	sort.Slice(summary.Contentions, func(i, j int) bool {
		if summary.Contentions[i].WaiterCount == summary.Contentions[j].WaiterCount {
			return summary.Contentions[i].LockID < summary.Contentions[j].LockID
		}
		return summary.Contentions[i].WaiterCount > summary.Contentions[j].WaiterCount
	})

	var deadlockSection strings.Builder
	deadlockSection.WriteString(deadlockText)

	// Detect lock cycle deadlock if not already flagged by JVM output
	if !summary.HasDeadlock && len(lockWaiters) > 0 {
		for _, t := range summary.Threads {
			if t.State == "BLOCKED" && t.WaitingOnLock != "" {
				visited := map[string]bool{t.Name: true}
				currLock := t.WaitingOnLock
				for step := 0; step < 20; step++ {
					owner, ok := lockOwners[currLock]
					if !ok || owner.Name == "" {
						break
					}
					if visited[owner.Name] {
						summary.HasDeadlock = true
						deadlockSection.WriteString(fmt.Sprintf(
							"Detected lock cycle involving thread %q and lock <%s> held by %q\n",
							t.Name, currLock, owner.Name))
						break
					}
					visited[owner.Name] = true
					if owner.State != "BLOCKED" || owner.WaitingOnLock == "" {
						break
					}
					currLock = owner.WaitingOnLock
				}
				if summary.HasDeadlock {
					break
				}
			}
		}
	}

	summary.DeadlockDetails = strings.TrimSpace(deadlockSection.String())
}

func BuildReport(s *DumpSummary, rawContent string) string {
	var sb strings.Builder
	sb.WriteString("Thread Dump Analysis Report\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString("## Thread Summary\n\n")
	sb.WriteString(fmt.Sprintf("Total threads found: %d", s.TotalThreads))
	if s.VirtualThreadCount > 0 {
		sb.WriteString(fmt.Sprintf(" (Platform: %d, Virtual: %d, Pinned Virtual: %d)",
			s.TotalThreads-s.VirtualThreadCount, s.VirtualThreadCount, len(s.PinnedThreads)))
	}
	sb.WriteString("\n\n")

	orderedStates := []string{"RUNNABLE", "WAITING", "TIMED_WAITING", "BLOCKED", "JVM_INTERNAL", "NEW", "TERMINATED"}
	for _, st := range orderedStates {
		cnt := s.StateCounts[st]
		if cnt > 0 {
			pct := 0.0
			if s.TotalThreads > 0 {
				pct = float64(cnt) * 100.0 / float64(s.TotalThreads)
			}
			sb.WriteString(fmt.Sprintf("  %-16s %4d  (%.1f%%)\n", st+":", cnt, pct))
		}
	}
	sb.WriteString("\n")

	// Java 21+ Virtual Threads & Carrier Starvation Section
	if s.VirtualThreadCount > 0 || len(s.PinnedThreads) > 0 {
		sb.WriteString("## Java 21+ Virtual Threads (Project Loom) & Pinning Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- Virtual Threads: **%d**\n", s.VirtualThreadCount))
		if s.CarrierThreadCount > 0 {
			sb.WriteString(fmt.Sprintf("- Carrier Threads (ForkJoinPool): **%d total** (%d active/busy)\n", s.CarrierThreadCount, s.ActiveCarrierCount))
		}
		sb.WriteString(fmt.Sprintf("- Pinned Virtual Threads: **%d**\n\n", len(s.PinnedThreads)))

		if len(s.PinnedThreads) > 0 {
			sb.WriteString("CRITICAL: The following Virtual Threads are **PINNED** to their carrier threads (preventing unmounting during blocking I/O or lock waits, which causes Carrier Thread Starvation):\n\n")
			for i, pt := range s.PinnedThreads {
				if i >= 20 {
					sb.WriteString(fmt.Sprintf("  ... and %d more pinned virtual threads\n", len(s.PinnedThreads)-20))
					break
				}
				sb.WriteString(fmt.Sprintf("  - **%s** (tid=%s) [%s] — %s\n    Stack: `%s`\n",
					pt.Name, pt.TID, pt.State, pt.PinReason, pt.Signature(5)))
			}
			sb.WriteString("\n")
		}
	}

	if s.HasDeadlock {
		sb.WriteString("## DEADLOCK DETECTED\n\n")
		sb.WriteString("```\n" + s.DeadlockDetails + "\n```\n\n")
	} else {
		sb.WriteString("## Deadlock Check\n\nNo deadlocks detected.\n\n")
	}

	if len(s.Contentions) > 0 {
		sb.WriteString("## Lock Contention Bottlenecks\n\n")
		for idx, c := range s.Contentions {
			if idx >= 10 {
				break
			}
			ownerInfo := "unknown owner"
			if c.OwnerThread != "" {
				ownerInfo = fmt.Sprintf("held by %q [%s] at %s", c.OwnerThread, c.OwnerState, c.OwnerTopFrame)
			}
			sb.WriteString(fmt.Sprintf("- Lock `<%s>` (%s): **%d blocked threads** (%s)\n",
				c.LockID, c.ClassName, c.WaiterCount, ownerInfo))
			limit := len(c.Waiters)
			if limit > 8 {
				limit = 8
			}
			sb.WriteString(fmt.Sprintf("  Waiters: %s", strings.Join(c.Waiters[:limit], ", ")))
			if len(c.Waiters) > limit {
				sb.WriteString(fmt.Sprintf(" ... (+%d more)", len(c.Waiters)-limit))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	// Blocked threads list
	var blocked []ThreadInfo
	var runnable []ThreadInfo
	for _, t := range s.Threads {
		if t.State == "BLOCKED" {
			blocked = append(blocked, t)
		} else if t.State == "RUNNABLE" {
			runnable = append(runnable, t)
		}
	}

	if len(blocked) > 0 {
		sb.WriteString(fmt.Sprintf("## Blocked Threads (%d)\n\n", len(blocked)))
		for i, t := range blocked {
			if i >= 25 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(blocked)-25))
				break
			}
			sb.WriteString(fmt.Sprintf("  - %s (at %s)\n", t.Name, t.TopFrame()))
		}
		sb.WriteString("\n")
	}

	// Top Thread Pools
	type poolEntry struct {
		name  string
		count int
	}
	var pools []poolEntry
	for k, v := range s.PoolCounts {
		pools = append(pools, poolEntry{k, v})
	}
	sort.Slice(pools, func(i, j int) bool {
		if pools[i].count == pools[j].count {
			return pools[i].name < pools[j].name
		}
		return pools[i].count > pools[j].count
	})
	if len(pools) > 0 {
		sb.WriteString("## Top Thread Pools / Groups\n\n")
		for i, p := range pools {
			if i >= 12 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %-32s %4d threads\n", p.name, p.count))
		}
		sb.WriteString("\n")
	}

	// Identical Stack Hotspots
	stackGroups := make(map[string]int)
	for _, t := range s.Threads {
		sig := t.Signature(4)
		if sig != "" {
			stackGroups[t.State+": "+sig]++
		}
	}
	var hotspots []poolEntry
	for sig, cnt := range stackGroups {
		if cnt >= 2 {
			hotspots = append(hotspots, poolEntry{sig, cnt})
		}
	}
	sort.Slice(hotspots, func(i, j int) bool {
		if hotspots[i].count == hotspots[j].count {
			return hotspots[i].name < hotspots[j].name
		}
		return hotspots[i].count > hotspots[j].count
	})
	if len(hotspots) > 0 {
		sb.WriteString("## Identical Stack Trace Hotspots (>= 2 threads)\n\n")
		for i, h := range hotspots {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  - **%d threads** in %s\n", h.count, h.name))
		}
		sb.WriteString("\n")
	}

	if len(runnable) > 0 {
		sb.WriteString(fmt.Sprintf("## Active (RUNNABLE) Threads (%d)\n\n", len(runnable)))
		for i, t := range runnable {
			if i >= 25 {
				sb.WriteString(fmt.Sprintf("  ... and %d more\n", len(runnable)-25))
				break
			}
			sb.WriteString(fmt.Sprintf("  - %s (at %s)\n", t.Name, t.TopFrame()))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Raw Thread Dump (for detailed stack trace analysis)\n\n```\n")
	rem := MaxReportChars - sb.Len() - 100
	raw := rawContent
	if rem > 0 && len(raw) > rem {
		raw = raw[:rem] + "\n\n[... THREAD DUMP TRUNCATED ...]"
	}
	sb.WriteString(raw)
	sb.WriteString("\n```\n")

	return sb.String()
}

// CompareFiles compares 2 or more sequential thread dumps to identify stuck threads,
// persistent lock contention, and thread pool growth.
func CompareFiles(paths []string) (string, error) {
	if len(paths) < 2 {
		return "", fmt.Errorf("at least 2 thread dump files are required for diff analysis")
	}

	var dumps []*DumpSummary
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		dumps = append(dumps, ParseContent(filepath.Base(p), string(data)))
	}

	return CompareSummaries(dumps), nil
}

func CompareSummaries(dumps []*DumpSummary) string {
	var sb strings.Builder
	sb.WriteString("Multi-Snapshot Thread Dump Diff Report\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	sb.WriteString(fmt.Sprintf("Snapshots compared: %d\n", len(dumps)))
	for i, d := range dumps {
		sb.WriteString(fmt.Sprintf("  #%d %s — %d total threads (RUNNABLE: %d, BLOCKED: %d, WAITING: %d, TIMED_WAITING: %d, Pinned Virtual: %d)\n",
			i+1, d.FileName, d.TotalThreads,
			d.StateCounts["RUNNABLE"], d.StateCounts["BLOCKED"],
			d.StateCounts["WAITING"], d.StateCounts["TIMED_WAITING"],
			len(d.PinnedThreads)))
	}
	sb.WriteString("\n")

	// 1. Identify Stuck Threads (threads present in ALL dumps with identical top stack frame in RUNNABLE or BLOCKED state)
	type stuckCandidate struct {
		Name     string
		State    string
		TopFrame string
		Sig      string
	}
	firstMap := make(map[string]ThreadInfo)
	for _, t := range dumps[0].Threads {
		if (t.State == "RUNNABLE" || t.State == "BLOCKED") && len(t.StackFrames) > 0 {
			if !isIdlePollerFrame(t.TopFrame()) {
				firstMap[t.Name] = t
			}
		}
	}

	var stuckThreads []stuckCandidate
	for name, baseThread := range firstMap {
		stuckInAll := true
		for i := 1; i < len(dumps); i++ {
			found := false
			for _, other := range dumps[i].Threads {
				if other.Name == name && other.State == baseThread.State && other.TopFrame() == baseThread.TopFrame() {
					found = true
					break
				}
			}
			if !found {
				stuckInAll = false
				break
			}
		}
		if stuckInAll {
			stuckThreads = append(stuckThreads, stuckCandidate{
				Name:     name,
				State:    baseThread.State,
				TopFrame: baseThread.TopFrame(),
				Sig:      baseThread.Signature(5),
			})
		}
	}
	sort.Slice(stuckThreads, func(i, j int) bool { return stuckThreads[i].Name < stuckThreads[j].Name })

	sb.WriteString(fmt.Sprintf("## Stuck / Unmoving Threads Across All %d Dumps (%d found)\n\n", len(dumps), len(stuckThreads)))
	if len(stuckThreads) == 0 {
		sb.WriteString("No non-idle RUNNABLE/BLOCKED threads remained at the exact same stack frame across all snapshots.\n\n")
	} else {
		sb.WriteString("CRITICAL: The following threads did not advance their top stack frame across snapshots:\n\n")
		for i, st := range stuckThreads {
			if i >= 30 {
				sb.WriteString(fmt.Sprintf("  ... and %d more stuck threads\n", len(stuckThreads)-30))
				break
			}
			sb.WriteString(fmt.Sprintf("- **%s** [%s]\n  Top Frame: `%s`\n  Call Chain: `%s`\n",
				st.Name, st.State, st.TopFrame, st.Sig))
		}
		sb.WriteString("\n")
	}

	// 2. Thread Pool Growth / Delta between First and Last Dump
	first := dumps[0]
	last := dumps[len(dumps)-1]
	sb.WriteString(fmt.Sprintf("## Thread Pool Delta (%s -> %s)\n\n", first.FileName, last.FileName))
	sb.WriteString(fmt.Sprintf("Total Threads: %d -> %d (Delta: %+d)\n\n",
		first.TotalThreads, last.TotalThreads, last.TotalThreads-first.TotalThreads))

	allPools := make(map[string]bool)
	for p := range first.PoolCounts {
		allPools[p] = true
	}
	for p := range last.PoolCounts {
		allPools[p] = true
	}
	type poolDelta struct {
		pool   string
		before int
		after  int
		delta  int
	}
	var deltas []poolDelta
	for p := range allPools {
		b := first.PoolCounts[p]
		a := last.PoolCounts[p]
		if b != a || a >= 3 {
			deltas = append(deltas, poolDelta{p, b, a, a - b})
		}
	}
	sort.Slice(deltas, func(i, j int) bool {
		if deltas[i].delta != deltas[j].delta {
			return deltas[i].delta > deltas[j].delta
		}
		if deltas[i].after == deltas[j].after {
			return deltas[i].pool < deltas[j].pool
		}
		return deltas[i].after > deltas[j].after
	})
	for i, d := range deltas {
		if i >= 15 {
			break
		}
		sb.WriteString(fmt.Sprintf("  %-32s %4d -> %4d  (%+d)\n", d.pool, d.before, d.after, d.delta))
	}
	sb.WriteString("\n")

	// 3. Persistent Lock Contention
	sb.WriteString("## Lock Contention Across Snapshots\n\n")
	hasAnyContention := false
	for i, d := range dumps {
		if len(d.Contentions) > 0 {
			hasAnyContention = true
			sb.WriteString(fmt.Sprintf("Snapshot #%d (%s):\n", i+1, d.FileName))
			for _, c := range d.Contentions {
				sb.WriteString(fmt.Sprintf("  - Lock `<%s>` (%s): %d waiters (Owner: %s [%s])\n",
					c.LockID, c.ClassName, c.WaiterCount, c.OwnerThread, c.OwnerState))
			}
		}
	}
	if !hasAnyContention {
		sb.WriteString("No BLOCKED lock contentions detected in any snapshot.\n")
	}
	sb.WriteString("\n")

	return sb.String()
}

func normalizePoolName(threadName string) string {
	norm := poolNormPattern.ReplaceAllString(strings.TrimSpace(threadName), "")
	if norm == "" {
		return threadName
	}
	return norm
}

func isIdlePollerFrame(frame string) bool {
	lower := strings.ToLower(frame)
	return strings.Contains(lower, " epollwait") ||
		strings.Contains(lower, ".epollwait") ||
		strings.Contains(lower, "kevent") ||
		strings.Contains(lower, "socketdispatcher.read0") ||
		strings.Contains(lower, " plaindatagramsocketimpl") ||
		strings.Contains(lower, "serversocketchannelimpl.accept")
}
