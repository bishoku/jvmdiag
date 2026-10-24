package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// procfs discovery does not depend on a shared /tmp/hsperfdata directory.
func listProcJVMs(root string) ([]JVMProcess, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []JVMProcess
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		base := filepath.Join(root, e.Name())
		exe, _ := os.Readlink(filepath.Join(base, "exe"))
		cmd, _ := os.ReadFile(filepath.Join(base, "cmdline"))
		fields := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
		isJava := filepath.Base(strings.TrimSuffix(exe, " (deleted)")) == "java"
		if !isJava && len(fields) > 0 {
			isJava = filepath.Base(fields[0]) == "java"
		}
		if !isJava {
			continue
		}
		args := ""
		if len(fields) > 1 {
			args = strings.Join(fields[1:], " ")
		}
		result = append(result, JVMProcess{PID: pid, MainClass: javaMain(fields[1:]), Args: args})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func targetRoot(pid int) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("--container requires Linux procfs")
	}
	root := filepath.Join("/proc", strconv.Itoa(pid))
	status, err := os.ReadFile(filepath.Join(root, "status"))
	if err != nil {
		return "", fmt.Errorf("target PID %d is not accessible: use kubectl debug --target=<java-container> and verify runtime PID namespace support: %w", pid, err)
	}
	if err = checkIdentity(string(status), os.Geteuid(), os.Getegid()); err != nil {
		return "", err
	}
	root = filepath.Join(root, "root")
	if _, err = os.Stat(root); err != nil {
		return "", fmt.Errorf("target filesystem %s is inaccessible: check UID/GID, procfs restrictions and AppArmor/SELinux policy: %w", root, err)
	}
	return root, nil
}

func checkIdentity(status string, uid, gid int) error {
	ids := map[string]int{}
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[0] == "Uid:" || fields[0] == "Gid:") {
			n, err := strconv.Atoi(fields[2])
			if err != nil {
				return fmt.Errorf("invalid target identity: %w", err)
			}
			ids[fields[0]] = n
		}
	}
	targetUID, uok := ids["Uid:"]
	targetGID, gok := ids["Gid:"]
	if !uok || !gok {
		return fmt.Errorf("cannot determine target effective UID/GID")
	}
	if targetUID != uid || targetGID != gid {
		return fmt.Errorf("attach requires matching effective UID/GID: target=%d:%d, diagnostic container=%d:%d; set runAsUser/runAsGroup in the custom debug profile", targetUID, targetGID, uid, gid)
	}
	return nil
}

// Display-only hint: attach always uses the explicitly selected numeric PID.
func javaMain(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-jar", "-m", "--module":
			if i+1 < len(args) {
				return args[i+1]
			}
			return "(java)"
		case "-cp", "-classpath", "--class-path", "-p", "--module-path", "--upgrade-module-path", "--add-modules", "--limit-modules", "--add-exports", "--add-opens", "--add-reads", "--patch-module", "--enable-native-access", "--source":
			i++
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			return arg
		}
	}
	return "(java)"
}

// JDK 17's Linux attach client only switches to /proc/PID/root/tmp when the
// visible PID differs from NSpid. Ephemeral containers can share the PID
// namespace yet have separate mounts, so bridge only that case. Never replace
// an existing local socket/link and never remove a trigger we did not create.
func prepareAttachBridge(root, localTmp, status string) (func(), error) {
	cleanup := func() {}
	targetTmp := filepath.Join(root, "tmp")
	localInfo, err := os.Stat(localTmp)
	if err != nil {
		return cleanup, err
	}
	targetInfo, err := os.Stat(targetTmp)
	if err != nil {
		return cleanup, fmt.Errorf("target /tmp unavailable for attach: %w", err)
	}
	if os.SameFile(localInfo, targetInfo) {
		return cleanup, nil
	}
	nsPID := ""
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "NSpid:" {
			nsPID = fields[len(fields)-1]
		}
	}
	n, err := strconv.Atoi(nsPID)
	if err != nil || n <= 0 {
		return cleanup, fmt.Errorf("cannot determine target namespace PID for attach bridge")
	}
	// The JDK already uses the target root when the visible PID differs.
	visiblePID := filepath.Base(filepath.Dir(root))
	if nsPID != visiblePID {
		return cleanup, nil
	}
	socket := filepath.Join(targetTmp, ".java_pid"+nsPID)
	alias := filepath.Join(localTmp, ".java_pid"+nsPID)
	if err = os.Symlink(socket, alias); err != nil {
		return cleanup, fmt.Errorf("cannot create private attach socket bridge %s (existing paths are not overwritten): %w", alias, err)
	}
	ownedTrigger := ""
	cleanup = func() {
		os.Remove(alias)
		if ownedTrigger != "" {
			os.Remove(ownedTrigger)
		}
	}
	trigger := filepath.Join(targetTmp, ".attach_pid"+nsPID)
	f, err := os.OpenFile(trigger, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		ownedTrigger = trigger
		err = f.Close()
	} else if os.IsExist(err) {
		err = nil
	}
	if err != nil {
		cleanup()
		return func() {}, fmt.Errorf("cannot create target attach trigger: %w", err)
	}
	return cleanup, nil
}
