package capture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeProcFixture(t *testing.T, root, pid, command, maps string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"cmdline": command, "maps": maps} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcDiscoveryFindsEmbeddedJVMWithoutJDKTools(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, "42", "/opt/idea/bin/idea\x00", "7f00-7f10 r-xp 00000000 08:01 100 /opt/idea/jbr/lib/server/libjvm.so\n")
	writeProcFixture(t, root, "7", "/opt/custom/launcher\x00", "7f00-7f10 r-xp 00000000 08:01 100 /opt/Runtime With Spaces/lib/server/libjvm.so (deleted)\n")
	writeProcFixture(t, root, "99", "/bin/sh\x00-c\x00echo libjvm.so\x00", "7f00-7f10 r-xp 00000000 08:01 100 /opt/libjvm.so.backup\n")
	procs, err := listProcJVMs(root)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for _, p := range procs {
		ids = append(ids, p.PID)
		if p.MainClass == "" {
			t.Fatal("embedded JVM has no display name")
		}
	}
	if !reflect.DeepEqual(ids, []int{7, 42}) {
		t.Fatalf("embedded JVM discovery: %+v", procs)
	}
}

func TestDiscoveryCombinesProcAndJDKProcesses(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, "3", "/opt/java/bin/java\x00-jar\x00container.jar\x00", "")
	writeProcFixture(t, root, "42", "/opt/idea/bin/idea\x00", "7f00-7f10 r-xp 00000000 08:01 100 /opt/jbr/lib/server/libjvm.so\n")
	var calls []string
	find := func(name string) string { return name }
	run := func(ctx context.Context, tool string, args ...string) ([]byte, error) {
		calls = append(calls, tool)
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("JDK discovery has no timeout")
		}
		if tool != "jcmd" || !reflect.DeepEqual(args, []string{"-l"}) {
			t.Fatalf("unexpected command: %s %v", tool, args)
		}
		return []byte("42 com.intellij.idea.Main\n3 com.acme.Main app-arg\n10 another.Main\n123 jdk.jcmd/sun.tools.jcmd.JCmd -l\n0 invalid\n"), nil
	}
	procs, err := listProcesses(context.Background(), root, find, run)
	if err != nil {
		t.Fatal(err)
	}
	want := []JVMProcess{{PID: 3, MainClass: "com.acme.Main", Args: "app-arg"}, {PID: 10, MainClass: "another.Main"}, {PID: 42, MainClass: "com.intellij.idea.Main"}}
	if !reflect.DeepEqual(procs, want) || !reflect.DeepEqual(calls, []string{"jcmd"}) {
		t.Fatalf("merged discovery: %+v, calls %v", procs, calls)
	}
}

func TestEmptyProcListingStillUsesJDKDiscovery(t *testing.T) {
	root := t.TempDir()
	for _, useJPS := range []bool{false, true} {
		var calls []string
		run := func(_ context.Context, tool string, args ...string) ([]byte, error) {
			calls = append(calls, tool)
			if tool == "jcmd" && useJPS {
				return []byte("99 jdk.jcmd/sun.tools.jcmd.JCmd -l\n"), nil
			}
			return []byte("42 com.intellij.idea.Main\n"), nil
		}
		procs, err := listProcesses(context.Background(), root, func(s string) string { return s }, run)
		if err != nil || len(procs) != 1 || procs[0].MainClass != "com.intellij.idea.Main" {
			t.Fatalf("empty proc fallback: %v %+v", err, procs)
		}
		want := []string{"jcmd"}
		if useJPS {
			want = append(want, "jps")
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("fallback calls: %v", calls)
		}
	}
}

func TestJDKFailureDoesNotLoseProcProcesses(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, "42", "/opt/idea/bin/idea\x00", "7f00-7f10 r-xp 00000000 08:01 100 /opt/jbr/lib/server/libjvm.so\n")
	for _, unavailable := range []bool{false, true} {
		find := func(s string) string {
			if unavailable {
				return ""
			}
			return s
		}
		run := func(_ context.Context, tool string, _ ...string) ([]byte, error) {
			if unavailable || tool == "ps" {
				t.Fatalf("unexpected fallback: %s", tool)
			}
			return nil, context.DeadlineExceeded
		}
		procs, err := listProcesses(context.Background(), root, find, run)
		if err != nil || len(procs) != 1 || procs[0].PID != 42 {
			t.Fatalf("lost embedded JVM when JDK unavailable/failed: %v %+v", err, procs)
		}
	}
}

func TestDiscoveryWithoutProcfs(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-proc")
	procs, err := listProcesses(context.Background(), missing, func(string) string { return "jcmd" },
		func(context.Context, string, ...string) ([]byte, error) {
			return []byte("42 com.intellij.idea.Main\n"), nil
		})
	if err != nil || len(procs) != 1 || procs[0].PID != 42 {
		t.Fatalf("JDK discovery without procfs: %v %+v", err, procs)
	}
	for _, fail := range []bool{false, true} {
		run := func(_ context.Context, tool string, args ...string) ([]byte, error) {
			if tool != "ps" {
				t.Fatalf("unexpected tool: %s", tool)
			}
			if fail {
				return nil, errors.New("unavailable")
			}
			return []byte("PID COMMAND\n8 /opt/java/bin/java -jar app.jar\n"), nil
		}
		procs, err := listProcesses(context.Background(), missing, func(string) string { return "" }, run)
		if fail {
			if err == nil {
				t.Fatal("all unavailable discovery sources succeeded")
			}
			continue
		}
		if err != nil || len(procs) != 1 || procs[0].PID != 8 {
			t.Fatalf("ps fallback: %v %+v", err, procs)
		}
	}
}
