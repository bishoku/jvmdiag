package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestHelpIncludesEveryRegisteredFlag(t *testing.T) {
	var all bytes.Buffer
	printAllHelp(&all)
	for _, command := range helpCommands {
		t.Run(command.name, func(t *testing.T) {
			var focused bytes.Buffer
			if !showCommandHelp(&focused, command.name) {
				t.Fatal("command missing help")
			}
			if !strings.Contains(all.String(), "Usage: jvmdiag "+command.usage) {
				t.Fatal("command missing from general help")
			}
			fs := commandFlags(command.name)
			if fs == nil {
				return
			}
			fs.VisitAll(func(f *flag.Flag) {
				for _, output := range []string{all.String(), focused.String()} {
					if !strings.Contains(output, "-"+f.Name) || !strings.Contains(output, f.Usage) {
						t.Errorf("missing flag or description: %s --%s", command.name, f.Name)
					}
				}
			})
		})
	}
	var alias, canonical bytes.Buffer
	showCommandHelp(&alias, "server")
	showCommandHelp(&canonical, "serve")
	if alias.String() != canonical.String() {
		t.Fatal("server alias help differs")
	}
	if showCommandHelp(&alias, "unknown") {
		t.Fatal("unknown command accepted")
	}
}

func TestHelpProcess(t *testing.T) {
	if os.Getenv("JVMDIAG_TEST_HELP_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"jvmdiag"}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing CLI arguments")
}

func TestCLIHelpExitsWithoutRunningCommands(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]string{{"help"}, {"--help"}, {"-h"}, {"help", "unknown"}}
	for _, c := range helpCommands {
		cases = append(cases, []string{"help", c.name}, []string{c.name, "--help"}, []string{c.name, "-h"})
	}
	cases = append(cases, []string{"server", "--help"}, []string{"help", "server"})
	for _, args := range cases {
		// "help --help" and "help -h" are the global help aliases.
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, append([]string{"-test.run=^TestHelpProcess$", "--"}, args...)...)
			// Help-only child processes do not need the race runtime exit delay.
			cmd.Env = append(os.Environ(), "JVMDIAG_TEST_HELP_PROCESS=1", "GORACE=atexit_sleep_ms=0")
			output, err := cmd.CombinedOutput()
			unknown := len(args) == 2 && args[1] == "unknown"
			if unknown {
				if err == nil || !strings.Contains(string(output), "Unknown command") {
					t.Fatalf("unknown help: %v %s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("help failed: %v %s", err, output)
			}
			if !strings.Contains(string(output), "Usage:") {
				t.Fatalf("help missing usage: %s", output)
			}
		})
	}
}
