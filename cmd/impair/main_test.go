// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func capture(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	f, e := os.CreateTemp(t.TempDir(), "stdout")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	saved := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = saved }()
	err := fn()
	if _, e = f.Seek(0, 0); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(f)
	if e != nil {
		t.Fatal(e)
	}
	return string(b), err
}
func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--version"}, {"plan", "--help"}, {"doctor", "--help"}} {
		if _, e := capture(t, func() error { return mainErr(args) }); e != nil {
			t.Fatal(e)
		}
	}
}
func TestCLIRejectsUnexpectedArgs(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"apply"}, {"plan", "extra"}, {"example", "--mode", "bridge"}, {"validate", "--unknown"}} {
		if _, e := capture(t, func() error { return mainErr(args) }); e == nil {
			t.Fatalf("accepted %+v", args)
		}
	}
}
func TestExampleOfflineRoundtrip(t *testing.T) {
	for _, mode := range []string{"host", "gateway"} {
		out, e := capture(t, func() error { return mainErr([]string{"example", "--mode", mode}) })
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), "profile.json")
		if e = os.WriteFile(path, []byte(out), 0600); e != nil {
			t.Fatal(e)
		}
		for _, cmd := range [][]string{{"validate", "--profile", path}, {"validate", "--profile", path, "--json"}, {"plan", "--profile", path}, {"plan", "--profile", path, "--json"}, {"apply", "--profile", path, "--dry-run"}} {
			text, e := capture(t, func() error { return mainErr(cmd) })
			if e != nil {
				t.Fatal(e)
			}
			if text == "" {
				t.Fatal("missing output")
			}
			if cmd[0] == "plan" && len(cmd) == 3 && !strings.Contains(text, "'tc' 'qdisc'") {
				t.Fatal("missing command plan")
			}
		}
	}
}
