package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStateInitAndValidateCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	initOut, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", root, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("state init failed: %v\n%s", err, initOut)
	}
	var initResult map[string]any
	if err := json.Unmarshal(initOut, &initResult); err != nil {
		t.Fatalf("init output is not json: %v\n%s", err, initOut)
	}
	if initResult["state"] != stateDir || initResult["repo"] != root {
		t.Fatalf("bad init output: %s", initOut)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "objects", "sha256"),
		filepath.Join(stateDir, "manifests"),
		filepath.Join(stateDir, "ledger.jsonl"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected initialized path %s: %v", path, err)
		}
	}
	validateOut, err := exec.Command(bin, "state", "validate", "--state", stateDir, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("state validate failed: %v\n%s", err, validateOut)
	}
	var validation struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(validateOut, &validation); err != nil {
		t.Fatalf("validate output is not json: %v\n%s", err, validateOut)
	}
	if !validation.OK {
		t.Fatalf("expected valid state: %s", validateOut)
	}
}
