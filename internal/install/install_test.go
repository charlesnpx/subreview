package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunPlanDoesNotWrite(t *testing.T) {
	stage := t.TempDir()
	result, err := Run(Options{Operation: "plan", Target: "all", InstallRoot: stage, Version: "test"})
	if err != nil {
		t.Fatalf("Run plan: %v", err)
	}
	if result.Schema != 1 || result.Name != "subreview" || result.Version != "test" || result.Operation != "plan" || result.Kind != "delegated" {
		t.Fatalf("bad result metadata: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(stage, ".local", "bin", "subreview")); !os.IsNotExist(err) {
		t.Fatalf("plan should not write staged binary, stat err=%v", err)
	}
	toolFiles := result.Targets["tools"].Files
	if len(toolFiles) != 1 {
		t.Fatalf("expected one tools file: %+v", result.Targets)
	}
	if !filepath.IsAbs(toolFiles[0].Path) {
		t.Fatalf("planned path should be absolute: %+v", toolFiles[0])
	}
	if toolFiles[0].SHA256 != "" {
		t.Fatalf("plan should not include sha256: %+v", toolFiles[0])
	}
	if len(result.Setup) != 1 || result.Setup[0].Kind != "executable" || result.Setup[0].Executable != "git" {
		t.Fatalf("expected git setup requirement: %+v", result.Setup)
	}
}

func TestRunInstallStagedAllTargets(t *testing.T) {
	stage := t.TempDir()
	result, err := Run(Options{Operation: "install", Target: "all", InstallRoot: stage, Version: "test-version"})
	if err != nil {
		t.Fatalf("Run install: %v", err)
	}
	binPath := filepath.Join(stage, ".local", "bin", "subreview")
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("expected staged binary %s: %v", binPath, err)
	}
	toolFiles := result.Targets["tools"].Files
	if len(toolFiles) != 1 || toolFiles[0].Path != binPath {
		t.Fatalf("bad tools target: %+v", result.Targets)
	}
	if len(toolFiles[0].SHA256) != 64 {
		t.Fatalf("missing sha256 after install: %+v", toolFiles[0])
	}
	out, err := exec.Command(binPath, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("staged subreview version failed: %v\n%s", err, out)
	}
	if got := string(out); got != "test-version\n" {
		t.Fatalf("version output mismatch: %q", got)
	}
	if _, ok := result.Targets["codex"]; ok {
		t.Fatalf("codex skill files are not part of Story 1: %+v", result.Targets)
	}
	if _, ok := result.Targets["claude"]; ok {
		t.Fatalf("claude skill files are not part of Story 1: %+v", result.Targets)
	}
}

func TestRunUninstallStagedTools(t *testing.T) {
	stage := t.TempDir()
	if _, err := Run(Options{Operation: "install", Target: "tools", InstallRoot: stage, Version: "test"}); err != nil {
		t.Fatalf("Run install: %v", err)
	}
	binPath := filepath.Join(stage, ".local", "bin", "subreview")
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("expected staged binary before uninstall: %v", err)
	}
	result, err := Run(Options{Operation: "uninstall", Target: "tools", InstallRoot: stage, Version: "test"})
	if err != nil {
		t.Fatalf("Run uninstall: %v", err)
	}
	if _, err := os.Stat(binPath); !os.IsNotExist(err) {
		t.Fatalf("expected staged binary removed, stat err=%v", err)
	}
	toolFiles := result.Targets["tools"].Files
	if len(toolFiles) != 1 || toolFiles[0].SHA256 != "" {
		t.Fatalf("uninstall result should include path without sha: %+v", result.Targets)
	}
}

func TestRunTargetFiltering(t *testing.T) {
	for _, target := range []string{"tools", "codex", "claude", "all"} {
		t.Run(target, func(t *testing.T) {
			result, err := Run(Options{Operation: "plan", Target: target, InstallRoot: t.TempDir(), Version: "test"})
			if err != nil {
				t.Fatalf("Run plan: %v", err)
			}
			if len(result.Targets) != 1 || len(result.Targets["tools"].Files) != 1 {
				t.Fatalf("Story 1 target %s should plan the required CLI tool only: %+v", target, result.Targets)
			}
		})
	}
}

func TestRunRejectsUnsupportedOperationAndTarget(t *testing.T) {
	if _, err := Run(Options{Operation: "sync", Target: "all", InstallRoot: t.TempDir()}); err == nil {
		t.Fatal("expected unsupported operation error")
	}
	if _, err := Run(Options{Operation: "plan", Target: "vim", InstallRoot: t.TempDir()}); err == nil {
		t.Fatal("expected unsupported target error")
	}
}

func TestResultJSONShape(t *testing.T) {
	result, err := Run(Options{Operation: "plan", Target: "all", InstallRoot: t.TempDir(), Version: "test"})
	if err != nil {
		t.Fatalf("Run plan: %v", err)
	}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	for _, key := range []string{"schema", "name", "version", "operation", "kind", "targets"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("delegated JSON missing required key %q: %s", key, body)
		}
	}
}
