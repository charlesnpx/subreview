package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
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
	if _, err := os.Stat(filepath.Join(stage, ".codex", "skills", "subreview", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatalf("plan should not write staged codex skill, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(stage, ".claude", "skills", "subreview", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatalf("plan should not write staged claude skill, stat err=%v", err)
	}
	if got := targetNames(result.Targets); !reflect.DeepEqual(got, []string{"claude", "codex", "tools"}) {
		t.Fatalf("all target plan mismatch: %+v", result.Targets)
	}
	toolFiles := result.Targets["tools"].Files
	if len(toolFiles) != 1 {
		t.Fatalf("expected one tools file: %+v", result.Targets)
	}
	assertPlanFiles(t, result)
	if len(result.Setup) != 1 || result.Setup[0].Kind != "executable" || result.Setup[0].Executable != "git" {
		t.Fatalf("expected git setup requirement: %+v", result.Setup)
	}
}

func TestRunPlanDoesNotRequireRepoRoot(t *testing.T) {
	t.Setenv("SUBREVIEW_REPO_ROOT", "")
	stage := t.TempDir()
	t.Chdir(t.TempDir())
	result, err := Run(Options{Operation: "plan", Target: "all", InstallRoot: stage, Version: "test"})
	if err != nil {
		t.Fatalf("Run plan outside repo: %v", err)
	}
	if got := targetNames(result.Targets); !reflect.DeepEqual(got, []string{"claude", "codex", "tools"}) {
		t.Fatalf("all target plan mismatch outside repo: %+v", result.Targets)
	}
	assertPlanFiles(t, result)
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
	codexSkill := filepath.Join(stage, ".codex", "skills", "subreview", "SKILL.md")
	claudeSkill := filepath.Join(stage, ".claude", "skills", "subreview", "SKILL.md")
	for _, path := range []string{codexSkill, claudeSkill} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected staged skill %s: %v", path, err)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read staged skill %s: %v", path, err)
		}
		content := string(body)
		for _, want := range []string{
			"subreview version",
			"subreview install-skills --plan --target all --json",
			"subreview artifact import --state <dir> --kind plan --path <file> --title <title>",
			"subreview artifact status --state <dir> --artifact <id> --json",
			"subreview packet build --state <dir> --kind artifact --artifact <id> --json",
			"subreview close --state <dir> --policy-profile <name> --json",
			"external subagent runner",
			"Do not claim that `subreview` spawns subagents",
			"Do not simulate unsupported `subreview` commands in prose",
			"explicit `--state <dir>` path",
			"Do not create hidden default state directories",
			"Do not claim code-review closure from a clean reviewer response alone",
		} {
			if !strings.Contains(content, want) {
				t.Fatalf("staged skill %s missing %q", path, want)
			}
		}
	}
	for target, files := range result.Targets {
		if len(files.Files) == 0 {
			t.Fatalf("target %s has no files", target)
		}
		for _, file := range files.Files {
			if !filepath.IsAbs(file.Path) {
				t.Fatalf("target %s path should be absolute: %+v", target, file)
			}
			if len(file.SHA256) != 64 {
				t.Fatalf("target %s file %s missing sha256: %+v", target, file.Path, file)
			}
		}
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

func TestAssistantUninstallDoesNotRemoveTools(t *testing.T) {
	stage := t.TempDir()
	if _, err := Run(Options{Operation: "install", Target: "all", InstallRoot: stage, Version: "test"}); err != nil {
		t.Fatalf("Run install all: %v", err)
	}
	binPath := filepath.Join(stage, ".local", "bin", "subreview")
	codexSkill := filepath.Join(stage, ".codex", "skills", "subreview", "SKILL.md")
	claudeSkill := filepath.Join(stage, ".claude", "skills", "subreview", "SKILL.md")
	for _, path := range []string{binPath, codexSkill, claudeSkill} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected staged file before uninstall %s: %v", path, err)
		}
	}
	if _, err := Run(Options{Operation: "uninstall", Target: "codex", InstallRoot: stage, Version: "test"}); err != nil {
		t.Fatalf("Run uninstall codex: %v", err)
	}
	if _, err := os.Stat(codexSkill); !os.IsNotExist(err) {
		t.Fatalf("expected codex skill removed, stat err=%v", err)
	}
	for _, path := range []string{binPath, claudeSkill} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("assistant uninstall should not remove %s: %v", path, err)
		}
	}
}

func TestRunTargetFiltering(t *testing.T) {
	tests := map[string][]string{
		"tools":  {"tools"},
		"codex":  {"codex"},
		"claude": {"claude"},
		"all":    {"claude", "codex", "tools"},
	}
	for target, wantTargets := range tests {
		t.Run(target, func(t *testing.T) {
			stage := t.TempDir()
			result, err := Run(Options{Operation: "plan", Target: target, InstallRoot: stage, Version: "test"})
			if err != nil {
				t.Fatalf("Run plan: %v", err)
			}
			if got := targetNames(result.Targets); !reflect.DeepEqual(got, wantTargets) {
				t.Fatalf("target %s mismatch: got %v want %v; targets=%+v", target, got, wantTargets, result.Targets)
			}
			if target != "all" && target != "tools" {
				if _, ok := result.Targets["tools"]; ok {
					t.Fatalf("target %s should not include tools target: %+v", target, result.Targets)
				}
			}
			if target == "codex" {
				assertSinglePath(t, result.Targets["codex"].Files, filepath.Join(stage, ".codex", "skills", "subreview", "SKILL.md"))
				if _, ok := result.Targets["claude"]; ok {
					t.Fatalf("codex target should not include claude skill: %+v", result.Targets)
				}
			}
			if target == "claude" {
				assertSinglePath(t, result.Targets["claude"].Files, filepath.Join(stage, ".claude", "skills", "subreview", "SKILL.md"))
				if _, ok := result.Targets["codex"]; ok {
					t.Fatalf("claude target should not include codex skill: %+v", result.Targets)
				}
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

func assertPlanFiles(t *testing.T, result Result) {
	t.Helper()
	for target, files := range result.Targets {
		for _, file := range files.Files {
			if !filepath.IsAbs(file.Path) {
				t.Fatalf("target %s planned path should be absolute: %+v", target, file)
			}
			if file.SHA256 != "" {
				t.Fatalf("target %s plan should not include sha256: %+v", target, file)
			}
		}
	}
}

func assertSinglePath(t *testing.T, files []File, want string) {
	t.Helper()
	if len(files) != 1 || files[0].Path != want {
		t.Fatalf("expected one path %s, got %+v", want, files)
	}
}

func targetNames(targets map[string]Files) []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
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
