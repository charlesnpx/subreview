package gate

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestCheckCatalogValidatesAndDigestsCommands(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	initGitRepo(t, repo)
	catalogPath := writeCatalog(t, root, Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("subreview_state_validate", []string{"/bin/sh", "-c", "printf state"}),
			testCommand("go_test_all", []string{"/bin/sh", "-c", "printf go"}),
		},
	})
	result, err := CheckCatalog(CheckOptions{CatalogPath: catalogPath, RepoPath: repo})
	if err != nil {
		t.Fatalf("CheckCatalog: %v", err)
	}
	if !result.OK || len(result.Commands) != 2 || result.Commands[0].ID != "go_test_all" || result.Commands[0].CommandDigest == "" {
		t.Fatalf("bad check result: %+v", result)
	}
	_, catalog, err := LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	if got, want := result.Commands[0].CommandDigest, CommandDigest(catalog.Commands[0]); got != want {
		t.Fatalf("command digest mismatch: %s != %s", got, want)
	}

	duplicatePath := writeCatalog(t, root, Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("go_test_all", []string{"/bin/sh", "-c", "true"}),
			testCommand("go_test_all", []string{"/bin/sh", "-c", "true"}),
		},
	})
	if _, err := CheckCatalog(CheckOptions{CatalogPath: duplicatePath, RepoPath: repo}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate command error, got %v", err)
	}

	pathlessPinned := testCommand("pathless", []string{"sh", "-c", "true"})
	pathlessPath := writeCatalog(t, root, Catalog{
		SchemaVersion: SchemaVersion,
		Commands:      []CommandDefinition{pathlessPinned},
	})
	if _, err := CheckCatalog(CheckOptions{CatalogPath: pathlessPath, RepoPath: repo}); err == nil || !strings.Contains(err.Error(), "environment_pinned argv[0]") {
		t.Fatalf("expected pathless pinned command error, got %v", err)
	}
}

func TestRunStoresCLIWitnessedGateEvidence(t *testing.T) {
	repo, stateDir := initializedGateState(t)
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("go_test_all", []string{"/bin/sh", "-c", "printf ok"}),
		},
	})
	result, err := Run(RunOptions{StateDir: stateDir, CatalogPath: catalogPath, CommandID: "go_test_all", SnapshotKind: "proposal", Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Repo != repo || result.Outcome != OutcomePass || result.Provenance != ProvenanceCLIWitnessed || result.Evidence.Digest == "" || result.Catalog.Digest == "" || result.PolicyDigest == "" {
		t.Fatalf("bad run result: %+v", result)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	body, err := store.Read(result.Evidence.Digest)
	if err != nil {
		t.Fatalf("Read evidence: %v", err)
	}
	var record EvidenceRecord
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatalf("Unmarshal evidence: %v", err)
	}
	if record.CommandID != "go_test_all" || record.Provenance != ProvenanceCLIWitnessed || record.Diagnostics.StdoutTail != "ok" || record.InputSnapshot.Kind != "proposal" {
		t.Fatalf("bad evidence record: %+v", record)
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	latest, err := LatestEvidenceByCommand(store, events, repo)
	if err != nil {
		t.Fatalf("LatestEvidenceByCommand: %v", err)
	}
	if latest["go_test_all"].Digest != result.Evidence.Digest || latest["go_test_all"].Record.Outcome != OutcomePass {
		t.Fatalf("latest evidence mismatch: %+v", latest)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestRunExecutesRestoredSnapshotNotDirtyWorkingTree(t *testing.T) {
	command := testCommand("go_test_all", []string{"/bin/sh", "-c", "test \"$(cat alpha.txt)\" = one"})
	repo, stateDir := initializedGateStateForCommand(t, command)
	writeFile(t, repo, "alpha.txt", "dirty\n")
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			command,
		},
	})
	result, err := Run(RunOptions{StateDir: stateDir, CatalogPath: catalogPath, CommandID: "go_test_all", SnapshotKind: "proposal", Now: time.Unix(250, 0)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Outcome != OutcomePass {
		t.Fatalf("gate should run against restored snapshot, got %+v", result)
	}
	if got := readFile(t, repo, "alpha.txt"); got != "dirty\n" {
		t.Fatalf("gate run should not modify live working tree, got %q", got)
	}
}

func TestRunRejectsCatalogCommandThatDoesNotMatchBoundPolicy(t *testing.T) {
	repo, stateDir := initializedGateState(t)
	marker := filepath.Join(repo, "untrusted-ran")
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("go_test_all", []string{"/bin/sh", "-c", "printf ran > " + marker}),
		},
	})
	_, err := Run(RunOptions{StateDir: stateDir, CatalogPath: catalogPath, CommandID: "go_test_all", SnapshotKind: "proposal", Now: time.Unix(255, 0)})
	if err == nil || !strings.Contains(err.Error(), "does not match bound policy digest") {
		t.Fatalf("Run should reject untrusted catalog command before execution, got %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("untrusted command should not execute, stat err=%v", err)
	}
}

func TestRunAndRecordRequireBoundPolicy(t *testing.T) {
	_, stateDir := initializedGateStateWithoutPolicy(t)
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("go_test_all", []string{"/bin/sh", "-c", "printf ok"}),
		},
	})
	if _, err := Run(RunOptions{StateDir: stateDir, CatalogPath: catalogPath, CommandID: "go_test_all", SnapshotKind: "proposal", Now: time.Unix(260, 0)}); err == nil || !strings.Contains(err.Error(), "policy is not bound") {
		t.Fatalf("Run should require policy binding, got %v", err)
	}
	if _, err := Record(RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "proposal",
		Outcome:      OutcomePass,
		Provenance:   ProvenanceExternalAsserted,
		Diagnostic:   "external pass",
		Now:          time.Unix(261, 0),
	}); err == nil || !strings.Contains(err.Error(), "policy is not bound") {
		t.Fatalf("Record should require policy binding, got %v", err)
	}
}

func TestRecordStoresExternalAssertedGateEvidence(t *testing.T) {
	_, stateDir := initializedGateState(t)
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands: []CommandDefinition{
			testCommand("go_test_all", []string{"/bin/sh", "-c", "printf ok"}),
		},
	})
	exitCode := 2
	result, err := Record(RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "proposal",
		Outcome:      OutcomeFail,
		Provenance:   ProvenanceExternalAsserted,
		Diagnostic:   "external CI failed",
		ExitCode:     &exitCode,
		Now:          time.Unix(300, 0),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if result.Outcome != OutcomeFail || result.Provenance != ProvenanceExternalAsserted || result.Evidence.Digest == "" {
		t.Fatalf("bad record result: %+v", result)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	body, err := store.Read(result.Evidence.Digest)
	if err != nil {
		t.Fatalf("Read evidence: %v", err)
	}
	var record EvidenceRecord
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatalf("Unmarshal evidence: %v", err)
	}
	if record.Provenance != ProvenanceExternalAsserted || record.Outcome != OutcomeFail || record.ExitCode == nil || *record.ExitCode != exitCode || record.Diagnostics.Summary != "external CI failed" {
		t.Fatalf("bad external evidence: %+v", record)
	}
	if _, err := Record(RecordOptions{StateDir: stateDir, CatalogPath: catalogPath, CommandID: "go_test_all", SnapshotKind: "proposal", Outcome: OutcomePass, Provenance: ProvenanceCLIWitnessed}); err == nil {
		t.Fatal("record should not accept cli_witnessed provenance")
	}
	badExitCode := 1
	if _, err := Record(RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "proposal",
		Outcome:      OutcomePass,
		Provenance:   ProvenanceExternalAsserted,
		ExitCode:     &badExitCode,
	}); err == nil || !strings.Contains(err.Error(), "does not match exit code") {
		t.Fatalf("expected pass with failing exit code to be rejected, got %v", err)
	}
}

func TestCustomCommandIDGateEvidenceValidates(t *testing.T) {
	command := testCommand("ci.custom-check_1", []string{"/bin/sh", "-c", "printf custom"})
	repo, stateDir := initializedGateStateForCommand(t, command)
	catalogPath := writeCatalog(t, t.TempDir(), Catalog{
		SchemaVersion: SchemaVersion,
		Commands:      []CommandDefinition{command},
	})
	result, err := Record(RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    command.ID,
		SnapshotKind: "proposal",
		Outcome:      OutcomePass,
		Provenance:   ProvenanceExternalAsserted,
		Diagnostic:   "custom gate passed",
		Now:          time.Unix(310, 0),
	})
	if err != nil {
		t.Fatalf("Record custom gate: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	latest, err := LatestEvidenceByCommand(store, events, repo)
	if err != nil {
		t.Fatalf("LatestEvidenceByCommand: %v", err)
	}
	observation, ok := latest[command.ID]
	if !ok || observation.Digest != result.Evidence.Digest || observation.Record.CommandID != command.ID {
		t.Fatalf("custom command evidence missing: %+v", latest)
	}
}

func TestTailBufferKeepsBoundedSuffix(t *testing.T) {
	var tail tailBuffer
	first := strings.Repeat("a", maxDiagnosticBytes)
	second := strings.Repeat("b", 100)
	if n, err := tail.Write([]byte(first)); err != nil || n != len(first) {
		t.Fatalf("first Write: n=%d err=%v", n, err)
	}
	if n, err := tail.Write([]byte(second)); err != nil || n != len(second) {
		t.Fatalf("second Write: n=%d err=%v", n, err)
	}
	got := tail.String()
	if len(got) != maxDiagnosticBytes {
		t.Fatalf("tail length = %d, want %d", len(got), maxDiagnosticBytes)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", maxDiagnosticBytes-len(second))) || !strings.HasSuffix(got, second) {
		t.Fatalf("tail did not preserve bounded suffix")
	}
	large := strings.Repeat("c", maxDiagnosticBytes+200)
	if n, err := tail.Write([]byte(large)); err != nil || n != len(large) {
		t.Fatalf("large Write: n=%d err=%v", n, err)
	}
	got = tail.String()
	if len(got) != maxDiagnosticBytes || got != strings.Repeat("c", maxDiagnosticBytes) {
		t.Fatalf("large write tail mismatch len=%d", len(got))
	}
}

func TestExecuteCommandEnvironmentPinnedDoesNotInheritAmbientEnvironment(t *testing.T) {
	t.Setenv("SUBREVIEW_AMBIENT_SECRET", "leaked")
	command := testCommand("go_test_all", []string{"/bin/sh", "-c", `test -z "$SUBREVIEW_AMBIENT_SECRET" && test "$SUBREVIEW_ALLOWED" = yes`})
	command.Env = map[string]string{"SUBREVIEW_ALLOWED": "yes"}
	command.AllowedExitCodes = []int{0}
	result := executeCommand(t.TempDir(), command, time.Now().UTC())
	if result.Outcome != OutcomePass {
		t.Fatalf("environment-pinned gate should only receive catalog env, got %+v", result)
	}
}

func TestExecuteCommandSignaledProcessDoesNotRecordInvalidExitCode(t *testing.T) {
	command := testCommand("go_test_all", []string{"/bin/sh", "-c", "kill -TERM $$"})
	result := executeCommand(t.TempDir(), command, time.Now().UTC())
	if result.Outcome != OutcomeError {
		t.Fatalf("signaled process should be recorded as error, got %+v", result)
	}
	if result.ExitCode != nil {
		t.Fatalf("signaled process should not record invalid exit code, got %+v", result)
	}
}

func TestExecuteCommandTimeoutKillsShellChildren(t *testing.T) {
	command := testCommand("go_test_all", []string{"/bin/sh", "-c", "sleep 5 & wait"})
	command.TimeoutSeconds = 1
	start := time.Now()
	result := executeCommand(t.TempDir(), command, start.UTC())
	elapsed := time.Since(start)
	if result.Outcome != OutcomeError || result.Summary != "gate command timed out" {
		t.Fatalf("expected timeout error, got %+v", result)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout should kill shell children promptly, elapsed %s", elapsed)
	}
}

func TestExecuteCommandCleansUpBackgroundChildrenAfterSuccess(t *testing.T) {
	root := t.TempDir()
	command := testCommand("go_test_all", []string{"/bin/sh", "-c", "(/bin/sleep 1; : > escaped-child) >/dev/null 2>&1 &"})
	command.AllowedExitCodes = []int{0}
	result := executeCommand(root, command, time.Now().UTC())
	if result.Outcome != OutcomePass {
		t.Fatalf("backgrounding gate should exit successfully, got %+v", result)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(root, "escaped-child")); !os.IsNotExist(err) {
		t.Fatalf("background child should have been killed before writing marker, stat err=%v", err)
	}
}

func initializedGateState(t *testing.T) (string, string) {
	t.Helper()
	return initializedGateStateForCommand(t, testCommand("go_test_all", []string{"/bin/sh", "-c", "printf ok"}))
}

func initializedGateStateForCommand(t *testing.T, command CommandDefinition) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigForCommand(t, root, command.ID, CommandDigest(command)), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	return repo, stateDir
}

func initializedGateStateWithoutPolicy(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	return repo, stateDir
}

func testCommand(id string, argv []string) CommandDefinition {
	return CommandDefinition{
		ID:                id,
		Argv:              argv,
		WorkingDir:        ".",
		ReplayClass:       ReplayEnvironmentBound,
		EnvironmentPinned: true,
		ExecutesRepoCode:  true,
		SideEffects:       SideEffectsNone,
		TimeoutSeconds:    5,
		AllowedExitCodes:  []int{0},
	}
}

func writeCatalog(t *testing.T, root string, catalog Catalog) string {
	t.Helper()
	body, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatalf("Marshal catalog: %v", err)
	}
	path := filepath.Join(root, "catalog-"+strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "-")+".json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write catalog: %v", err)
	}
	return path
}

func writePolicyConfig(t *testing.T, root, commandDigest string) string {
	t.Helper()
	return writePolicyConfigForCommand(t, root, "go_test_all", commandDigest)
}

func writePolicyConfigForCommand(t *testing.T, root, commandID, commandDigest string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [{"command_id": "` + commandID + `", "command_digest": "` + commandDigest + `", "required": true}],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["required_gates_satisfied", "primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
      "risk_routing": [],
      "closure_basis": {"allowed_basis": ["clean", "fixed", "deterministic_refutation"], "require_basis_for_unresolved": true}
    }
  }
}
`)
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func initGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "Test User")
}

func git(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}
