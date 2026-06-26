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
}

func initializedGateState(t *testing.T) (string, string) {
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
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
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

func writePolicyConfig(t *testing.T, root string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [{"command_id": "go_test_all", "required": true}],
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
