package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestHelpLiteralIsAcceptedAsFlagValue(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	repo := filepath.Join(root, "help")
	stateDir := filepath.Join(root, "state")
	initCLIGitRepo(t, repo)
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init should accept repo path ending in help: %v\n%s", err, out)
	}
}

func TestPolicyCheckBindAndExplainCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	configPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(configPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "required": true},
        {"command_id": "subreview_state_validate", "command_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "required": true}
      ],
      "route_limits": {
        "primary_semantic_reviews": 1,
        "targeted_verifications": 1,
        "fresh_final_reviews": 0,
        "context_expansion_rounds": 1
      },
      "required_evidence_facts": [
        "required_gates_satisfied",
        "primary_review_completed",
        "blocking_findings_verified",
        "coverage_obligations_satisfied",
        "policy_bound"
      ],
      "risk_routing": [
        {"risk_tier": "high", "review_effort": "medium", "require_independent_final": true}
      ],
      "closure_basis": {
        "allowed_basis": ["clean", "fixed", "deterministic_refutation"],
        "require_basis_for_unresolved": true
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	checkOut, err := exec.Command(bin, "policy", "check", "--config", configPath, "--repo", root, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("policy check failed: %v\n%s", err, checkOut)
	}
	var checkResult struct {
		OK       bool `json:"ok"`
		Profiles []struct {
			Profile           string `json:"profile"`
			ClosurePredicates []struct {
				Fact string `json:"fact"`
			} `json:"closure_predicates"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(checkOut, &checkResult); err != nil {
		t.Fatalf("check output is not json: %v\n%s", err, checkOut)
	}
	if !checkResult.OK || len(checkResult.Profiles) != 1 || checkResult.Profiles[0].Profile != "default" || len(checkResult.Profiles[0].ClosurePredicates) == 0 {
		t.Fatalf("bad check output: %s", checkOut)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", root, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	bindOut, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", configPath, "--profile", "default", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("policy bind failed: %v\n%s", err, bindOut)
	}
	var bindResult struct {
		Profile string `json:"profile"`
		Policy  struct {
			Digest string `json:"digest"`
		} `json:"policy"`
		EventID string `json:"event_id"`
	}
	if err := json.Unmarshal(bindOut, &bindResult); err != nil {
		t.Fatalf("bind output is not json: %v\n%s", err, bindOut)
	}
	if bindResult.Profile != "default" || bindResult.Policy.Digest == "" || bindResult.EventID == "" {
		t.Fatalf("bad bind output: %s", bindOut)
	}
	explainOut, err := exec.Command(bin, "policy", "explain", "--state", stateDir, "--profile", "default", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("policy explain failed: %v\n%s", err, explainOut)
	}
	var explainResult struct {
		Profile           string `json:"profile"`
		PolicyDigest      string `json:"policy_digest"`
		ClosurePredicates []struct {
			Fact string `json:"fact"`
		} `json:"closure_predicates"`
	}
	if err := json.Unmarshal(explainOut, &explainResult); err != nil {
		t.Fatalf("explain output is not json: %v\n%s", err, explainOut)
	}
	if explainResult.Profile != "default" || explainResult.PolicyDigest != bindResult.Policy.Digest || len(explainResult.ClosurePredicates) == 0 {
		t.Fatalf("bad explain output: %s", explainOut)
	}
}

func TestGatesCheckRunAndRecordCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initCLIGitRepo(t, repo)
	writeCLIFile(t, repo, "alpha.txt", "one\n")
	runCLIGit(t, repo, "add", ".")
	runCLIGit(t, repo, "commit", "-m", "initial")
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "required": true}
      ],
      "route_limits": {
        "primary_semantic_reviews": 1,
        "targeted_verifications": 1,
        "fresh_final_reviews": 0,
        "context_expansion_rounds": 1
      },
      "required_evidence_facts": [
        "required_gates_satisfied",
        "primary_review_completed",
        "blocking_findings_verified",
        "coverage_obligations_satisfied",
        "policy_bound"
      ],
      "risk_routing": [],
      "closure_basis": {
        "allowed_basis": ["clean", "fixed", "deterministic_refutation"],
        "require_basis_for_unresolved": true
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	catalogPath := filepath.Join(root, "gate-catalog.json")
	if err := os.WriteFile(catalogPath, []byte(`{
  "schema_version": 1,
  "commands": [
    {
      "id": "go_test_all",
      "argv": ["/bin/sh", "-c", "printf gate-ok"],
      "working_dir": ".",
      "replay_class": "environment_bound",
      "environment_pinned": true,
      "executes_repo_code": true,
      "side_effects": "none",
      "timeout_seconds": 5
    }
  ]
}
`), 0o644); err != nil {
		t.Fatalf("write gate catalog: %v", err)
	}
	checkOut, err := exec.Command(bin, "gates", "check-catalog", "--catalog", catalogPath, "--repo", repo, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("gates check-catalog failed: %v\n%s", err, checkOut)
	}
	var check struct {
		OK       bool `json:"ok"`
		Commands []struct {
			ID            string `json:"id"`
			CommandDigest string `json:"command_digest"`
		} `json:"commands"`
	}
	if err := json.Unmarshal(checkOut, &check); err != nil {
		t.Fatalf("check-catalog output is not json: %v\n%s", err, checkOut)
	}
	if !check.OK || len(check.Commands) != 1 || check.Commands[0].ID != "go_test_all" || check.Commands[0].CommandDigest == "" {
		t.Fatalf("bad check-catalog output: %s", checkOut)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", policyPath, "--profile", "default", "--json").CombinedOutput(); err != nil {
		t.Fatalf("policy bind failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "proposal", "--repo", repo, "--ref", "HEAD", "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot proposal failed: %v\n%s", err, out)
	}
	runOut, err := exec.Command(bin, "gates", "run", "--state", stateDir, "--catalog", catalogPath, "--command-id", "go_test_all", "--snapshot", "proposal", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("gates run failed: %v\n%s", err, runOut)
	}
	var run struct {
		CommandID  string `json:"command_id"`
		Outcome    string `json:"outcome"`
		Provenance string `json:"provenance"`
		Evidence   struct {
			Digest string `json:"digest"`
			Path   string `json:"path"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(runOut, &run); err != nil {
		t.Fatalf("gates run output is not json: %v\n%s", err, runOut)
	}
	if run.CommandID != "go_test_all" || run.Outcome != "pass" || run.Provenance != "cli_witnessed" || run.Evidence.Digest == "" {
		t.Fatalf("bad gates run output: %s", runOut)
	}
	if _, err := os.Stat(run.Evidence.Path); err != nil {
		t.Fatalf("gate evidence object should exist %s: %v\n%s", run.Evidence.Path, err, runOut)
	}
	failingCatalogPath := filepath.Join(root, "failing-gate-catalog.json")
	if err := os.WriteFile(failingCatalogPath, []byte(`{
  "schema_version": 1,
  "commands": [
    {
      "id": "go_test_all",
      "argv": ["/bin/sh", "-c", "exit 7"],
      "working_dir": ".",
      "replay_class": "environment_bound",
      "environment_pinned": true,
      "executes_repo_code": true,
      "side_effects": "none",
      "timeout_seconds": 5
    }
  ]
}
`), 0o644); err != nil {
		t.Fatalf("write failing gate catalog: %v", err)
	}
	failingCmd := exec.Command(bin, "gates", "run", "--state", stateDir, "--catalog", failingCatalogPath, "--command-id", "go_test_all", "--snapshot", "proposal", "--json")
	failingOut, err := failingCmd.Output()
	if err == nil {
		t.Fatalf("failing gates run should exit non-zero: %s", failingOut)
	}
	var failingRun struct {
		Outcome  string `json:"outcome"`
		Evidence struct {
			Digest string `json:"digest"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(failingOut, &failingRun); err != nil {
		t.Fatalf("failing gates run stdout should be json: %v\n%s", err, failingOut)
	}
	if failingRun.Outcome != "fail" || failingRun.Evidence.Digest == "" {
		t.Fatalf("bad failing gates run output: %s", failingOut)
	}
	recordOut, err := exec.Command(bin, "gates", "record", "--state", stateDir, "--catalog", catalogPath, "--command-id", "go_test_all", "--snapshot", "proposal", "--outcome", "fail", "--diagnostic", "external failed", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("gates record failed: %v\n%s", err, recordOut)
	}
	var record struct {
		Outcome    string `json:"outcome"`
		Provenance string `json:"provenance"`
		Evidence   struct {
			Digest string `json:"digest"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(recordOut, &record); err != nil {
		t.Fatalf("gates record output is not json: %v\n%s", err, recordOut)
	}
	if record.Outcome != "fail" || record.Provenance != "external_asserted" || record.Evidence.Digest == "" {
		t.Fatalf("bad gates record output: %s", recordOut)
	}
	validateOut, err := exec.Command(bin, "state", "validate", "--state", stateDir, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("state validate failed: %v\n%s", err, validateOut)
	}
}

func TestSnapshotCaptureRestoreAndDiffCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initCLIGitRepo(t, repo)
	writeCLIFile(t, repo, "alpha.txt", "one\n")
	runCLIGit(t, repo, "add", "alpha.txt")
	runCLIGit(t, repo, "commit", "-m", "initial")
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000", "required": true}
      ],
      "route_limits": {
        "primary_semantic_reviews": 1,
        "targeted_verifications": 1,
        "fresh_final_reviews": 0,
        "context_expansion_rounds": 1
      },
      "required_evidence_facts": [
        "required_gates_satisfied",
        "primary_review_completed",
        "blocking_findings_verified",
        "coverage_obligations_satisfied",
        "policy_bound",
        "independent_final_completed"
      ],
      "risk_routing": [
        {"risk_tier": "high", "review_effort": "medium", "require_independent_final": true}
      ],
      "closure_basis": {
        "allowed_basis": ["clean", "fixed", "deterministic_refutation"],
        "require_basis_for_unresolved": true
      }
    }
  }
}
`), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	if out, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", policyPath, "--profile", "default", "--json").CombinedOutput(); err != nil {
		t.Fatalf("policy bind failed: %v\n%s", err, out)
	}

	baseOut, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "base", "--repo", repo, "--ref", "HEAD", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("snapshot base failed: %v\n%s", err, baseOut)
	}
	var base struct {
		Kind            string `json:"kind"`
		CommitSHA       string `json:"commit_sha"`
		GitTreeSHA      string `json:"git_tree_sha"`
		EntryCount      int    `json:"entry_count"`
		Reconstructable bool   `json:"reconstructable"`
		Snapshot        struct {
			Digest string `json:"digest"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(baseOut, &base); err != nil {
		t.Fatalf("base output is not json: %v\n%s", err, baseOut)
	}
	if base.Kind != "base" || base.CommitSHA == "" || base.GitTreeSHA == "" || base.EntryCount != 1 || !base.Reconstructable || base.Snapshot.Digest == "" {
		t.Fatalf("bad base output: %s", baseOut)
	}

	writeCLIFile(t, repo, "alpha.txt", "two\n")
	writeCLIFile(t, repo, "beta.txt", "beta\n")
	proposalOut, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "proposal", "--repo", repo, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("snapshot proposal failed: %v\n%s", err, proposalOut)
	}
	var proposal struct {
		Kind            string `json:"kind"`
		CommitSHA       string `json:"commit_sha"`
		Dirty           bool   `json:"dirty"`
		EntryCount      int    `json:"entry_count"`
		Reconstructable bool   `json:"reconstructable"`
		Snapshot        struct {
			Digest string `json:"digest"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(proposalOut, &proposal); err != nil {
		t.Fatalf("proposal output is not json: %v\n%s", err, proposalOut)
	}
	if proposal.Kind != "proposal" || !proposal.Dirty || proposal.CommitSHA != "" || proposal.EntryCount != 2 || !proposal.Reconstructable || proposal.Snapshot.Digest == "" {
		t.Fatalf("bad proposal output: %s", proposalOut)
	}

	diffOut, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "proposal", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("diff create failed: %v\n%s", err, diffOut)
	}
	var diff struct {
		FromSnapshot string `json:"from_snapshot"`
		ToSnapshot   string `json:"to_snapshot"`
		HasChanges   bool   `json:"has_changes"`
		Patch        struct {
			Digest string `json:"digest"`
		} `json:"patch"`
	}
	if err := json.Unmarshal(diffOut, &diff); err != nil {
		t.Fatalf("diff output is not json: %v\n%s", err, diffOut)
	}
	if diff.FromSnapshot != base.Snapshot.Digest || diff.ToSnapshot != proposal.Snapshot.Digest || !diff.HasChanges || diff.Patch.Digest == "" {
		t.Fatalf("bad diff output: %s", diffOut)
	}

	anchorsPath := filepath.Join(root, "anchors.json")
	if err := os.WriteFile(anchorsPath, []byte(`{
  "schema_version": 1,
  "anchors": [
    {"id": "alpha-file", "kind": "file", "path": "alpha.txt"},
    {"id": "missing-file", "kind": "file", "path": "missing.txt"}
  ]
}`), 0o644); err != nil {
		t.Fatalf("write anchors manifest: %v", err)
	}
	anchorsOut, err := exec.Command(bin, "anchors", "migrate", "--state", stateDir, "--from", "base", "--to", "proposal", "--anchors", anchorsPath, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("anchors migrate failed: %v\n%s", err, anchorsOut)
	}
	var anchorsResult struct {
		FromSnapshot string `json:"from_snapshot"`
		ToSnapshot   string `json:"to_snapshot"`
		EventID      string `json:"event_id"`
		Diff         struct {
			Path string `json:"path"`
		} `json:"diff"`
		Patch struct {
			Path string `json:"path"`
		} `json:"patch"`
		Results []struct {
			Anchor struct {
				ID string `json:"id"`
			} `json:"anchor"`
			Status        string `json:"status"`
			BlocksClosure bool   `json:"blocks_closure"`
		} `json:"results"`
		ClosureBlockers []struct {
			AnchorID string `json:"anchor_id"`
			Status   string `json:"status"`
		} `json:"closure_blockers"`
	}
	if err := json.Unmarshal(anchorsOut, &anchorsResult); err != nil {
		t.Fatalf("anchors output is not json: %v\n%s", err, anchorsOut)
	}
	if anchorsResult.FromSnapshot != base.Snapshot.Digest || anchorsResult.ToSnapshot != proposal.Snapshot.Digest || anchorsResult.EventID == "" || len(anchorsResult.Results) != 2 {
		t.Fatalf("bad anchors output: %s", anchorsOut)
	}
	for _, path := range []string{anchorsResult.Diff.Path, anchorsResult.Patch.Path} {
		if path == "" {
			t.Fatalf("anchor migration emitted empty object path: %s", anchorsOut)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("anchor migration object path should exist %s: %v\n%s", path, err, anchorsOut)
		}
	}
	statuses := map[string]string{}
	for _, result := range anchorsResult.Results {
		statuses[result.Anchor.ID] = result.Status
	}
	if statuses["alpha-file"] != "modified" || statuses["missing-file"] != "unresolved" || len(anchorsResult.ClosureBlockers) != 1 || anchorsResult.ClosureBlockers[0].AnchorID != "missing-file" {
		t.Fatalf("bad anchor migration statuses: %s", anchorsOut)
	}

	writeCLIFile(t, repo, "alpha.txt", "three\n")
	writeCLIFile(t, repo, "beta.txt", "beta\n")
	finalOut, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "final", "--repo", repo, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("snapshot final failed: %v\n%s", err, finalOut)
	}
	var final struct {
		Kind     string `json:"kind"`
		Dirty    bool   `json:"dirty"`
		Snapshot struct {
			Digest string `json:"digest"`
		} `json:"snapshot"`
	}
	if err := json.Unmarshal(finalOut, &final); err != nil {
		t.Fatalf("final output is not json: %v\n%s", err, finalOut)
	}
	if final.Kind != "final" || !final.Dirty || final.Snapshot.Digest == "" {
		t.Fatalf("bad final output: %s", finalOut)
	}
	baseFinalOut, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "final", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("base->final diff create failed: %v\n%s", err, baseFinalOut)
	}
	obligationsOut, err := exec.Command(bin, "obligations", "build", "--state", stateDir, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("obligations build failed: %v\n%s", err, obligationsOut)
	}
	var obligationsResult struct {
		Manifest struct {
			Digest string `json:"digest"`
			Path   string `json:"path"`
		} `json:"manifest"`
		ObligationCount int    `json:"obligation_count"`
		BlockerCount    int    `json:"blocker_count"`
		EventID         string `json:"event_id"`
	}
	if err := json.Unmarshal(obligationsOut, &obligationsResult); err != nil {
		t.Fatalf("obligations output is not json: %v\n%s", err, obligationsOut)
	}
	if obligationsResult.Manifest.Digest == "" || obligationsResult.Manifest.Path == "" || obligationsResult.ObligationCount == 0 || obligationsResult.BlockerCount != 0 || obligationsResult.EventID == "" {
		t.Fatalf("bad obligations build output: %s", obligationsOut)
	}
	if _, err := os.Stat(obligationsResult.Manifest.Path); err != nil {
		t.Fatalf("obligations manifest object path should exist %s: %v\n%s", obligationsResult.Manifest.Path, err, obligationsOut)
	}
	statusOut, err := exec.Command(bin, "obligations", "status", "--state", stateDir, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("obligations status failed: %v\n%s", err, statusOut)
	}
	var obligationStatus struct {
		Closed                       bool     `json:"closed"`
		UnsatisfiedCount             int      `json:"unsatisfied_count"`
		UnsatisfiedSatisfactionKinds []string `json:"unsatisfied_satisfaction_kinds"`
		Blockers                     []struct {
			Code string `json:"code"`
		} `json:"blockers"`
	}
	if err := json.Unmarshal(statusOut, &obligationStatus); err != nil {
		t.Fatalf("obligations status output is not json: %v\n%s", err, statusOut)
	}
	if obligationStatus.Closed || obligationStatus.UnsatisfiedCount == 0 || len(obligationStatus.UnsatisfiedSatisfactionKinds) == 0 {
		t.Fatalf("bad obligations status output: %s", statusOut)
	}
	statusBlockers := map[string]bool{}
	for _, blocker := range obligationStatus.Blockers {
		statusBlockers[blocker.Code] = true
	}
	for _, want := range []string{"unsatisfied_required_check", "unsatisfied_coverage", "unresolved_anchor"} {
		if !statusBlockers[want] {
			t.Fatalf("obligations status missing blocker %s: %s", want, statusOut)
		}
	}

	restoreDir := filepath.Join(root, "restore")
	restoreOut, err := exec.Command(bin, "snapshot", "restore", "--state", stateDir, "--kind", "proposal", "--output", restoreDir, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("snapshot restore failed: %v\n%s", err, restoreOut)
	}
	if got := readCLIFile(t, restoreDir, "alpha.txt"); got != "two\n" {
		t.Fatalf("restored alpha mismatch: %q", got)
	}
	if got := readCLIFile(t, restoreDir, "beta.txt"); got != "beta\n" {
		t.Fatalf("restored beta mismatch: %q", got)
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

func initCLIGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runCLIGit(t, repo, "init")
	runCLIGit(t, repo, "config", "user.email", "test@example.com")
	runCLIGit(t, repo, "config", "user.name", "Test User")
}

func runCLIGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeCLIFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func readCLIFile(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}
