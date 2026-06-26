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
        {"command_id": "go_test_all", "required": true},
        {"command_id": "subreview_state_validate", "required": true}
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
