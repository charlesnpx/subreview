package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/subreview/internal/gate"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
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

func TestArtifactImportAndStatusCLI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	assertCLIHelpContains(t, bin, []string{"artifact", "--help"}, "Standalone artifact review")
	assertCLIHelpContains(t, bin, []string{"artifact", "status", "--help"}, "Artifact review loops use packet build, result import, and artifact status")
	assertCLIHelpContains(t, bin, []string{"packet", "build", "--help"}, "Artifact packets use --kind artifact --artifact <id>")
	assertCLIHelpContains(t, bin, []string{"result", "import", "--help"}, "For artifact_review packets")
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	stateDir := filepath.Join(root, "state")
	planPath := filepath.Join(root, "plan.md")
	if err := os.WriteFile(planPath, []byte("# Plan\n\nReview me.\n"), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	assertCLIStateValid(t, bin, stateDir)
	importOut, err := exec.Command(bin, "artifact", "import", "--state", stateDir, "--kind", "plan", "--path", planPath, "--title", "CLI Plan", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact import failed: %v\n%s", err, importOut)
	}
	var imported struct {
		ArtifactID    string `json:"artifact_id"`
		Kind          string `json:"kind"`
		Title         string `json:"title"`
		ContentDigest string `json:"content_digest"`
		EventID       string `json:"event_id"`
	}
	if err := json.Unmarshal(importOut, &imported); err != nil {
		t.Fatalf("import output is not json: %v\n%s", err, importOut)
	}
	if imported.ArtifactID == "" || imported.Kind != "plan" || imported.Title != "CLI Plan" || imported.ContentDigest == "" || imported.EventID == "" {
		t.Fatalf("bad import output: %s", importOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	statusOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact status failed: %v\n%s", err, statusOut)
	}
	var status struct {
		ArtifactID     string `json:"artifact_id"`
		Status         string `json:"status"`
		ReviewRequired bool   `json:"review_required"`
		Artifact       struct {
			ContentDigest string `json:"content_digest"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(statusOut, &status); err != nil {
		t.Fatalf("status output is not json: %v\n%s", err, statusOut)
	}
	if status.ArtifactID != imported.ArtifactID || status.Status != "no_review_packet" || !status.ReviewRequired || status.Artifact.ContentDigest != imported.ContentDigest {
		t.Fatalf("bad status output: %s", statusOut)
	}
	statusTextOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", imported.ArtifactID).CombinedOutput()
	if err != nil {
		t.Fatalf("artifact status text failed: %v\n%s", err, statusTextOut)
	}
	if got := string(statusTextOut); !strings.Contains(got, "artifact status: "+imported.ArtifactID) || !strings.Contains(got, "status=no_review_packet") {
		t.Fatalf("bad text status output: %s", statusTextOut)
	}
	packetOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "artifact", "--artifact", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact packet build failed: %v\n%s", err, packetOut)
	}
	var builtPacket struct {
		Kind    string `json:"kind"`
		RunKind string `json:"run_kind"`
		Route   string `json:"route"`
		Packet  struct {
			Digest string `json:"digest"`
		} `json:"packet"`
		Artifact struct {
			ID string `json:"id"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(packetOut, &builtPacket); err != nil {
		t.Fatalf("packet output is not json: %v\n%s", err, packetOut)
	}
	if builtPacket.Kind != "artifact" || builtPacket.RunKind != "discovery" || builtPacket.Route != "artifact_review" || builtPacket.Packet.Digest == "" || builtPacket.Artifact.ID != imported.ArtifactID {
		t.Fatalf("bad packet output: %s", packetOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	statusAfterPacketOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact status after packet failed: %v\n%s", err, statusAfterPacketOut)
	}
	var statusAfterPacket struct {
		Status       string `json:"status"`
		LatestPacket struct {
			Packet string `json:"packet"`
			Route  string `json:"route"`
		} `json:"latest_packet"`
	}
	if err := json.Unmarshal(statusAfterPacketOut, &statusAfterPacket); err != nil {
		t.Fatalf("status after packet output is not json: %v\n%s", err, statusAfterPacketOut)
	}
	if statusAfterPacket.Status != "waiting_for_result" || statusAfterPacket.LatestPacket.Packet != builtPacket.Packet.Digest || statusAfterPacket.LatestPacket.Route != "artifact_review" {
		t.Fatalf("bad status after packet output: %s", statusAfterPacketOut)
	}
	artifactResultOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", builtPacket.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        builtPacket.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RouteArtifactReview,
		Outcome:       reviewresult.OutcomeFindings,
		Findings: []reviewresult.FindingInput{{
			ID:              "artifact-cli",
			Severity:        "high",
			Class:           "correctness",
			Claim:           "The plan omits an actionable release verification step.",
			FailureScenario: "An operator follows the plan and cannot prove the upgraded release version is correct.",
			ArtifactRefs: []reviewresult.ArtifactRef{{
				ArtifactID: imported.ArtifactID,
				Section:    "Plan",
				StartLine:  1,
				EndLine:    2,
				Quote:      "Review me",
			}},
		}},
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact result import failed: %v\n%s", err, artifactResultOut)
	}
	var artifactResult struct {
		ArtifactID           string `json:"artifact_id"`
		Outcome              string `json:"outcome"`
		AcceptedFindingCount int    `json:"accepted_finding_count"`
	}
	if err := json.Unmarshal(artifactResultOut, &artifactResult); err != nil {
		t.Fatalf("artifact result output is not json: %v\n%s", err, artifactResultOut)
	}
	if artifactResult.ArtifactID != imported.ArtifactID || artifactResult.Outcome != "findings" || artifactResult.AcceptedFindingCount != 1 {
		t.Fatalf("bad artifact result output: %s", artifactResultOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	statusAfterResultOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact status after result failed: %v\n%s", err, statusAfterResultOut)
	}
	var statusAfterResult struct {
		Status               string `json:"status"`
		ReviewRequired       bool   `json:"review_required"`
		Outcome              string `json:"outcome"`
		Clean                bool   `json:"clean"`
		AcceptedFindingCount int    `json:"accepted_finding_count"`
		LatestArtifactID     string `json:"latest_artifact_id"`
		IsLatest             bool   `json:"is_latest"`
		LatestResult         struct {
			Packet  string `json:"packet"`
			Outcome string `json:"outcome"`
		} `json:"latest_result"`
	}
	if err := json.Unmarshal(statusAfterResultOut, &statusAfterResult); err != nil {
		t.Fatalf("status after result output is not json: %v\n%s", err, statusAfterResultOut)
	}
	if statusAfterResult.Status != "findings" || !statusAfterResult.ReviewRequired || statusAfterResult.Outcome != "findings" || statusAfterResult.Clean || statusAfterResult.AcceptedFindingCount != 1 || statusAfterResult.LatestArtifactID != imported.ArtifactID || !statusAfterResult.IsLatest || statusAfterResult.LatestResult.Packet != builtPacket.Packet.Digest || statusAfterResult.LatestResult.Outcome != "findings" {
		t.Fatalf("bad status after artifact result output: %s", statusAfterResultOut)
	}
	revisedPath := filepath.Join(root, "revised-plan.md")
	if err := os.WriteFile(revisedPath, []byte("# Revised Plan\n\nReview me again.\n"), 0o644); err != nil {
		t.Fatalf("write revised plan: %v", err)
	}
	revisedOut, err := exec.Command(bin, "artifact", "import", "--state", stateDir, "--kind", "plan", "--path", revisedPath, "--title", "CLI Plan Revision", "--revises", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("revised artifact import failed: %v\n%s", err, revisedOut)
	}
	var revised struct {
		ArtifactID string `json:"artifact_id"`
		Revises    string `json:"revises"`
	}
	if err := json.Unmarshal(revisedOut, &revised); err != nil {
		t.Fatalf("revised import output is not json: %v\n%s", err, revisedOut)
	}
	if revised.ArtifactID == "" || revised.ArtifactID == imported.ArtifactID || revised.Revises != imported.ArtifactID {
		t.Fatalf("bad revised import output: %s", revisedOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	revisedPacketOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "artifact", "--artifact", revised.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("revised artifact packet build failed: %v\n%s", err, revisedPacketOut)
	}
	var revisedPacket struct {
		Kind    string `json:"kind"`
		RunKind string `json:"run_kind"`
		Route   string `json:"route"`
		Packet  struct {
			Digest string `json:"digest"`
		} `json:"packet"`
		Artifact struct {
			ID string `json:"id"`
		} `json:"artifact"`
	}
	if err := json.Unmarshal(revisedPacketOut, &revisedPacket); err != nil {
		t.Fatalf("revised packet output is not json: %v\n%s", err, revisedPacketOut)
	}
	if revisedPacket.Kind != "artifact" || revisedPacket.RunKind != "discovery" || revisedPacket.Route != "artifact_review" || revisedPacket.Packet.Digest == "" || revisedPacket.Artifact.ID != revised.ArtifactID {
		t.Fatalf("bad revised packet output: %s", revisedPacketOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	statusAfterRevisionPacketOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", revised.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact status after revised packet failed: %v\n%s", err, statusAfterRevisionPacketOut)
	}
	var statusAfterRevisionPacket struct {
		Status         string `json:"status"`
		ReviewRequired bool   `json:"review_required"`
		LatestPacket   struct {
			Packet string `json:"packet"`
		} `json:"latest_packet"`
		SupersededFindings []struct {
			FindingID string `json:"finding_id"`
		} `json:"superseded_findings"`
	}
	if err := json.Unmarshal(statusAfterRevisionPacketOut, &statusAfterRevisionPacket); err != nil {
		t.Fatalf("status after revised packet output is not json: %v\n%s", err, statusAfterRevisionPacketOut)
	}
	if statusAfterRevisionPacket.Status != "waiting_for_result" || !statusAfterRevisionPacket.ReviewRequired || statusAfterRevisionPacket.LatestPacket.Packet != revisedPacket.Packet.Digest || len(statusAfterRevisionPacket.SupersededFindings) != 1 || statusAfterRevisionPacket.SupersededFindings[0].FindingID != "artifact-cli" {
		t.Fatalf("bad status after revised packet output: %s", statusAfterRevisionPacketOut)
	}
	cleanResultOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", revisedPacket.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        revisedPacket.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RouteArtifactReview,
		Outcome:       reviewresult.OutcomeClean,
		Summary:       "No actionable findings remain in the revised plan.",
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("clean artifact result import failed: %v\n%s", err, cleanResultOut)
	}
	var cleanResult struct {
		ArtifactID           string `json:"artifact_id"`
		Outcome              string `json:"outcome"`
		AcceptedFindingCount int    `json:"accepted_finding_count"`
	}
	if err := json.Unmarshal(cleanResultOut, &cleanResult); err != nil {
		t.Fatalf("clean artifact result output is not json: %v\n%s", err, cleanResultOut)
	}
	if cleanResult.ArtifactID != revised.ArtifactID || cleanResult.Outcome != "clean" || cleanResult.AcceptedFindingCount != 0 {
		t.Fatalf("bad clean artifact result output: %s", cleanResultOut)
	}
	assertCLIStateValid(t, bin, stateDir)
	finalStatusOut, err := exec.Command(bin, "artifact", "status", "--state", stateDir, "--artifact", revised.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("final artifact status failed: %v\n%s", err, finalStatusOut)
	}
	var finalStatus struct {
		Status           string `json:"status"`
		ReviewRequired   bool   `json:"review_required"`
		Outcome          string `json:"outcome"`
		Clean            bool   `json:"clean"`
		LatestArtifactID string `json:"latest_artifact_id"`
		IsLatest         bool   `json:"is_latest"`
		LatestResult     struct {
			Packet  string `json:"packet"`
			Outcome string `json:"outcome"`
		} `json:"latest_result"`
		SupersededFindings []struct {
			FindingID string `json:"finding_id"`
		} `json:"superseded_findings"`
	}
	if err := json.Unmarshal(finalStatusOut, &finalStatus); err != nil {
		t.Fatalf("final status output is not json: %v\n%s", err, finalStatusOut)
	}
	if finalStatus.Status != "clean" || finalStatus.ReviewRequired || finalStatus.Outcome != "clean" || !finalStatus.Clean || finalStatus.LatestArtifactID != revised.ArtifactID || !finalStatus.IsLatest || finalStatus.LatestResult.Packet != revisedPacket.Packet.Digest || finalStatus.LatestResult.Outcome != "clean" || len(finalStatus.SupersededFindings) != 1 {
		t.Fatalf("bad final artifact status output: %s", finalStatusOut)
	}
	assertCLIStateValid(t, bin, stateDir)
}

func TestResultValidateCLIJSONAndContextBounds(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	stateDir := filepath.Join(root, "state")
	planPath := filepath.Join(root, "plan.md")
	if err := os.WriteFile(planPath, []byte("# Plan\n\nReview me.\n"), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	importOut, err := exec.Command(bin, "artifact", "import", "--state", stateDir, "--kind", "plan", "--path", planPath, "--title", "Validate Plan", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact import failed: %v\n%s", err, importOut)
	}
	var imported struct {
		ArtifactID string `json:"artifact_id"`
	}
	if err := json.Unmarshal(importOut, &imported); err != nil {
		t.Fatalf("artifact import output is not json: %v\n%s", err, importOut)
	}
	packetOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "artifact", "--artifact", imported.ArtifactID, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("artifact packet build failed: %v\n%s", err, packetOut)
	}
	var builtPacket struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
	}
	if err := json.Unmarshal(packetOut, &builtPacket); err != nil {
		t.Fatalf("packet output is not json: %v\n%s", err, packetOut)
	}
	validPath := writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        builtPacket.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RouteArtifactReview,
		Outcome:       reviewresult.OutcomeClean,
		Summary:       "No actionable findings.",
	})
	validOut, err := exec.Command(bin, "result", "validate", "--state", stateDir, "--packet", builtPacket.Packet.Digest, "--result", validPath, "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("valid result validate failed: %v\n%s", err, validOut)
	}
	var valid struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(validOut, &valid); err != nil || !valid.Valid {
		t.Fatalf("valid result validate output is wrong: err=%v out=%s", err, validOut)
	}
	invalidPath := filepath.Join(root, "invalid-result.json")
	if err := os.WriteFile(invalidPath, []byte(`{"schema_version": 1,`), 0o644); err != nil {
		t.Fatalf("write invalid result: %v", err)
	}
	cmd := exec.Command(bin, "result", "validate", "--state", stateDir, "--packet", builtPacket.Packet.Digest, "--result", invalidPath, "--json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	invalidOut, err := cmd.Output()
	if err == nil {
		t.Fatalf("invalid result validate should exit non-zero: %s", invalidOut)
	}
	if stderr.Len() != 0 {
		t.Fatalf("invalid result validate should not write stderr: %s", stderr.String())
	}
	if bytes.Contains(invalidOut, []byte("\n  ")) {
		t.Fatalf("invalid result validate should be compact json: %s", invalidOut)
	}
	var invalid struct {
		SchemaVersion int    `json:"schema_version"`
		Valid         bool   `json:"valid"`
		Error         string `json:"error"`
	}
	if err := json.Unmarshal(invalidOut, &invalid); err != nil {
		t.Fatalf("invalid result output is not json: %v\n%s", err, invalidOut)
	}
	if invalid.SchemaVersion != 1 || invalid.Valid || invalid.Error == "" {
		t.Fatalf("bad invalid result output: %s", invalidOut)
	}
	for _, raw := range []string{"0", "-1", "262145"} {
		args := []string{"packet", "build", "--state", filepath.Join(root, "missing-state"), "--kind", "primary", "--max-context-bytes=" + raw}
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), "--max-context-bytes") {
			t.Fatalf("max-context-bytes=%s should fail before packet build, err=%v out=%s", raw, err, out)
		}
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
	passCommand := cliGateCommand("go_test_all", "printf gate-ok")
	catalogPath := filepath.Join(root, "gate-catalog.json")
	writeCLIGateCatalog(t, catalogPath, passCommand)
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "`+gate.CommandDigest(passCommand)+`", "required": true}
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
	failingCommand := cliGateCommand("go_test_all", "exit 7")
	failingCatalogPath := filepath.Join(root, "failing-gate-catalog.json")
	writeCLIGateCatalog(t, failingCatalogPath, failingCommand)
	failingPolicyPath := filepath.Join(root, "failing-policy.json")
	if err := os.WriteFile(failingPolicyPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "`+gate.CommandDigest(failingCommand)+`", "required": true}
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
		t.Fatalf("write failing policy config: %v", err)
	}
	if out, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", failingPolicyPath, "--profile", "default", "--json").CombinedOutput(); err != nil {
		t.Fatalf("failing policy bind failed: %v\n%s", err, out)
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
	packetOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "primary", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("packet build failed: %v\n%s", err, packetOut)
	}
	var packetResult struct {
		Kind           string `json:"kind"`
		RunKind        string `json:"run_kind"`
		StableDigest   string `json:"stable_digest"`
		VolatileDigest string `json:"volatile_digest"`
		Packet         struct {
			Digest string `json:"digest"`
			Path   string `json:"path"`
		} `json:"packet"`
		Markdown struct {
			Digest string `json:"digest"`
			Path   string `json:"path"`
		} `json:"markdown"`
		SemanticDedupeKey struct {
			Digest string `json:"digest"`
		} `json:"semantic_dedupe_key"`
		Leakage struct {
			OK bool `json:"ok"`
		} `json:"leakage"`
		Context struct {
			EntryCount int `json:"entry_count"`
		} `json:"context"`
	}
	if err := json.Unmarshal(packetOut, &packetResult); err != nil {
		t.Fatalf("packet output is not json: %v\n%s", err, packetOut)
	}
	if packetResult.Kind != "primary" || packetResult.RunKind != "discovery" || packetResult.StableDigest == "" || packetResult.VolatileDigest == "" || packetResult.Packet.Digest == "" || packetResult.Markdown.Digest == "" || packetResult.SemanticDedupeKey.Digest == "" || !packetResult.Leakage.OK || packetResult.Context.EntryCount == 0 {
		t.Fatalf("bad packet output: %s", packetOut)
	}
	for _, path := range []string{packetResult.Packet.Path, packetResult.Markdown.Path} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("packet object path should exist %s: %v\n%s", path, err, packetOut)
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

func TestResultImportCLI(t *testing.T) {
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
      "gate_requirements": [],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
      "risk_routing": [],
      "closure_basis": {"allowed_basis": ["clean", "fixed", "deterministic_refutation"], "require_basis_for_unresolved": true}
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", policyPath, "--profile", "default", "--json").CombinedOutput(); err != nil {
		t.Fatalf("policy bind failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "base", "--repo", repo, "--ref", "HEAD", "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot base failed: %v\n%s", err, out)
	}
	writeCLIFile(t, repo, "alpha.txt", "one\ntwo\n")
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "proposal", "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot proposal failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "proposal", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff base->proposal failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "obligations", "build", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("proposal obligations build failed: %v\n%s", err, out)
	}
	packetOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "primary", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("packet build failed: %v\n%s", err, packetOut)
	}
	var packetResult struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
	}
	if err := json.Unmarshal(packetOut, &packetResult); err != nil {
		t.Fatalf("packet output is not json: %v\n%s", err, packetOut)
	}
	if packetResult.Packet.Digest == "" {
		t.Fatalf("packet digest missing: %s", packetOut)
	}

	cleanOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", packetResult.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        packetResult.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RoutePrimaryReview,
		Outcome:       reviewresult.OutcomeClean,
		Summary:       "No actionable findings.",
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("result import clean failed: %v\n%s", err, cleanOut)
	}
	var cleanResult struct {
		Outcome               string `json:"outcome"`
		PrimaryReviewEvidence bool   `json:"primary_review_evidence"`
		Result                struct {
			Digest string `json:"digest"`
		} `json:"result"`
	}
	if err := json.Unmarshal(cleanOut, &cleanResult); err != nil {
		t.Fatalf("clean result output is not json: %v\n%s", err, cleanOut)
	}
	if cleanResult.Outcome != reviewresult.OutcomeClean || !cleanResult.PrimaryReviewEvidence || cleanResult.Result.Digest == "" {
		t.Fatalf("bad clean result import: %s", cleanOut)
	}

	findingOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", packetResult.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        packetResult.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RoutePrimaryReview,
		Outcome:       reviewresult.OutcomeFindings,
		Findings: []reviewresult.FindingInput{{
			ID:              "finding-cli",
			Severity:        "high",
			Class:           "correctness",
			Claim:           "alpha.txt can hide the newly added line from downstream readers.",
			FailureScenario: "A consumer that expects the proposal's second line reads only the original content.",
			Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 2}},
			Anchors:         []reviewresult.AnchorRef{{Kind: "hunk", Path: "alpha.txt", StartLine: 1, EndLine: 2}},
		}},
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("result import finding failed: %v\n%s", err, findingOut)
	}
	var findingResult struct {
		FindingCount         int `json:"finding_count"`
		AcceptedFindingCount int `json:"accepted_finding_count"`
	}
	if err := json.Unmarshal(findingOut, &findingResult); err != nil {
		t.Fatalf("finding result output is not json: %v\n%s", err, findingOut)
	}
	if findingResult.FindingCount != 1 || findingResult.AcceptedFindingCount != 1 {
		t.Fatalf("bad finding result import: %s", findingOut)
	}
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "final", "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "final", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff base->final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "proposal", "--to", "final", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff proposal->final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "obligations", "build", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("final obligations build failed: %v\n%s", err, out)
	}
	verificationOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "verification", "--finding", "finding-cli", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("verification packet build failed: %v\n%s", err, verificationOut)
	}
	var verificationResult struct {
		Kind    string `json:"kind"`
		RunKind string `json:"run_kind"`
		Route   string `json:"route"`
		Packet  struct {
			Digest string `json:"digest"`
		} `json:"packet"`
		Verification struct {
			FindingID          string   `json:"finding_id"`
			ProposalFinalPatch string   `json:"proposal_final_patch"`
			Questions          []string `json:"questions"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(verificationOut, &verificationResult); err != nil {
		t.Fatalf("verification packet output is not json: %v\n%s", err, verificationOut)
	}
	if verificationResult.Kind != "verification" || verificationResult.RunKind != "verification" || verificationResult.Route != "targeted_verification" || verificationResult.Packet.Digest == "" || verificationResult.Verification.FindingID != "finding-cli" || verificationResult.Verification.ProposalFinalPatch == "" || len(verificationResult.Verification.Questions) == 0 {
		t.Fatalf("bad verification packet output: %s", verificationOut)
	}

	needsContextOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", packetResult.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        packetResult.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RoutePrimaryReview,
		Outcome:       reviewresult.OutcomeNeedsContext,
		NeedsContext: []reviewresult.ContextRequest{{
			Question: "Please include alpha_test.txt for follow-up review.",
			Reason:   "The reviewer needs nearby test coverage.",
			Paths:    []string{"alpha_test.txt"},
		}},
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("result import needs-context failed: %v\n%s", err, needsContextOut)
	}
	var needsContextResult struct {
		Outcome           string `json:"outcome"`
		NeedsContextCount int    `json:"needs_context_count"`
	}
	if err := json.Unmarshal(needsContextOut, &needsContextResult); err != nil {
		t.Fatalf("needs-context result output is not json: %v\n%s", err, needsContextOut)
	}
	if needsContextResult.Outcome != reviewresult.OutcomeNeedsContext || needsContextResult.NeedsContextCount != 1 {
		t.Fatalf("bad needs-context result import: %s", needsContextOut)
	}

	malformedPath := filepath.Join(root, "malformed-result.json")
	if err := os.WriteFile(malformedPath, []byte(`{"schema_version": 1,`), 0o644); err != nil {
		t.Fatalf("write malformed result: %v", err)
	}
	if out, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", packetResult.Packet.Digest, "--result", malformedPath, "--json").CombinedOutput(); err == nil {
		t.Fatalf("malformed result import should fail: %s", out)
	}
	if out, err := exec.Command(bin, "state", "validate", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state validate failed after result imports: %v\n%s", err, out)
	}
}

func TestCloseCLIEndToEndSmoke(t *testing.T) {
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

	passCommand := cliGateCommand("go_test_all", "test -f alpha.txt")
	catalogPath := filepath.Join(root, "gate-catalog.json")
	writeCLIGateCatalog(t, catalogPath, passCommand)
	policyPath := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{
  "schema_version": 1,
  "policy_id": "v1-default",
  "profiles": {
    "default": {
      "gate_requirements": [
        {"command_id": "go_test_all", "command_digest": "`+gate.CommandDigest(passCommand)+`", "required": true}
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
        "context_requests_resolved",
        "basis_fixed",
        "policy_bound"
      ],
      "risk_routing": [],
      "closure_basis": {
        "allowed_basis": ["clean", "fixed", "deterministic_refutation"],
        "require_basis_for_unresolved": true
      }
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	if out, err := exec.Command(bin, "state", "init", "--state", stateDir, "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state init failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "policy", "bind", "--state", stateDir, "--config", policyPath, "--profile", "default", "--json").CombinedOutput(); err != nil {
		t.Fatalf("policy bind failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "base", "--repo", repo, "--ref", "HEAD", "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot base failed: %v\n%s", err, out)
	}
	writeCLIFile(t, repo, "alpha.txt", "one\nbug\n")
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "proposal", "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot proposal failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "proposal", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff base->proposal failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "obligations", "build", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("proposal obligations build failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "gates", "run", "--state", stateDir, "--catalog", catalogPath, "--command-id", "go_test_all", "--snapshot", "proposal", "--json").CombinedOutput(); err != nil {
		t.Fatalf("proposal gate run failed: %v\n%s", err, out)
	}
	packetOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "primary", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("primary packet build failed: %v\n%s", err, packetOut)
	}
	var primary struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
	}
	if err := json.Unmarshal(packetOut, &primary); err != nil {
		t.Fatalf("primary packet output is not json: %v\n%s", err, packetOut)
	}
	if primary.Packet.Digest == "" {
		t.Fatalf("missing primary packet digest: %s", packetOut)
	}
	findingOut, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", primary.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        primary.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RoutePrimaryReview,
		Outcome:       reviewresult.OutcomeFindings,
		Summary:       "The proposal has one actionable finding.",
		Findings: []reviewresult.FindingInput{{
			ID:              "finding-close",
			Severity:        "high",
			Class:           "correctness",
			Claim:           "alpha.txt keeps the bug marker in the proposed final content.",
			FailureScenario: "A caller that reads alpha.txt observes the bug marker instead of the fixed value.",
			Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 2}},
			Anchors:         []reviewresult.AnchorRef{{Kind: "hunk", Path: "alpha.txt", StartLine: 1, EndLine: 2}},
		}},
		Telemetry: reviewresult.TokenTelemetry{
			GrossDiscoveryTokens:       210,
			IncrementalDiscoveryTokens: 180,
			OutputTokens:               30,
		},
	}), "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("finding result import failed: %v\n%s", err, findingOut)
	}
	writeCLIFile(t, repo, "alpha.txt", "one\nfixed\n")
	if out, err := exec.Command(bin, "snapshot", "capture", "--state", stateDir, "--kind", "final", "--repo", repo, "--json").CombinedOutput(); err != nil {
		t.Fatalf("snapshot final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "base", "--to", "final", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff base->final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "diff", "create", "--state", stateDir, "--from", "proposal", "--to", "final", "--json").CombinedOutput(); err != nil {
		t.Fatalf("diff proposal->final failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "obligations", "build", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("final obligations build failed: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "gates", "run", "--state", stateDir, "--catalog", catalogPath, "--command-id", "go_test_all", "--snapshot", "final", "--json").CombinedOutput(); err != nil {
		t.Fatalf("final gate run failed: %v\n%s", err, out)
	}
	finalPacketOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "primary", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("final primary packet build failed: %v\n%s", err, finalPacketOut)
	}
	var finalPrimary struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
	}
	if err := json.Unmarshal(finalPacketOut, &finalPrimary); err != nil {
		t.Fatalf("final primary packet output is not json: %v\n%s", err, finalPacketOut)
	}
	if finalPrimary.Packet.Digest == "" {
		t.Fatalf("missing final primary packet digest: %s", finalPacketOut)
	}
	if out, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", finalPrimary.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        finalPrimary.Packet.Digest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RoutePrimaryReview,
		Outcome:       reviewresult.OutcomeClean,
		Summary:       "No additional final-state findings.",
	}), "--json").CombinedOutput(); err != nil {
		t.Fatalf("final primary result import failed: %v\n%s", err, out)
	}
	verificationOut, err := exec.Command(bin, "packet", "build", "--state", stateDir, "--kind", "verification", "--finding", "finding-close", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("verification packet build failed: %v\n%s", err, verificationOut)
	}
	var verification struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
		Verification struct {
			FindingID          string `json:"finding_id"`
			ProposalFinalPatch string `json:"proposal_final_patch"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(verificationOut, &verification); err != nil {
		t.Fatalf("verification packet output is not json: %v\n%s", err, verificationOut)
	}
	if verification.Packet.Digest == "" || verification.Verification.FindingID != "finding-close" || verification.Verification.ProposalFinalPatch == "" {
		t.Fatalf("bad verification packet output: %s", verificationOut)
	}
	if out, err := exec.Command(bin, "result", "import", "--state", stateDir, "--packet", verification.Packet.Digest, "--result", writeCLIWorkerResult(t, reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        verification.Packet.Digest,
		RunKind:       reviewresult.RunKindVerification,
		Route:         reviewresult.RouteTargetedVerification,
		Outcome:       reviewresult.OutcomeVerification,
		Summary:       "The finding is fixed in the final state.",
		VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
			FindingID:        "finding-close",
			Outcome:          reviewresult.VerificationResolved,
			State:            reviewresult.StateVerified,
			Basis:            reviewresult.BasisFixVerification,
			Summary:          "alpha.txt now contains fixed rather than bug.",
			VerifierRelation: reviewresult.RelationFreshBlinded,
			RelationEvidence: reviewresult.RelationEvidenceCLIWitnessed,
		}},
		Telemetry: reviewresult.TokenTelemetry{
			GrossVerificationTokens:       130,
			IncrementalVerificationTokens: 95,
			OutputTokens:                  18,
		},
	}), "--json").CombinedOutput(); err != nil {
		t.Fatalf("verification result import failed: %v\n%s", err, out)
	}
	closeOut, err := exec.Command(bin, "close", "--state", stateDir, "--policy-profile", "default", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("close failed: %v\n%s", err, closeOut)
	}
	var closeResult struct {
		Closed bool `json:"closed"`
		Report struct {
			Digest string `json:"digest"`
			Path   string `json:"path"`
		} `json:"report"`
		Facts struct {
			RequiredGatesSatisfied       bool `json:"required_gates_satisfied"`
			PrimaryReviewCompleted       bool `json:"primary_review_completed"`
			BlockingFindingsVerified     bool `json:"blocking_findings_verified"`
			CoverageObligationsSatisfied bool `json:"coverage_obligations_satisfied"`
			ContextRequestsResolved      bool `json:"context_requests_resolved"`
			BasisFixed                   bool `json:"basis_fixed"`
			FreshBlindedReview           bool `json:"fresh_blinded_review"`
			CLIWitnessed                 bool `json:"cli_witnessed"`
		} `json:"facts"`
		Gates struct {
			RequiredCount int `json:"required_count"`
			PassCount     int `json:"pass_count"`
		} `json:"gates"`
		Findings struct {
			AcceptedCount     int `json:"accepted_count"`
			OpenBlockingCount int `json:"open_blocking_count"`
		} `json:"findings"`
		Runs struct {
			DiscoveryRuns         int `json:"discovery_runs"`
			VerificationRuns      int `json:"verification_runs"`
			PrimaryRuns           int `json:"primary_runs"`
			TargetedVerifications int `json:"targeted_verifications"`
		} `json:"runs"`
		Tokens struct {
			FullCycle struct {
				Available         bool `json:"available"`
				IncrementalTokens int  `json:"incremental_tokens"`
			} `json:"full_cycle_estimate"`
		} `json:"tokens"`
		Scheduler struct {
			AntiThrashOK bool `json:"anti_thrash_ok"`
		} `json:"scheduler"`
		Blockers []struct {
			Code string `json:"code"`
		} `json:"blockers"`
	}
	if err := json.Unmarshal(closeOut, &closeResult); err != nil {
		t.Fatalf("close output is not json: %v\n%s", err, closeOut)
	}
	if !closeResult.Closed || len(closeResult.Blockers) != 0 {
		t.Fatalf("expected closure success: %s", closeOut)
	}
	if !closeResult.Facts.RequiredGatesSatisfied || !closeResult.Facts.PrimaryReviewCompleted || !closeResult.Facts.BlockingFindingsVerified || !closeResult.Facts.CoverageObligationsSatisfied || !closeResult.Facts.ContextRequestsResolved || !closeResult.Facts.BasisFixed || !closeResult.Facts.FreshBlindedReview || !closeResult.Facts.CLIWitnessed {
		t.Fatalf("closure facts incomplete: %s", closeOut)
	}
	if closeResult.Gates.RequiredCount != 1 || closeResult.Gates.PassCount != 2 || closeResult.Findings.AcceptedCount != 1 || closeResult.Findings.OpenBlockingCount != 0 {
		t.Fatalf("bad gate/finding report: %s", closeOut)
	}
	if closeResult.Runs.DiscoveryRuns != 2 || closeResult.Runs.VerificationRuns != 1 || closeResult.Runs.PrimaryRuns != 2 || closeResult.Runs.TargetedVerifications != 1 {
		t.Fatalf("bad run report: %s", closeOut)
	}
	if !closeResult.Tokens.FullCycle.Available || closeResult.Tokens.FullCycle.IncrementalTokens != 275 || !closeResult.Scheduler.AntiThrashOK {
		t.Fatalf("bad token or scheduler report: %s", closeOut)
	}
	if closeResult.Report.Digest == "" || closeResult.Report.Path == "" {
		t.Fatalf("closure report object missing: %s", closeOut)
	}
	if _, err := os.Stat(closeResult.Report.Path); err != nil {
		t.Fatalf("closure report path should exist %s: %v", closeResult.Report.Path, err)
	}
	if out, err := exec.Command(bin, "state", "validate", "--state", stateDir, "--json").CombinedOutput(); err != nil {
		t.Fatalf("state validate failed after closure: %v\n%s", err, out)
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

func cliGateCommand(commandID, script string) gate.CommandDefinition {
	return gate.CommandDefinition{
		ID:                commandID,
		Argv:              []string{"/bin/sh", "-c", script},
		WorkingDir:        ".",
		ReplayClass:       gate.ReplayEnvironmentBound,
		EnvironmentPinned: true,
		ExecutesRepoCode:  true,
		SideEffects:       gate.SideEffectsNone,
		TimeoutSeconds:    5,
		AllowedExitCodes:  []int{0},
	}
}

func writeCLIGateCatalog(t *testing.T, path string, command gate.CommandDefinition) {
	t.Helper()
	body, err := json.MarshalIndent(gate.Catalog{
		SchemaVersion: gate.SchemaVersion,
		Commands:      []gate.CommandDefinition{command},
	}, "", "  ")
	if err != nil {
		t.Fatalf("Marshal gate catalog: %v", err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write gate catalog: %v", err)
	}
}

func writeCLIWorkerResult(t *testing.T, value reviewresult.WorkerResult) string {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal worker result: %v", err)
	}
	path := filepath.Join(t.TempDir(), "worker-result.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write worker result: %v", err)
	}
	return path
}

func assertCLIStateValid(t *testing.T, bin, stateDir string) {
	t.Helper()
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

func assertCLIHelpContains(t *testing.T, bin string, args []string, want string) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s help failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	if !strings.Contains(string(out), want) {
		t.Fatalf("%s help missing %q:\n%s", strings.Join(args, " "), want, out)
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
