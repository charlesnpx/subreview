package result_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/packet"
	"github.com/charlesnpx/subreview/internal/policy"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestImportCleanPrimaryReviewSatisfiesCoverageStatus(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	imported, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings.",
		}),
		Now: time.Unix(200, 0),
	})
	if err != nil {
		t.Fatalf("Import clean result: %v", err)
	}
	if !imported.PrimaryReviewEvidence || imported.FindingCount != 0 || imported.Result.Digest == "" {
		t.Fatalf("bad import result: %+v", imported)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !status.Closed {
		t.Fatalf("clean primary result should satisfy coverage obligations without blockers: %+v", status.Blockers)
	}
	for _, item := range status.Obligations {
		if item.Obligation.Required && !item.Satisfied {
			t.Fatalf("required obligation should be satisfied: %+v", item)
		}
	}
}

func TestImportRejectsMalformedAndOversizedWithoutLedgerProgress(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	before := readEvents(t, stateDir)
	malformedPath := filepath.Join(t.TempDir(), "malformed.json")
	if err := os.WriteFile(malformedPath, []byte(`{"schema_version": 1,`), 0o644); err != nil {
		t.Fatalf("write malformed result: %v", err)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{StateDir: stateDir, PacketID: built.Packet.Digest, ResultPath: malformedPath}); err == nil {
		t.Fatal("malformed result should be rejected")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("malformed import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
	oversizedPath := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(oversizedPath, []byte(strings.Repeat("x", 300*1024)), 0o644); err != nil {
		t.Fatalf("write oversized result: %v", err)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{StateDir: stateDir, PacketID: built.Packet.Digest, ResultPath: oversizedPath}); err == nil {
		t.Fatal("oversized result should be rejected")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("oversized import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsDiscoveryRouteMismatch(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RouteIndependentFinal,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings.",
		}),
	}); err == nil {
		t.Fatal("primary packet should not accept independent-final discovery evidence")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("route mismatch should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsDiscoverySelfVerification(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("finding-one")},
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID:        "finding-one",
				State:            reviewresult.StateInvalidated,
				Basis:            reviewresult.BasisFreshSemantic,
				Summary:          "The primary reviewer tried to invalidate its own finding.",
				VerifierRelation: reviewresult.RelationFreshBlinded,
				RelationEvidence: reviewresult.RelationEvidenceCallerAssert,
			}},
		}),
	}); err == nil {
		t.Fatal("discovery findings result should not import verifier outcomes")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("self-verification import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportNormalizesTerminalDiscoveryFindingToNeedsConfirmation(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	finding := validFinding("terminal-start")
	finding.State = reviewresult.StateInvalidated
	imported, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{finding},
		}),
		Now: time.Unix(235, 0),
	})
	if err != nil {
		t.Fatalf("Import terminal-state finding: %v", err)
	}
	if imported.AcceptedFindingCount != 1 || imported.RejectedStructuralCount != 0 {
		t.Fatalf("terminal-state finding should remain accepted but blocking: %+v", imported)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].FindingID != "terminal-start" || blockers[0].State != reviewresult.StateNeedsConfirmation {
		t.Fatalf("terminal-state finding should require confirmation: %+v", blockers)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Closed || !hasStatusBlocker(status, "open_finding") {
		t.Fatalf("terminal-start finding should keep closure blocked: %+v", status)
	}
}

func TestFindingDedupeIsScopedToCoverageManifest(t *testing.T) {
	repo, stateDir, firstPacket, _ := initializedResultState(t)
	first, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: firstPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        firstPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("finding-one")},
		}),
		Now: time.Unix(240, 0),
	})
	if err != nil {
		t.Fatalf("Import first finding result: %v", err)
	}
	if first.AcceptedFindingCount != 1 || first.DuplicateFindingCount != 0 {
		t.Fatalf("first finding should be accepted: %+v", first)
	}

	writeFile(t, repo, "alpha.txt", "one\ntwo\nthree\n")
	secondPacket := rebuildResultPacket(t, stateDir, repo)
	second, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: secondPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        secondPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("finding-one")},
		}),
		Now: time.Unix(250, 0),
	})
	if err != nil {
		t.Fatalf("Import second finding result: %v", err)
	}
	if second.AcceptedFindingCount != 1 || second.DuplicateFindingCount != 0 {
		t.Fatalf("same finding digest should not be duplicate across manifests: %+v", second)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, secondPacket.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].FindingID != "finding-one" {
		t.Fatalf("second manifest should retain its active finding blocker: %+v", blockers)
	}
}

func TestFindingsDedupeStructuralRejectionAndLifecycle(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	first, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings: []reviewresult.FindingInput{
				validFinding("finding-one"),
				validFinding("finding-duplicate"),
				{
					ID:              "missing-anchor",
					Severity:        "medium",
					Class:           "correctness",
					Claim:           "The finding is missing concrete anchor evidence.",
					FailureScenario: "The controller cannot later map this claim to an obligation.",
					Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
				},
			},
		}),
		Now: time.Unix(210, 0),
	})
	if err != nil {
		t.Fatalf("Import findings result: %v", err)
	}
	if first.AcceptedFindingCount != 1 || first.DuplicateFindingCount != 1 || first.RejectedStructuralCount != 1 {
		t.Fatalf("bad finding counts: %+v", first)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].FindingID != "finding-one" {
		t.Fatalf("expected one active finding blocker: %+v", blockers)
	}
	second, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID:        "finding-one",
				State:            reviewresult.StateInvalidated,
				Basis:            reviewresult.BasisFreshSemantic,
				Summary:          "A fresh reviewer checked the target behavior and found the claim false.",
				VerifierRelation: reviewresult.RelationFreshBlinded,
				RelationEvidence: reviewresult.RelationEvidenceCallerAssert,
			}},
		}),
		Now: time.Unix(220, 0),
	})
	if err != nil {
		t.Fatalf("Import verifier result: %v", err)
	}
	if second.VerifierOutcomeCount != 1 {
		t.Fatalf("bad verifier import: %+v", second)
	}
	observations = readObservations(t, stateDir)
	if blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest); len(blockers) != 0 {
		t.Fatalf("invalidated finding should not block closure: %+v", blockers)
	}
}

func TestDuplicateFindingIDsRejectLaterDistinctFinding(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	secondFinding := validFinding("same-id")
	secondFinding.Claim = "alpha.txt can hide an entirely different downstream failure."
	secondFinding.FailureScenario = "A different consumer observes a distinct failure path from the same proposal."
	imported, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings: []reviewresult.FindingInput{
				validFinding("same-id"),
				secondFinding,
			},
		}),
		Now: time.Unix(260, 0),
	})
	if err != nil {
		t.Fatalf("Import duplicate-id findings: %v", err)
	}
	if imported.AcceptedFindingCount != 1 || imported.RejectedStructuralCount != 1 {
		t.Fatalf("distinct findings sharing one id should reject the second as structural: %+v", imported)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].FindingID != "same-id" {
		t.Fatalf("duplicate id should not collapse active blockers: %+v", blockers)
	}
}

func TestDuplicateFindingIDAcrossImportsRejectsLaterDistinctFinding(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	first, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("same-id")},
		}),
		Now: time.Unix(261, 0),
	})
	if err != nil {
		t.Fatalf("Import first finding: %v", err)
	}
	if first.AcceptedFindingCount != 1 {
		t.Fatalf("first finding should be accepted: %+v", first)
	}
	secondFinding := validFinding("same-id")
	secondFinding.Claim = "alpha.txt can hide a later, distinct downstream failure."
	secondFinding.FailureScenario = "A later importer uses the same id for a distinct finding on this manifest."
	second, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{secondFinding},
		}),
		Now: time.Unix(262, 0),
	})
	if err != nil {
		t.Fatalf("Import second finding: %v", err)
	}
	if second.AcceptedFindingCount != 0 || second.RejectedStructuralCount != 1 {
		t.Fatalf("later distinct finding reusing an id should be structurally rejected: %+v", second)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].FindingID != "same-id" {
		t.Fatalf("later duplicate id should not replace prior blocker: %+v", blockers)
	}
}

func TestDeterministicRefutationSatisfiesSpecificObligation(t *testing.T) {
	_, stateDir, built, manifest := initializedResultState(t)
	obligationID := firstCoverageObligationID(t, manifest)
	imported, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				ObligationIDs: []string{obligationID},
				Basis:         reviewresult.BasisDeterministicRefutation,
				EvidenceKind:  "test",
				Summary:       "A focused regression test proves this obligation does not represent a defect.",
				Citations:     []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(230, 0),
	})
	if err != nil {
		t.Fatalf("Import deterministic refutation: %v", err)
	}
	if !imported.DeterministicRefutationEvidence {
		t.Fatalf("expected deterministic refutation evidence: %+v", imported)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, item := range status.Obligations {
		if item.Obligation.ID != obligationID {
			continue
		}
		if !item.Satisfied || len(item.SatisfiedBy) != 1 || item.SatisfiedBy[0].Kind != obligation.SatisfactionDeterministicRefute {
			t.Fatalf("obligation should be satisfied by deterministic refutation: %+v", item)
		}
		return
	}
	t.Fatalf("missing obligation %s", obligationID)
}

func initializedResultState(t *testing.T) (string, string, packet.BuildResult, obligation.CoverageManifest) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	builtObligations, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	builtPacket, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindPrimary, Now: time.Unix(110, 0)})
	if err != nil {
		t.Fatalf("Build packet: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	body, err := store.Read(builtObligations.Manifest.Digest)
	if err != nil {
		t.Fatalf("Read manifest: %v", err)
	}
	var manifest obligation.CoverageManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}
	return repo, stateDir, builtPacket, manifest
}

func rebuildResultPacket(t *testing.T, stateDir, repo string) packet.BuildResult {
	t.Helper()
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture replacement proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff replacement base->proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture replacement final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff replacement base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build replacement obligations: %v", err)
	}
	result, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindPrimary, Now: time.Unix(120, 0)})
	if err != nil {
		t.Fatalf("Build replacement packet: %v", err)
	}
	return result
}

func validFinding(id string) reviewresult.FindingInput {
	return reviewresult.FindingInput{
		ID:              id,
		Severity:        "high",
		Class:           "correctness",
		Claim:           "alpha.txt can hide the newly added line from downstream readers.",
		FailureScenario: "A consumer that expects the proposal's second line reads only the original content.",
		Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 2}},
		Anchors:         []reviewresult.AnchorRef{{Kind: "hunk", Path: "alpha.txt", StartLine: 1, EndLine: 2}},
		ExpectedFixSurface: []reviewresult.FixSurface{{
			Kind: "file",
			Path: "alpha.txt",
		}},
	}
}

func writeWorkerResult(t *testing.T, value reviewresult.WorkerResult) string {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("Marshal worker result: %v", err)
	}
	path := filepath.Join(t.TempDir(), "worker-result.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write worker result: %v", err)
	}
	return path
}

func readEvents(t *testing.T, stateDir string) []state.Event {
	t.Helper()
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	return events
}

func readObservations(t *testing.T, stateDir string) []reviewresult.EvidenceObservation {
	t.Helper()
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	events := readEvents(t, stateDir)
	observations, err := reviewresult.Observations(store, events, events[0].Repo)
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	return observations
}

func firstCoverageObligationID(t *testing.T, manifest obligation.CoverageManifest) string {
	t.Helper()
	for _, item := range manifest.Obligations {
		if item.Kind == obligation.KindChangedHunk || item.Kind == obligation.KindChangedFile || item.Kind == obligation.KindChangedPath {
			return item.ID
		}
	}
	t.Fatalf("manifest has no coverage obligation: %+v", manifest.Obligations)
	return ""
}

func hasStatusBlocker(status obligation.StatusResult, code string) bool {
	for _, blocker := range status.Blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func writePolicyConfig(t *testing.T, root string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
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
