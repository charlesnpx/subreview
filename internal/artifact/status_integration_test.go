package artifact_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/artifact"
	"github.com/charlesnpx/subreview/internal/packet"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestStatusReportsArtifactResultOutcomes(t *testing.T) {
	cases := []struct {
		name           string
		outcome        string
		wantStatus     string
		wantReview     bool
		wantClean      bool
		wantFindings   int
		wantNeedsCount int
	}{
		{name: "clean", outcome: reviewresult.OutcomeClean, wantStatus: "clean", wantClean: true},
		{name: "findings", outcome: reviewresult.OutcomeFindings, wantStatus: "findings", wantReview: true, wantFindings: 1},
		{name: "needs_context", outcome: reviewresult.OutcomeNeedsContext, wantStatus: "needs_context", wantReview: true, wantNeedsCount: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, stateDir := initializedStatusState(t)
			imported := importStatusArtifact(t, stateDir, repo, "plan.md", "Status Plan", "# Plan\n\nReview me.\n", "")
			built := buildStatusPacket(t, stateDir, imported.ArtifactID)
			importStatusResult(t, stateDir, built.Packet.Digest, imported.ArtifactID, tc.outcome, "finding-one")

			status, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: imported.ArtifactID})
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if status.Status != tc.wantStatus || status.ReviewRequired != tc.wantReview || status.Clean != tc.wantClean {
				t.Fatalf("bad status flags: %+v", status)
			}
			if !status.IsLatest || status.LatestArtifactID != imported.ArtifactID || status.Outcome != tc.outcome {
				t.Fatalf("bad latest artifact fields: %+v", status)
			}
			if status.LatestPacket == nil || status.LatestPacket.Packet != built.Packet.Digest {
				t.Fatalf("missing latest packet: %+v", status.LatestPacket)
			}
			if status.LatestResult == nil || status.LatestResult.Packet != built.Packet.Digest || status.LatestResult.Outcome != tc.outcome {
				t.Fatalf("missing latest result: %+v", status.LatestResult)
			}
			if status.AcceptedFindings != tc.wantFindings || status.NeedsContextCount != tc.wantNeedsCount {
				t.Fatalf("bad result counts: %+v", status)
			}
		})
	}
}

func TestStatusReportsRevisionSupersessionAndHistoricalFindings(t *testing.T) {
	repo, stateDir := initializedStatusState(t)
	parent := importStatusArtifact(t, stateDir, repo, "parent.md", "Parent Plan", "# Parent\n\nReview me.\n", "")
	parentPacket := buildStatusPacket(t, stateDir, parent.ArtifactID)
	importStatusResult(t, stateDir, parentPacket.Packet.Digest, parent.ArtifactID, reviewresult.OutcomeFindings, "parent-finding")

	child := importStatusArtifact(t, stateDir, repo, "child.md", "Child Plan", "# Child\n\nReview me again.\n", parent.ArtifactID)

	parentStatus, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: parent.ArtifactID})
	if err != nil {
		t.Fatalf("parent Status: %v", err)
	}
	if parentStatus.Status != "superseded" || parentStatus.ReviewRequired || parentStatus.IsLatest || parentStatus.LatestArtifactID != child.ArtifactID || parentStatus.Successor != child.ArtifactID {
		t.Fatalf("parent should report superseded by child: %+v", parentStatus)
	}
	if len(parentStatus.SupersededFindings) != 1 || parentStatus.SupersededFindings[0].FindingID != "parent-finding" {
		t.Fatalf("parent historical finding missing: %+v", parentStatus.SupersededFindings)
	}

	childStatus, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: child.ArtifactID})
	if err != nil {
		t.Fatalf("child Status: %v", err)
	}
	if childStatus.Status != "no_review_packet" || !childStatus.ReviewRequired || !childStatus.IsLatest || childStatus.LatestArtifactID != child.ArtifactID {
		t.Fatalf("child should require its own review without inheriting parent finding: %+v", childStatus)
	}
	if len(childStatus.SupersededFindings) != 1 || childStatus.SupersededFindings[0].FindingID != "parent-finding" {
		t.Fatalf("child should display historical parent finding: %+v", childStatus.SupersededFindings)
	}

	childPacket := buildStatusPacket(t, stateDir, child.ArtifactID)
	importStatusResult(t, stateDir, childPacket.Packet.Digest, child.ArtifactID, reviewresult.OutcomeClean, "")
	cleanChildStatus, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: child.ArtifactID})
	if err != nil {
		t.Fatalf("clean child Status: %v", err)
	}
	if cleanChildStatus.Status != "clean" || cleanChildStatus.ReviewRequired || !cleanChildStatus.Clean {
		t.Fatalf("child clean result should close latest artifact review: %+v", cleanChildStatus)
	}
	if len(cleanChildStatus.SupersededFindings) != 1 {
		t.Fatalf("clean child should retain historical superseded findings: %+v", cleanChildStatus.SupersededFindings)
	}
}

func TestStatusUsesLatestArtifactResultDeterministically(t *testing.T) {
	repo, stateDir := initializedStatusState(t)
	imported := importStatusArtifact(t, stateDir, repo, "plan.md", "Latest Result Plan", "# Plan\n\nReview me.\n", "")
	built := buildStatusPacket(t, stateDir, imported.ArtifactID)
	importStatusResult(t, stateDir, built.Packet.Digest, imported.ArtifactID, reviewresult.OutcomeClean, "")
	importStatusResult(t, stateDir, built.Packet.Digest, imported.ArtifactID, reviewresult.OutcomeNeedsContext, "")

	status, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: imported.ArtifactID})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "needs_context" || status.Clean || status.NeedsContextCount != 1 || status.LatestResult == nil || status.LatestResult.Outcome != reviewresult.OutcomeNeedsContext {
		t.Fatalf("status should use latest artifact result: %+v", status)
	}
}

func TestStatusRequiresResultForLatestArtifactPacket(t *testing.T) {
	repo, stateDir := initializedStatusState(t)
	imported := importStatusArtifact(t, stateDir, repo, "plan.md", "Rebuilt Packet Plan", "# Plan\n\nReview me.\n", "")
	firstPacket := buildStatusPacket(t, stateDir, imported.ArtifactID)
	importStatusResult(t, stateDir, firstPacket.Packet.Digest, imported.ArtifactID, reviewresult.OutcomeClean, "")

	secondPacket, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindArtifact, ArtifactID: imported.ArtifactID, Now: time.Unix(31, 0)})
	if err != nil {
		t.Fatalf("Build second artifact packet: %v", err)
	}
	if secondPacket.Packet.Digest == firstPacket.Packet.Digest {
		t.Fatalf("second packet should have a distinct digest")
	}
	status, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: imported.ArtifactID})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "waiting_for_result" || !status.ReviewRequired || status.Clean || status.Outcome != "" {
		t.Fatalf("rebuilt latest packet should wait for a matching result: %+v", status)
	}
	if status.LatestPacket == nil || status.LatestPacket.Packet != secondPacket.Packet.Digest {
		t.Fatalf("status should expose rebuilt latest packet: %+v", status.LatestPacket)
	}
	if status.LatestResult == nil || status.LatestResult.Packet != firstPacket.Packet.Digest || status.LatestResult.Outcome != reviewresult.OutcomeClean {
		t.Fatalf("status should retain latest imported stale result metadata: %+v", status.LatestResult)
	}
	if status.FindingCount != 0 || status.AcceptedFindings != 0 || status.NeedsContextCount != 0 {
		t.Fatalf("stale result should not contribute current counts: %+v", status)
	}
}

func TestStatusReportsDuplicateArtifactResultImports(t *testing.T) {
	repo, stateDir := initializedStatusState(t)
	imported := importStatusArtifact(t, stateDir, repo, "plan.md", "Duplicate Result Plan", "# Plan\n\nReview me.\n", "")
	built := buildStatusPacket(t, stateDir, imported.ArtifactID)
	importStatusResult(t, stateDir, built.Packet.Digest, imported.ArtifactID, reviewresult.OutcomeFindings, "same-finding")
	importStatusResult(t, stateDir, built.Packet.Digest, imported.ArtifactID, reviewresult.OutcomeFindings, "same-finding")

	status, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: imported.ArtifactID})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "findings" || !status.ReviewRequired || status.LatestResult == nil {
		t.Fatalf("duplicate findings result should remain dirty: %+v", status)
	}
	if status.LatestResult.AcceptedFindings != 0 || status.LatestResult.DuplicateFindings != 1 {
		t.Fatalf("latest duplicate result counts are wrong: %+v", status.LatestResult)
	}
}

func initializedStatusState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	return repo, stateDir
}

func importStatusArtifact(t *testing.T, stateDir, repo, name, title, body, revises string) artifact.ImportResult {
	t.Helper()
	path := filepath.Join(repo, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	result, err := artifact.Import(artifact.ImportOptions{
		StateDir: stateDir,
		Kind:     artifact.KindPlan,
		Path:     path,
		Title:    title,
		Revises:  revises,
		Now:      time.Unix(20, 0),
	})
	if err != nil {
		t.Fatalf("Import artifact: %v", err)
	}
	return result
}

func buildStatusPacket(t *testing.T, stateDir, artifactID string) packet.BuildResult {
	t.Helper()
	result, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindArtifact, ArtifactID: artifactID, Now: time.Unix(30, 0)})
	if err != nil {
		t.Fatalf("Build artifact packet: %v", err)
	}
	return result
}

func importStatusResult(t *testing.T, stateDir, packetID, artifactID, outcome, findingID string) reviewresult.ImportResult {
	t.Helper()
	worker := reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        packetID,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RouteArtifactReview,
		Outcome:       outcome,
		Summary:       "No actionable findings.",
	}
	switch outcome {
	case reviewresult.OutcomeFindings:
		worker.Summary = ""
		worker.Findings = []reviewresult.FindingInput{{
			ID:              findingID,
			Severity:        "high",
			Class:           "correctness",
			Claim:           "The plan omits an actionable release verification step.",
			FailureScenario: "An operator follows the plan and cannot prove the upgraded release version is correct.",
			ArtifactRefs: []reviewresult.ArtifactRef{{
				ArtifactID: artifactID,
				Section:    "Plan",
				StartLine:  1,
				EndLine:    2,
				Quote:      "Review me",
			}},
		}}
	case reviewresult.OutcomeNeedsContext:
		worker.Summary = ""
		worker.NeedsContext = []reviewresult.ContextRequest{{
			Question: "Which version should be verified?",
			Reason:   "The artifact leaves the expected version ambiguous.",
			Paths:    []string{"plan.md"},
		}}
	}
	path := filepath.Join(t.TempDir(), "result.json")
	body, err := json.Marshal(worker)
	if err != nil {
		t.Fatalf("Marshal worker result: %v", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write worker result: %v", err)
	}
	result, err := reviewresult.Import(reviewresult.ImportOptions{StateDir: stateDir, PacketID: packetID, ResultPath: path, Now: time.Unix(40, 0)})
	if err != nil {
		t.Fatalf("Import worker result: %v", err)
	}
	return result
}
