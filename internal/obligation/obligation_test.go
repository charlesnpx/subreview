package obligation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/anchor"
	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestBuildAndStatusReportUnsatisfiedEvidenceSlots(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, true)

	writeObligationFile(t, repo, "alpha.txt", "one\ntwo\n")
	writeObligationFile(t, repo, "beta.txt", "beta\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	writeObligationFile(t, repo, "alpha.txt", "one\ntwo\nthree\n")
	writeObligationFile(t, repo, "beta.txt", "beta\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}

	built, err := Build(BuildOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.Manifest.Digest == "" || built.EventID == "" || built.ObligationCount == 0 || built.BlockerCount != 0 {
		t.Fatalf("bad build result: %+v", built)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	manifest := readManifestForTest(t, store, built.Manifest.Digest)
	assertHasObligation(t, manifest.Obligations, KindChangedPath, "base->proposal", "alpha.txt")
	assertHasObligation(t, manifest.Obligations, KindChangedFile, "base->proposal", "alpha.txt")
	assertHasObligation(t, manifest.Obligations, KindChangedHunk, "base->proposal", "alpha.txt")
	assertHasObligation(t, manifest.Obligations, KindChangedHunk, "base->final", "alpha.txt")
	assertHasObligation(t, manifest.Obligations, KindGateRequirement, "", "")
	assertHasObligation(t, manifest.Obligations, KindPolicyFinalReview, "", "")
	assertHasObligation(t, manifest.Obligations, KindContextRequest, "", "")

	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Closed || status.SatisfiedCount != 1 || status.UnsatisfiedCount != len(status.Obligations)-1 {
		t.Fatalf("status should remain open with required evidence slots unsatisfied: %+v", status)
	}
	for _, want := range []string{
		SatisfactionGateEvidence,
		SatisfactionPrimaryReviewEvidence,
		SatisfactionVerificationEvidence,
		SatisfactionDeterministicRefute,
		SatisfactionCarriedForward,
	} {
		if !containsString(status.UnsatisfiedSatisfactionKinds, want) {
			t.Fatalf("status missing unsatisfied kind %s: %+v", want, status.UnsatisfiedSatisfactionKinds)
		}
	}
	for _, want := range []string{"unsatisfied_required_check", "unsatisfied_coverage", "unsatisfied_policy_final_review"} {
		if !hasBlocker(status.Blockers, want) {
			t.Fatalf("status missing blocker %s: %+v", want, status.Blockers)
		}
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestGateEvidenceSatisfiesGateRequirementObligation(t *testing.T) {
	repo, stateDir := initializedStateWithBuiltObligations(t)
	catalogPath := writeGateCatalog(t, t.TempDir(), "go_test_all")
	if _, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "final",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "external pass",
		Now:          time.Unix(200, 0),
	}); err != nil {
		t.Fatalf("Record gate pass for repo %s: %v", repo, err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	gateStatus := gateObligationStatus(t, status, "go_test_all")
	if !gateStatus.Satisfied || len(gateStatus.SatisfiedBy) != 1 || gateStatus.UnsatisfiedSatisfactionKinds != nil && containsString(gateStatus.UnsatisfiedSatisfactionKinds, SatisfactionGateEvidence) {
		t.Fatalf("gate obligation should be satisfied by evidence: %+v", gateStatus)
	}
	if hasBlocker(status.Blockers, "unsatisfied_required_check") {
		t.Fatalf("gate evidence should remove unsatisfied required-check blocker: %+v", status.Blockers)
	}
}

func TestGateEvidenceMustMatchManifestSnapshot(t *testing.T) {
	_, stateDir := initializedStateWithBuiltObligations(t)
	catalogPath := writeGateCatalog(t, t.TempDir(), "go_test_all")
	if _, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "proposal",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "external pass on proposal",
		Now:          time.Unix(200, 0),
	}); err != nil {
		t.Fatalf("Record proposal gate pass: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "stale_gate_evidence") {
		t.Fatalf("proposal evidence should not satisfy final-state manifest: %+v", status.Blockers)
	}
	gateStatus := gateObligationStatus(t, status, "go_test_all")
	if gateStatus.Satisfied {
		t.Fatalf("stale snapshot gate evidence should not satisfy obligation: %+v", gateStatus)
	}
}

func TestGateEvidenceUsesLatestManifestMatchingRecord(t *testing.T) {
	_, stateDir := initializedStateWithBuiltObligations(t)
	catalogPath := writeGateCatalog(t, t.TempDir(), "go_test_all")
	finalEvidence, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "final",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "external pass on final",
		Now:          time.Unix(200, 0),
	})
	if err != nil {
		t.Fatalf("Record final gate pass: %v", err)
	}
	if _, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "proposal",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "later external pass on proposal",
		Now:          time.Unix(300, 0),
	}); err != nil {
		t.Fatalf("Record later proposal gate pass: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	gateStatus := gateObligationStatus(t, status, "go_test_all")
	if !gateStatus.Satisfied || len(gateStatus.SatisfiedBy) != 1 || gateStatus.SatisfiedBy[0].Digest != finalEvidence.Evidence.Digest {
		t.Fatalf("gate obligation should use latest manifest-matching evidence: %+v", gateStatus)
	}
	if hasBlocker(status.Blockers, "stale_gate_evidence") {
		t.Fatalf("later stale evidence should not mask matching final evidence: %+v", status.Blockers)
	}
}

func TestGateFailureBlocksReview(t *testing.T) {
	_, stateDir := initializedStateWithBuiltObligations(t)
	catalogPath := writeGateCatalog(t, t.TempDir(), "go_test_all")
	if _, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    "go_test_all",
		SnapshotKind: "final",
		Outcome:      gate.OutcomeFail,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "external failure",
		Now:          time.Unix(200, 0),
	}); err != nil {
		t.Fatalf("Record gate failure: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "gate_failed_blocks_review") {
		t.Fatalf("gate failure should block review: %+v", status.Blockers)
	}
	gateStatus := gateObligationStatus(t, status, "go_test_all")
	if gateStatus.Satisfied {
		t.Fatalf("failed gate should not satisfy obligation: %+v", gateStatus)
	}
}

func TestObligationsFromDiffIncludesHeaderOnlyChanges(t *testing.T) {
	obligations := obligationsFromDiff(diffBinding{
		Transition: "base->proposal",
		PatchBody:  []byte("diff --git from/script.sh to/script.sh\nold mode 100644\nnew mode 100755\n"),
	})
	assertHasObligation(t, obligations, KindChangedPath, "base->proposal", "script.sh")
	assertHasObligation(t, obligations, KindChangedFile, "base->proposal", "script.sh")
	for _, obligation := range obligations {
		if obligation.Kind == KindChangedHunk {
			t.Fatalf("mode-only diff should not create hunk obligations: %+v", obligations)
		}
	}
	spacePathObligations := obligationsFromDiff(diffBinding{
		Transition: "base->proposal",
		PatchBody:  []byte("diff --git a/a b.sh b/a b.sh\nold mode 100644\nnew mode 100755\n"),
	})
	assertHasObligation(t, spacePathObligations, KindChangedPath, "base->proposal", "a b.sh")
	assertHasObligation(t, spacePathObligations, KindChangedFile, "base->proposal", "a b.sh")
	separatorPathObligations := obligationsFromDiff(diffBinding{
		Transition: "base->proposal",
		PatchBody:  []byte("diff --git from/a to/file.txt to/a to/file.txt\nold mode 100644\nnew mode 100755\n"),
	})
	assertHasObligation(t, separatorPathObligations, KindChangedPath, "base->proposal", "a to/file.txt")
	assertHasObligation(t, separatorPathObligations, KindChangedFile, "base->proposal", "a to/file.txt")
	renameObligations := obligationsFromDiff(diffBinding{
		Transition: "base->proposal",
		PatchBody:  []byte("diff --git from/old to/file.txt to/new to/file.txt\nsimilarity index 100%\nrename from old to/file.txt\nrename to new to/file.txt\n"),
	})
	assertHasObligation(t, renameObligations, KindChangedPath, "base->proposal", "new to/file.txt")
	assertHasObligation(t, renameObligations, KindChangedFile, "base->proposal", "new to/file.txt")
	for _, obligation := range renameObligations {
		if obligation.Path == "new to/file.txt" && obligation.OldPath != "old to/file.txt" {
			t.Fatalf("rename obligation should preserve old path, got %+v", obligation)
		}
	}
	quotedPathObligations := obligationsFromDiff(diffBinding{
		Transition: "base->proposal",
		PatchBody: []byte(`diff --git "from/a\tb.txt" "to/a\tb.txt"
--- "from/a\tb.txt"
+++ "to/a\tb.txt"
@@ -1 +1 @@
-old
+new
`),
	})
	assertHasObligation(t, quotedPathObligations, KindChangedPath, "base->proposal", "a\tb.txt")
	assertHasObligation(t, quotedPathObligations, KindChangedFile, "base->proposal", "a\tb.txt")
	assertHasObligation(t, quotedPathObligations, KindChangedHunk, "base->proposal", "a\tb.txt")
}

func TestBuildRecordsHiddenScopeUncertaintyWhenFinalDiffIsMissing(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "alpha.txt", "two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}

	built, err := Build(BuildOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if built.BlockerCount != 1 {
		t.Fatalf("expected hidden scope blocker, got %+v", built)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "hidden_scope_uncertainty") {
		t.Fatalf("status missing hidden scope blocker: %+v", status.Blockers)
	}
}

func TestStatusRejectsCarriedForwardEvidenceOnAmbiguousAnchors(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\nstay\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\ndup\nstay\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := anchor.Migrate(anchor.MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []anchor.Anchor{
			{ID: "ambiguous-hunk", Kind: anchor.KindHunk, Path: "ambiguous.txt", StartLine: 1, EndLine: 1, Text: "dup\n"},
		},
	}); err != nil {
		t.Fatalf("Migrate anchors: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "ambiguous_anchor") {
		t.Fatalf("status missing ambiguous anchor blocker: %+v", status.Blockers)
	}
}

func TestStatusReportsStaleManifestAfterNewerSnapshot(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "alpha.txt", "two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	writeObligationFile(t, repo, "alpha.txt", "three\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture newer proposal: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "stale_coverage_manifest") {
		t.Fatalf("status should report stale coverage manifest after newer snapshot: %+v", status.Blockers)
	}
}

func TestStatusReportsStaleManifestAfterPolicyRebind(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "alpha.txt", "two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, true)
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "stale_coverage_manifest") {
		t.Fatalf("status should report stale coverage manifest after policy rebind: %+v", status.Blockers)
	}
}

func TestStatusUsesLatestAnchorMigrationForActiveTransition(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\nstay\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\ndup\nstay\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := anchor.Migrate(anchor.MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []anchor.Anchor{
			{ID: "same-anchor", Kind: anchor.KindHunk, Path: "ambiguous.txt", StartLine: 1, EndLine: 1, Text: "dup\n"},
		},
	}); err != nil {
		t.Fatalf("Migrate ambiguous anchor: %v", err)
	}
	if _, err := anchor.Migrate(anchor.MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []anchor.Anchor{
			{ID: "same-anchor", Kind: anchor.KindHunk, Path: "ambiguous.txt", StartLine: 2, EndLine: 2, Text: "stay\n"},
		},
	}); err != nil {
		t.Fatalf("Migrate resolved anchor: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if hasBlocker(status.Blockers, "ambiguous_anchor") {
		t.Fatalf("status should ignore superseded ambiguous anchor blocker: %+v", status.Blockers)
	}
}

func TestStatusDoesNotSupersedeDifferentAnchorOnSameTransition(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\nstay\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "ambiguous.txt", "dup\ndup\nstay\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := anchor.Migrate(anchor.MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []anchor.Anchor{
			{ID: "still-ambiguous", Kind: anchor.KindHunk, Path: "ambiguous.txt", StartLine: 1, EndLine: 1, Text: "dup\n"},
		},
	}); err != nil {
		t.Fatalf("Migrate ambiguous anchor: %v", err)
	}
	if _, err := anchor.Migrate(anchor.MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []anchor.Anchor{
			{ID: "resolved-other", Kind: anchor.KindHunk, Path: "ambiguous.txt", StartLine: 2, EndLine: 2, Text: "stay\n"},
		},
	}); err != nil {
		t.Fatalf("Migrate resolved anchor: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	status, err := Status(StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasBlocker(status.Blockers, "ambiguous_anchor") {
		t.Fatalf("status should retain older blocker for different anchor id: %+v", status.Blockers)
	}
}

func TestBuildRejectsStaleDiffAfterNewerSnapshot(t *testing.T) {
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "alpha.txt", "two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	writeObligationFile(t, repo, "alpha.txt", "three\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture newer proposal: %v", err)
	}
	_, err := Build(BuildOptions{StateDir: stateDir})
	if err == nil || !strings.Contains(err.Error(), "does not match latest snapshots") {
		t.Fatalf("expected stale diff error, got %v", err)
	}
}

func initializedStateWithBuiltObligations(t *testing.T) (string, string) {
	t.Helper()
	repo, stateDir := initializedReviewState(t)
	writeObligationFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	bindDefaultPolicy(t, stateDir, repo, false)
	writeObligationFile(t, repo, "alpha.txt", "two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	return repo, stateDir
}

func writeGateCatalog(t *testing.T, root, commandID string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "commands": [
    {
      "id": "` + commandID + `",
      "argv": ["/bin/sh", "-c", "printf ok"],
      "working_dir": ".",
      "replay_class": "environment_bound",
      "environment_pinned": true,
      "executes_repo_code": true,
      "side_effects": "none",
      "timeout_seconds": 5
    }
  ]
}
`)
	path := filepath.Join(root, "gate-catalog.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write gate catalog: %v", err)
	}
	return path
}

func gateObligationStatus(t *testing.T, status StatusResult, commandID string) ObligationStatus {
	t.Helper()
	for _, obligationStatus := range status.Obligations {
		if obligationStatus.Obligation.Kind == KindGateRequirement && obligationStatus.Obligation.CommandID == commandID {
			return obligationStatus
		}
	}
	t.Fatalf("missing gate obligation for %s: %+v", commandID, status.Obligations)
	return ObligationStatus{}
}

func initializedReviewState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	return repo, stateDir
}

func bindDefaultPolicy(t *testing.T, stateDir, repo string, independentFinal bool) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "policy.json")
	facts := []string{
		"required_gates_satisfied",
		"primary_review_completed",
		"blocking_findings_verified",
		"coverage_obligations_satisfied",
		"policy_bound",
	}
	if independentFinal {
		facts = append(facts, "independent_final_completed")
	}
	cfg := policy.Config{
		SchemaVersion: policy.SchemaVersion,
		PolicyID:      "test-policy",
		Profiles: map[string]policy.Profile{
			"default": {
				GateRequirements: []policy.GateRequirement{
					{CommandID: "go_test_all", Required: true},
				},
				RouteLimits: policy.RouteLimits{
					PrimarySemanticReviews: 1,
					TargetedVerifications:  1,
					FreshFinalReviews:      0,
					ContextExpansionRounds: 1,
				},
				RequiredEvidenceFacts: facts,
				RiskRouting: []policy.RiskRoute{
					{RiskTier: "high", ReviewEffort: "medium", RequireIndependentFinal: independentFinal},
				},
				ClosureBasis: policy.ClosureBasis{
					AllowedBasis:              []string{"clean", "fixed", "deterministic_refutation"},
					RequireBasisForUnresolved: true,
				},
			},
		},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal policy: %v", err)
	}
	if err := os.WriteFile(configPath, body, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: configPath, Profile: "default"}); err != nil {
		t.Fatalf("Bind policy for repo %s: %v", repo, err)
	}
}

func readManifestForTest(t *testing.T, store state.Store, digest string) CoverageManifest {
	t.Helper()
	body, err := store.Read(digest)
	if err != nil {
		t.Fatalf("Read manifest: %v", err)
	}
	var manifest CoverageManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}
	return manifest
}

func assertHasObligation(t *testing.T, obligations []Obligation, kind, transition, path string) {
	t.Helper()
	for _, obligation := range obligations {
		if obligation.Kind != kind {
			continue
		}
		if transition != "" && obligation.Transition != transition {
			continue
		}
		if path != "" && obligation.Path != path {
			continue
		}
		return
	}
	t.Fatalf("missing obligation kind=%s transition=%s path=%s in %+v", kind, transition, path, obligations)
}

func hasBlocker(blockers []Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

func writeObligationFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
