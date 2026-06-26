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

func TestImportRejectsVerifierOutcomeOnPrimaryPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationResolved,
				Summary:   "The final state removes the reported failure.",
			}},
		}),
	}); err == nil {
		t.Fatal("primary packet should not accept verifier outcomes")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("verification route mismatch should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsVerifierOutcomeForDifferentFindingThanPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	secondFinding := validFinding("finding-two")
	secondFinding.Claim = "alpha.txt can also expose a separate downstream ordering defect."
	secondFinding.FailureScenario = "A consumer observes the second line before the first line is initialized."
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
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
				secondFinding,
			},
		}),
		Now: time.Unix(231, 0),
	}); err != nil {
		t.Fatalf("Import findings: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-two",
				Outcome:   reviewresult.VerificationResolved,
				Summary:   "This attempts to use finding-one context to close finding-two.",
			}},
		}),
		Now: time.Unix(232, 0),
	}); err == nil {
		t.Fatal("verification packet should reject outcomes for another finding")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("mismatched finding import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsDeterministicRefutationForDifferentFindingThanPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	secondFinding := validFinding("finding-two")
	secondFinding.Claim = "alpha.txt can also expose a separate downstream ordering defect."
	secondFinding.FailureScenario = "A consumer observes the second line before the first line is initialized."
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
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
				secondFinding,
			},
		}),
		Now: time.Unix(233, 0),
	}); err != nil {
		t.Fatalf("Import findings: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				FindingID:    "finding-two",
				EvidenceKind: "test",
				Summary:      "This attempts to use finding-one context to refute finding-two.",
				Citations:    []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(234, 0),
	}); err == nil {
		t.Fatal("verification packet should reject deterministic refutations for another finding")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("mismatched deterministic refutation import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsFindingRefutationOnPrimaryPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(234, 1),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				FindingID:    "finding-one",
				EvidenceKind: "test",
				Summary:      "This attempts to use a primary packet to refute a finding.",
				Citations:    []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(234, 2),
	}); err == nil {
		t.Fatal("primary packet should not accept finding-level deterministic refutations")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("primary-packet finding refutation should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsObligationRefutationOnTargetedVerificationPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(234, 3),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				FindingID:     "finding-one",
				ObligationIDs: []string{"coverage-alpha"},
				EvidenceKind:  "test",
				Summary:       "This attempts to use targeted finding context to refute a coverage obligation.",
				Citations:     []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(234, 4),
	}); err == nil {
		t.Fatal("targeted verification packet should not accept obligation-level deterministic refutations")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("targeted obligation refutation should not append ledger event: before=%d after=%d", len(before), len(after))
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				ObligationIDs: []string{"coverage-beta"},
				EvidenceKind:  "test",
				Summary:       "This attempts to use targeted finding context to refute only a coverage obligation.",
				Citations:     []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(234, 5),
	}); err == nil {
		t.Fatal("targeted verification packet should not accept obligation-only deterministic refutations")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("targeted obligation-only refutation should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestImportRejectsNonVerificationOutcomeOnTargetedPacket(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(234, 6),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	cases := []struct {
		name   string
		result reviewresult.WorkerResult
	}{
		{
			name: "clean",
			result: reviewresult.WorkerResult{
				SchemaVersion: reviewresult.SchemaVersion,
				Packet:        verificationPacket.Packet.Digest,
				RunKind:       reviewresult.RunKindVerification,
				Route:         reviewresult.RouteTargetedVerification,
				Outcome:       reviewresult.OutcomeClean,
				Summary:       "No actionable findings.",
			},
		},
		{
			name: "findings",
			result: reviewresult.WorkerResult{
				SchemaVersion: reviewresult.SchemaVersion,
				Packet:        verificationPacket.Packet.Digest,
				RunKind:       reviewresult.RunKindVerification,
				Route:         reviewresult.RouteTargetedVerification,
				Outcome:       reviewresult.OutcomeFindings,
				Findings:      []reviewresult.FindingInput{validFinding("new-finding")},
			},
		},
		{
			name: "needs_context",
			result: reviewresult.WorkerResult{
				SchemaVersion: reviewresult.SchemaVersion,
				Packet:        verificationPacket.Packet.Digest,
				RunKind:       reviewresult.RunKindVerification,
				Route:         reviewresult.RouteTargetedVerification,
				Outcome:       reviewresult.OutcomeNeedsContext,
				NeedsContext: []reviewresult.ContextRequest{{
					Question: "What extra file is needed?",
					Reason:   "The targeted verification packet should not request result-level context.",
					Paths:    []string{"alpha.txt"},
				}},
			},
		},
	}
	before := readEvents(t, stateDir)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := reviewresult.Import(reviewresult.ImportOptions{
				StateDir:   stateDir,
				PacketID:   verificationPacket.Packet.Digest,
				ResultPath: writeWorkerResult(t, tc.result),
				Now:        time.Unix(234, 7),
			}); err == nil {
				t.Fatalf("targeted verification packet should reject %s outcome", tc.name)
			}
			if after := readEvents(t, stateDir); len(after) != len(before) {
				t.Fatalf("%s targeted outcome should not append ledger event: before=%d after=%d", tc.name, len(before), len(after))
			}
		})
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

func TestFindingNeedsContextDoesNotCreatePermanentContextBlocker(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	finding := validFinding("needs-context-finding")
	finding.State = reviewresult.StateNeedsContext
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
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
		Now: time.Unix(236, 0),
	}); err != nil {
		t.Fatalf("Import needs-context finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "needs-context-finding")
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID:        "needs-context-finding",
				State:            reviewresult.StateInvalidated,
				Basis:            reviewresult.BasisFreshSemantic,
				Summary:          "Follow-up context showed the finding is not a defect.",
				VerifierRelation: reviewresult.RelationFreshBlinded,
				RelationEvidence: reviewresult.RelationEvidenceCallerAssert,
			}},
		}),
		Now: time.Unix(237, 0),
	}); err != nil {
		t.Fatalf("Import verifier outcome: %v", err)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if hasStatusBlocker(status, "needs_context") || hasStatusBlocker(status, "open_finding") {
		t.Fatalf("resolved finding-level needs_context should not leave blockers: %+v", status.Blockers)
	}
}

func TestTopLevelNeedsContextCanBeResolvedByLaterDiscovery(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeNeedsContext,
			NeedsContext: []reviewresult.ContextRequest{{
				Question: "Please include alpha_test.txt.",
				Reason:   "The reviewer needs nearby test coverage.",
				Paths:    []string{"alpha_test.txt"},
			}},
		}),
		Now: time.Unix(238, 0),
	}); err != nil {
		t.Fatalf("Import needs-context result: %v", err)
	}
	blocked, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status after context request: %v", err)
	}
	if !hasStatusBlocker(blocked, "needs_context") {
		t.Fatalf("top-level needs-context result should block closure: %+v", blocked.Blockers)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "The requested context is now sufficient.",
		}),
		Now: time.Unix(239, 0),
	}); err != nil {
		t.Fatalf("Import resolving clean result: %v", err)
	}
	resolved, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status after resolved context: %v", err)
	}
	if hasStatusBlocker(resolved, "needs_context") {
		t.Fatalf("later discovery result should resolve top-level context request: %+v", resolved.Blockers)
	}
}

func TestCarriedProposalPrimaryOnlySatisfiesProposalCoverage(t *testing.T) {
	repo, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "The proposal diff has no actionable findings.",
		}),
		Now: time.Unix(240, 0),
	}); err != nil {
		t.Fatalf("Import proposal clean result: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "one\ntwo\nfinal-only\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final-only state: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build final obligations: %v", err)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Closed {
		t.Fatalf("final-only coverage should keep status open: %+v", status)
	}
	foundProposalCoverage := false
	foundFinalCoverage := false
	for _, item := range status.Obligations {
		if !isCoverageStatus(item) {
			continue
		}
		switch item.Obligation.Transition {
		case "base->proposal":
			foundProposalCoverage = true
			if !item.Satisfied || !satisfiedByKind(item, obligation.SatisfactionCarriedForward) {
				t.Fatalf("base->proposal coverage should be carried by proposal review: %+v", item)
			}
		case "base->final":
			foundFinalCoverage = true
			if item.Satisfied {
				t.Fatalf("base->final coverage should not be satisfied by carried proposal review: %+v", item)
			}
		}
	}
	if !foundProposalCoverage || !foundFinalCoverage {
		t.Fatalf("expected proposal and final coverage obligations: %+v", status.Obligations)
	}
}

func TestLatestProposalNeedsContextBlocksCarriedReview(t *testing.T) {
	repo, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "The proposal diff has no actionable findings.",
		}),
		Now: time.Unix(240, 0),
	}); err != nil {
		t.Fatalf("Import proposal clean result: %v", err)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeNeedsContext,
			NeedsContext: []reviewresult.ContextRequest{{
				Question: "Please include the integration test for alpha.txt.",
				Reason:   "The later review could not close without more context.",
				Paths:    []string{"alpha_test.txt"},
			}},
		}),
		Now: time.Unix(241, 0),
	}); err != nil {
		t.Fatalf("Import later needs-context result: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final state: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build final obligations: %v", err)
	}
	_, manifest := readLatestCoverageManifest(t, stateDir)
	observations := readObservations(t, stateDir)
	if _, ok := reviewresult.LatestPrimaryReviewForTargetState(observations, proposalDigestFromManifest(t, manifest), manifest.Policy.Digest); ok {
		t.Fatal("older clean proposal review should not carry past newer needs-context result")
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !hasStatusBlocker(status, "needs_context") {
		t.Fatalf("latest proposal needs-context should block final closure: %+v", status.Blockers)
	}
}

func TestCarriedPrimaryReviewMustMatchPolicy(t *testing.T) {
	repo, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings under the original policy.",
		}),
		Now: time.Unix(240, 0),
	}); err != nil {
		t.Fatalf("Import original-policy clean result: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigWithID(t, t.TempDir(), "replacement-policy"), Profile: "default"}); err != nil {
		t.Fatalf("Bind replacement policy: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build replacement-policy obligations: %v", err)
	}
	_, manifest := readLatestCoverageManifest(t, stateDir)
	observations := readObservations(t, stateDir)
	if _, ok := reviewresult.LatestPrimaryReviewForTargetState(observations, proposalDigestFromManifest(t, manifest), manifest.Policy.Digest); ok {
		t.Fatal("primary review from prior policy should not carry into replacement policy")
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Closed {
		t.Fatalf("replacement policy should require fresh primary review evidence for %s: %+v", repo, status)
	}
}

func TestClosureFindingCarryForwardMustMatchPolicy(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("old-policy-finding")},
		}),
		Now: time.Unix(241, 0),
	}); err != nil {
		t.Fatalf("Import original-policy finding result: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigWithID(t, t.TempDir(), "replacement-policy"), Profile: "default"}); err != nil {
		t.Fatalf("Bind replacement policy: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build replacement-policy obligations: %v", err)
	}
	manifestRef, manifest := readLatestCoverageManifest(t, stateDir)
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ClosureFindingBlockers(observations, manifestRef.Digest, proposalDigestFromManifest(t, manifest), manifest.Policy.Digest)
	if len(blockers) != 0 {
		t.Fatalf("finding from prior policy should not carry into replacement policy: %+v", blockers)
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if hasStatusBlocker(status, "open_finding") {
		t.Fatalf("replacement policy should not inherit old-policy finding blocker: %+v", status.Blockers)
	}
}

func TestVerificationPacketDoesNotCarryFindingAcrossPolicy(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: built.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        built.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings:      []reviewresult.FindingInput{validFinding("old-policy-finding")},
		}),
		Now: time.Unix(242, 0),
	}); err != nil {
		t.Fatalf("Import original-policy finding result: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigWithID(t, t.TempDir(), "replacement-policy"), Profile: "default"}); err != nil {
		t.Fatalf("Bind replacement policy: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build replacement-policy obligations: %v", err)
	}
	if _, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindVerification, FindingID: "old-policy-finding"}); err == nil {
		t.Fatal("verification packet should not carry finding from a different policy")
	}
}

func TestVerificationOutcomeVocabularyMapsToLifecycle(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(238, 0),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	resolved, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationResolved,
				Summary:   "The final state removes the reported failure.",
			}},
		}),
		Now: time.Unix(239, 0),
	})
	if err != nil {
		t.Fatalf("Import resolved verifier outcome: %v", err)
	}
	if resolved.VerifierOutcomeCount != 1 {
		t.Fatalf("bad resolved import: %+v", resolved)
	}
	observations := readObservations(t, stateDir)
	if blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest); len(blockers) != 0 {
		t.Fatalf("resolved outcome should clear finding blocker: %+v", blockers)
	}
}

func TestVerificationOutcomeRejectsContradictoryStateAndBasis(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(239, 0),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationResolved,
				State:     reviewresult.StateNeedsConfirmation,
				Summary:   "The outcome text and lifecycle state disagree.",
			}},
		}),
		Now: time.Unix(239, 1),
	}); err == nil {
		t.Fatal("verification outcome should reject contradictory lifecycle state")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("contradictory state should not append ledger event: before=%d after=%d", len(before), len(after))
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationNotResolved,
				Basis:     reviewresult.BasisFreshSemantic,
				Summary:   "The outcome text and evidence basis disagree.",
			}},
		}),
		Now: time.Unix(239, 2),
	}); err == nil {
		t.Fatal("verification outcome should reject contradictory basis")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("contradictory basis should not append ledger event: before=%d after=%d", len(before), len(after))
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				State:     reviewresult.StateVerified,
				Basis:     reviewresult.BasisDeterministicRefutation,
				Summary:   "The omitted outcome would otherwise be inferred inconsistently.",
			}},
		}),
		Now: time.Unix(239, 3),
	}); err == nil {
		t.Fatal("omitted verification outcome should still reject contradictory state and basis")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("omitted-outcome contradiction should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestVerificationOutcomeRejectsDuplicateTargetedOutcomes(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(239, 4),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{
				{
					FindingID: "finding-one",
					Outcome:   reviewresult.VerificationResolved,
					Summary:   "The final state removes the reported failure.",
				},
				{
					FindingID: "finding-one",
					Outcome:   reviewresult.VerificationNotResolved,
					Summary:   "The final state still leaves the reported failure.",
				},
			},
		}),
		Now: time.Unix(239, 5),
	}); err == nil {
		t.Fatal("targeted verification should reject duplicate verifier outcomes")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("duplicate outcome import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestVerificationOutcomeRejectsContradictoryRefutationEvidence(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(239, 6),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	before := readEvents(t, stateDir)
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationNotResolved,
				Summary:   "The final state still leaves the reported failure.",
			}},
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				FindingID:    "finding-one",
				EvidenceKind: "test",
				Summary:      "This contradictory refutation would otherwise close the finding.",
				Citations:    []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(239, 7),
	}); err == nil {
		t.Fatal("verification outcome should reject contradictory deterministic refutation evidence")
	}
	if after := readEvents(t, stateDir); len(after) != len(before) {
		t.Fatalf("contradictory refutation import should not append ledger event: before=%d after=%d", len(before), len(after))
	}
}

func TestVerificationNotResolvedAndDeterministicRefutedOutcomes(t *testing.T) {
	_, stateDir, built, _ := initializedResultState(t)
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
		}),
		Now: time.Unix(240, 0),
	}); err != nil {
		t.Fatalf("Import finding: %v", err)
	}
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationNotResolved,
				Summary:   "The final state still leaves the failure visible.",
			}},
		}),
		Now: time.Unix(241, 0),
	}); err != nil {
		t.Fatalf("Import not_resolved outcome: %v", err)
	}
	observations := readObservations(t, stateDir)
	blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].State != reviewresult.StateNeedsConfirmation {
		t.Fatalf("not_resolved should keep finding blocked for confirmation: %+v", blockers)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationUnexpectedScope,
				Summary:   "The final state changed neighboring behavior that needs confirmation.",
			}},
		}),
		Now: time.Unix(242, 0),
	}); err != nil {
		t.Fatalf("Import unexpected_scope outcome: %v", err)
	}
	observations = readObservations(t, stateDir)
	blockers = reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest)
	if len(blockers) != 1 || blockers[0].State != reviewresult.StateNeedsConfirmation {
		t.Fatalf("unexpected_scope should keep finding blocked for confirmation: %+v", blockers)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID: "finding-one",
				Outcome:   reviewresult.VerificationDeterministicRefuted,
				Summary:   "A deterministic check refutes the finding.",
			}},
			DeterministicRefutations: []reviewresult.DeterministicRefutationInput{{
				FindingID:    "finding-one",
				EvidenceKind: "test",
				Summary:      "A focused regression test proves the finding is false.",
				Citations:    []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 1}},
			}},
		}),
		Now: time.Unix(243, 0),
	}); err != nil {
		t.Fatalf("Import deterministic_refuted outcome: %v", err)
	}
	observations = readObservations(t, stateDir)
	if blockers := reviewresult.ActiveFindingBlockers(observations, built.CoverageManifest.Digest); len(blockers) != 0 {
		t.Fatalf("deterministic_refuted should clear finding blocker: %+v", blockers)
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
	verificationPacket := buildVerificationResultPacket(t, stateDir, "finding-one")
	second, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: verificationPacket.Packet.Digest,
		ResultPath: writeWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        verificationPacket.Packet.Digest,
			RunKind:       reviewresult.RunKindVerification,
			Route:         reviewresult.RouteTargetedVerification,
			Outcome:       reviewresult.OutcomeVerification,
			VerifierOutcomes: []reviewresult.VerifierOutcomeInput{{
				FindingID:        "finding-one",
				Outcome:          reviewresult.VerificationFindingInvalid,
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
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "proposal", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff proposal->final: %v", err)
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

func buildVerificationResultPacket(t *testing.T, stateDir, findingID string) packet.BuildResult {
	t.Helper()
	result, err := packet.Build(packet.BuildOptions{
		StateDir:  stateDir,
		Kind:      packet.KindVerification,
		FindingID: findingID,
		Now:       time.Unix(115, 0),
	})
	if err != nil {
		t.Fatalf("Build verification packet: %v", err)
	}
	return result
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

func readLatestCoverageManifest(t *testing.T, stateDir string) (state.ObjectRef, obligation.CoverageManifest) {
	t.Helper()
	status, err := obligation.Status(obligation.StatusOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	body, err := store.Read(status.Manifest.Digest)
	if err != nil {
		t.Fatalf("Read latest manifest: %v", err)
	}
	var manifest obligation.CoverageManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("Unmarshal latest manifest: %v", err)
	}
	return status.Manifest, manifest
}

func proposalDigestFromManifest(t *testing.T, manifest obligation.CoverageManifest) string {
	t.Helper()
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == "base" && diff.ToKind == "proposal" {
			return diff.ToSnapshot
		}
	}
	t.Fatalf("manifest has no base->proposal transition: %+v", manifest.SourceDiffs)
	return ""
}

func isCoverageStatus(status obligation.ObligationStatus) bool {
	switch status.Obligation.Kind {
	case obligation.KindChangedPath, obligation.KindChangedFile, obligation.KindChangedHunk:
		return true
	default:
		return false
	}
}

func satisfiedByKind(status obligation.ObligationStatus, kind string) bool {
	for _, evidence := range status.SatisfiedBy {
		if evidence.Kind == kind {
			return true
		}
	}
	return false
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
	return writePolicyConfigWithID(t, root, "test-policy")
}

func writePolicyConfigWithID(t *testing.T, root, policyID string) string {
	t.Helper()
	body := []byte(strings.ReplaceAll(`{
  "schema_version": 1,
  "policy_id": "$POLICY_ID",
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
`, "$POLICY_ID", policyID))
	path := filepath.Join(root, policyID+".json")
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
