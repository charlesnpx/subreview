package packet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/artifact"
	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestBuildArtifactPacketWithoutCoverageManifest(t *testing.T) {
	repo, stateDir := initializedArtifactOnlyState(t)
	imported, err := artifact.Import(artifact.ImportOptions{
		StateDir: stateDir,
		Kind:     artifact.KindPlan,
		Path:     writeArtifactPlanFile(t, repo, "plan.md", "# Plan\n\n- ship it\n"),
		Title:    "Artifact Plan",
		Now:      time.Unix(10, 0),
	})
	if err != nil {
		t.Fatalf("Import artifact: %v", err)
	}
	first, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: imported.ArtifactID, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build artifact packet: %v", err)
	}
	second, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: imported.ArtifactID, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build second artifact packet: %v", err)
	}
	if first.Kind != KindArtifact || first.Route != RouteArtifact || first.RunKind != RunKindDiscovery || first.Artifact == nil {
		t.Fatalf("bad artifact packet result: %+v", first)
	}
	if first.CoverageManifest.Digest != "" || first.TargetState.Digest != "" {
		t.Fatalf("artifact packet should not require code coverage refs: %+v", first)
	}
	if first.StableDigest != second.StableDigest {
		t.Fatalf("stable digest should ignore generated time: %s != %s", first.StableDigest, second.StableDigest)
	}
	if first.VolatileDigest == second.VolatileDigest {
		t.Fatalf("volatile digest should include generated time")
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	markdown, err := store.Read(first.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	for _, want := range []string{"# Subreview Artifact Review Packet", "route: artifact_review", "artifact_id: " + imported.ArtifactID, "- ship it", "artifact_refs"} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("artifact markdown missing %q:\n%s", want, markdown)
		}
	}
	packetBody, err := store.Read(first.Packet.Digest)
	if err != nil {
		t.Fatalf("Read packet: %v", err)
	}
	var record PacketRecord
	if err := json.Unmarshal(packetBody, &record); err != nil {
		t.Fatalf("Unmarshal packet: %v", err)
	}
	if record.Artifact == nil || record.Artifact.ID != imported.ArtifactID || record.StableDigest != first.StableDigest {
		t.Fatalf("bad artifact packet record: %+v", record)
	}
	status, err := artifact.Status(artifact.StatusOptions{StateDir: stateDir, ArtifactID: imported.ArtifactID})
	if err != nil {
		t.Fatalf("Artifact status: %v", err)
	}
	if status.Status != "waiting_for_result" || status.LatestPacket == nil || status.LatestPacket.Packet != second.Packet.Digest {
		t.Fatalf("status should report latest artifact packet: %+v", status)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestBuildArtifactPacketRequiresArtifactID(t *testing.T) {
	_, stateDir := initializedArtifactOnlyState(t)
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact})
	if err == nil || !strings.Contains(err.Error(), "--artifact is required") {
		t.Fatalf("expected missing artifact error, got %v", err)
	}
}

func TestBuildArtifactPacketRejectsUnknownArtifactWithoutCoverageError(t *testing.T) {
	_, stateDir := initializedArtifactOnlyState(t)
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: "artifact-missing"})
	if err == nil || !strings.Contains(err.Error(), "artifact not found") {
		t.Fatalf("expected artifact not found error, got %v", err)
	}
	if strings.Contains(err.Error(), "coverage manifest") {
		t.Fatalf("artifact packet should not try coverage manifest lookup: %v", err)
	}
}

func TestBuildArtifactPacketContextBudgetOmission(t *testing.T) {
	repo, stateDir := initializedArtifactOnlyState(t)
	imported, err := artifact.Import(artifact.ImportOptions{
		StateDir: stateDir,
		Kind:     artifact.KindPlan,
		Path:     writeArtifactPlanFile(t, repo, "plan.md", strings.Repeat("line\n", 20)),
		Title:    "Big Plan",
	})
	if err != nil {
		t.Fatalf("Import artifact: %v", err)
	}
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: imported.ArtifactID, MaxContextBytes: 8})
	if err != nil {
		t.Fatalf("Build artifact packet: %v", err)
	}
	if result.SourceCompleteness != "partial" || !hasPacketOmission(result.Context.Omissions, "context_budget_exceeded") {
		t.Fatalf("expected context budget omission: %+v", result)
	}
}

func TestBuildArtifactPacketBinaryContentOmitted(t *testing.T) {
	repo, stateDir := initializedArtifactOnlyState(t)
	artifactID := appendRawArtifactRecord(t, stateDir, repo, "artifact-binary", []byte{0, 1, 2})
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: artifactID})
	if err != nil {
		t.Fatalf("Build artifact packet: %v", err)
	}
	if result.SourceCompleteness != "partial" || !hasPacketOmission(result.Context.Omissions, "binary_context_omitted") {
		t.Fatalf("expected binary context omission: %+v", result)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	markdown, err := store.Read(result.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	if strings.Contains(string(markdown), string([]byte{0, 1, 2})) {
		t.Fatalf("binary content should not be embedded in markdown")
	}
}

func TestBuildArtifactPacketStableDigestIgnoresUnrelatedLedgerEvents(t *testing.T) {
	repo, stateDir := initializedArtifactOnlyState(t)
	imported, err := artifact.Import(artifact.ImportOptions{
		StateDir: stateDir,
		Kind:     artifact.KindPlan,
		Path:     writeArtifactPlanFile(t, repo, "plan.md", "same\n"),
		Title:    "Same Plan",
		Now:      time.Unix(10, 0),
	})
	if err != nil {
		t.Fatalf("Import artifact: %v", err)
	}
	first, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: imported.ArtifactID, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build artifact packet: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{Type: "unrelated.event", Repo: repo}); err != nil {
		t.Fatalf("Append unrelated event: %v", err)
	}
	second, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: imported.ArtifactID, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build second artifact packet: %v", err)
	}
	if first.StableDigest != second.StableDigest {
		t.Fatalf("stable digest should ignore unrelated ledger event: %s != %s", first.StableDigest, second.StableDigest)
	}
}

func TestBuildArtifactPacketStableDigestIgnoresImportPathAndTime(t *testing.T) {
	repo, stateDir := initializedArtifactOnlyState(t)
	firstImport, err := artifact.Import(artifact.ImportOptions{
		StateDir: stateDir,
		Kind:     artifact.KindPlan,
		Path:     writeArtifactPlanFile(t, repo, "first.md", "same\n"),
		Title:    "Same Plan",
		Now:      time.Unix(10, 0),
	})
	if err != nil {
		t.Fatalf("Import first artifact: %v", err)
	}
	firstPacket, err := Build(BuildOptions{StateDir: stateDir, Kind: KindArtifact, ArtifactID: firstImport.ArtifactID, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build first artifact packet: %v", err)
	}
	secondStateDir := filepath.Join(t.TempDir(), "state")
	if _, err := state.Init(state.InitOptions{StateDir: secondStateDir, RepoPath: repo, Now: time.Unix(30, 0)}); err != nil {
		t.Fatalf("Init second state: %v", err)
	}
	secondImport, err := artifact.Import(artifact.ImportOptions{
		StateDir: secondStateDir,
		Kind:     artifact.KindPlan,
		Path:     writeArtifactPlanFile(t, repo, "second.md", "same\n"),
		Title:    "Same Plan",
		Now:      time.Unix(40, 0),
	})
	if err != nil {
		t.Fatalf("Import second artifact: %v", err)
	}
	secondPacket, err := Build(BuildOptions{StateDir: secondStateDir, Kind: KindArtifact, ArtifactID: secondImport.ArtifactID, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build second artifact packet: %v", err)
	}
	if firstImport.ArtifactID != secondImport.ArtifactID {
		t.Fatalf("same artifact content should produce same id across states: first=%+v second=%+v", firstImport, secondImport)
	}
	if firstPacket.StableDigest != secondPacket.StableDigest {
		t.Fatalf("stable digest should ignore import path/time: %s != %s", firstPacket.StableDigest, secondPacket.StableDigest)
	}
}

func TestBuildPrimaryPacketStableDigestAndDedupeIgnoreVolatileTime(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	first, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build first: %v", err)
	}
	second, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build second: %v", err)
	}
	if first.StableDigest == "" || first.Packet.Digest == "" || first.Markdown.Digest == "" || first.Context.EntryCount == 0 {
		t.Fatalf("bad packet result: %+v", first)
	}
	if first.PromptDigest != first.Markdown.Digest {
		t.Fatalf("prompt digest should match stored markdown bytes: prompt=%s markdown=%s", first.PromptDigest, first.Markdown.Digest)
	}
	if first.StableDigest != second.StableDigest {
		t.Fatalf("stable digest should ignore generated time: %s != %s", first.StableDigest, second.StableDigest)
	}
	if first.SemanticDedupeKey.Digest != second.SemanticDedupeKey.Digest {
		t.Fatalf("dedupe key should ignore volatile generated time: %s != %s", first.SemanticDedupeKey.Digest, second.SemanticDedupeKey.Digest)
	}
	if first.TargetState.Tree == "" || first.SemanticDedupeKey.TargetState != "proposal:"+first.TargetState.Tree {
		t.Fatalf("dedupe target should use content tree identity: target=%+v key=%+v", first.TargetState, first.SemanticDedupeKey)
	}
	if first.VolatileDigest == second.VolatileDigest {
		t.Fatalf("volatile digest should include generated time")
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	markdown, err := store.Read(first.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	for _, want := range []string{"# Subreview Primary Review Packet", "## Selected Context", "semantic_dedupe_digest"} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("markdown missing %q:\n%s", want, markdown)
		}
	}
	packetBody, err := store.Read(first.Packet.Digest)
	if err != nil {
		t.Fatalf("Read packet: %v", err)
	}
	var record PacketRecord
	if err := json.Unmarshal(packetBody, &record); err != nil {
		t.Fatalf("Unmarshal packet: %v", err)
	}
	if record.StableDigest != first.StableDigest || record.SemanticDedupeKey.Digest != first.SemanticDedupeKey.Digest {
		t.Fatalf("packet record mismatch: %+v", record)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestBuildPrimaryPacketReportsContextBudgetOmissions(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", strings.Repeat("line\n", 50))
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0), MaxContextBytes: 8})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.SourceCompleteness != "partial" {
		t.Fatalf("source completeness should be partial under budget pressure: %+v", result)
	}
	if !hasPacketOmission(result.Context.Omissions, "context_budget_exceeded") {
		t.Fatalf("expected context budget omission: %+v", result.Context.Omissions)
	}
}

func TestBuildRejectsPolicyRebindAfterCoverageManifest(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigWithID(t, t.TempDir(), "new-policy"), Profile: "default"}); err != nil {
		t.Fatalf("Bind replacement policy: %v", err)
	}
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err == nil || !strings.Contains(err.Error(), "policy rebind") {
		t.Fatalf("expected stale manifest policy rebind error, got %v", err)
	}
}

func TestBuildRejectsNewProposalDiffAfterCoverageManifest(t *testing.T) {
	repo, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	writeFile(t, repo, "alpha.txt", "one\ntwo\nthree\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture replacement proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff replacement proposal: %v", err)
	}
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err == nil || !strings.Contains(err.Error(), "does not match latest snapshots") {
		t.Fatalf("expected stale manifest latest snapshot error, got %v", err)
	}
}

func TestBuildRejectsUnrepresentedBaseFinalDiffAfterCoverageManifest(t *testing.T) {
	repo, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err == nil || !strings.Contains(err.Error(), "base->final diff") {
		t.Fatalf("expected stale manifest base->final error, got %v", err)
	}
}

func TestBuildPrimaryPacketHunkContextDoesNotAnchorPastEOF(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	for _, entry := range record.Context.Entries {
		if entry.Path == "alpha.txt" && entry.Kind == "changed_hunk" {
			if entry.EndLine != 2 {
				t.Fatalf("hunk end line should clip to real EOF, got %+v", entry)
			}
			return
		}
	}
	t.Fatalf("changed hunk context missing: %+v", record.Context.Entries)
}

func TestBuildPrimaryPacketIncludesPatchContextForExistingFileHunks(t *testing.T) {
	_, stateDir := initializedPacketState(t, "keep\nremove\n", "keep\n")
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	hasTargetContext := false
	for _, entry := range record.Context.Entries {
		if entry.Path != "alpha.txt" {
			continue
		}
		if entry.Kind == "changed_hunk" {
			hasTargetContext = true
		}
		if entry.Kind == "patch_hunk" {
			if !strings.Contains(entry.Content, "-remove") {
				t.Fatalf("patch hunk should include deleted lines: %+v", entry)
			}
			if !hasTargetContext {
				for _, candidate := range record.Context.Entries {
					if candidate.Path == "alpha.txt" && candidate.Kind == "changed_hunk" {
						hasTargetContext = true
						break
					}
				}
			}
			if !hasTargetContext {
				t.Fatalf("existing file hunk should include target context as well as patch context: %+v", record.Context.Entries)
			}
			return
		}
	}
	t.Fatalf("patch hunk context missing for existing file: %+v", record.Context.Entries)
}

func TestBuildPrimaryPacketIncludesPatchFileForNoHunkDiff(t *testing.T) {
	_, stateDir := initializedModeOnlyPacketState(t)
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	hasChangedFile := false
	for _, entry := range record.Context.Entries {
		if entry.Path != "alpha.sh" {
			continue
		}
		if entry.Kind == "changed_file" {
			hasChangedFile = true
		}
		if entry.Kind == "patch_file" {
			if !strings.Contains(entry.Content, "old mode 100644") || !strings.Contains(entry.Content, "new mode 100755") {
				t.Fatalf("mode-only patch metadata missing: %+v", entry)
			}
			if !hasChangedFile {
				for _, candidate := range record.Context.Entries {
					if candidate.Path == "alpha.sh" && candidate.Kind == "changed_file" {
						hasChangedFile = true
						break
					}
				}
			}
			if !hasChangedFile {
				t.Fatalf("mode-only text file should include target file context: %+v", record.Context.Entries)
			}
			return
		}
	}
	t.Fatalf("patch_file context missing for no-hunk diff: %+v", record.Context.Entries)
}

func TestBuildPrimaryPacketOmitsBinaryTargetContext(t *testing.T) {
	_, stateDir := initializedBinaryPacketState(t)
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.SourceCompleteness != "partial" {
		t.Fatalf("binary target omission should mark source partial: %+v", result)
	}
	if !hasPacketOmission(result.Context.Omissions, "binary_context_omitted") {
		t.Fatalf("binary target omission missing: %+v", result.Context.Omissions)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	for _, entry := range record.Context.Entries {
		if entry.Path != "data.bin" {
			continue
		}
		if entry.Kind == "changed_file" {
			t.Fatalf("binary target bytes should not be rendered as changed_file context: %+v", entry)
		}
		if entry.Kind == "patch_file" {
			if !strings.Contains(entry.Content, "GIT binary patch") {
				t.Fatalf("binary patch metadata missing: %+v", entry)
			}
			return
		}
	}
	t.Fatalf("patch_file context missing for binary diff: %+v", record.Context.Entries)
}

func TestLeakageDetectionRejectsEvaluationLabels(t *testing.T) {
	report := CheckLeakage("this packet mentions a true_miss adjudication")
	if report.OK || len(report.ForbiddenTerms) == 0 {
		t.Fatalf("expected leakage terms, got %+v", report)
	}
}

func TestLeakageScanIgnoresContextEntryContent(t *testing.T) {
	material := recordLeakageMaterial{
		Repo: "repo",
		Target: SnapshotRef{
			Kind:   "proposal",
			Digest: "sha256:target",
			Tree:   "sha256:tree",
		},
		Manifest: state.ObjectRef{Digest: "sha256:manifest", MediaType: "application/json", Size: 1},
		SourceDiffs: []SourceDiff{{
			Transition:   "base->proposal",
			FromKind:     "base",
			ToKind:       "proposal",
			Patch:        state.ObjectRef{Digest: "sha256:patch", MediaType: "text/x-patch", Size: 10},
			PatchDigest:  "sha256:patch",
			HasChanges:   true,
			ChangedPaths: []string{"false_positive_test.go"},
			HunkCount:    1,
		}},
		Context: ContextBundle{Entries: []ContextEntry{{
			Kind:         "changed_file",
			Path:         "scripts/apply_verification_adjudications.py",
			SnapshotKind: "proposal",
			Digest:       "sha256:source",
			Bytes:        64,
			Content:      "This legitimate source mentions false_positive and adjudication.",
		}}, Omissions: []Omission{{
			Code:    "path_not_in_target_snapshot",
			Path:    "gold label notes.md",
			Message: "source path omitted",
		}}},
		Dedupe:         NewSemanticDedupeKey(SemanticDedupeFields{Route: RoutePrimary, RunKind: RunKindDiscovery}),
		SourceComplete: "complete",
		TokenTelemetry: NewTokenTelemetry(RunKindDiscovery, "complete"),
	}
	report := CheckLeakage(leakageScanText(material))
	if !report.OK {
		t.Fatalf("source content and paths should be excluded from leakage scan: %+v", report)
	}
}

func TestVerificationLeakageScanIncludesFindingText(t *testing.T) {
	material := recordLeakageMaterial{
		Repo: "repo",
		Target: SnapshotRef{
			Kind:   "final",
			Digest: "sha256:target",
		},
		Manifest:       state.ObjectRef{Digest: "sha256:manifest"},
		Dedupe:         NewSemanticDedupeKey(SemanticDedupeFields{Route: RouteVerification, RunKind: RunKindVerification}),
		SourceComplete: "complete",
		TokenTelemetry: NewTokenTelemetry(RunKindVerification, "complete"),
	}
	finding := reviewresult.FindingRecord{
		ID:              "finding-one",
		Severity:        "high",
		Class:           "correctness",
		Claim:           "This claim mentions true_miss.",
		FailureScenario: "The verifier should reject leaked evaluation terms.",
	}
	report := CheckLeakage(verificationLeakageScanText(material, VerificationRecord{
		Finding:  &finding,
		Findings: []reviewresult.FindingRecord{finding},
	}))
	if report.OK || len(report.ForbiddenTerms) == 0 {
		t.Fatalf("verification leakage scan should include finding text: %+v", report)
	}
}

func TestRenderStablePrefixEscapesPathMetadata(t *testing.T) {
	markdown := renderStablePrefix(stableRenderData{
		Repo: "repo",
		Target: SnapshotRef{
			Kind:   "proposal",
			Digest: "sha256:target",
		},
		Manifest: state.ObjectRef{Digest: "sha256:manifest"},
		Context: ContextBundle{
			Entries: []ContextEntry{{
				Kind:    "changed_file",
				Path:    "docs/name\n## injected.md",
				Digest:  "sha256:source",
				Content: "body",
			}},
			Omissions: []Omission{{
				Code:    "path_not_in_target_snapshot",
				Path:    "missing\n- forged",
				Message: "missing",
			}},
		},
		Dedupe:         NewSemanticDedupeKey(SemanticDedupeFields{Route: RoutePrimary, RunKind: RunKindDiscovery}),
		SourceComplete: "partial",
		TokenTelemetry: NewTokenTelemetry(RunKindDiscovery, "partial"),
	})
	if strings.Contains(markdown, "docs/name\n## injected.md") || strings.Contains(markdown, "missing\n- forged") {
		t.Fatalf("raw path metadata should not render with literal newlines:\n%s", markdown)
	}
	for _, want := range []string{`"docs/name\n## injected.md"`, `"missing\n- forged"`} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown missing escaped path %q:\n%s", want, markdown)
		}
	}
}

func TestMarkdownFenceExceedsEmbeddedBackticks(t *testing.T) {
	if got, want := markdownFence("plain text"), "```"; got != want {
		t.Fatalf("unexpected default fence: got %q want %q", got, want)
	}
	if got, want := markdownFence("code ``` nested ```` fence"), "`````"; got != want {
		t.Fatalf("unexpected expanded fence: got %q want %q", got, want)
	}
}

func TestSemanticDedupeAndReusedTelemetryHelpers(t *testing.T) {
	fields := SemanticDedupeFields{
		PolicyID:             "policy",
		PolicyDigest:         "sha256:policy",
		Route:                RoutePrimary,
		TargetState:          "sha256:target",
		ContentBundleHash:    "sha256:content",
		RunKind:              RunKindDiscovery,
		AllowedContextBundle: "sha256:context",
	}
	first := NewSemanticDedupeKey(fields)
	second := NewSemanticDedupeKey(fields)
	if first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("dedupe key should be stable: %+v %+v", first, second)
	}
	telemetry := ReusedTokenTelemetry(RunKindDiscovery, "complete", "packet-1", 1234)
	if telemetry.ExecutionReusedFromPacketID != "packet-1" || telemetry.GrossDiscoveryTokens != 1234 || telemetry.IncrementalDiscoveryTokens != 0 {
		t.Fatalf("bad reused telemetry: %+v", telemetry)
	}
}

func TestContentBundleDigestMaterialIgnoresCASRecordIdentities(t *testing.T) {
	first := []SourceDiff{{
		Transition:   "base->proposal",
		FromKind:     "base",
		ToKind:       "proposal",
		FromSnapshot: "sha256:volatile-base-one",
		ToSnapshot:   "sha256:volatile-proposal-one",
		Diff:         state.ObjectRef{Digest: "sha256:volatile-diff-one", MediaType: "application/vnd.subreview.diff+json", Size: 12, Path: "/tmp/one/diff"},
		Patch:        state.ObjectRef{Digest: "sha256:patch", MediaType: "text/x-patch", Size: 34, Path: "/tmp/one/patch"},
		PatchDigest:  "sha256:patch",
		HasChanges:   true,
		ChangedPaths: []string{"beta.txt", "alpha.txt"},
		HunkCount:    2,
	}}
	second := []SourceDiff{{
		Transition:   "base->proposal",
		FromKind:     "base",
		ToKind:       "proposal",
		FromSnapshot: "sha256:volatile-base-two",
		ToSnapshot:   "sha256:volatile-proposal-two",
		Diff:         state.ObjectRef{Digest: "sha256:volatile-diff-two", MediaType: "application/vnd.subreview.diff+json", Size: 12, Path: "/tmp/two/diff"},
		Patch:        state.ObjectRef{Digest: "sha256:patch", MediaType: "text/x-patch", Size: 34, Path: "/tmp/two/patch"},
		PatchDigest:  "sha256:patch",
		HasChanges:   true,
		ChangedPaths: []string{"alpha.txt", "beta.txt"},
		HunkCount:    2,
	}}
	firstGates := []GateSummary{{
		CommandID:     "go_test_all",
		CommandDigest: "sha256:command",
		Outcome:       "pass",
		Provenance:    "cli_witnessed",
		SnapshotKind:  "proposal",
		Snapshot:      "sha256:volatile-snapshot-one",
		PolicyDigest:  "sha256:volatile-policy-one",
		Evidence:      "sha256:volatile-evidence-one",
		EventID:       "event-one",
	}}
	secondGates := []GateSummary{{
		CommandID:     "go_test_all",
		CommandDigest: "sha256:command",
		Outcome:       "pass",
		Provenance:    "cli_witnessed",
		SnapshotKind:  "proposal",
		Snapshot:      "sha256:volatile-snapshot-two",
		PolicyDigest:  "sha256:volatile-policy-two",
		Evidence:      "sha256:volatile-evidence-two",
		EventID:       "event-two",
	}}
	targetOne := SnapshotRef{Kind: "proposal", Digest: "sha256:volatile-target-one", Tree: "sha256:tree"}
	targetTwo := SnapshotRef{Kind: "proposal", Digest: "sha256:volatile-target-two", Tree: "sha256:tree"}
	got := digestJSON(contentBundleDigestMaterial(first, targetOne, "sha256:context", firstGates))
	want := digestJSON(contentBundleDigestMaterial(second, targetTwo, "sha256:context", secondGates))
	if got != want {
		t.Fatalf("content bundle material should ignore volatile CAS record identities: got %s want %s", got, want)
	}
}

func TestVerificationContentBundleIncludesExpectedFixSurface(t *testing.T) {
	baseFinding := reviewresult.FindingRecord{
		ID:           "finding-one",
		DedupeDigest: "sha256:finding",
		Severity:     "high",
		Class:        "correctness",
		ExpectedFixSurface: []reviewresult.FixSurface{{
			Kind:      "file",
			Path:      "alpha.txt",
			StartLine: 1,
			EndLine:   2,
		}},
	}
	changedFinding := baseFinding
	changedFinding.ExpectedFixSurface = []reviewresult.FixSurface{{
		Kind:      "file",
		Path:      "beta.txt",
		StartLine: 3,
		EndLine:   4,
	}}
	target := SnapshotRef{Kind: "final", Digest: "sha256:target", Tree: "sha256:tree"}
	first := digestJSON(verificationContentBundleDigestMaterial(nil, target, "sha256:context", nil, []reviewresult.FindingRecord{baseFinding}))
	second := digestJSON(verificationContentBundleDigestMaterial(nil, target, "sha256:context", nil, []reviewresult.FindingRecord{changedFinding}))
	if first == second {
		t.Fatalf("verification content bundle digest should include expected fix surface: %s", first)
	}
}

func TestBuildPrimaryPacketIncludesDeletedPatchContext(t *testing.T) {
	_, stateDir := initializedDeletedPacketState(t, "old\n```source\n")
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, omission := range result.Context.Omissions {
		if omission.Code == "path_not_in_target_snapshot" && omission.Path == "alpha.txt" {
			t.Fatalf("deleted file should use patch context instead of target omission: %+v", result.Context.Omissions)
		}
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	packetBody, err := store.Read(result.Packet.Digest)
	if err != nil {
		t.Fatalf("Read packet: %v", err)
	}
	var record PacketRecord
	if err := json.Unmarshal(packetBody, &record); err != nil {
		t.Fatalf("Unmarshal packet: %v", err)
	}
	var deleted *ContextEntry
	for i := range record.Context.Entries {
		entry := &record.Context.Entries[i]
		if entry.Path == "alpha.txt" && entry.Kind == "patch_hunk" {
			deleted = entry
			break
		}
	}
	if deleted == nil {
		t.Fatalf("deleted file patch context missing: %+v", record.Context.Entries)
	}
	if deleted.SnapshotKind != "patch" || !strings.Contains(deleted.Content, "-old") || !strings.Contains(deleted.Content, "-```source") {
		t.Fatalf("deleted file patch context should include removed hunk text: %+v", deleted)
	}
	markdown, err := store.Read(result.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	if !strings.Contains(string(markdown), "````\n@@ ") || !strings.Contains(string(markdown), "-```source\n````") {
		t.Fatalf("markdown should use an expanded fence around embedded backticks:\n%s", markdown)
	}
}

func TestBuildPrimaryPacketFiltersStaleGateEvidence(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	command := packetGateCommand("go_test_all")
	catalogPath := writePacketGateCatalog(t, root, command)
	_, normalizedCatalog, err := gate.LoadCatalog(catalogPath)
	if err != nil {
		t.Fatalf("Load gate catalog: %v", err)
	}
	command = normalizedCatalog.Commands[0]
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfigWithGate(t, root, command.ID, gate.CommandDigest(command)), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "proposal one\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture first proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff first proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build first obligations: %v", err)
	}
	staleEvidence, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    command.ID,
		SnapshotKind: "proposal",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "pass on first proposal",
		Now:          time.Unix(20, 0),
	})
	if err != nil {
		t.Fatalf("Record stale proposal gate: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "proposal two\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture second proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff second proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build second obligations: %v", err)
	}
	staleResult, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(30, 0)})
	if err != nil {
		t.Fatalf("Build stale packet: %v", err)
	}
	assertNoGateEvidence(t, staleResult, stateDir, staleEvidence.Evidence.Digest)
	currentEvidence, err := gate.Record(gate.RecordOptions{
		StateDir:     stateDir,
		CatalogPath:  catalogPath,
		CommandID:    command.ID,
		SnapshotKind: "proposal",
		Outcome:      gate.OutcomePass,
		Provenance:   gate.ProvenanceExternalAsserted,
		Diagnostic:   "pass on second proposal",
		Now:          time.Unix(40, 0),
	})
	if err != nil {
		t.Fatalf("Record current proposal gate: %v", err)
	}
	currentResult, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(50, 0)})
	if err != nil {
		t.Fatalf("Build current packet: %v", err)
	}
	assertHasGateEvidence(t, currentResult, stateDir, currentEvidence.Evidence.Digest)
}

func TestBuildVerificationPacketUsesProposalFinalState(t *testing.T) {
	_, stateDir, findingID := initializedVerificationPacketState(t, true)
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindVerification, FindingID: findingID, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build verification packet: %v", err)
	}
	if result.Kind != KindVerification || result.RunKind != RunKindVerification || result.Route != RouteVerification || result.Verification == nil {
		t.Fatalf("bad verification result: %+v", result)
	}
	if result.Verification.FindingID != findingID || result.Verification.ProposalState == "" || result.Verification.FinalState == "" || result.Verification.ProposalFinalPatch == "" || len(result.Verification.Questions) == 0 {
		t.Fatalf("verification summary incomplete: %+v", result.Verification)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	if record.Verification == nil || record.Verification.Finding == nil || record.Verification.Finding.ID != findingID || len(record.Verification.Findings) != 1 || record.Verification.Findings[0].ID != findingID || record.TargetState.Kind != "final" {
		t.Fatalf("verification record incomplete: %+v", record.Verification)
	}
	if record.SemanticDedupeKey.RunKind != RunKindVerification || record.SemanticDedupeKey.Route != RouteVerification {
		t.Fatalf("verification dedupe key should be route-specific: %+v", record.SemanticDedupeKey)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	markdown, err := store.Read(result.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	for _, want := range []string{"# Subreview Verification Packet", "## Verification Questions", "proposal-to-final", "resolved, not_resolved, regression_introduced", "finding_invalid requires verifier_relation=fresh_blinded", "deterministic_refuted requires matching deterministic_refutations", "- citations:", "- anchors:", "\"alpha.txt\":1-2", "kind=hunk"} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("verification markdown missing %q:\n%s", want, markdown)
		}
	}
}

func TestBuildVerificationPacketSupportsBatchFindingIDs(t *testing.T) {
	_, stateDir, firstID := initializedVerificationPacketState(t, true)
	primary, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(205, 0)})
	if err != nil {
		t.Fatalf("Build follow-up primary packet: %v", err)
	}
	secondID := "finding-beta"
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writePacketWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings: []reviewresult.FindingInput{{
				ID:              secondID,
				Severity:        "high",
				Class:           "correctness",
				Claim:           "alpha.txt leaves a second independent bug marker visible.",
				FailureScenario: "A reader sees a second marker that should not ship.",
				Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 2}},
				Anchors:         []reviewresult.AnchorRef{{Kind: "hunk", Path: "alpha.txt", StartLine: 1, EndLine: 2}},
			}},
		}),
		Now: time.Unix(206, 0),
	}); err != nil {
		t.Fatalf("Import second finding: %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir, Kind: KindVerification, FindingIDs: []string{firstID, " " + firstID + " "}, Now: time.Unix(207, 0)}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate finding rejection, got %v", err)
	}
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindVerification, FindingIDs: []string{secondID, firstID}, Now: time.Unix(208, 0)})
	if err != nil {
		t.Fatalf("Build batch verification packet: %v", err)
	}
	if result.Verification == nil || result.Verification.FindingID != "" || strings.Join(result.Verification.FindingIDs, ",") != firstID+","+secondID {
		t.Fatalf("bad batch verification summary: %+v", result.Verification)
	}
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	if record.Verification == nil || record.Verification.Finding != nil || len(record.Verification.Findings) != 2 || strings.Join(record.Verification.FindingIDs, ",") != firstID+","+secondID {
		t.Fatalf("bad batch verification record: %+v", record.Verification)
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	last := events[len(events)-1]
	if last.Details["finding_id"] != "" || last.Details["finding_ids"] != firstID+","+secondID {
		t.Fatalf("batch event should use finding_ids only: %+v", last.Details)
	}
}

func TestBuildRejectsInvalidMaxContextBytes(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	if _, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, MaxContextBytes: -1}); err == nil || !strings.Contains(err.Error(), "max context bytes") {
		t.Fatalf("expected negative max context error, got %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, MaxContextBytes: MaxContextBytesLimit + 1}); err == nil || !strings.Contains(err.Error(), "max context bytes") {
		t.Fatalf("expected oversized max context error, got %v", err)
	}
	if _, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, MaxContextBytes: 0}); err != nil {
		t.Fatalf("zero max context should use default: %v", err)
	}
}

func TestBuildVerificationPacketRequiresProposalFinalDiff(t *testing.T) {
	_, stateDir, findingID := initializedVerificationPacketState(t, false)
	_, err := Build(BuildOptions{StateDir: stateDir, Kind: KindVerification, FindingID: findingID, Now: time.Unix(200, 0)})
	if err == nil || !strings.Contains(err.Error(), "proposal->final diff") {
		t.Fatalf("expected missing proposal->final diff error, got %v", err)
	}
}

func TestParsePatchHandlesQuotedAndSeparatorPaths(t *testing.T) {
	files := parsePatch([]byte(`diff --git "from/a\tb.txt" "to/a\tb.txt"
--- "from/a\tb.txt"
+++ "to/a\tb.txt"
@@ -1 +1 @@
-old
+new
diff --git from/a to/file.txt to/a to/file.txt
old mode 100644
new mode 100755
diff --git from/old to/file.txt to/new to/file.txt
similarity index 100%
rename from old to/file.txt
rename to new to/file.txt
`))
	paths := make([]string, 0, len(files))
	hunksByPath := map[string]int{}
	for _, file := range files {
		paths = append(paths, file.Path)
		hunksByPath[file.Path] = len(file.Hunks)
	}
	if got, want := strings.Join(paths, "|"), "a\tb.txt|a to/file.txt|new to/file.txt"; got != want {
		t.Fatalf("unexpected parsed paths: got %q want %q", got, want)
	}
	if hunksByPath["a\tb.txt"] != 1 {
		t.Fatalf("quoted path should retain hunk, got %+v", files)
	}
}

func TestDecodeStrictRejectsTrailingJSON(t *testing.T) {
	var record struct {
		Name string `json:"name"`
	}
	if err := decodeStrict([]byte(`{"name":"one"} {"name":"two"}`), &record); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
	if err := decodeStrict([]byte(`{"name":"one"}`), &record); err != nil {
		t.Fatalf("valid JSON should pass: %v", err)
	}
}

func initializedPacketState(t *testing.T, baseBody, proposalBody string) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", baseBody)
	writeFile(t, repo, "alpha_test.txt", "package fixture\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeFile(t, repo, "alpha.txt", proposalBody)
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	return repo, stateDir
}

func initializedDeletedPacketState(t *testing.T, baseBody string) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", baseBody)
	writeFile(t, repo, "alpha_test.txt", "package fixture\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	if err := os.Remove(filepath.Join(repo, "alpha.txt")); err != nil {
		t.Fatalf("remove alpha.txt: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	return repo, stateDir
}

func initializedModeOnlyPacketState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.sh", "#!/bin/sh\necho hi\n")
	if err := os.Chmod(filepath.Join(repo, "alpha.sh"), 0o644); err != nil {
		t.Fatalf("chmod alpha.sh: %v", err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	if err := os.Chmod(filepath.Join(repo, "alpha.sh"), 0o755); err != nil {
		t.Fatalf("chmod alpha.sh executable: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	return repo, stateDir
}

func initializedArtifactOnlyState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	initGitRepo(t, repo)
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	return repo, stateDir
}

func initializedBinaryPacketState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeBytes(t, repo, "data.bin", []byte{0, 1, 2, 'o', 'l', 'd'})
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeBytes(t, repo, "data.bin", []byte{0, 1, 2, 'n', 'e', 'w'})
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	return repo, stateDir
}

func initializedVerificationPacketState(t *testing.T, withProposalFinalDiff bool) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	writeFile(t, repo, "alpha_test.txt", "package fixture\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "one\nbug\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	writeFile(t, repo, "alpha.txt", "one\nfixed\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if withProposalFinalDiff {
		if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "proposal", ToKind: "final"}); err != nil {
			t.Fatalf("CreateDiff proposal->final: %v", err)
		}
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	primary, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(20, 0)})
	if err != nil {
		t.Fatalf("Build primary packet: %v", err)
	}
	findingID := "finding-alpha"
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writePacketWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeFindings,
			Findings: []reviewresult.FindingInput{{
				ID:              findingID,
				Severity:        "high",
				Class:           "correctness",
				Claim:           "alpha.txt leaves the proposal bug visible to readers.",
				FailureScenario: "A reader sees the literal bug marker in the proposal output.",
				Citations:       []reviewresult.LineRef{{Path: "alpha.txt", StartLine: 1, EndLine: 2}},
				Anchors:         []reviewresult.AnchorRef{{Kind: "hunk", Path: "alpha.txt", StartLine: 1, EndLine: 2}},
				ExpectedFixSurface: []reviewresult.FixSurface{{
					Kind: "file",
					Path: "alpha.txt",
				}},
			}},
		}),
		Now: time.Unix(30, 0),
	}); err != nil {
		t.Fatalf("Import finding result: %v", err)
	}
	return repo, stateDir, findingID
}

func writePacketWorkerResult(t *testing.T, value reviewresult.WorkerResult) string {
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

func assertNoGateEvidence(t *testing.T, result BuildResult, stateDir, evidenceDigest string) {
	t.Helper()
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	for _, summary := range record.Gates {
		if summary.Evidence == evidenceDigest {
			t.Fatalf("stale gate evidence should not be included: %+v", record.Gates)
		}
	}
}

func assertHasGateEvidence(t *testing.T, result BuildResult, stateDir, evidenceDigest string) {
	t.Helper()
	record := readPacketRecord(t, stateDir, result.Packet.Digest)
	for _, summary := range record.Gates {
		if summary.Evidence == evidenceDigest {
			return
		}
	}
	t.Fatalf("current gate evidence missing: want %s got %+v", evidenceDigest, record.Gates)
}

func readPacketRecord(t *testing.T, stateDir, digest string) PacketRecord {
	t.Helper()
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	body, err := store.Read(digest)
	if err != nil {
		t.Fatalf("Read packet: %v", err)
	}
	var record PacketRecord
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatalf("Unmarshal packet: %v", err)
	}
	return record
}

func writePolicyConfig(t *testing.T, root string) string {
	t.Helper()
	return writePolicyConfigWithID(t, root, "test-policy")
}

func writePolicyConfigWithID(t *testing.T, root, policyID string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "` + policyID + `",
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

func writePolicyConfigWithGate(t *testing.T, root, commandID, commandDigest string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [{"command_id": "` + commandID + `", "command_digest": "` + commandDigest + `", "required": true}],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
      "risk_routing": [],
      "closure_basis": {"allowed_basis": ["clean", "fixed", "deterministic_refutation"], "require_basis_for_unresolved": true}
    }
  }
}
`)
	path := filepath.Join(root, "policy-with-gate.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func packetGateCommand(commandID string) gate.CommandDefinition {
	return gate.CommandDefinition{
		ID:                commandID,
		Description:       "test gate",
		Argv:              []string{"/bin/sh", "-c", "true"},
		ReplayClass:       gate.ReplayContentPure,
		EnvironmentPinned: true,
		ExecutesRepoCode:  false,
		SideEffects:       gate.SideEffectsNone,
		TimeoutSeconds:    30,
	}
}

func writePacketGateCatalog(t *testing.T, root string, command gate.CommandDefinition) string {
	t.Helper()
	body, err := json.Marshal(gate.Catalog{SchemaVersion: gate.SchemaVersion, Commands: []gate.CommandDefinition{command}})
	if err != nil {
		t.Fatalf("marshal gate catalog: %v", err)
	}
	path := filepath.Join(root, "gate-catalog.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write gate catalog: %v", err)
	}
	return path
}

func hasPacketOmission(omissions []Omission, code string) bool {
	for _, omission := range omissions {
		if omission.Code == code {
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

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	writeBytes(t, root, rel, []byte(body))
}

func writeArtifactPlanFile(t *testing.T, root, rel, body string) string {
	t.Helper()
	writeFile(t, root, rel, body)
	return filepath.Join(root, filepath.FromSlash(rel))
}

func appendRawArtifactRecord(t *testing.T, stateDir, repo, id string, body []byte) string {
	t.Helper()
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	content, err := store.PutBytes(body, artifact.MediaTypePlanText)
	if err != nil {
		t.Fatalf("Put content: %v", err)
	}
	record := artifact.ArtifactRecord{
		SchemaVersion: artifact.SchemaVersion,
		ID:            id,
		Kind:          artifact.KindPlan,
		Title:         id,
		SourcePath:    filepath.Join(repo, id+".md"),
		Repo:          repo,
		CreatedAt:     time.Unix(20, 0).UTC().Format(time.RFC3339Nano),
		Content:       content,
		ContentDigest: content.Digest,
		Text:          artifact.TextMetadata{Encoding: "binary", UTF8: false, ContainsNUL: true},
	}
	artifactRef, err := store.PutJSON(record, artifact.MediaTypeArtifact)
	if err != nil {
		t.Fatalf("Put artifact: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          artifact.EventTypeImported,
		ObjectDigests: []string{artifactRef.Digest, content.Digest},
		Repo:          repo,
		Details: map[string]string{
			"artifact":       artifactRef.Digest,
			"artifact_id":    id,
			"kind":           artifact.KindPlan,
			"title":          id,
			"content":        content.Digest,
			"content_digest": content.Digest,
		},
	}); err != nil {
		t.Fatalf("Append artifact event: %v", err)
	}
	return id
}

func writeBytes(t *testing.T, root, rel string, body []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
