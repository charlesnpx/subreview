package packet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

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
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
