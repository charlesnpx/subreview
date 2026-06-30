package packettrust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/state"
)

func TestResolveEventRejectsMarkdownNotBuiltFromStableAndVolatile(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("ensure repo: %v", err)
	}
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	wrongMarkdown, err := store.PutBytes([]byte("different prompt\n"), "text/markdown; charset=utf-8")
	if err != nil {
		t.Fatalf("Put markdown: %v", err)
	}
	stable := "stable packet content"
	volatile := "volatile packet content"
	var record packetRecord
	record.SchemaVersion = SchemaVersion
	record.Kind = "primary"
	record.RunKind = "discovery"
	record.Route = "primary_review"
	record.Repo = repo
	record.CoverageManifest = state.ObjectRef{Digest: digestString("coverage")}
	record.TargetState = SnapshotRef{Kind: "proposal", Digest: digestString("target")}
	record.SourceDiffs = []SourceDiff{{
		Transition:   "base->proposal",
		FromKind:     "base",
		ToKind:       "proposal",
		FromSnapshot: digestString("base"),
		ToSnapshot:   record.TargetState.Digest,
		Patch:        state.ObjectRef{Digest: digestString("patch")},
		PatchDigest:  digestString("patch"),
	}}
	record.TransitionKey = TransitionKey("base", "proposal", record.SourceDiffs[0].FromSnapshot, record.SourceDiffs[0].ToSnapshot)
	record.StablePrefix = stable
	record.VolatileSuffix = volatile
	record.StableDigest = digestString(stable)
	record.VolatileDigest = digestString(volatile)
	record.PromptDigest = wrongMarkdown.Digest
	record.SemanticDedupeKey.Digest = digestString("dedupe")
	record.SourceCompleteness = "complete"
	packetObject, err := store.PutJSON(record, "application/vnd.subreview.packet+json")
	if err != nil {
		t.Fatalf("Put packet: %v", err)
	}
	event := state.Event{
		Type:          EventTypePacketBuilt,
		ObjectDigests: []string{packetObject.Digest, wrongMarkdown.Digest},
		Repo:          repo,
		Details: map[string]string{
			"kind":                   record.Kind,
			"run_kind":               record.RunKind,
			"route":                  record.Route,
			"packet":                 packetObject.Digest,
			"markdown":               wrongMarkdown.Digest,
			"coverage_manifest":      record.CoverageManifest.Digest,
			"target_state":           record.TargetState.Digest,
			"stable_digest":          record.StableDigest,
			"volatile_digest":        record.VolatileDigest,
			"prompt_digest":          record.PromptDigest,
			"semantic_dedupe_digest": record.SemanticDedupeKey.Digest,
			"transition_key":         record.TransitionKey,
			"source_completeness":    record.SourceCompleteness,
		},
	}
	_, err = ResolveEvent(store, stateDir, repo, event)
	if err == nil || !strings.Contains(err.Error(), "stable/volatile packet content") {
		t.Fatalf("expected stable/volatile prompt mismatch, got %v", err)
	}
}

func TestResolveEventRejectsMismatchedVerificationIDs(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("ensure repo: %v", err)
	}
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	stable := "stable packet content"
	volatile := "volatile packet content"
	markdown := stable + "\n\n" + volatile + "\n"
	markdownRef, err := store.PutBytes([]byte(markdown), "text/markdown; charset=utf-8")
	if err != nil {
		t.Fatalf("Put markdown: %v", err)
	}
	var record packetRecord
	record.SchemaVersion = SchemaVersion
	record.Kind = "verification"
	record.RunKind = "verification"
	record.Route = "targeted_verification"
	record.Repo = repo
	record.CoverageManifest = state.ObjectRef{Digest: digestString("coverage")}
	record.TargetState = SnapshotRef{Kind: "final", Digest: digestString("target")}
	record.SourceDiffs = []SourceDiff{{
		Transition:   "proposal->final",
		FromKind:     "proposal",
		ToKind:       "final",
		FromSnapshot: digestString("proposal"),
		ToSnapshot:   record.TargetState.Digest,
		Patch:        state.ObjectRef{Digest: digestString("patch")},
		PatchDigest:  digestString("patch"),
	}}
	record.TransitionKey = TransitionKey("proposal", "final", record.SourceDiffs[0].FromSnapshot, record.SourceDiffs[0].ToSnapshot)
	record.StablePrefix = stable
	record.VolatileSuffix = volatile
	record.StableDigest = digestString(stable)
	record.VolatileDigest = digestString(volatile)
	record.PromptDigest = markdownRef.Digest
	record.SemanticDedupeKey.Digest = digestString("dedupe")
	record.SourceCompleteness = "complete"
	record.Verification = &verificationRecord{
		FindingIDs: []string{"finding-a", "finding-b"},
		Findings:   []verificationFinding{{ID: "finding-a"}},
	}
	packetObject, err := store.PutJSON(record, "application/vnd.subreview.packet+json")
	if err != nil {
		t.Fatalf("Put packet: %v", err)
	}
	event := state.Event{
		Type:          EventTypePacketBuilt,
		ObjectDigests: []string{packetObject.Digest, markdownRef.Digest},
		Repo:          repo,
		Details: map[string]string{
			"kind":                   record.Kind,
			"run_kind":               record.RunKind,
			"route":                  record.Route,
			"packet":                 packetObject.Digest,
			"markdown":               markdownRef.Digest,
			"coverage_manifest":      record.CoverageManifest.Digest,
			"target_state":           record.TargetState.Digest,
			"stable_digest":          record.StableDigest,
			"volatile_digest":        record.VolatileDigest,
			"prompt_digest":          record.PromptDigest,
			"semantic_dedupe_digest": record.SemanticDedupeKey.Digest,
			"transition_key":         record.TransitionKey,
			"source_completeness":    record.SourceCompleteness,
			"finding_ids":            "finding-a,finding-b",
		},
	}
	_, err = ResolveEvent(store, stateDir, repo, event)
	if err == nil || !strings.Contains(err.Error(), "verification finding ids mismatch") {
		t.Fatalf("expected verification id mismatch, got %v", err)
	}
}
