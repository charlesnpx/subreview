package artifact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/state"
)

func TestImportPlanArtifactAndStatus(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	planPath := writeArtifactFile(t, repo, "plan.md", "# Plan\n\nDo the work.\n")

	result, err := Import(ImportOptions{
		StateDir: stateDir,
		Kind:     KindPlan,
		Path:     planPath,
		Title:    "Test Plan",
		Now:      time.Unix(100, 0),
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if result.ArtifactID == "" || result.Artifact.Digest == "" || result.ContentDigest == "" || result.EventID == "" {
		t.Fatalf("import result missing ids: %+v", result)
	}
	if result.Repo != repo || result.Kind != KindPlan || result.Title != "Test Plan" || result.SourcePath != planPath {
		t.Fatalf("bad import result: %+v", result)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate after import: %+v", validation.Errors)
	}

	status, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: result.ArtifactID})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "no_review_packet" || !status.ReviewRequired || status.Artifact.ID != result.ArtifactID {
		t.Fatalf("bad status: %+v", status)
	}
	if len(status.SupersededBy) != 0 || len(status.Blockers) != 0 {
		t.Fatalf("fresh artifact should have no supersession or blockers: %+v", status)
	}
}

func TestImportDuplicateIsDeterministic(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	planPath := writeArtifactFile(t, repo, "plan.md", "duplicate\n")
	first, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: planPath, Title: "Duplicate", Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("first Import: %v", err)
	}
	secondPath := writeArtifactFile(t, repo, "same.md", "duplicate\n")
	second, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: secondPath, Title: "Duplicate", Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if !second.AlreadyImported {
		t.Fatalf("duplicate import should be marked already imported: %+v", second)
	}
	if second.ArtifactID != first.ArtifactID || second.EventID != first.EventID || second.CreatedAt != first.CreatedAt {
		t.Fatalf("duplicate import should return original record: first=%+v second=%+v", first, second)
	}
}

func TestImportRejectsInvalidInputs(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	validPath := writeArtifactFile(t, repo, "valid.md", "valid\n")
	emptyPath := writeArtifactFile(t, repo, "empty.md", "")
	oversizePath := writeArtifactFile(t, repo, "oversize.md", "12345")
	invalidUTF8Path := writeArtifactBytes(t, repo, "invalid.md", []byte{0xff, '\n'})
	nulPath := writeArtifactBytes(t, repo, "nul.md", []byte("a\x00b\n"))

	tests := []struct {
		name string
		opts ImportOptions
		want string
	}{
		{
			name: "invalid kind",
			opts: ImportOptions{StateDir: stateDir, Kind: "note", Path: validPath, Title: "Bad"},
			want: "unsupported artifact kind",
		},
		{
			name: "missing file",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: filepath.Join(repo, "missing.md"), Title: "Missing"},
			want: "no such file",
		},
		{
			name: "empty file",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: emptyPath, Title: "Empty"},
			want: "empty",
		},
		{
			name: "oversize file",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: oversizePath, Title: "Oversize", MaxArtifactBytes: 4},
			want: "exceeds 4 byte limit",
		},
		{
			name: "invalid utf8",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: invalidUTF8Path, Title: "Invalid"},
			want: "valid UTF-8",
		},
		{
			name: "nul byte",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: nulPath, Title: "Nul"},
			want: "NUL",
		},
		{
			name: "missing title",
			opts: ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: validPath},
			want: "--title is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Import(tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestRevisionChainAndForkRejection(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	parentPath := writeArtifactFile(t, repo, "parent.md", "parent\n")
	parent, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: parentPath, Title: "Parent"})
	if err != nil {
		t.Fatalf("parent Import: %v", err)
	}
	childPath := writeArtifactFile(t, repo, "child.md", "child\n")
	child, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: childPath, Title: "Child", Revises: parent.ArtifactID})
	if err != nil {
		t.Fatalf("child Import: %v", err)
	}
	parentStatus, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: parent.ArtifactID})
	if err != nil {
		t.Fatalf("parent Status: %v", err)
	}
	if got := strings.Join(parentStatus.SupersededBy, ","); got != child.ArtifactID {
		t.Fatalf("parent superseded_by mismatch: %q", got)
	}
	if _, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: writeArtifactFile(t, repo, "missing-revises.md", "x\n"), Title: "Missing Revises", Revises: "artifact-missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing revises error, got %v", err)
	}
	if _, err := Import(ImportOptions{StateDir: stateDir, Kind: KindPlan, Path: writeArtifactFile(t, repo, "fork.md", "fork\n"), Title: "Fork", Revises: parent.ArtifactID}); err == nil || !strings.Contains(err.Error(), "forked_revision") {
		t.Fatalf("expected forked_revision error, got %v", err)
	}
}

func TestStatusReportsMalformedForkBlocker(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	appendArtifactRecord(t, stateDir, repo, "artifact-parent", "", "parent\n")
	appendArtifactRecord(t, stateDir, repo, "artifact-child-a", "artifact-parent", "a\n")
	appendArtifactRecord(t, stateDir, repo, "artifact-child-b", "artifact-parent", "b\n")

	status, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: "artifact-parent"})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "blocked" || status.ReviewRequired {
		t.Fatalf("forked revision should block status: %+v", status)
	}
	if len(status.Blockers) != 1 || status.Blockers[0].Code != "forked_revision" {
		t.Fatalf("expected forked_revision blocker: %+v", status.Blockers)
	}
}

func TestStatusReportsMalformedCycleBlocker(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	appendArtifactRecord(t, stateDir, repo, "artifact-a", "artifact-c", "a\n")
	appendArtifactRecord(t, stateDir, repo, "artifact-b", "artifact-a", "b\n")
	appendArtifactRecord(t, stateDir, repo, "artifact-c", "artifact-b", "c\n")

	status, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: "artifact-a"})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "blocked" || status.ReviewRequired {
		t.Fatalf("revision cycle should block status: %+v", status)
	}
	if !hasBlocker(status.Blockers, "revision_cycle") {
		t.Fatalf("expected revision_cycle blocker: %+v", status.Blockers)
	}
}

func TestStatusReportsMissingRevisionTargetBlocker(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	appendArtifactRecord(t, stateDir, repo, "artifact-child", "artifact-missing", "child\n")

	status, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: "artifact-child"})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "blocked" || status.ReviewRequired {
		t.Fatalf("missing revision target should block status: %+v", status)
	}
	if !hasBlocker(status.Blockers, "missing_revision_target") {
		t.Fatalf("expected missing_revision_target blocker: %+v", status.Blockers)
	}
}

func TestStatusIgnoresUnrelatedMalformedRevisionChain(t *testing.T) {
	repo, stateDir := initializedArtifactState(t)
	clean := appendArtifactRecord(t, stateDir, repo, "artifact-clean", "", "clean\n")
	appendArtifactRecord(t, stateDir, repo, "artifact-bad", "artifact-missing", "bad\n")

	status, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: clean})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.Status != "no_review_packet" || !status.ReviewRequired {
		t.Fatalf("unrelated malformed chain should not block clean artifact: %+v", status)
	}
	if len(status.Blockers) != 0 {
		t.Fatalf("clean artifact should not include unrelated blockers: %+v", status.Blockers)
	}
}

func TestStatusRejectsUnknownArtifact(t *testing.T) {
	_, stateDir := initializedArtifactState(t)
	_, err := Status(StatusOptions{StateDir: stateDir, ArtifactID: "artifact-missing"})
	if err == nil || !strings.Contains(err.Error(), "artifact not found") {
		t.Fatalf("expected unknown artifact error, got %v", err)
	}
}

func hasBlocker(blockers []Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func initializedArtifactState(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("state init: %v", err)
	}
	return repo, stateDir
}

func writeArtifactFile(t *testing.T, repo, name, body string) string {
	t.Helper()
	return writeArtifactBytes(t, repo, name, []byte(body))
}

func writeArtifactBytes(t *testing.T, repo, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(repo, name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	return path
}

func appendArtifactRecord(t *testing.T, stateDir, repo, id, revises, body string) string {
	t.Helper()
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("state open: %v", err)
	}
	content, err := store.PutBytes([]byte(body), MediaTypePlanText)
	if err != nil {
		t.Fatalf("put content: %v", err)
	}
	record := ArtifactRecord{
		SchemaVersion: SchemaVersion,
		ID:            id,
		Kind:          KindPlan,
		Title:         id,
		SourcePath:    filepath.Join(repo, id+".md"),
		Repo:          repo,
		CreatedAt:     time.Unix(20, 0).UTC().Format(time.RFC3339Nano),
		Revises:       revises,
		Content:       content,
		ContentDigest: content.Digest,
		Text:          TextMetadata{Encoding: "utf-8", UTF8: true},
	}
	artifactRef, err := store.PutJSON(record, MediaTypeArtifact)
	if err != nil {
		t.Fatalf("put artifact: %v", err)
	}
	details := map[string]string{
		"artifact":       artifactRef.Digest,
		"artifact_id":    id,
		"kind":           KindPlan,
		"title":          id,
		"content":        content.Digest,
		"content_digest": content.Digest,
	}
	if revises != "" {
		details["revises"] = revises
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          EventTypeImported,
		ObjectDigests: []string{artifactRef.Digest, content.Digest},
		Repo:          repo,
		Details:       details,
	}); err != nil {
		t.Fatalf("append artifact event: %v", err)
	}
	return id
}
