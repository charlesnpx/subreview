package anchor

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

type goldenAnchorResult struct {
	ID            string   `json:"id"`
	Status        string   `json:"status"`
	ToPath        string   `json:"to_path,omitempty"`
	ToStartLine   int      `json:"to_start_line,omitempty"`
	ToEndLine     int      `json:"to_end_line,omitempty"`
	Candidates    []string `json:"candidates,omitempty"`
	BlocksClosure bool     `json:"blocks_closure"`
}

func TestAnchorMigrationGoldenCases(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "edit.txt", "alpha\nbeta\ngamma\n")
	writeFile(t, repo, "adjacent.txt", "keep\nanchor\nend\n")
	writeFile(t, repo, "delete.txt", "gone\n")
	writeFile(t, repo, "rename-old.txt", "same\n")
	writeFile(t, repo, "ambiguous.txt", "dup\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}

	writeFile(t, repo, "edit.txt", "alpha\nbeta changed\ngamma\n")
	writeFile(t, repo, "adjacent.txt", "inserted\nkeep\nanchor\nend\n")
	if err := os.Remove(filepath.Join(repo, "delete.txt")); err != nil {
		t.Fatalf("remove delete.txt: %v", err)
	}
	if err := os.Rename(filepath.Join(repo, "rename-old.txt"), filepath.Join(repo, "rename-new.txt")); err != nil {
		t.Fatalf("rename file: %v", err)
	}
	writeFile(t, repo, "ambiguous.txt", "dup\nmiddle\ndup\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff: %v", err)
	}
	result, err := Migrate(MigrateOptions{
		StateDir:    stateDir,
		FromKind:    "base",
		ToKind:      "proposal",
		WriteLedger: true,
		Anchors: []Anchor{
			{ID: "path_unchanged", Kind: KindPath, Path: "edit.txt"},
			{ID: "file_modified", Kind: KindFile, Path: "edit.txt"},
			{ID: "hunk_adjacent", Kind: KindHunk, Path: "adjacent.txt", StartLine: 2, EndLine: 2, Text: "anchor\n"},
			{ID: "file_deleted", Kind: KindFile, Path: "delete.txt"},
			{ID: "file_renamed", Kind: KindFile, Path: "rename-old.txt"},
			{ID: "hunk_ambiguous", Kind: KindHunk, Path: "ambiguous.txt", StartLine: 1, EndLine: 1, Text: "dup\n"},
			{ID: "file_unresolved", Kind: KindFile, Path: "missing.txt"},
		},
	})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if result.EventID == "" || result.Migration.Digest == "" || result.AnchorManifest.Digest == "" {
		t.Fatalf("expected migration ledger and CAS refs: %+v", result)
	}
	if len(result.ClosureBlockers) != 2 {
		t.Fatalf("expected ambiguous and unresolved closure blockers, got %+v", result.ClosureBlockers)
	}
	for _, blocker := range result.ClosureBlockers {
		if blocker.Status != StatusAmbiguous && blocker.Status != StatusUnresolved {
			t.Fatalf("unexpected blocker: %+v", blocker)
		}
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}

	got := projectGoldenResults(result.Results)
	gotJSON := marshalIndent(t, got)
	want, err := os.ReadFile(filepath.Join("testdata", "golden", "migration_cases.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(gotJSON), bytes.TrimSpace(want)) {
		t.Fatalf("golden mismatch\nwant:\n%s\n\ngot:\n%s", want, gotJSON)
	}
}

func TestAnchorManifestReadSupportsObjectAndArrayForms(t *testing.T) {
	root := t.TempDir()
	objectPath := filepath.Join(root, "object.json")
	if err := os.WriteFile(objectPath, []byte(`{"schema_version":1,"anchors":[{"id":"a","kind":"file","path":"a.txt"}]}`), 0o644); err != nil {
		t.Fatalf("write object manifest: %v", err)
	}
	objectManifest, err := ReadManifest(objectPath)
	if err != nil {
		t.Fatalf("ReadManifest object: %v", err)
	}
	if len(objectManifest.Anchors) != 1 || objectManifest.Anchors[0].ID != "a" {
		t.Fatalf("bad object manifest: %+v", objectManifest)
	}
	arrayPath := filepath.Join(root, "array.json")
	if err := os.WriteFile(arrayPath, []byte(`[{"id":"b","kind":"path","path":"b.txt"}]`), 0o644); err != nil {
		t.Fatalf("write array manifest: %v", err)
	}
	arrayManifest, err := ReadManifest(arrayPath)
	if err != nil {
		t.Fatalf("ReadManifest array: %v", err)
	}
	if len(arrayManifest.Anchors) != 1 || arrayManifest.Anchors[0].ID != "b" {
		t.Fatalf("bad array manifest: %+v", arrayManifest)
	}
}

func TestFindTextOccurrencesMatchesWholeLinesOnly(t *testing.T) {
	locations := findTextOccurrences([]byte("foo\nfoobar\nbaz\n"), "bar\n", "target.txt", "sha256:test")
	if len(locations) != 0 {
		t.Fatalf("line anchor should not match substring inside changed line: %+v", locations)
	}
	locations = findTextOccurrences([]byte("foo\nbar\nbaz\n"), "bar\n", "target.txt", "sha256:test")
	if len(locations) != 1 || locations[0].StartLine != 2 || locations[0].EndLine != 2 {
		t.Fatalf("expected exact whole-line match, got %+v", locations)
	}
}

func TestFindTextOccurrencesDetectsOverlappingRepeatedRanges(t *testing.T) {
	locations := findTextOccurrences([]byte("a\na\na\n"), "a\na\n", "target.txt", "sha256:test")
	if len(locations) != 2 {
		t.Fatalf("expected overlapping repeated ranges to be detected, got %+v", locations)
	}
	if locations[0].StartLine != 1 || locations[0].EndLine != 2 || locations[1].StartLine != 2 || locations[1].EndLine != 3 {
		t.Fatalf("unexpected overlapping locations: %+v", locations)
	}
}

func projectGoldenResults(results []AnchorResult) []goldenAnchorResult {
	projected := make([]goldenAnchorResult, 0, len(results))
	for _, result := range results {
		item := goldenAnchorResult{
			ID:            result.Anchor.ID,
			Status:        result.Status,
			BlocksClosure: result.BlocksClosure,
		}
		if result.To != nil {
			item.ToPath = result.To.Path
			item.ToStartLine = result.To.StartLine
			item.ToEndLine = result.To.EndLine
		}
		for _, candidate := range result.Candidates {
			item.Candidates = append(item.Candidates, candidate.Path+":"+strconv.Itoa(candidate.StartLine)+"-"+strconv.Itoa(candidate.EndLine))
		}
		projected = append(projected, item)
	}
	return projected
}

func marshalIndent(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	return append(body, '\n')
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
