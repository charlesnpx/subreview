package snapshot

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/state"
)

func TestCaptureRestoreAndDiffCommittedAndUncommittedSnapshots(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	base, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"})
	if err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	if base.CommitSHA == "" || base.GitTreeSHA == "" || base.EntryCount != 1 || !base.Reconstructable {
		t.Fatalf("bad base snapshot: %+v", base)
	}

	writeFile(t, repo, "alpha.txt", "two\n")
	writeFile(t, repo, "new.txt", "new\n")
	proposal, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"})
	if err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if !proposal.Dirty || proposal.CommitSHA != "" || proposal.HeadCommitSHA == "" || proposal.EntryCount != 2 {
		t.Fatalf("bad proposal snapshot: %+v", proposal)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	proposalRecord := readSnapshotRecordForTest(t, store, proposal.Snapshot.Digest)
	if proposalRecord.Provenance.CommitPresent {
		t.Fatalf("dirty proposal should not claim committed snapshot provenance: %+v", proposalRecord.Provenance)
	}

	restoreDir := filepath.Join(root, "restore")
	restored, err := Restore(RestoreOptions{StateDir: stateDir, Kind: "proposal", Output: restoreDir})
	if err != nil {
		t.Fatalf("Restore proposal: %v", err)
	}
	if restored.RestoredFiles != 2 {
		t.Fatalf("unexpected restored file count: %+v", restored)
	}
	if got := readFile(t, restoreDir, "alpha.txt"); got != "two\n" {
		t.Fatalf("restored alpha mismatch: %q", got)
	}
	if got := readFile(t, restoreDir, "new.txt"); got != "new\n" {
		t.Fatalf("restored new mismatch: %q", got)
	}

	diff, err := CreateDiff(DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"})
	if err != nil {
		t.Fatalf("CreateDiff: %v", err)
	}
	if !diff.HasChanges || diff.FromSnapshot != base.Snapshot.Digest || diff.ToSnapshot != proposal.Snapshot.Digest {
		t.Fatalf("bad diff result: %+v", diff)
	}
	patch, err := store.Read(diff.Patch.Digest)
	if err != nil {
		t.Fatalf("Read patch: %v", err)
	}
	for _, want := range []string{"from/alpha.txt", "to/alpha.txt", "+two", "to/new.txt"} {
		if !strings.Contains(string(patch), want) {
			t.Fatalf("patch missing %q:\n%s", want, patch)
		}
	}
	writeFile(t, repo, "alpha.txt", "three\n")
	writeFile(t, repo, "new.txt", "new\n")
	writeFile(t, repo, "done.txt", "done\n")
	final, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"})
	if err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if !final.Dirty || final.CommitSHA != "" || final.EntryCount != 3 || final.Snapshot.Digest == "" {
		t.Fatalf("bad final snapshot: %+v", final)
	}
	finalRecord := readSnapshotRecordForTest(t, store, final.Snapshot.Digest)
	if finalRecord.Provenance.CommitPresent {
		t.Fatalf("dirty final should not claim committed snapshot provenance: %+v", finalRecord.Provenance)
	}
	proposalToFinal, err := CreateDiff(DiffOptions{StateDir: stateDir, FromKind: "proposal", ToKind: "final"})
	if err != nil {
		t.Fatalf("CreateDiff proposal->final: %v", err)
	}
	if !proposalToFinal.HasChanges || proposalToFinal.FromSnapshot != proposal.Snapshot.Digest || proposalToFinal.ToSnapshot != final.Snapshot.Digest {
		t.Fatalf("bad proposal->final diff: %+v", proposalToFinal)
	}
	baseToFinal, err := CreateDiff(DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"})
	if err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if !baseToFinal.HasChanges || baseToFinal.FromSnapshot != base.Snapshot.Digest || baseToFinal.ToSnapshot != final.Snapshot.Digest {
		t.Fatalf("bad base->final diff: %+v", baseToFinal)
	}
	validation := state.Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestCreateDiffFailsWhenSnapshotIsMissing(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	_, err := CreateDiff(DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"})
	if err == nil || !strings.Contains(err.Error(), "proposal") {
		t.Fatalf("expected missing proposal snapshot error, got %v", err)
	}
	restoreDir := filepath.Join(root, "missing-restore")
	_, err = Restore(RestoreOptions{StateDir: stateDir, Kind: "proposal", Output: restoreDir})
	if err == nil || !strings.Contains(err.Error(), "proposal") {
		t.Fatalf("expected missing proposal restore error, got %v", err)
	}
	if _, statErr := os.Stat(restoreDir); !os.IsNotExist(statErr) {
		t.Fatalf("restore should not create output after missing snapshot, stat err=%v", statErr)
	}
}

func TestRestoreRejectsSnapshotEventTreeMismatch(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	captured, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"})
	if err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	otherTree, err := store.PutJSON(TreeManifest{SchemaVersion: SchemaVersion}, "application/vnd.subreview.snapshot-tree+json")
	if err != nil {
		t.Fatalf("PutJSON other tree: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "snapshot.captured",
		ObjectDigests: []string{captured.Snapshot.Digest, otherTree.Digest},
		Repo:          repo,
		Details: map[string]string{
			"kind":     "base",
			"snapshot": captured.Snapshot.Digest,
			"tree":     otherTree.Digest,
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Restore(RestoreOptions{StateDir: stateDir, Kind: "base", Output: filepath.Join(root, "restore")})
	if err == nil || !strings.Contains(err.Error(), "tree digest mismatch") {
		t.Fatalf("expected tree digest mismatch error, got %v", err)
	}
}

func TestRestoreRejectsSnapshotEventMissingPinnedBlobDigest(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	captured, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"})
	if err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "snapshot.captured",
		ObjectDigests: []string{captured.Snapshot.Digest, captured.Tree.Digest},
		Repo:          repo,
		Details: map[string]string{
			"kind":     "base",
			"snapshot": captured.Snapshot.Digest,
			"tree":     captured.Tree.Digest,
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Restore(RestoreOptions{StateDir: stateDir, Kind: "base", Output: filepath.Join(root, "restore")})
	if err == nil || !strings.Contains(err.Error(), "does not pin tree entry digest") {
		t.Fatalf("expected missing pinned blob error, got %v", err)
	}
}

func TestRestoreDoesNotPartiallyWriteWhenBlobIsMissing(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "a.txt", "a\n")
	writeFile(t, repo, "b.txt", "b\n")
	git(t, repo, "add", "a.txt", "b.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	captured, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"})
	if err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	treeBody, err := store.Read(captured.Tree.Digest)
	if err != nil {
		t.Fatalf("read tree: %v", err)
	}
	var tree TreeManifest
	if err := decodeStrict(treeBody, &tree); err != nil {
		t.Fatalf("decode tree: %v", err)
	}
	if len(tree.Entries) != 2 {
		t.Fatalf("bad setup entries=%+v", tree.Entries)
	}
	missingPath := objectPathForTest(stateDir, tree.Entries[1].Digest)
	if err := os.Remove(missingPath); err != nil {
		t.Fatalf("remove object: %v", err)
	}
	validation := state.Validate(stateDir)
	if validation.OK {
		t.Fatalf("state validation should fail after pinned blob removal")
	}
	restoreDir := filepath.Join(root, "restore")
	err = restoreEntries(store, tree.Entries, restoreDir)
	if err == nil {
		t.Fatal("expected missing blob restore failure")
	}
	if _, statErr := os.Stat(filepath.Join(restoreDir, "a.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("restore should not partially write a.txt, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(restoreDir, "b.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("restore should not partially write b.txt, stat err=%v", statErr)
	}
}

func TestCaptureWorkingTreeRejectsGitlinkDirectory(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "seed.txt", "seed\n")
	git(t, repo, "add", "seed.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	head := gitOutput(t, repo, "rev-parse", "HEAD")
	git(t, repo, "update-index", "--add", "--cacheinfo", "160000,"+head+",vendor/lib")
	if err := os.MkdirAll(filepath.Join(repo, "vendor", "lib"), 0o755); err != nil {
		t.Fatalf("mkdir gitlink path: %v", err)
	}
	_, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"})
	if err == nil || !strings.Contains(err.Error(), "unsupported working tree directory entry") {
		t.Fatalf("expected gitlink directory capture error, got %v", err)
	}
}

func TestRestoreRejectsSymlinkedOutputPath(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0o755); err != nil {
		t.Fatalf("mkdir external: %v", err)
	}
	output := filepath.Join(root, "restore-link")
	if err := os.Symlink(external, output); err != nil {
		t.Fatalf("symlink output: %v", err)
	}
	_, err := Restore(RestoreOptions{StateDir: stateDir, Kind: "base", Output: output})
	if err == nil || !strings.Contains(err.Error(), "output path must not be a symlink") {
		t.Fatalf("expected symlink output error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(external, "alpha.txt")); !os.IsNotExist(statErr) {
		t.Fatalf("restore should not write through output symlink, stat err=%v", statErr)
	}
}

func TestRestoreRejectsSymlinkedOutputParent(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	external := filepath.Join(root, "external")
	if err := os.Mkdir(external, 0o755); err != nil {
		t.Fatalf("mkdir external: %v", err)
	}
	linkParent := filepath.Join(root, "link-parent")
	if err := os.Symlink(external, linkParent); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}
	_, err := Restore(RestoreOptions{StateDir: stateDir, Kind: "base", Output: filepath.Join(linkParent, "restore")})
	if err == nil || !strings.Contains(err.Error(), "output parent path must not be a symlink") {
		t.Fatalf("expected symlink parent error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(external, "restore")); !os.IsNotExist(statErr) {
		t.Fatalf("restore should not create output through symlink parent, stat err=%v", statErr)
	}
}

func TestRestoreRejectsMalformedTreeTopologyBeforeWriting(t *testing.T) {
	tests := map[string][]string{
		"duplicate":               {"a.txt", "a.txt"},
		"file_parent_first":       {"a", "a/b.txt"},
		"file_parent_second":      {"a/b.txt", "a"},
		"nested_file_parent_late": {"a/b/c.txt", "a/b"},
		"nul_path":                {"valid.txt", "bad\x00path.txt"},
	}
	for name, paths := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "repo")
			stateDir := filepath.Join(root, "state")
			initGitRepo(t, repo)
			writeFile(t, repo, "seed.txt", "seed\n")
			git(t, repo, "add", "seed.txt")
			git(t, repo, "commit", "-m", "initial")
			if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
				t.Fatalf("Init: %v", err)
			}
			appendMalformedSnapshot(t, stateDir, repo, "base", paths)
			restoreDir := filepath.Join(root, "restore")
			_, err := Restore(RestoreOptions{StateDir: stateDir, Kind: "base", Output: restoreDir})
			if err == nil || !strings.Contains(err.Error(), "tree entry path") && !strings.Contains(err.Error(), "duplicate tree entry") && !strings.Contains(err.Error(), "invalid repository-relative path") {
				t.Fatalf("expected tree topology error, got %v", err)
			}
			if _, statErr := os.Stat(restoreDir); !os.IsNotExist(statErr) {
				t.Fatalf("restore should not create output for malformed topology, stat err=%v", statErr)
			}
		})
	}
}

func TestCaptureRejectsStateInsideRepo(t *testing.T) {
	repo := filepath.Join(t.TempDir(), "repo")
	stateDir := filepath.Join(repo, "subreview-state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", "one\n")
	git(t, repo, "add", "alpha.txt")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err := Capture(CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"})
	if err == nil || !strings.Contains(err.Error(), "outside repo") {
		t.Fatalf("expected state-inside-repo error, got %v", err)
	}
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

func gitOutput(t *testing.T, repo string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
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

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

func readSnapshotRecordForTest(t *testing.T, store state.Store, digest string) SnapshotRecord {
	t.Helper()
	body, err := store.Read(digest)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var record SnapshotRecord
	if err := decodeStrict(body, &record); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	return record
}

func appendMalformedSnapshot(t *testing.T, stateDir, repo, kind string, paths []string) {
	t.Helper()
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	entries := make([]TreeEntry, 0, len(paths))
	for i, path := range paths {
		ref, err := store.PutText(fmt.Sprintf("body-%d\n", i))
		if err != nil {
			t.Fatalf("PutText: %v", err)
		}
		entries = append(entries, TreeEntry{Path: path, Mode: "100644", Digest: ref.Digest, Size: ref.Size})
	}
	tree, err := store.PutJSON(TreeManifest{SchemaVersion: SchemaVersion, Entries: entries}, "application/vnd.subreview.snapshot-tree+json")
	if err != nil {
		t.Fatalf("PutJSON tree: %v", err)
	}
	record := SnapshotRecord{
		SchemaVersion:   SchemaVersion,
		Kind:            kind,
		Repo:            repo,
		Source:          "test",
		TreeDigest:      tree.Digest,
		Tree:            tree,
		EntryCount:      len(entries),
		Reconstructable: true,
		Provenance:      SnapshotProvenance{CaptureMode: "test"},
	}
	snapshotRef, err := store.PutJSON(record, "application/vnd.subreview.snapshot+json")
	if err != nil {
		t.Fatalf("PutJSON snapshot: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "snapshot.captured",
		ObjectDigests: snapshotObjectDigests(snapshotRef.Digest, tree.Digest, entries),
		Repo:          repo,
		Details: map[string]string{
			"kind":     kind,
			"snapshot": snapshotRef.Digest,
			"tree":     tree.Digest,
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
}

func objectPathForTest(stateDir, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest)
}
