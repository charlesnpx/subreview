package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

var validKinds = map[string]struct{}{
	"base":     {},
	"proposal": {},
	"final":    {},
}

type CaptureOptions struct {
	StateDir string
	RepoPath string
	Kind     string
	Ref      string
}

type RestoreOptions struct {
	StateDir string
	Kind     string
	Output   string
}

type DiffOptions struct {
	StateDir string
	FromKind string
	ToKind   string
}

type CaptureResult struct {
	SchemaVersion   int             `json:"schema_version"`
	State           string          `json:"state"`
	Repo            string          `json:"repo"`
	Kind            string          `json:"kind"`
	Snapshot        state.ObjectRef `json:"snapshot"`
	Tree            state.ObjectRef `json:"tree"`
	TreeDigest      string          `json:"tree_digest"`
	GitTreeSHA      string          `json:"git_tree_sha,omitempty"`
	CommitSHA       string          `json:"commit_sha,omitempty"`
	HeadCommitSHA   string          `json:"head_commit_sha,omitempty"`
	Dirty           bool            `json:"dirty"`
	EntryCount      int             `json:"entry_count"`
	Reconstructable bool            `json:"reconstructable"`
	EventID         string          `json:"event_id"`
}

type RestoreResult struct {
	SchemaVersion  int    `json:"schema_version"`
	State          string `json:"state"`
	Kind           string `json:"kind"`
	Output         string `json:"output"`
	SnapshotDigest string `json:"snapshot_digest"`
	RestoredFiles  int    `json:"restored_files"`
}

type DiffResult struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	FromKind      string          `json:"from_kind"`
	ToKind        string          `json:"to_kind"`
	FromSnapshot  string          `json:"from_snapshot"`
	ToSnapshot    string          `json:"to_snapshot"`
	Diff          state.ObjectRef `json:"diff"`
	Patch         state.ObjectRef `json:"patch"`
	HasChanges    bool            `json:"has_changes"`
	EventID       string          `json:"event_id"`
}

type SnapshotRecord struct {
	SchemaVersion   int                `json:"schema_version"`
	Kind            string             `json:"kind"`
	Repo            string             `json:"repo"`
	Source          string             `json:"source"`
	Ref             string             `json:"ref,omitempty"`
	CommitSHA       string             `json:"commit_sha,omitempty"`
	HeadCommitSHA   string             `json:"head_commit_sha,omitempty"`
	GitTreeSHA      string             `json:"git_tree_sha,omitempty"`
	TreeDigest      string             `json:"tree_digest"`
	Tree            state.ObjectRef    `json:"tree"`
	Dirty           bool               `json:"dirty"`
	EntryCount      int                `json:"entry_count"`
	Reconstructable bool               `json:"reconstructable"`
	Provenance      SnapshotProvenance `json:"provenance"`
}

type SnapshotProvenance struct {
	CaptureMode   string `json:"capture_mode"`
	CommitPresent bool   `json:"commit_present"`
	Dirty         bool   `json:"dirty"`
}

type TreeManifest struct {
	SchemaVersion int         `json:"schema_version"`
	Entries       []TreeEntry `json:"entries"`
}

type TreeEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type DiffRecord struct {
	SchemaVersion int             `json:"schema_version"`
	FromKind      string          `json:"from_kind"`
	ToKind        string          `json:"to_kind"`
	FromSnapshot  string          `json:"from_snapshot"`
	ToSnapshot    string          `json:"to_snapshot"`
	Patch         state.ObjectRef `json:"patch"`
	HasChanges    bool            `json:"has_changes"`
}

type stateBinding struct {
	State string
	Repo  string
}

type snapshotBinding struct {
	Digest  string
	Kind    string
	Tree    string
	Objects []string
}

type verifiedEntry struct {
	Entry TreeEntry
	Body  []byte
}

func Capture(opts CaptureOptions) (CaptureResult, error) {
	if err := validateKind(opts.Kind); err != nil {
		return CaptureResult{}, err
	}
	stateDir, repo, err := boundStateAndRepo(opts.StateDir, opts.RepoPath)
	if err != nil {
		return CaptureResult{}, err
	}
	if err := rejectStateInsideRepo(stateDir, repo); err != nil {
		return CaptureResult{}, err
	}
	store, err := state.Open(stateDir)
	if err != nil {
		return CaptureResult{}, err
	}
	git, err := gitInfo(repo)
	if err != nil {
		return CaptureResult{}, err
	}
	var entries []TreeEntry
	record := SnapshotRecord{
		SchemaVersion: SchemaVersion,
		Kind:          opts.Kind,
		Repo:          repo,
		HeadCommitSHA: git.HeadCommitSHA,
	}
	if strings.TrimSpace(opts.Ref) != "" {
		record.Source = "git_ref"
		record.Ref = opts.Ref
		record.Provenance.CaptureMode = "git_ref"
		record.GitTreeSHA, err = gitTreeSHA(repo, opts.Ref)
		if err != nil {
			return CaptureResult{}, err
		}
		record.CommitSHA = gitCommitSHA(repo, opts.Ref)
		entries, err = captureGitTree(store, repo, record.GitTreeSHA)
		if err != nil {
			return CaptureResult{}, err
		}
	} else {
		record.Source = "working_tree"
		record.Provenance.CaptureMode = "working_tree"
		record.Dirty = git.Dirty
		record.Provenance.Dirty = git.Dirty
		if !git.Dirty && git.HeadCommitSHA != "" {
			record.CommitSHA = git.HeadCommitSHA
			record.GitTreeSHA, _ = gitTreeSHA(repo, "HEAD")
		}
		entries, err = captureWorkingTree(store, repo)
		if err != nil {
			return CaptureResult{}, err
		}
	}
	record.Provenance.CommitPresent = record.CommitSHA != ""
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	tree, err := store.PutJSON(TreeManifest{SchemaVersion: SchemaVersion, Entries: entries}, "application/vnd.subreview.snapshot-tree+json")
	if err != nil {
		return CaptureResult{}, err
	}
	record.Tree = tree
	record.TreeDigest = tree.Digest
	record.EntryCount = len(entries)
	record.Reconstructable = true
	snapshotRef, err := store.PutJSON(record, "application/vnd.subreview.snapshot+json")
	if err != nil {
		return CaptureResult{}, err
	}
	objectDigests := snapshotObjectDigests(snapshotRef.Digest, tree.Digest, entries)
	event, err := state.AppendEvent(stateDir, state.Event{
		Type:          "snapshot.captured",
		ObjectDigests: objectDigests,
		Repo:          repo,
		Details: map[string]string{
			"kind":            opts.Kind,
			"snapshot":        snapshotRef.Digest,
			"tree":            tree.Digest,
			"source":          record.Source,
			"commit_sha":      record.CommitSHA,
			"head_commit_sha": record.HeadCommitSHA,
			"git_tree_sha":    record.GitTreeSHA,
			"dirty":           fmt.Sprintf("%t", record.Dirty),
			"reconstructable": "true",
		},
	})
	if err != nil {
		return CaptureResult{}, err
	}
	return CaptureResult{
		SchemaVersion:   SchemaVersion,
		State:           stateDir,
		Repo:            repo,
		Kind:            opts.Kind,
		Snapshot:        snapshotRef,
		Tree:            tree,
		TreeDigest:      tree.Digest,
		GitTreeSHA:      record.GitTreeSHA,
		CommitSHA:       record.CommitSHA,
		HeadCommitSHA:   record.HeadCommitSHA,
		Dirty:           record.Dirty,
		EntryCount:      len(entries),
		Reconstructable: true,
		EventID:         event.EventID,
	}, nil
}

func Restore(opts RestoreOptions) (RestoreResult, error) {
	if err := validateKind(opts.Kind); err != nil {
		return RestoreResult{}, err
	}
	if strings.TrimSpace(opts.Output) == "" {
		return RestoreResult{}, errors.New("--output is required")
	}
	stateInfo, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return RestoreResult{}, err
	}
	stateDir := stateInfo.State
	output, err := filepath.Abs(opts.Output)
	if err != nil {
		return RestoreResult{}, err
	}
	store, err := state.Open(stateDir)
	if err != nil {
		return RestoreResult{}, err
	}
	binding, err := latestSnapshotBinding(stateDir, opts.Kind)
	if err != nil {
		return RestoreResult{}, err
	}
	record, entries, err := readSnapshot(store, binding, opts.Kind)
	if err != nil {
		return RestoreResult{}, err
	}
	if !record.Reconstructable {
		return RestoreResult{}, fmt.Errorf("snapshot is not reconstructable: %s", binding.Digest)
	}
	verified, err := verifyEntries(store, entries)
	if err != nil {
		return RestoreResult{}, err
	}
	if err := ensureEmptyOutputDir(output); err != nil {
		return RestoreResult{}, err
	}
	if err := writeVerifiedEntries(verified, output); err != nil {
		return RestoreResult{}, err
	}
	return RestoreResult{
		SchemaVersion:  SchemaVersion,
		State:          stateDir,
		Kind:           opts.Kind,
		Output:         output,
		SnapshotDigest: binding.Digest,
		RestoredFiles:  len(entries),
	}, nil
}

func CreateDiff(opts DiffOptions) (DiffResult, error) {
	if err := validateKind(opts.FromKind); err != nil {
		return DiffResult{}, fmt.Errorf("--from: %w", err)
	}
	if err := validateKind(opts.ToKind); err != nil {
		return DiffResult{}, fmt.Errorf("--to: %w", err)
	}
	if opts.FromKind == opts.ToKind {
		return DiffResult{}, errors.New("--from and --to must be different snapshot kinds")
	}
	stateInfo, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return DiffResult{}, err
	}
	stateDir := stateInfo.State
	repo := stateInfo.Repo
	store, err := state.Open(stateDir)
	if err != nil {
		return DiffResult{}, err
	}
	fromBinding, err := latestSnapshotBinding(stateDir, opts.FromKind)
	if err != nil {
		return DiffResult{}, err
	}
	toBinding, err := latestSnapshotBinding(stateDir, opts.ToKind)
	if err != nil {
		return DiffResult{}, err
	}
	fromRecord, fromEntries, err := readSnapshot(store, fromBinding, opts.FromKind)
	if err != nil {
		return DiffResult{}, err
	}
	toRecord, toEntries, err := readSnapshot(store, toBinding, opts.ToKind)
	if err != nil {
		return DiffResult{}, err
	}
	if !fromRecord.Reconstructable || !toRecord.Reconstructable {
		return DiffResult{}, errors.New("both snapshots must be reconstructable")
	}
	tmp, err := os.MkdirTemp("", "subreview-diff-*")
	if err != nil {
		return DiffResult{}, err
	}
	defer os.RemoveAll(tmp)
	fromDir := filepath.Join(tmp, "from")
	toDir := filepath.Join(tmp, "to")
	if err := os.Mkdir(fromDir, 0o755); err != nil {
		return DiffResult{}, err
	}
	if err := os.Mkdir(toDir, 0o755); err != nil {
		return DiffResult{}, err
	}
	if err := restoreEntries(store, fromEntries, fromDir); err != nil {
		return DiffResult{}, err
	}
	if err := restoreEntries(store, toEntries, toDir); err != nil {
		return DiffResult{}, err
	}
	patch, err := gitNoIndexDiff(tmp)
	if err != nil {
		return DiffResult{}, err
	}
	patchRef, err := store.PutBytes(patch, "text/x-diff; charset=utf-8")
	if err != nil {
		return DiffResult{}, err
	}
	diffRecord := DiffRecord{
		SchemaVersion: SchemaVersion,
		FromKind:      opts.FromKind,
		ToKind:        opts.ToKind,
		FromSnapshot:  fromBinding.Digest,
		ToSnapshot:    toBinding.Digest,
		Patch:         patchRef,
		HasChanges:    len(patch) > 0,
	}
	diffRef, err := store.PutJSON(diffRecord, "application/vnd.subreview.diff+json")
	if err != nil {
		return DiffResult{}, err
	}
	event, err := state.AppendEvent(stateDir, state.Event{
		Type:          "diff.created",
		ObjectDigests: []string{diffRef.Digest, patchRef.Digest},
		Repo:          repo,
		Details: map[string]string{
			"from_kind":     opts.FromKind,
			"to_kind":       opts.ToKind,
			"from_snapshot": fromBinding.Digest,
			"to_snapshot":   toBinding.Digest,
			"diff":          diffRef.Digest,
			"patch":         patchRef.Digest,
			"has_changes":   fmt.Sprintf("%t", diffRecord.HasChanges),
		},
	})
	if err != nil {
		return DiffResult{}, err
	}
	return DiffResult{
		SchemaVersion: SchemaVersion,
		State:         stateDir,
		FromKind:      opts.FromKind,
		ToKind:        opts.ToKind,
		FromSnapshot:  fromBinding.Digest,
		ToSnapshot:    toBinding.Digest,
		Diff:          diffRef,
		Patch:         patchRef,
		HasChanges:    diffRecord.HasChanges,
		EventID:       event.EventID,
	}, nil
}

func boundStateAndRepo(stateDir, repoPath string) (string, string, error) {
	binding, err := stateBindingFromState(stateDir)
	if err != nil {
		return "", "", err
	}
	repo, err := explicitRepoPath(repoPath)
	if err != nil {
		return "", "", err
	}
	if repo != binding.Repo {
		return "", "", fmt.Errorf("repo does not match initialized state: %s != %s", repo, binding.Repo)
	}
	return binding.State, repo, nil
}

func stateBindingFromState(stateDir string) (stateBinding, error) {
	root, err := state.ResolveStateDir(stateDir)
	if err != nil {
		return stateBinding{}, err
	}
	if result := state.Validate(root); !result.OK {
		return stateBinding{}, stateValidationError(result)
	}
	events, err := state.ReadEvents(root)
	if err != nil {
		return stateBinding{}, err
	}
	if len(events) == 0 || events[0].Type != "state.initialized" {
		return stateBinding{}, errors.New("state first event is not state.initialized")
	}
	return stateBinding{State: root, Repo: events[0].Repo}, nil
}

func stateValidationError(result state.ValidationResult) error {
	if len(result.Errors) == 0 {
		return fmt.Errorf("state validation failed: %s", result.State)
	}
	first := result.Errors[0]
	return fmt.Errorf("state validation failed: %s: %s: %s", result.State, first.Code, first.Message)
}

func explicitRepoPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--repo is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("repo path is not a directory: %s", abs)
	}
	if _, err := runGit(abs, "rev-parse", "--is-inside-work-tree"); err != nil {
		return "", fmt.Errorf("repo path is not a git work tree: %s", abs)
	}
	return abs, nil
}

func rejectStateInsideRepo(stateDir, repo string) error {
	repoReal, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return err
	}
	stateReal, err := filepath.EvalSymlinks(stateDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(repoReal, stateReal)
	if err != nil {
		return err
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)) {
		return fmt.Errorf("state directory must be outside repo for snapshot capture: %s", stateDir)
	}
	return nil
}

type repoGitInfo struct {
	HeadCommitSHA string
	Dirty         bool
}

func gitInfo(repo string) (repoGitInfo, error) {
	head := gitCommitSHA(repo, "HEAD")
	status, err := runGit(repo, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil {
		return repoGitInfo{}, err
	}
	return repoGitInfo{HeadCommitSHA: head, Dirty: strings.TrimSpace(string(status)) != ""}, nil
}

func gitCommitSHA(repo, ref string) string {
	out, err := runGit(repo, "rev-parse", "--verify", ref+"^{commit}")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func gitTreeSHA(repo, ref string) (string, error) {
	out, err := runGit(repo, "rev-parse", "--verify", ref+"^{tree}")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func captureGitTree(store state.Store, repo, treeSHA string) ([]TreeEntry, error) {
	out, err := runGit(repo, "ls-tree", "-r", "-z", treeSHA)
	if err != nil {
		return nil, err
	}
	records := bytes.Split(out, []byte{0})
	entries := make([]TreeEntry, 0, len(records))
	for _, raw := range records {
		if len(raw) == 0 {
			continue
		}
		meta, path, ok := bytes.Cut(raw, []byte{'\t'})
		if !ok {
			return nil, fmt.Errorf("unexpected git ls-tree record: %q", raw)
		}
		fields := strings.Fields(string(meta))
		if len(fields) != 3 {
			return nil, fmt.Errorf("unexpected git ls-tree metadata: %q", meta)
		}
		mode, typ, objectID := fields[0], fields[1], fields[2]
		if typ != "blob" || (mode != "100644" && mode != "100755") {
			return nil, fmt.Errorf("unsupported git tree entry %s %s %s", mode, typ, path)
		}
		rel, err := cleanRepoPath(string(path))
		if err != nil {
			return nil, err
		}
		body, err := runGit(repo, "cat-file", "-p", objectID)
		if err != nil {
			return nil, err
		}
		ref, err := store.PutBytes(body, "application/octet-stream")
		if err != nil {
			return nil, err
		}
		entries = append(entries, TreeEntry{Path: rel, Mode: mode, Digest: ref.Digest, Size: ref.Size})
	}
	return entries, nil
}

func captureWorkingTree(store state.Store, repo string) ([]TreeEntry, error) {
	indexModes, err := gitIndexModes(repo)
	if err != nil {
		return nil, err
	}
	out, err := runGit(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	rawPaths := bytes.Split(out, []byte{0})
	entries := make([]TreeEntry, 0, len(rawPaths))
	for _, raw := range rawPaths {
		if len(raw) == 0 {
			continue
		}
		rel, err := cleanRepoPath(string(raw))
		if err != nil {
			return nil, err
		}
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		if mode := indexModes[rel]; mode != "" {
			if mode == "160000" {
				return nil, fmt.Errorf("unsupported working tree gitlink entry: %s", rel)
			}
			if mode != "100644" && mode != "100755" {
				return nil, fmt.Errorf("unsupported working tree index mode %s: %s", mode, rel)
			}
		}
		path := filepath.Join(repo, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if info.IsDir() {
			return nil, fmt.Errorf("unsupported working tree directory entry, possible gitlink/submodule: %s", rel)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("unsupported working tree entry: %s", rel)
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		ref, err := store.PutBytes(body, "application/octet-stream")
		if err != nil {
			return nil, err
		}
		mode := "100644"
		if info.Mode()&0o111 != 0 {
			mode = "100755"
		}
		entries = append(entries, TreeEntry{Path: rel, Mode: mode, Digest: ref.Digest, Size: ref.Size})
	}
	return entries, nil
}

func gitIndexModes(repo string) (map[string]string, error) {
	out, err := runGit(repo, "ls-files", "-s", "-z")
	if err != nil {
		return nil, err
	}
	modes := map[string]string{}
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) == 0 {
			continue
		}
		meta, path, ok := bytes.Cut(raw, []byte{'\t'})
		if !ok {
			return nil, fmt.Errorf("unexpected git ls-files record: %q", raw)
		}
		fields := strings.Fields(string(meta))
		if len(fields) < 3 {
			return nil, fmt.Errorf("unexpected git ls-files metadata: %q", meta)
		}
		rel, err := cleanRepoPath(string(path))
		if err != nil {
			return nil, err
		}
		modes[rel] = fields[0]
	}
	return modes, nil
}

func latestSnapshotBinding(stateDir, kind string) (snapshotBinding, error) {
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		return snapshotBinding{}, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Details["kind"] != kind {
			continue
		}
		digest := event.Details["snapshot"]
		tree := event.Details["tree"]
		if strings.TrimSpace(digest) == "" || strings.TrimSpace(tree) == "" {
			return snapshotBinding{}, fmt.Errorf("malformed snapshot.captured event for kind %s", kind)
		}
		if len(event.ObjectDigests) < 2 || !containsDigest(event.ObjectDigests, digest) || !containsDigest(event.ObjectDigests, tree) {
			return snapshotBinding{}, fmt.Errorf("malformed snapshot.captured event for kind %s: object_digests must include snapshot and tree", kind)
		}
		return snapshotBinding{Digest: digest, Kind: kind, Tree: tree, Objects: append([]string(nil), event.ObjectDigests...)}, nil
	}
	return snapshotBinding{}, fmt.Errorf("snapshot kind is not captured in state: %s", kind)
}

func snapshotObjectDigests(snapshotDigest, treeDigest string, entries []TreeEntry) []string {
	digests := []string{snapshotDigest, treeDigest}
	for _, entry := range entries {
		digests = append(digests, entry.Digest)
	}
	return digests
}

func containsDigest(values []string, digest string) bool {
	for _, value := range values {
		if value == digest {
			return true
		}
	}
	return false
}

func readSnapshot(store state.Store, binding snapshotBinding, kind string) (SnapshotRecord, []TreeEntry, error) {
	body, err := store.Read(binding.Digest)
	if err != nil {
		return SnapshotRecord{}, nil, err
	}
	var record SnapshotRecord
	if err := decodeStrict(body, &record); err != nil {
		return SnapshotRecord{}, nil, err
	}
	if err := validateSnapshotRecord(record, kind); err != nil {
		return SnapshotRecord{}, nil, err
	}
	if record.TreeDigest != binding.Tree {
		return SnapshotRecord{}, nil, fmt.Errorf("snapshot.captured tree digest mismatch for kind %s", kind)
	}
	treeBody, err := store.Read(record.TreeDigest)
	if err != nil {
		return SnapshotRecord{}, nil, err
	}
	var tree TreeManifest
	if err := decodeStrict(treeBody, &tree); err != nil {
		return SnapshotRecord{}, nil, err
	}
	if tree.SchemaVersion != SchemaVersion {
		return SnapshotRecord{}, nil, fmt.Errorf("unsupported tree schema_version: %d", tree.SchemaVersion)
	}
	if len(tree.Entries) != record.EntryCount {
		return SnapshotRecord{}, nil, fmt.Errorf("snapshot tree entry count mismatch: %d != %d", len(tree.Entries), record.EntryCount)
	}
	if err := validateTreeTopology(tree.Entries); err != nil {
		return SnapshotRecord{}, nil, err
	}
	for _, entry := range tree.Entries {
		if err := validateTreeEntry(entry); err != nil {
			return SnapshotRecord{}, nil, err
		}
		if !containsDigest(binding.Objects, entry.Digest) {
			return SnapshotRecord{}, nil, fmt.Errorf("snapshot.captured event for kind %s does not pin tree entry digest %s", kind, entry.Digest)
		}
	}
	return record, tree.Entries, nil
}

func validateSnapshotRecord(record SnapshotRecord, kind string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported snapshot schema_version: %d", record.SchemaVersion)
	}
	if record.Kind != kind {
		return fmt.Errorf("snapshot kind mismatch: %s != %s", record.Kind, kind)
	}
	if strings.TrimSpace(record.Repo) == "" || strings.TrimSpace(record.TreeDigest) == "" || strings.TrimSpace(record.Tree.Digest) == "" {
		return errors.New("snapshot record is missing required reconstruction fields")
	}
	if record.TreeDigest != record.Tree.Digest {
		return errors.New("snapshot tree digest mismatch")
	}
	if !record.Reconstructable {
		return errors.New("snapshot record is not reconstructable")
	}
	if record.EntryCount < 0 {
		return errors.New("snapshot entry_count must not be negative")
	}
	return nil
}

func validateTreeTopology(entries []TreeEntry) error {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		rel, err := cleanRepoPath(entry.Path)
		if err != nil {
			return err
		}
		if _, ok := seen[rel]; ok {
			return fmt.Errorf("duplicate tree entry path: %s", rel)
		}
		for existing := range seen {
			if strings.HasPrefix(existing, rel+"/") {
				return fmt.Errorf("tree entry path conflicts with file descendant: %s", rel)
			}
		}
		seen[rel] = struct{}{}
		parts := strings.Split(rel, "/")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], "/")
			if _, ok := seen[parent]; ok {
				return fmt.Errorf("tree entry path conflicts with file parent: %s", rel)
			}
		}
	}
	return nil
}

func validateTreeEntry(entry TreeEntry) error {
	if _, err := cleanRepoPath(entry.Path); err != nil {
		return err
	}
	if entry.Mode != "100644" && entry.Mode != "100755" {
		return fmt.Errorf("unsupported tree entry mode: %s", entry.Mode)
	}
	if strings.TrimSpace(entry.Digest) == "" {
		return fmt.Errorf("tree entry missing digest: %s", entry.Path)
	}
	if entry.Size < 0 {
		return fmt.Errorf("tree entry has negative size: %s", entry.Path)
	}
	return nil
}

func restoreEntries(store state.Store, entries []TreeEntry, output string) error {
	verified, err := verifyEntries(store, entries)
	if err != nil {
		return err
	}
	return writeVerifiedEntries(verified, output)
}

func verifyEntries(store state.Store, entries []TreeEntry) ([]verifiedEntry, error) {
	verified := make([]verifiedEntry, 0, len(entries))
	for _, entry := range entries {
		rel, err := cleanRepoPath(entry.Path)
		if err != nil {
			return nil, err
		}
		body, err := store.Read(entry.Digest)
		if err != nil {
			return nil, err
		}
		if int64(len(body)) != entry.Size {
			return nil, fmt.Errorf("tree entry size mismatch for %s", rel)
		}
		verified = append(verified, verifiedEntry{Entry: entry, Body: body})
	}
	return verified, nil
}

func writeVerifiedEntries(verified []verifiedEntry, output string) error {
	for _, item := range verified {
		entry := item.Entry
		body := item.Body
		rel, err := cleanRepoPath(entry.Path)
		if err != nil {
			return err
		}
		path := filepath.Join(output, filepath.FromSlash(rel))
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if entry.Mode == "100755" {
			mode = 0o755
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		n, writeErr := f.Write(body)
		if writeErr == nil && n != len(body) {
			writeErr = errors.New("short write")
		}
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func ensureEmptyOutputDir(path string) error {
	if err := rejectSymlinkedNearestOutputParent(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return os.MkdirAll(path, 0o755)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output path must not be a symlink: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("output path is not a directory: %s", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory must be empty: %s", path)
	}
	return nil
}

func rejectSymlinkedNearestOutputParent(path string) error {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				next := filepath.Dir(dir)
				if next == dir || next == "." || next == "" {
					return err
				}
				dir = next
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output parent path must not be a symlink: %s", dir)
		}
		if !info.IsDir() {
			return fmt.Errorf("output parent path is not a directory: %s", dir)
		}
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		realDir, err := filepath.EvalSymlinks(absDir)
		if err != nil {
			return err
		}
		if !sameOutputParentPath(absDir, realDir) {
			return fmt.Errorf("output parent path must not contain a symlink: %s", dir)
		}
		return nil
	}
}

func sameOutputParentPath(absDir, realDir string) bool {
	absDir = filepath.Clean(absDir)
	realDir = filepath.Clean(realDir)
	if absDir == realDir {
		return true
	}
	if runtime.GOOS == "darwin" && realDir == filepath.Clean("/private"+absDir) {
		return true
	}
	return false
}

func gitNoIndexDiff(workdir string) ([]byte, error) {
	cmd := exec.Command("git", "diff", "--no-index", "--binary", "--no-prefix", "from", "to")
	cmd.Dir = workdir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return out, nil
	}
	return nil, fmt.Errorf("git diff --no-index failed: %w\n%s", err, out)
}

func cleanRepoPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty repository path")
	}
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	slash := filepath.ToSlash(path)
	clean := filepath.Clean(slash)
	clean = filepath.ToSlash(clean)
	if clean != slash || clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
		return "", fmt.Errorf("invalid repository-relative path: %s", path)
	}
	if clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", fmt.Errorf("repository metadata path cannot be captured: %s", path)
	}
	return clean, nil
}

func validateKind(kind string) error {
	if _, ok := validKinds[kind]; !ok {
		return fmt.Errorf("kind must be base, proposal, or final: %s", kind)
	}
	return nil
}

func runGit(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("git %s failed: %w\n%s", strings.Join(args, " "), err, exitErr.Stderr)
		}
		return nil, err
	}
	return out, nil
}

func decodeStrict(body []byte, dest any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("multiple JSON values")
}
