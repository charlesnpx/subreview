package anchor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	KindFile = "file"
	KindHunk = "hunk"
	KindPath = "path"

	StatusUnchanged  = "unchanged"
	StatusMoved      = "moved"
	StatusModified   = "modified"
	StatusDeleted    = "deleted"
	StatusAmbiguous  = "ambiguous"
	StatusUnresolved = "unresolved"
)

type MigrateOptions struct {
	StateDir    string
	FromKind    string
	ToKind      string
	Anchors     []Anchor
	AnchorPath  string
	WriteLedger bool
}

type MigrateResult struct {
	SchemaVersion   int              `json:"schema_version"`
	State           string           `json:"state"`
	Repo            string           `json:"repo"`
	FromKind        string           `json:"from_kind"`
	ToKind          string           `json:"to_kind"`
	FromSnapshot    string           `json:"from_snapshot"`
	ToSnapshot      string           `json:"to_snapshot"`
	Diff            state.ObjectRef  `json:"diff"`
	Patch           state.ObjectRef  `json:"patch"`
	AnchorManifest  state.ObjectRef  `json:"anchor_manifest"`
	Migration       state.ObjectRef  `json:"migration"`
	Results         []AnchorResult   `json:"results"`
	ClosureBlockers []ClosureBlocker `json:"closure_blockers"`
	EventID         string           `json:"event_id,omitempty"`
}

type AnchorManifest struct {
	SchemaVersion int      `json:"schema_version"`
	Anchors       []Anchor `json:"anchors"`
}

type Anchor struct {
	SchemaVersion int    `json:"schema_version,omitempty"`
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	Text          string `json:"text,omitempty"`
}

type AnchorRef struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type AnchorResult struct {
	Anchor        Anchor           `json:"anchor"`
	Status        string           `json:"status"`
	From          AnchorLocation   `json:"from"`
	To            *AnchorLocation  `json:"to,omitempty"`
	Candidates    []AnchorLocation `json:"candidates,omitempty"`
	Reason        string           `json:"reason"`
	BlocksClosure bool             `json:"blocks_closure"`
}

type AnchorLocation struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type ClosureBlocker struct {
	AnchorID string `json:"anchor_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

type migrationRecord struct {
	SchemaVersion   int              `json:"schema_version"`
	Repo            string           `json:"repo"`
	FromKind        string           `json:"from_kind"`
	ToKind          string           `json:"to_kind"`
	FromSnapshot    string           `json:"from_snapshot"`
	ToSnapshot      string           `json:"to_snapshot"`
	Diff            state.ObjectRef  `json:"diff"`
	Patch           state.ObjectRef  `json:"patch"`
	AnchorManifest  state.ObjectRef  `json:"anchor_manifest"`
	Results         []AnchorResult   `json:"results"`
	ClosureBlockers []ClosureBlocker `json:"closure_blockers"`
}

type stateBinding struct {
	State string
	Repo  string
}

type snapshotView struct {
	Kind   string
	Digest string
	Tree   string
	Files  map[string]fileView
}

type fileView struct {
	Path   string
	Digest string
	Body   []byte
}

type diffBinding struct {
	Diff         state.ObjectRef
	Patch        state.ObjectRef
	FromSnapshot string
	ToSnapshot   string
}

func Migrate(opts MigrateOptions) (MigrateResult, error) {
	if err := validateKind(opts.FromKind); err != nil {
		return MigrateResult{}, fmt.Errorf("--from: %w", err)
	}
	if err := validateKind(opts.ToKind); err != nil {
		return MigrateResult{}, fmt.Errorf("--to: %w", err)
	}
	if opts.FromKind == opts.ToKind {
		return MigrateResult{}, errors.New("--from and --to must be different snapshot kinds")
	}
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return MigrateResult{}, err
	}
	stateDir := binding.State
	store, err := state.Open(stateDir)
	if err != nil {
		return MigrateResult{}, err
	}
	anchors := append([]Anchor(nil), opts.Anchors...)
	if strings.TrimSpace(opts.AnchorPath) != "" {
		manifest, err := ReadManifest(opts.AnchorPath)
		if err != nil {
			return MigrateResult{}, err
		}
		anchors = manifest.Anchors
	}
	anchors, err = normalizeAnchors(anchors)
	if err != nil {
		return MigrateResult{}, err
	}
	from, err := loadSnapshot(store, stateDir, opts.FromKind, binding.Repo)
	if err != nil {
		return MigrateResult{}, err
	}
	to, err := loadSnapshot(store, stateDir, opts.ToKind, binding.Repo)
	if err != nil {
		return MigrateResult{}, err
	}
	diff, err := latestDiffBinding(store, stateDir, opts.FromKind, opts.ToKind, binding.Repo, from.Digest, to.Digest)
	if err != nil {
		return MigrateResult{}, err
	}
	results := migrateAnchors(anchors, from, to)
	blockers := closureBlockers(results)
	manifestRef, err := store.PutJSON(AnchorManifest{SchemaVersion: SchemaVersion, Anchors: anchors}, "application/vnd.subreview.anchor-manifest+json")
	if err != nil {
		return MigrateResult{}, err
	}
	record := migrationRecord{
		SchemaVersion:   SchemaVersion,
		Repo:            binding.Repo,
		FromKind:        opts.FromKind,
		ToKind:          opts.ToKind,
		FromSnapshot:    from.Digest,
		ToSnapshot:      to.Digest,
		Diff:            diff.Diff,
		Patch:           diff.Patch,
		AnchorManifest:  manifestRef,
		Results:         results,
		ClosureBlockers: blockers,
	}
	migrationRef, err := store.PutJSON(record, "application/vnd.subreview.anchor-migration+json")
	if err != nil {
		return MigrateResult{}, err
	}
	result := MigrateResult{
		SchemaVersion:   SchemaVersion,
		State:           stateDir,
		Repo:            binding.Repo,
		FromKind:        opts.FromKind,
		ToKind:          opts.ToKind,
		FromSnapshot:    from.Digest,
		ToSnapshot:      to.Digest,
		Diff:            diff.Diff,
		Patch:           diff.Patch,
		AnchorManifest:  manifestRef,
		Migration:       migrationRef,
		Results:         results,
		ClosureBlockers: blockers,
	}
	if opts.WriteLedger {
		event, err := state.AppendEvent(stateDir, state.Event{
			Type:          "anchors.migrated",
			ObjectDigests: []string{manifestRef.Digest, migrationRef.Digest},
			Repo:          binding.Repo,
			Details: map[string]string{
				"from_kind":       opts.FromKind,
				"to_kind":         opts.ToKind,
				"from_snapshot":   from.Digest,
				"to_snapshot":     to.Digest,
				"diff":            diff.Diff.Digest,
				"patch":           diff.Patch.Digest,
				"anchor_manifest": manifestRef.Digest,
				"migration":       migrationRef.Digest,
				"blockers":        fmt.Sprintf("%d", len(blockers)),
			},
		})
		if err != nil {
			return MigrateResult{}, err
		}
		result.EventID = event.EventID
	}
	return result, nil
}

func ReadManifest(path string) (AnchorManifest, error) {
	if strings.TrimSpace(path) == "" {
		return AnchorManifest{}, errors.New("anchor manifest path is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return AnchorManifest{}, err
	}
	var manifest AnchorManifest
	manifestErr := decodeStrict(body, &manifest)
	if manifestErr == nil && (manifest.SchemaVersion != 0 || manifest.Anchors != nil) {
		if manifest.SchemaVersion == 0 {
			manifest.SchemaVersion = SchemaVersion
		}
		if manifest.SchemaVersion != SchemaVersion {
			return AnchorManifest{}, fmt.Errorf("unsupported anchor manifest schema_version: %d", manifest.SchemaVersion)
		}
		anchors, err := normalizeAnchors(manifest.Anchors)
		if err != nil {
			return AnchorManifest{}, err
		}
		manifest.Anchors = anchors
		return manifest, nil
	}
	var anchors []Anchor
	if err := decodeStrict(body, &anchors); err != nil {
		return AnchorManifest{}, err
	}
	anchors, err = normalizeAnchors(anchors)
	if err != nil {
		return AnchorManifest{}, err
	}
	return AnchorManifest{SchemaVersion: SchemaVersion, Anchors: anchors}, nil
}

func migrateAnchors(anchors []Anchor, from, to snapshotView) []AnchorResult {
	results := make([]AnchorResult, 0, len(anchors))
	toByDigest := filesByDigest(to.Files)
	for _, anchor := range anchors {
		switch anchor.Kind {
		case KindPath:
			results = append(results, migratePathAnchor(anchor, from, to, toByDigest))
		case KindFile:
			results = append(results, migrateFileAnchor(anchor, from, to, toByDigest))
		case KindHunk:
			results = append(results, migrateHunkAnchor(anchor, from, to))
		default:
			results = append(results, unresolved(anchor, "unsupported anchor kind"))
		}
	}
	return results
}

func migratePathAnchor(anchor Anchor, from, to snapshotView, toByDigest map[string][]fileView) AnchorResult {
	fromFile, ok := from.Files[anchor.Path]
	if !ok {
		return unresolved(anchor, "anchor path is absent from source snapshot")
	}
	fromLoc := AnchorLocation{Path: anchor.Path, Digest: fromFile.Digest}
	if toFile, ok := to.Files[anchor.Path]; ok {
		return AnchorResult{Anchor: anchor, Status: StatusUnchanged, From: fromLoc, To: ptr(AnchorLocation{Path: anchor.Path, Digest: toFile.Digest}), Reason: "path exists in target snapshot"}
	}
	matches := locationsForDigest(toByDigest[fromFile.Digest])
	switch len(matches) {
	case 0:
		return AnchorResult{Anchor: anchor, Status: StatusDeleted, From: fromLoc, Reason: "path is absent from target snapshot"}
	case 1:
		return AnchorResult{Anchor: anchor, Status: StatusMoved, From: fromLoc, To: &matches[0], Reason: "path moved to unique file with matching content"}
	default:
		return blocker(AnchorResult{Anchor: anchor, Status: StatusAmbiguous, From: fromLoc, Candidates: matches, Reason: "path content appears at multiple target paths"})
	}
}

func migrateFileAnchor(anchor Anchor, from, to snapshotView, toByDigest map[string][]fileView) AnchorResult {
	fromFile, ok := from.Files[anchor.Path]
	if !ok {
		return unresolved(anchor, "anchor file is absent from source snapshot")
	}
	fromLoc := AnchorLocation{Path: anchor.Path, Digest: fromFile.Digest}
	if toFile, ok := to.Files[anchor.Path]; ok {
		status := StatusUnchanged
		reason := "file content is unchanged"
		if toFile.Digest != fromFile.Digest {
			status = StatusModified
			reason = "file exists at the same path with modified content"
		}
		return AnchorResult{Anchor: anchor, Status: status, From: fromLoc, To: ptr(AnchorLocation{Path: anchor.Path, Digest: toFile.Digest}), Reason: reason}
	}
	matches := locationsForDigest(toByDigest[fromFile.Digest])
	switch len(matches) {
	case 0:
		return AnchorResult{Anchor: anchor, Status: StatusDeleted, From: fromLoc, Reason: "file is absent from target snapshot"}
	case 1:
		return AnchorResult{Anchor: anchor, Status: StatusMoved, From: fromLoc, To: &matches[0], Reason: "file moved to unique path with matching content"}
	default:
		return blocker(AnchorResult{Anchor: anchor, Status: StatusAmbiguous, From: fromLoc, Candidates: matches, Reason: "file content appears at multiple target paths"})
	}
}

func migrateHunkAnchor(anchor Anchor, from, to snapshotView) AnchorResult {
	fromFile, ok := from.Files[anchor.Path]
	if !ok {
		return unresolved(anchor, "anchor hunk path is absent from source snapshot")
	}
	fromText, err := anchorText(anchor, fromFile.Body)
	fromLoc := AnchorLocation{Path: anchor.Path, StartLine: anchor.StartLine, EndLine: anchor.EndLine, Digest: fromFile.Digest}
	if err != nil {
		result := unresolved(anchor, err.Error())
		result.From = fromLoc
		return result
	}
	samePath, samePathExists := to.Files[anchor.Path]
	if samePathExists {
		occurrences := findTextOccurrences(samePath.Body, fromText, anchor.Path, samePath.Digest)
		switch len(occurrences) {
		case 0:
			status := StatusDeleted
			reason := "hunk text is absent from target file"
			if hunkAppearsModified(fromText, samePath.Body) {
				status = StatusModified
				reason = "target file still contains related hunk text but not an exact match"
			}
			return AnchorResult{Anchor: anchor, Status: status, From: fromLoc, To: ptr(AnchorLocation{Path: anchor.Path, Digest: samePath.Digest}), Reason: reason}
		case 1:
			status := StatusMoved
			reason := "hunk moved within the same file"
			if occurrences[0].StartLine == anchor.StartLine && occurrences[0].EndLine == anchor.EndLine {
				status = StatusUnchanged
				reason = "hunk text remains at the same location"
			}
			return AnchorResult{Anchor: anchor, Status: status, From: fromLoc, To: &occurrences[0], Reason: reason}
		default:
			return blocker(AnchorResult{Anchor: anchor, Status: StatusAmbiguous, From: fromLoc, Candidates: occurrences, Reason: "hunk text appears multiple times in target file"})
		}
	}
	allMatches := []AnchorLocation{}
	for _, file := range sortedFiles(to.Files) {
		allMatches = append(allMatches, findTextOccurrences(file.Body, fromText, file.Path, file.Digest)...)
	}
	switch len(allMatches) {
	case 0:
		return AnchorResult{Anchor: anchor, Status: StatusDeleted, From: fromLoc, Reason: "hunk path and text are absent from target snapshot"}
	case 1:
		return AnchorResult{Anchor: anchor, Status: StatusMoved, From: fromLoc, To: &allMatches[0], Reason: "hunk moved to unique target path"}
	default:
		return blocker(AnchorResult{Anchor: anchor, Status: StatusAmbiguous, From: fromLoc, Candidates: allMatches, Reason: "hunk text appears at multiple target paths"})
	}
}

func closureBlockers(results []AnchorResult) []ClosureBlocker {
	blockers := []ClosureBlocker{}
	for _, result := range results {
		if result.BlocksClosure {
			blockers = append(blockers, ClosureBlocker{AnchorID: result.Anchor.ID, Status: result.Status, Reason: result.Reason})
		}
	}
	return blockers
}

func anchorText(anchor Anchor, body []byte) (string, error) {
	if anchor.Text != "" {
		expected, err := textFromLineRange(body, anchor.StartLine, anchor.EndLine)
		if err != nil {
			return "", err
		}
		if expected != anchor.Text {
			return "", errors.New("anchor text does not match source snapshot")
		}
		return anchor.Text, nil
	}
	return textFromLineRange(body, anchor.StartLine, anchor.EndLine)
}

func textFromLineRange(body []byte, start, end int) (string, error) {
	if start <= 0 || end <= 0 || start > end {
		return "", errors.New("hunk anchor requires a valid start_line and end_line")
	}
	lines := splitLines(body)
	if start > len(lines) || end > len(lines) {
		return "", errors.New("hunk anchor line range is outside source snapshot")
	}
	return strings.Join(lines[start-1:end], ""), nil
}

func splitLines(body []byte) []string {
	if len(body) == 0 {
		return []string{}
	}
	raw := strings.SplitAfter(string(body), "\n")
	if raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	return raw
}

func findTextOccurrences(body []byte, text, path, digest string) []AnchorLocation {
	if text == "" {
		return nil
	}
	content := string(body)
	locations := []AnchorLocation{}
	offset := 0
	for {
		index := strings.Index(content[offset:], text)
		if index < 0 {
			break
		}
		absolute := offset + index
		start := 1 + strings.Count(content[:absolute], "\n")
		end := start + textLineSpan(text) - 1
		locations = append(locations, AnchorLocation{Path: path, StartLine: start, EndLine: end, Digest: digest})
		offset = absolute + len(text)
	}
	return locations
}

func textLineSpan(text string) int {
	if text == "" {
		return 0
	}
	count := strings.Count(text, "\n")
	if strings.HasSuffix(text, "\n") {
		if count == 0 {
			return 1
		}
		return count
	}
	return count + 1
}

func hunkAppearsModified(fromText string, body []byte) bool {
	target := string(body)
	for _, line := range strings.Split(fromText, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(target, line) {
			return true
		}
	}
	return false
}

func normalizeAnchors(anchors []Anchor) ([]Anchor, error) {
	normalized := make([]Anchor, len(anchors))
	ids := map[string]struct{}{}
	for i, anchor := range anchors {
		if anchor.SchemaVersion != 0 && anchor.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("unsupported anchor schema_version for %s: %d", anchor.ID, anchor.SchemaVersion)
		}
		anchor.SchemaVersion = SchemaVersion
		anchor.ID = strings.TrimSpace(anchor.ID)
		anchor.Kind = strings.TrimSpace(anchor.Kind)
		if anchor.ID == "" {
			anchor.ID = fmt.Sprintf("anchor_%d", i+1)
		}
		if _, ok := ids[anchor.ID]; ok {
			return nil, fmt.Errorf("duplicate anchor id: %s", anchor.ID)
		}
		ids[anchor.ID] = struct{}{}
		if err := validateAnchor(anchor); err != nil {
			return nil, err
		}
		normalized[i] = anchor
	}
	return normalized, nil
}

func validateAnchor(anchor Anchor) error {
	if _, err := cleanRepoPath(anchor.Path); err != nil {
		return err
	}
	switch anchor.Kind {
	case KindFile, KindPath:
		return nil
	case KindHunk:
		if anchor.StartLine <= 0 || anchor.EndLine <= 0 || anchor.StartLine > anchor.EndLine {
			return fmt.Errorf("hunk anchor %s requires a valid start_line and end_line", anchor.ID)
		}
		return nil
	default:
		return fmt.Errorf("unsupported anchor kind: %s", anchor.Kind)
	}
}

func loadSnapshot(store state.Store, stateDir, kind, repo string) (snapshotView, error) {
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		return snapshotView{}, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Details["kind"] != kind {
			continue
		}
		if event.Repo != repo {
			return snapshotView{}, fmt.Errorf("malformed snapshot.captured event for kind %s: repo mismatch", kind)
		}
		snapshotDigest := event.Details["snapshot"]
		treeDigest := event.Details["tree"]
		if strings.TrimSpace(snapshotDigest) == "" || strings.TrimSpace(treeDigest) == "" {
			return snapshotView{}, fmt.Errorf("malformed snapshot.captured event for kind %s", kind)
		}
		if len(event.ObjectDigests) != 2 || !containsDigest(event.ObjectDigests, snapshotDigest) || !containsDigest(event.ObjectDigests, treeDigest) {
			return snapshotView{}, fmt.Errorf("malformed snapshot.captured event for kind %s: object_digests must contain only snapshot and tree", kind)
		}
		recordBody, err := store.Read(snapshotDigest)
		if err != nil {
			return snapshotView{}, err
		}
		var record snapshot.SnapshotRecord
		if err := decodeStrict(recordBody, &record); err != nil {
			return snapshotView{}, err
		}
		if record.SchemaVersion != snapshot.SchemaVersion || record.Kind != kind || record.Repo != repo || record.TreeDigest != treeDigest {
			return snapshotView{}, fmt.Errorf("snapshot record does not match event for kind %s", kind)
		}
		if record.TreeDigest != record.Tree.Digest {
			return snapshotView{}, fmt.Errorf("snapshot record tree digest mismatch for kind %s", kind)
		}
		if !record.Reconstructable {
			return snapshotView{}, fmt.Errorf("snapshot record is not reconstructable for kind %s", kind)
		}
		treeBody, err := store.Read(record.TreeDigest)
		if err != nil {
			return snapshotView{}, err
		}
		var tree snapshot.TreeManifest
		if err := decodeStrict(treeBody, &tree); err != nil {
			return snapshotView{}, err
		}
		if tree.SchemaVersion != snapshot.SchemaVersion {
			return snapshotView{}, fmt.Errorf("unsupported snapshot tree schema_version for kind %s: %d", kind, tree.SchemaVersion)
		}
		if len(tree.Entries) != record.EntryCount {
			return snapshotView{}, fmt.Errorf("snapshot tree entry count mismatch for kind %s: %d != %d", kind, len(tree.Entries), record.EntryCount)
		}
		files := map[string]fileView{}
		for _, entry := range tree.Entries {
			path, err := cleanRepoPath(entry.Path)
			if err != nil {
				return snapshotView{}, err
			}
			if entry.Mode != "100644" && entry.Mode != "100755" {
				return snapshotView{}, fmt.Errorf("unsupported snapshot tree entry mode for %s: %s", path, entry.Mode)
			}
			if strings.TrimSpace(entry.Digest) == "" {
				return snapshotView{}, fmt.Errorf("snapshot tree entry missing digest: %s", path)
			}
			if entry.Size < 0 {
				return snapshotView{}, fmt.Errorf("snapshot tree entry has negative size: %s", path)
			}
			if _, exists := files[path]; exists {
				return snapshotView{}, fmt.Errorf("duplicate snapshot path: %s", path)
			}
			body, err := store.Read(entry.Digest)
			if err != nil {
				return snapshotView{}, err
			}
			files[path] = fileView{Path: path, Digest: entry.Digest, Body: body}
		}
		return snapshotView{Kind: kind, Digest: snapshotDigest, Tree: treeDigest, Files: files}, nil
	}
	return snapshotView{}, fmt.Errorf("snapshot kind is not captured in state: %s", kind)
}

func latestDiffBinding(store state.Store, stateDir, fromKind, toKind, repo, fromSnapshot, toSnapshot string) (diffBinding, error) {
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		return diffBinding{}, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "diff.created" || event.Details["from_kind"] != fromKind || event.Details["to_kind"] != toKind {
			continue
		}
		if event.Repo != repo {
			return diffBinding{}, fmt.Errorf("malformed diff.created event for %s->%s: repo mismatch", fromKind, toKind)
		}
		if event.Details["from_snapshot"] != fromSnapshot || event.Details["to_snapshot"] != toSnapshot {
			return diffBinding{}, fmt.Errorf("latest diff.created event for %s->%s does not match latest snapshots", fromKind, toKind)
		}
		diffDigest := event.Details["diff"]
		patchDigest := event.Details["patch"]
		if len(event.ObjectDigests) != 2 || !containsDigest(event.ObjectDigests, diffDigest) || !containsDigest(event.ObjectDigests, patchDigest) {
			return diffBinding{}, fmt.Errorf("malformed diff.created event for %s->%s: object_digests must contain only diff and patch", fromKind, toKind)
		}
		diffBody, err := store.Read(diffDigest)
		if err != nil {
			return diffBinding{}, err
		}
		patchBody, err := store.Read(patchDigest)
		if err != nil {
			return diffBinding{}, err
		}
		var record snapshot.DiffRecord
		if err := decodeStrict(diffBody, &record); err != nil {
			return diffBinding{}, err
		}
		if record.SchemaVersion != snapshot.SchemaVersion || record.FromKind != fromKind || record.ToKind != toKind || record.FromSnapshot != fromSnapshot || record.ToSnapshot != toSnapshot || record.Patch.Digest != patchDigest {
			return diffBinding{}, fmt.Errorf("diff record does not match event for %s->%s", fromKind, toKind)
		}
		diffRef := state.ObjectRef{Digest: diffDigest, MediaType: "application/vnd.subreview.diff+json", Size: int64(len(diffBody)), Path: objectPathBestEffort(stateDir, diffDigest)}
		patchRef := state.ObjectRef{Digest: patchDigest, MediaType: "text/x-diff; charset=utf-8", Size: int64(len(patchBody)), Path: objectPathBestEffort(stateDir, patchDigest)}
		return diffBinding{Diff: diffRef, Patch: patchRef, FromSnapshot: fromSnapshot, ToSnapshot: toSnapshot}, nil
	}
	return diffBinding{}, fmt.Errorf("diff %s->%s is not captured in state", fromKind, toKind)
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

func validateKind(kind string) error {
	switch kind {
	case "base", "proposal", "final":
		return nil
	default:
		return fmt.Errorf("invalid snapshot kind: %s", kind)
	}
}

func filesByDigest(files map[string]fileView) map[string][]fileView {
	byDigest := map[string][]fileView{}
	for _, file := range files {
		byDigest[file.Digest] = append(byDigest[file.Digest], file)
	}
	for digest := range byDigest {
		sort.Slice(byDigest[digest], func(i, j int) bool { return byDigest[digest][i].Path < byDigest[digest][j].Path })
	}
	return byDigest
}

func locationsForDigest(files []fileView) []AnchorLocation {
	locations := make([]AnchorLocation, 0, len(files))
	for _, file := range files {
		locations = append(locations, AnchorLocation{Path: file.Path, Digest: file.Digest})
	}
	return locations
}

func sortedFiles(files map[string]fileView) []fileView {
	values := make([]fileView, 0, len(files))
	for _, file := range files {
		values = append(values, file)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Path < values[j].Path })
	return values
}

func blocker(result AnchorResult) AnchorResult {
	result.BlocksClosure = true
	return result
}

func unresolved(anchor Anchor, reason string) AnchorResult {
	return blocker(AnchorResult{Anchor: anchor, Status: StatusUnresolved, From: AnchorLocation{Path: anchor.Path, StartLine: anchor.StartLine, EndLine: anchor.EndLine}, Reason: reason})
}

func ptr(location AnchorLocation) *AnchorLocation {
	return &location
}

func containsDigest(values []string, digest string) bool {
	for _, value := range values {
		if value == digest {
			return true
		}
	}
	return false
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
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	if clean != slash {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	return clean, nil
}

func objectPathBestEffort(stateDir, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return ""
	}
	return filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest)
}

func decodeStrict(body []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
