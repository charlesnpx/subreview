package state

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = 1

type InitOptions struct {
	StateDir string
	RepoPath string
	Now      time.Time
}

type InitResult struct {
	SchemaVersion int          `json:"schema_version"`
	State         string       `json:"state"`
	Repo          string       `json:"repo"`
	Layout        LayoutResult `json:"layout"`
	Manifest      ObjectRef    `json:"manifest"`
	EventID       string       `json:"event_id"`
}

type LayoutResult struct {
	ObjectsDir   string `json:"objects_dir"`
	ManifestsDir string `json:"manifests_dir"`
	LedgerPath   string `json:"ledger_path"`
}

type ObjectRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
	Path      string `json:"path"`
}

type Event struct {
	SchemaVersion int               `json:"schema_version"`
	EventID       string            `json:"event_id"`
	Time          string            `json:"time"`
	Type          string            `json:"type"`
	PriorEventID  string            `json:"prior_event_id,omitempty"`
	ObjectDigests []string          `json:"object_digests,omitempty"`
	Repo          string            `json:"repo,omitempty"`
	Details       map[string]string `json:"details,omitempty"`
}

type ValidationResult struct {
	SchemaVersion int               `json:"schema_version"`
	State         string            `json:"state"`
	OK            bool              `json:"ok"`
	Errors        []ValidationIssue `json:"errors"`
	Warnings      []ValidationIssue `json:"warnings"`
	EventCount    int               `json:"event_count"`
	ObjectCount   int               `json:"object_count"`
}

type ValidationIssue struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message"`
}

type Store struct {
	root string
}

type layout struct {
	root         string
	objectsDir   string
	manifestsDir string
	ledgerPath   string
}

func Init(opts InitOptions) (InitResult, error) {
	root, err := explicitStateDir(opts.StateDir)
	if err != nil {
		return InitResult{}, err
	}
	repo, err := explicitRepoPath(opts.RepoPath)
	if err != nil {
		return InitResult{}, err
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	lay := stateLayout(root)
	if err := os.MkdirAll(lay.objectsDir, 0o755); err != nil {
		return InitResult{}, err
	}
	if err := os.MkdirAll(lay.manifestsDir, 0o755); err != nil {
		return InitResult{}, err
	}
	if ledgerHasContent(lay.ledgerPath) {
		return InitResult{}, fmt.Errorf("state already initialized: %s", lay.ledgerPath)
	}
	if _, err := os.OpenFile(lay.ledgerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644); err != nil {
		if !os.IsExist(err) {
			return InitResult{}, err
		}
	}
	store := Store{root: root}
	manifestObject := map[string]any{
		"schema_version": SchemaVersion,
		"repo":           repo,
		"state":          root,
		"created_at":     now.Format(time.RFC3339Nano),
		"layout": map[string]string{
			"objects_dir":   "objects/sha256",
			"manifests_dir": "manifests",
			"ledger_path":   "ledger.jsonl",
		},
	}
	manifest, err := store.PutJSON(manifestObject, "application/vnd.subreview.state-manifest+json")
	if err != nil {
		return InitResult{}, err
	}
	manifestPath := filepath.Join(lay.manifestsDir, "state.json")
	if err := writeJSONFile(manifestPath, map[string]any{
		"schema_version": SchemaVersion,
		"manifest":       manifest,
	}); err != nil {
		return InitResult{}, err
	}
	event, err := AppendEvent(root, Event{
		Time:          now.Format(time.RFC3339Nano),
		Type:          "state.initialized",
		ObjectDigests: []string{manifest.Digest},
		Repo:          repo,
		Details: map[string]string{
			"manifest": manifest.Digest,
		},
	})
	if err != nil {
		return InitResult{}, err
	}
	return InitResult{
		SchemaVersion: SchemaVersion,
		State:         root,
		Repo:          repo,
		Layout:        layoutResult(lay),
		Manifest:      manifest,
		EventID:       event.EventID,
	}, nil
}

func Open(root string) (Store, error) {
	stateRoot, err := explicitStateDir(root)
	if err != nil {
		return Store{}, err
	}
	return Store{root: stateRoot}, nil
}

func (s Store) PutJSON(value any, mediaType string) (ObjectRef, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return ObjectRef{}, err
	}
	return s.PutBytes(body, mediaType)
}

func (s Store) PutText(text string) (ObjectRef, error) {
	return s.PutBytes([]byte(text), "text/plain; charset=utf-8")
}

func (s Store) PutBytes(body []byte, mediaType string) (ObjectRef, error) {
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	digest := digestBytes(body)
	path, err := objectPath(s.root, digest)
	if err != nil {
		return ObjectRef{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ObjectRef{}, err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return ObjectRef{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ObjectRef{}, err
	}
	return ObjectRef{Digest: digest, MediaType: mediaType, Size: int64(len(body)), Path: abs}, nil
}

func (s Store) Read(digest string) ([]byte, error) {
	path, err := objectPath(s.root, digest)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("object missing: %s", digest)
		}
		return nil, err
	}
	got := digestBytes(body)
	if got != digest {
		return nil, fmt.Errorf("object digest mismatch: %s != %s", got, digest)
	}
	return body, nil
}

func AppendEvent(stateDir string, event Event) (Event, error) {
	root, err := explicitStateDir(stateDir)
	if err != nil {
		return Event{}, err
	}
	lay := stateLayout(root)
	if err := os.MkdirAll(filepath.Dir(lay.ledgerPath), 0o755); err != nil {
		return Event{}, err
	}
	prior, err := lastEventID(lay.ledgerPath)
	if err != nil {
		return Event{}, err
	}
	event.SchemaVersion = SchemaVersion
	event.PriorEventID = prior
	event.ObjectDigests = append([]string(nil), event.ObjectDigests...)
	sort.Strings(event.ObjectDigests)
	if event.Time == "" {
		event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.Type == "" {
		return Event{}, errors.New("event type is required")
	}
	event.EventID = eventID(event)
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	f, err := os.OpenFile(lay.ledgerPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return Event{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Event{}, err
	}
	return event, nil
}

func Validate(stateDir string) ValidationResult {
	root, err := filepath.Abs(stateDir)
	if err != nil {
		root = stateDir
	}
	result := ValidationResult{SchemaVersion: SchemaVersion, State: root, OK: true}
	lay := stateLayout(root)
	if !dirExists(lay.objectsDir) {
		result.addError("missing_objects_dir", lay.objectsDir, 0, "objects directory is missing")
	}
	if !dirExists(lay.manifestsDir) {
		result.addError("missing_manifests_dir", lay.manifestsDir, 0, "manifests directory is missing")
	}
	if !fileExists(lay.ledgerPath) {
		result.addError("missing_ledger", lay.ledgerPath, 0, "ledger.jsonl is missing")
		return result.finalize()
	}
	result.ObjectCount = validateObjectFiles(lay, &result)
	referenced := validateLedger(lay, &result)
	store := Store{root: root}
	for _, digest := range referenced {
		if _, err := store.Read(digest); err != nil {
			result.addError("object_read_failed", objectPathBestEffort(root, digest), 0, err.Error())
		}
	}
	return result.finalize()
}

func validateObjectFiles(lay layout, result *ValidationResult) int {
	count := 0
	_ = filepath.WalkDir(lay.objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			result.addError("object_walk_failed", path, 0, err.Error())
			return nil
		}
		if d.IsDir() {
			return nil
		}
		count++
		rel, err := filepath.Rel(lay.objectsDir, path)
		if err != nil {
			result.addError("object_path_failed", path, 0, err.Error())
			return nil
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) != 2 || parts[0] != parts[1][:min(2, len(parts[1]))] {
			result.addError("invalid_object_path", path, 0, "object path must be objects/sha256/<prefix>/<sha256>")
			return nil
		}
		wantHex := parts[1]
		if len(wantHex) != 64 || !isHex(wantHex) {
			result.addError("invalid_object_path", path, 0, "object path does not encode a sha256 digest")
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			result.addError("object_read_failed", path, 0, err.Error())
			return nil
		}
		got := strings.TrimPrefix(digestBytes(body), "sha256:")
		if got != wantHex {
			result.addError("object_digest_mismatch", path, 0, fmt.Sprintf("expected sha256:%s, got sha256:%s", wantHex, got))
		}
		return nil
	})
	return count
}

func validateLedger(lay layout, result *ValidationResult) []string {
	f, err := os.Open(lay.ledgerPath)
	if err != nil {
		result.addError("ledger_open_failed", lay.ledgerPath, 0, err.Error())
		return nil
	}
	defer f.Close()
	var referenced []string
	scanner := bufio.NewScanner(f)
	lineNo := 0
	prior := ""
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			result.addError("malformed_event", lay.ledgerPath, lineNo, err.Error())
			continue
		}
		result.EventCount++
		if event.SchemaVersion != SchemaVersion {
			result.addError("unsupported_event_schema", lay.ledgerPath, lineNo, fmt.Sprintf("event schema_version=%d", event.SchemaVersion))
		}
		if event.Type == "" {
			result.addError("missing_event_type", lay.ledgerPath, lineNo, "event type is required")
		}
		if event.PriorEventID != prior {
			result.addError("prior_event_mismatch", lay.ledgerPath, lineNo, fmt.Sprintf("expected prior_event_id %q, got %q", prior, event.PriorEventID))
		}
		if expected := eventID(event); event.EventID != expected {
			result.addError("event_id_mismatch", lay.ledgerPath, lineNo, fmt.Sprintf("expected %s, got %s", expected, event.EventID))
		}
		for _, digest := range event.ObjectDigests {
			if err := validateDigest(digest); err != nil {
				result.addError("invalid_object_digest", lay.ledgerPath, lineNo, err.Error())
				continue
			}
			referenced = append(referenced, digest)
		}
		prior = event.EventID
	}
	if err := scanner.Err(); err != nil {
		result.addError("ledger_read_failed", lay.ledgerPath, lineNo, err.Error())
	}
	return referenced
}

func eventID(event Event) string {
	payload := struct {
		SchemaVersion int               `json:"schema_version"`
		Time          string            `json:"time"`
		Type          string            `json:"type"`
		PriorEventID  string            `json:"prior_event_id,omitempty"`
		ObjectDigests []string          `json:"object_digests,omitempty"`
		Repo          string            `json:"repo,omitempty"`
		Details       map[string]string `json:"details,omitempty"`
	}{
		SchemaVersion: event.SchemaVersion,
		Time:          event.Time,
		Type:          event.Type,
		PriorEventID:  event.PriorEventID,
		ObjectDigests: append([]string(nil), event.ObjectDigests...),
		Repo:          event.Repo,
		Details:       event.Details,
	}
	sort.Strings(payload.ObjectDigests)
	body, _ := json.Marshal(payload)
	sum := sha256.Sum256(body)
	return "evt_" + hex.EncodeToString(sum[:])[:24]
}

func stateLayout(root string) layout {
	return layout{
		root:         root,
		objectsDir:   filepath.Join(root, "objects", "sha256"),
		manifestsDir: filepath.Join(root, "manifests"),
		ledgerPath:   filepath.Join(root, "ledger.jsonl"),
	}
}

func layoutResult(lay layout) LayoutResult {
	return LayoutResult{
		ObjectsDir:   lay.objectsDir,
		ManifestsDir: lay.manifestsDir,
		LedgerPath:   lay.ledgerPath,
	}
}

func explicitStateDir(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--state is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(filepath.Base(abs), ".") {
		return "", fmt.Errorf("state directory must not be hidden: %s", abs)
	}
	return abs, nil
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
	return abs, nil
}

func objectPath(root, digest string) (string, error) {
	if err := validateDigest(digest); err != nil {
		return "", err
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(root, "objects", "sha256", hexDigest[:2], hexDigest), nil
}

func objectPathBestEffort(root, digest string) string {
	if path, err := objectPath(root, digest); err == nil {
		return path
	}
	return filepath.Join(root, "objects", digest)
}

func validateDigest(digest string) error {
	if !strings.HasPrefix(digest, "sha256:") {
		return fmt.Errorf("digest must start with sha256: %s", digest)
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) != 64 || !isHex(hexDigest) {
		return fmt.Errorf("invalid sha256 digest: %s", digest)
	}
	return nil
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func lastEventID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	last := ""
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return "", fmt.Errorf("malformed ledger event at line %d: %w", lineNo, err)
		}
		last = event.EventID
	}
	return last, scanner.Err()
}

func ledgerHasContent(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func writeJSONFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o644)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isHex(value string) bool {
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *ValidationResult) addError(code, path string, line int, message string) {
	r.Errors = append(r.Errors, ValidationIssue{Code: code, Path: path, Line: line, Message: message})
}

func (r ValidationResult) finalize() ValidationResult {
	r.OK = len(r.Errors) == 0
	return r
}

func CopyObject(dst io.Writer, store Store, digest string) error {
	body, err := store.Read(digest)
	if err != nil {
		return err
	}
	_, err = dst.Write(body)
	return err
}
