package state

import (
	"bufio"
	"bytes"
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

const (
	SchemaVersion           = 1
	maxLedgerLineBytes      = 1 << 20
	maxLedgerScanTokenBytes = maxLedgerLineBytes + 1
)

var (
	ledgerLockTimeout      = 10 * time.Second
	ledgerLockPollInterval = 10 * time.Millisecond
)

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

type manifestInfo struct {
	Digest string
	Repo   string
}

type ledgerInfo struct {
	Referenced []string
	FirstEvent *Event
	FirstLine  int
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
	if err := ensureStateSubdir(root, "objects", "sha256"); err != nil {
		return InitResult{}, err
	}
	if err := ensureStateSubdir(root, "manifests"); err != nil {
		return InitResult{}, err
	}
	manifestPath := filepath.Join(lay.manifestsDir, "state.json")
	if fileExists(manifestPath) {
		return InitResult{}, fmt.Errorf("state already initialized: %s", root)
	}
	if err := prepareLedgerForInit(root, lay.ledgerPath); err != nil {
		return InitResult{}, err
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
	if err := writeJSONFileExclusive(manifestPath, map[string]any{
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
		if rollbackErr := rollbackManifestIfEmptyLedger(manifestPath, lay.ledgerPath); rollbackErr != nil {
			return InitResult{}, fmt.Errorf("initial ledger event failed: %w; rollback failed: %v", err, rollbackErr)
		}
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
	if err := s.ensureObject(body, digest); err != nil {
		return ObjectRef{}, err
	}
	path, err := objectPath(s.root, digest)
	if err != nil {
		return ObjectRef{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ObjectRef{}, err
	}
	return ObjectRef{Digest: digest, MediaType: mediaType, Size: int64(len(body)), Path: abs}, nil
}

func writeFileExclusive(path string, body []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "tmp-"+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)
	chmodErr := f.Chmod(mode)
	n, writeErr := f.Write(body)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if chmodErr != nil {
		return chmodErr
	}
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func checkRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file: %s", path)
	}
	return nil
}

func verifyExistingObject(path, digest string) error {
	if err := checkRegularFile(path); err != nil {
		return err
	}
	existing, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if digestBytes(existing) != digest {
		return fmt.Errorf("existing object digest mismatch: %s", digest)
	}
	return nil
}

func (s Store) ensureObject(body []byte, digest string) error {
	path, err := objectPath(s.root, digest)
	if err != nil {
		return err
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if err := ensureStateSubdir(s.root, "objects", "sha256", hexDigest[:2]); err != nil {
		return err
	}
	if err := ensureStateSubdir(s.root, "objects", "tmp"); err != nil {
		return err
	}
	return writeObjectAtomic(filepath.Join(s.root, "objects", "tmp"), path, body, digest)
}

func (s Store) Read(digest string) ([]byte, error) {
	path, err := objectPath(s.root, digest)
	if err != nil {
		return nil, err
	}
	if err := checkRegularFile(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("object missing: %s", digest)
		}
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

func withLedgerLock(root string, fn func() (Event, error)) (Event, error) {
	lockPath := filepath.Join(root, "ledger.lock")
	deadline := time.Now().Add(ledgerLockTimeout)
	for {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, writeErr := fmt.Fprintf(f, "%d\n", os.Getpid())
			closeErr := f.Close()
			if writeErr != nil {
				_ = os.Remove(lockPath)
				return Event{}, writeErr
			}
			if closeErr != nil {
				_ = os.Remove(lockPath)
				return Event{}, closeErr
			}
			defer os.Remove(lockPath)
			return fn()
		}
		if !os.IsExist(err) {
			return Event{}, err
		}
		if time.Now().After(deadline) {
			return Event{}, fmt.Errorf("timed out waiting for ledger lock: %s", lockPath)
		}
		time.Sleep(ledgerLockPollInterval)
	}
}

func appendLedgerLine(path string, event Event) (Event, error) {
	line, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if len(line) > maxLedgerLineBytes {
		return Event{}, fmt.Errorf("ledger event exceeds %d byte line limit", maxLedgerLineBytes)
	}
	var f *os.File
	needsSeparator := false
	created := false
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return Event{}, fmt.Errorf("path is not a regular file: %s", path)
		}
		if info.Size() > 0 {
			needsSeparator, err = ledgerNeedsSeparator(path, info.Size())
			if err != nil {
				return Event{}, err
			}
		}
		f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return Event{}, err
		}
	} else if os.IsNotExist(err) {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return Event{}, err
		}
		created = true
	} else {
		return Event{}, err
	}
	body := append([]byte(nil), line...)
	body = append(body, '\n')
	if needsSeparator {
		body = append([]byte{'\n'}, body...)
	}
	n, writeErr := f.Write(body)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if writeErr == nil {
		syncErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return Event{}, writeErr
	}
	if syncErr != nil {
		return Event{}, syncErr
	}
	if closeErr != nil {
		return Event{}, closeErr
	}
	if created {
		if err := syncDir(filepath.Dir(path)); err != nil {
			return Event{}, err
		}
	}
	return event, nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func ledgerNeedsSeparator(path string, size int64) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	var last [1]byte
	_, readErr := f.ReadAt(last[:], size-1)
	closeErr := f.Close()
	if readErr != nil {
		return false, readErr
	}
	if closeErr != nil {
		return false, closeErr
	}
	return last[0] != '\n', nil
}

func AppendEvent(stateDir string, event Event) (Event, error) {
	root, err := explicitStateDir(stateDir)
	if err != nil {
		return Event{}, err
	}
	lay := stateLayout(root)
	event.SchemaVersion = SchemaVersion
	event.ObjectDigests = append([]string(nil), event.ObjectDigests...)
	sort.Strings(event.ObjectDigests)
	if event.Time == "" {
		event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := time.Parse(time.RFC3339Nano, event.Time); err != nil {
		return Event{}, fmt.Errorf("invalid event time: %w", err)
	}
	if event.Type == "" {
		return Event{}, errors.New("event type is required")
	}
	store := Store{root: root}
	for _, digest := range event.ObjectDigests {
		if err := validateDigest(digest); err != nil {
			return Event{}, err
		}
		if _, err := store.Read(digest); err != nil {
			return Event{}, err
		}
	}
	if err := ensureStateSubdir(root); err != nil {
		return Event{}, err
	}
	return withLedgerLock(root, func() (Event, error) {
		prior, err := lastEventID(lay.ledgerPath)
		if err != nil {
			return Event{}, err
		}
		event.PriorEventID = prior
		event.EventID = eventID(event)
		return appendLedgerLine(lay.ledgerPath, event)
	})
}

func Validate(stateDir string) ValidationResult {
	stateLabel, err := filepath.Abs(stateDir)
	if err != nil {
		stateLabel = stateDir
	}
	result := ValidationResult{SchemaVersion: SchemaVersion, State: stateLabel, OK: true}
	root, err := explicitStateDir(stateDir)
	if err != nil {
		result.addError("invalid_state_path", stateLabel, 0, err.Error())
		return result.finalize()
	}
	result.State = root
	lay := stateLayout(root)
	if err := requireExistingStateSubdir(lay.root, "objects", "sha256"); err != nil {
		result.addError("invalid_objects_dir", lay.objectsDir, 0, err.Error())
	}
	if err := requireExistingStateSubdir(lay.root, "manifests"); err != nil {
		result.addError("invalid_manifests_dir", lay.manifestsDir, 0, err.Error())
	}
	if !fileExists(lay.ledgerPath) {
		result.addError("missing_ledger", lay.ledgerPath, 0, "ledger.jsonl is missing")
		return result.finalize()
	}
	manifestPath := filepath.Join(lay.manifestsDir, "state.json")
	var referenced []string
	manifest := manifestInfo{}
	if !fileExists(manifestPath) {
		result.addError("missing_manifest", manifestPath, 0, "manifests/state.json is missing")
	} else {
		manifest = validateManifestFile(root, manifestPath, &result)
		if manifest.Digest != "" {
			referenced = append(referenced, manifest.Digest)
		}
	}
	result.ObjectCount = validateObjectFiles(lay, &result)
	ledger := validateLedger(lay, &result)
	referenced = append(referenced, ledger.Referenced...)
	validateInitialLedgerEvent(lay.ledgerPath, manifest, ledger, &result)
	if result.EventCount == 0 {
		result.addError("empty_ledger", lay.ledgerPath, 0, "ledger has no events")
	}
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
		if err := checkRegularFile(path); err != nil {
			result.addError("object_not_regular", path, 0, err.Error())
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

func validateLedger(lay layout, result *ValidationResult) ledgerInfo {
	if err := checkRegularFile(lay.ledgerPath); err != nil {
		result.addError("ledger_not_regular", lay.ledgerPath, 0, err.Error())
		return ledgerInfo{}
	}
	f, err := os.Open(lay.ledgerPath)
	if err != nil {
		result.addError("ledger_open_failed", lay.ledgerPath, 0, err.Error())
		return ledgerInfo{}
	}
	defer f.Close()
	info := ledgerInfo{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLedgerScanTokenBytes)
	lineNo := 0
	prior := ""
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := decodeStrictJSON([]byte(line), &event); err != nil {
			result.addError("malformed_event", lay.ledgerPath, lineNo, err.Error())
			continue
		}
		result.EventCount++
		if info.FirstEvent == nil {
			first := event
			info.FirstEvent = &first
			info.FirstLine = lineNo
		}
		validateLedgerEvent(event, prior, func(code, message string) {
			result.addError(code, lay.ledgerPath, lineNo, message)
		}, func(digest string) {
			info.Referenced = append(info.Referenced, digest)
		})
		prior = event.EventID
	}
	if err := scanner.Err(); err != nil {
		result.addError("ledger_read_failed", lay.ledgerPath, lineNo, err.Error())
	}
	return info
}

func validateLedgerEvent(event Event, prior string, addIssue func(string, string), addReferenced func(string)) {
	if event.SchemaVersion != SchemaVersion {
		addIssue("unsupported_event_schema", fmt.Sprintf("event schema_version=%d", event.SchemaVersion))
	}
	if event.Type == "" {
		addIssue("missing_event_type", "event type is required")
	}
	if event.Time == "" {
		addIssue("missing_event_time", "event time is required")
	} else if _, err := time.Parse(time.RFC3339Nano, event.Time); err != nil {
		addIssue("invalid_event_time", err.Error())
	}
	if event.PriorEventID != prior {
		addIssue("prior_event_mismatch", fmt.Sprintf("expected prior_event_id %q, got %q", prior, event.PriorEventID))
	}
	if expected := eventID(event); event.EventID != expected {
		addIssue("event_id_mismatch", fmt.Sprintf("expected %s, got %s", expected, event.EventID))
	}
	for _, digest := range event.ObjectDigests {
		if err := validateDigest(digest); err != nil {
			addIssue("invalid_object_digest", err.Error())
			continue
		}
		if addReferenced != nil {
			addReferenced(digest)
		}
	}
}

func validateManifestFile(root, path string, result *ValidationResult) manifestInfo {
	if err := checkRegularFile(path); err != nil {
		result.addError("manifest_not_regular", path, 0, err.Error())
		return manifestInfo{}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		result.addError("manifest_read_failed", path, 0, err.Error())
		return manifestInfo{}
	}
	var manifest struct {
		SchemaVersion int       `json:"schema_version"`
		Manifest      ObjectRef `json:"manifest"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		result.addError("malformed_manifest", path, 0, err.Error())
		return manifestInfo{}
	}
	if manifest.SchemaVersion != SchemaVersion {
		result.addError("unsupported_manifest_schema", path, 0, fmt.Sprintf("manifest schema_version=%d", manifest.SchemaVersion))
	}
	if manifest.Manifest.Digest == "" {
		result.addError("missing_manifest_digest", path, 0, "manifest object digest is required")
		return manifestInfo{}
	}
	if err := validateDigest(manifest.Manifest.Digest); err != nil {
		result.addError("invalid_manifest_digest", path, 0, err.Error())
		return manifestInfo{}
	}
	return manifestInfo{Digest: manifest.Manifest.Digest, Repo: validateManifestObject(root, manifest.Manifest.Digest, result)}
}

func validateManifestObject(root, digest string, result *ValidationResult) string {
	path := objectPathBestEffort(root, digest)
	body, err := Store{root: root}.Read(digest)
	if err != nil {
		result.addError("object_read_failed", path, 0, err.Error())
		return ""
	}
	var manifest struct {
		SchemaVersion int    `json:"schema_version"`
		Repo          string `json:"repo"`
		State         string `json:"state"`
		CreatedAt     string `json:"created_at"`
		Layout        struct {
			ObjectsDir   string `json:"objects_dir"`
			ManifestsDir string `json:"manifests_dir"`
			LedgerPath   string `json:"ledger_path"`
		} `json:"layout"`
	}
	if err := json.Unmarshal(body, &manifest); err != nil {
		result.addError("malformed_manifest_object", path, 0, err.Error())
		return ""
	}
	if manifest.SchemaVersion != SchemaVersion {
		result.addError("unsupported_manifest_object_schema", path, 0, fmt.Sprintf("manifest object schema_version=%d", manifest.SchemaVersion))
	}
	if manifest.Repo == "" {
		result.addError("missing_manifest_repo", path, 0, "manifest object repo is required")
	}
	if manifest.State != root {
		result.addError("manifest_state_mismatch", path, 0, fmt.Sprintf("expected state %q, got %q", root, manifest.State))
	}
	if manifest.CreatedAt == "" {
		result.addError("missing_manifest_created_at", path, 0, "manifest object created_at is required")
	} else if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		result.addError("invalid_manifest_created_at", path, 0, err.Error())
	}
	if manifest.Layout.ObjectsDir != "objects/sha256" ||
		manifest.Layout.ManifestsDir != "manifests" ||
		manifest.Layout.LedgerPath != "ledger.jsonl" {
		result.addError("manifest_layout_mismatch", path, 0, "manifest object layout must match state layout")
	}
	return manifest.Repo
}

func validateInitialLedgerEvent(path string, manifest manifestInfo, ledger ledgerInfo, result *ValidationResult) {
	if manifest.Digest == "" || ledger.FirstEvent == nil {
		return
	}
	event := ledger.FirstEvent
	line := ledger.FirstLine
	if event.Type != "state.initialized" {
		result.addError("initial_event_type_mismatch", path, line, fmt.Sprintf("expected state.initialized, got %q", event.Type))
	}
	if len(event.ObjectDigests) != 1 || event.ObjectDigests[0] != manifest.Digest {
		result.addError("initial_manifest_mismatch", path, line, fmt.Sprintf("expected initial object_digests to contain only %s", manifest.Digest))
	}
	if event.Details == nil || event.Details["manifest"] != manifest.Digest {
		result.addError("initial_manifest_detail_mismatch", path, line, fmt.Sprintf("expected details.manifest %s", manifest.Digest))
	}
	if manifest.Repo != "" && event.Repo != manifest.Repo {
		result.addError("initial_repo_mismatch", path, line, fmt.Sprintf("expected repo %q, got %q", manifest.Repo, event.Repo))
	}
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
	clean := filepath.Clean(abs)
	if hasHiddenComponent(clean) {
		return "", fmt.Errorf("state path must not include hidden directories: %s", abs)
	}
	resolvedParent, err := resolveExistingParent(clean)
	if err != nil {
		return "", err
	}
	if hasHiddenComponent(resolvedParent) {
		return "", fmt.Errorf("state path must not resolve through hidden directories: %s", abs)
	}
	return clean, nil
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

func decodeStrictJSON(body []byte, dest any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func lastEventID(path string) (string, error) {
	if err := checkRegularFile(path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLedgerScanTokenBytes)
	last := ""
	lineNo := 0
	prior := ""
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event Event
		if err := decodeStrictJSON([]byte(line), &event); err != nil {
			return "", fmt.Errorf("malformed ledger event at line %d: %w", lineNo, err)
		}
		var validationErr error
		validateLedgerEvent(event, prior, func(code, message string) {
			if validationErr == nil {
				validationErr = fmt.Errorf("%s at ledger line %d: %s", code, lineNo, message)
			}
		}, nil)
		if validationErr != nil {
			return "", validationErr
		}
		prior = event.EventID
		last = event.EventID
	}
	return last, scanner.Err()
}

func prepareLedgerForInit(root, path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return syncDir(filepath.Dir(path))
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("ledger path is not a regular file: %s", path)
	}
	if info.Size() > 0 {
		return fmt.Errorf("state already initialized: %s", root)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

func writeObjectAtomic(tmpDir, path string, body []byte, digest string) error {
	if err := verifyExistingObject(path, digest); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(tmpDir, "object-")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)
	chmodErr := f.Chmod(0o644)
	n, writeErr := f.Write(body)
	if writeErr == nil && n != len(body) {
		writeErr = io.ErrShortWrite
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if chmodErr != nil {
		return chmodErr
	}
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return verifyExistingObject(path, digest)
		}
		return err
	}
	return nil
}

func rollbackManifestIfEmptyLedger(manifestPath, ledgerPath string) error {
	info, err := os.Stat(ledgerPath)
	if err == nil && info.Size() != 0 {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func writeJSONFileExclusive(path string, value any) error {
	if err := ensureRealDirPath(filepath.Dir(path)); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return writeFileExclusive(path, body, 0o644)
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

func hasHiddenComponent(path string) bool {
	clean := filepath.Clean(path)
	for _, part := range strings.Split(clean, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func ensureStateSubdir(root string, parts ...string) error {
	if err := ensureStateRoot(root); err != nil {
		return err
	}
	path := filepath.Clean(root)
	for _, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("state layout path is a symlink: %s", path)
			}
			if !info.IsDir() {
				return fmt.Errorf("state layout path is not a directory: %s", path)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.Mkdir(path, 0o755); err != nil {
			if os.IsExist(err) {
				if err := requireExistingRealDir(path); err != nil {
					return err
				}
				continue
			}
			return err
		}
	}
	return nil
}

func ensureStateRoot(root string) error {
	clean := filepath.Clean(root)
	info, err := os.Lstat(clean)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state root is a symlink: %s", clean)
		}
		if !info.IsDir() {
			return fmt.Errorf("state root is not a directory: %s", clean)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(clean)
	if parent != clean {
		if err := ensureRealDirPath(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(clean, 0o755); err != nil {
		if os.IsExist(err) {
			return requireExistingRealDir(clean)
		}
		return err
	}
	return nil
}

func ensureRealDirPath(path string) error {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state layout path is a symlink: %s", clean)
		}
		if !info.IsDir() {
			return fmt.Errorf("state layout path is not a directory: %s", clean)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(clean)
	if parent != clean {
		if err := ensureRealDirPath(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(clean, 0o755); err != nil {
		if os.IsExist(err) {
			return requireExistingRealDir(clean)
		}
		return err
	}
	return nil
}

func requireExistingStateSubdir(root string, parts ...string) error {
	path := filepath.Clean(root)
	if err := requireExistingRealDir(path); err != nil {
		return err
	}
	for _, part := range parts {
		path = filepath.Join(path, part)
		if err := requireExistingRealDir(path); err != nil {
			return err
		}
	}
	return nil
}

func requireExistingRealDir(path string) error {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("directory is missing: %s", clean)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory is a symlink: %s", clean)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", clean)
	}
	return nil
}

func resolveExistingParent(path string) (string, error) {
	current := filepath.Clean(path)
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if current == path && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return "", fmt.Errorf("state path exists and is not a directory: %s", path)
			}
			if current != path && !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				return "", fmt.Errorf("state parent exists and is not a directory: %s", current)
			}
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		next := filepath.Dir(current)
		if next == current {
			return current, nil
		}
		current = next
	}
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
