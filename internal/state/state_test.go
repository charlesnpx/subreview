package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestInitCreatesExplicitStateAndValidates(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "subreview-state")
	result, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if result.SchemaVersion != SchemaVersion || result.State != stateDir || result.Repo != root {
		t.Fatalf("bad init result: %+v", result)
	}
	for _, path := range []string{
		filepath.Join(stateDir, "objects", "sha256"),
		filepath.Join(stateDir, "manifests"),
		filepath.Join(stateDir, "ledger.jsonl"),
		filepath.Join(stateDir, "manifests", "state.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected state path %s: %v", path, err)
		}
	}
	validation := Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
	if validation.EventCount != 1 || validation.ObjectCount != 1 {
		t.Fatalf("unexpected validation counts: %+v", validation)
	}
}

func TestInitRejectsHiddenStateDir(t *testing.T) {
	if _, err := Init(InitOptions{StateDir: filepath.Join(t.TempDir(), ".subreview"), RepoPath: t.TempDir()}); err == nil {
		t.Fatal("expected hidden state directory error")
	}
}

func TestInitRejectsHiddenStateParent(t *testing.T) {
	root := t.TempDir()
	if _, err := Init(InitOptions{StateDir: filepath.Join(root, ".subreview", "state"), RepoPath: root}); err == nil {
		t.Fatal("expected hidden state parent error")
	}
	if _, err := os.Stat(filepath.Join(root, ".subreview")); !os.IsNotExist(err) {
		t.Fatalf("hidden parent should not be created, stat err=%v", err)
	}
}

func TestInitRejectsSymlinkedHiddenStateParent(t *testing.T) {
	root := t.TempDir()
	hidden := filepath.Join(root, ".subreview")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatalf("mkdir hidden parent: %v", err)
	}
	link := filepath.Join(root, "visible-link")
	if err := os.Symlink(hidden, link); err != nil {
		t.Fatalf("symlink hidden parent: %v", err)
	}
	if _, err := Init(InitOptions{StateDir: filepath.Join(link, "state"), RepoPath: root}); err == nil {
		t.Fatal("expected symlinked hidden state parent error")
	}
	if _, err := os.Stat(filepath.Join(hidden, "state")); !os.IsNotExist(err) {
		t.Fatalf("state should not be created through hidden symlink, stat err=%v", err)
	}
}

func TestInitDoesNotOverwriteExistingManifest(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	manifestPath := filepath.Join(stateDir, "manifests", "state.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("mkdir manifest parent: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("sentinel"), 0o644); err != nil {
		t.Fatalf("write manifest sentinel: %v", err)
	}
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root}); err == nil {
		t.Fatal("expected existing manifest to block init")
	}
	body, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest sentinel: %v", err)
	}
	if string(body) != "sentinel" {
		t.Fatalf("manifest was overwritten: %q", body)
	}
}

func TestInitRejectsSymlinkedLayoutDirs(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	hidden := filepath.Join(root, ".objects")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatalf("mkdir hidden target: %v", err)
	}
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state root: %v", err)
	}
	if err := os.Symlink(hidden, filepath.Join(stateDir, "objects")); err != nil {
		t.Fatalf("symlink objects dir: %v", err)
	}
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root}); err == nil {
		t.Fatal("expected symlinked layout directory error")
	}
	if entries, err := os.ReadDir(hidden); err != nil || len(entries) != 0 {
		t.Fatalf("hidden symlink target should remain untouched, entries=%v err=%v", entries, err)
	}
}

func TestInitRejectsInvalidExistingLedgerBeforeWritingManifest(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir state root: %v", err)
	}
	externalLedger := filepath.Join(root, "external-ledger.jsonl")
	if err := os.WriteFile(externalLedger, nil, 0o644); err != nil {
		t.Fatalf("write external ledger: %v", err)
	}
	if err := os.Symlink(externalLedger, filepath.Join(stateDir, "ledger.jsonl")); err != nil {
		t.Fatalf("symlink ledger: %v", err)
	}
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root}); err == nil || !strings.Contains(err.Error(), "ledger path is not a regular file") {
		t.Fatalf("expected invalid ledger path error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "manifests", "state.json")); !os.IsNotExist(err) {
		t.Fatalf("manifest should not be written after ledger preflight failure, stat err=%v", err)
	}
}

func TestValidateRejectsSymlinkedLayoutDirs(t *testing.T) {
	tests := map[string]string{
		"objects":        "invalid_objects_dir",
		"objects_sha256": "invalid_objects_dir",
		"manifests":      "invalid_manifests_dir",
	}
	for name, issueCode := range tests {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			stateDir := filepath.Join(root, "state")
			if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
				t.Fatalf("Init: %v", err)
			}
			var replacePath string
			switch name {
			case "objects":
				replacePath = filepath.Join(stateDir, "objects")
			case "objects_sha256":
				replacePath = filepath.Join(stateDir, "objects", "sha256")
			case "manifests":
				replacePath = filepath.Join(stateDir, "manifests")
			}
			external := filepath.Join(root, "external-"+name)
			if err := os.Rename(replacePath, external); err != nil {
				t.Fatalf("move layout dir: %v", err)
			}
			if err := os.Symlink(external, replacePath); err != nil {
				t.Fatalf("symlink layout dir: %v", err)
			}
			validation := Validate(stateDir)
			if validation.OK {
				t.Fatalf("expected symlinked layout validation failure")
			}
			requireIssue(t, validation, issueCode)
		})
	}
}

func TestValidateRejectsHiddenStateDir(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".subreview-state")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir hidden state dir: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatal("expected hidden state validation failure")
	}
	requireIssue(t, validation, "invalid_state_path")
}

func TestValidateRejectsSymlinkedHiddenStateParent(t *testing.T) {
	root := t.TempDir()
	hidden := filepath.Join(root, ".subreview")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatalf("mkdir hidden parent: %v", err)
	}
	link := filepath.Join(root, "visible-link")
	if err := os.Symlink(hidden, link); err != nil {
		t.Fatalf("symlink hidden parent: %v", err)
	}
	validation := Validate(filepath.Join(link, "state"))
	if validation.OK {
		t.Fatal("expected symlinked hidden state validation failure")
	}
	requireIssue(t, validation, "invalid_state_path")
}

func TestCASRoundTripsAndDetectsDigestMismatch(t *testing.T) {
	store := Store{root: t.TempDir()}
	text, err := store.PutText("hello")
	if err != nil {
		t.Fatalf("PutText: %v", err)
	}
	got, err := store.Read(text.Digest)
	if err != nil {
		t.Fatalf("Read text: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("text mismatch: %q", got)
	}
	obj, err := store.PutJSON(map[string]any{"b": 2, "a": 1}, "application/json")
	if err != nil {
		t.Fatalf("PutJSON: %v", err)
	}
	body, err := store.Read(obj.Digest)
	if err != nil {
		t.Fatalf("Read json: %v", err)
	}
	if string(body) != `{"a":1,"b":2}` {
		t.Fatalf("json should be canonical compact encoding, got %s", body)
	}
	path, err := objectPath(store.root, text.Digest)
	if err != nil {
		t.Fatalf("objectPath: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper object: %v", err)
	}
	if _, err := store.PutText("hello"); err == nil || !strings.Contains(err.Error(), "existing object digest mismatch") {
		t.Fatalf("expected immutable CAS write failure, got %v", err)
	}
	if _, err := store.Read(text.Digest); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestCASRejectsSymlinkObject(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	store := Store{root: stateDir}
	text, err := store.PutText("hello")
	if err != nil {
		t.Fatalf("PutText: %v", err)
	}
	path, err := objectPath(store.root, text.Digest)
	if err != nil {
		t.Fatalf("objectPath: %v", err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write external object: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove object: %v", err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatalf("symlink object: %v", err)
	}
	if _, err := store.Read(text.Digest); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected symlink read rejection, got %v", err)
	}
	if _, err := store.PutText("hello"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected symlink put rejection, got %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatal("expected symlink object validation failure")
	}
	requireIssue(t, validation, "object_not_regular")
}

func TestEnsureStateSubdirToleratesConcurrentCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	errs := make(chan error, 100)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ensureStateSubdir(root, "objects", "sha256", "aa")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("ensureStateSubdir concurrent: %v", err)
		}
	}
	if err := requireExistingRealDir(filepath.Join(root, "objects", "sha256", "aa")); err != nil {
		t.Fatalf("expected shard directory: %v", err)
	}
}

func TestLedgerAppendsPriorEventLinkage(t *testing.T) {
	stateDir := t.TempDir()
	store := Store{root: stateDir}
	obj, err := store.PutText("payload")
	if err != nil {
		t.Fatalf("PutText: %v", err)
	}
	first, err := AppendEvent(stateDir, Event{Time: time.Unix(1, 0).UTC().Format(time.RFC3339Nano), Type: "first", ObjectDigests: []string{obj.Digest}})
	if err != nil {
		t.Fatalf("AppendEvent first: %v", err)
	}
	second, err := AppendEvent(stateDir, Event{Time: time.Unix(2, 0).UTC().Format(time.RFC3339Nano), Type: "second"})
	if err != nil {
		t.Fatalf("AppendEvent second: %v", err)
	}
	if first.EventID == "" || second.EventID == "" || second.PriorEventID != first.EventID {
		t.Fatalf("bad event linkage: first=%+v second=%+v", first, second)
	}
	var events []Event
	body, err := os.ReadFile(filepath.Join(stateDir, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal ledger line: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 2 || events[1].PriorEventID != events[0].EventID {
		t.Fatalf("ledger order mismatch: %+v", events)
	}
}

func TestLedgerAppendPreservesLedgerWithoutTrailingNewline(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ledgerPath := filepath.Join(stateDir, "ledger.jsonl")
	body, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if !strings.HasSuffix(string(body), "\n") {
		t.Fatalf("expected initialized ledger to end with newline")
	}
	if err := os.WriteFile(ledgerPath, []byte(strings.TrimSuffix(string(body), "\n")), 0o644); err != nil {
		t.Fatalf("strip ledger newline: %v", err)
	}
	if _, err := AppendEvent(stateDir, Event{Time: time.Unix(101, 0).UTC().Format(time.RFC3339Nano), Type: "second"}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	validation := Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should validate after appending to no-newline ledger: %+v", validation.Errors)
	}
	body, err = os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read appended ledger: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two ledger lines, got %d: %q", len(lines), body)
	}
	for _, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal ledger line %q: %v", line, err)
		}
	}
}

func TestLedgerAcceptsSupportedLargeEvents(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := AppendEvent(stateDir, Event{
		Time: time.Unix(101, 0).UTC().Format(time.RFC3339Nano),
		Type: "large",
		Details: map[string]string{
			"payload": strings.Repeat("x", 70*1024),
		},
	}); err != nil {
		t.Fatalf("AppendEvent large: %v", err)
	}
	if _, err := AppendEvent(stateDir, Event{Time: time.Unix(102, 0).UTC().Format(time.RFC3339Nano), Type: "after_large"}); err != nil {
		t.Fatalf("AppendEvent after large: %v", err)
	}
	validation := Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should validate with supported large event: %+v", validation.Errors)
	}
	if validation.EventCount != 3 {
		t.Fatalf("unexpected event count after large event: %+v", validation)
	}
}

func TestLedgerRejectsOversizedEvents(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := AppendEvent(stateDir, Event{
		Time: time.Unix(101, 0).UTC().Format(time.RFC3339Nano),
		Type: "too_large",
		Details: map[string]string{
			"payload": strings.Repeat("x", maxLedgerLineBytes),
		},
	}); err == nil || !strings.Contains(err.Error(), "ledger event exceeds") {
		t.Fatalf("expected oversized ledger event rejection, got %v", err)
	}
	validation := Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should remain valid after oversized event rejection: %+v", validation.Errors)
	}
	if validation.EventCount != 1 {
		t.Fatalf("oversized event should not be written: %+v", validation)
	}
}

func TestLedgerConcurrentAppendsRemainLinked(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := AppendEvent(stateDir, Event{Type: "concurrent"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("AppendEvent concurrent: %v", err)
		}
	}
	validation := Validate(stateDir)
	if !validation.OK {
		t.Fatalf("state should validate after concurrent appends: %+v", validation.Errors)
	}
	if validation.EventCount != 21 {
		t.Fatalf("unexpected event count after concurrent appends: %+v", validation)
	}
}

func TestAppendEventRejectsInvalidInputs(t *testing.T) {
	stateDir := t.TempDir()
	if _, err := AppendEvent(stateDir, Event{Time: "not-a-time", Type: "bad"}); err == nil {
		t.Fatal("expected invalid event time error")
	}
	if _, err := AppendEvent(stateDir, Event{Time: time.Unix(1, 0).UTC().Format(time.RFC3339Nano), Type: "bad", ObjectDigests: []string{"not-a-digest"}}); err == nil {
		t.Fatal("expected invalid object digest error")
	}
	missingDigest := "sha256:" + strings.Repeat("a", 64)
	if _, err := AppendEvent(stateDir, Event{Time: time.Unix(1, 0).UTC().Format(time.RFC3339Nano), Type: "missing", ObjectDigests: []string{missingDigest}}); err == nil {
		t.Fatal("expected missing object error")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "ledger.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("invalid events should not create ledger, stat err=%v", err)
	}
}

func TestValidateReportsMissingMalformedAndMismatchedState(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	initResult, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	path, err := objectPath(stateDir, initResult.Manifest.Digest)
	if err != nil {
		t.Fatalf("objectPath: %v", err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper object: %v", err)
	}
	ledgerPath := filepath.Join(stateDir, "ledger.jsonl")
	f, err := os.OpenFile(ledgerPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	if _, err := f.WriteString("{not-json}\n"); err != nil {
		_ = f.Close()
		t.Fatalf("append malformed ledger: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatalf("expected validation failures")
	}
	requireIssue(t, validation, "object_digest_mismatch")
	requireIssue(t, validation, "object_read_failed")
	requireIssue(t, validation, "malformed_event")
}

func TestValidateRejectsInvalidManifestObject(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	badManifest, err := Store{root: stateDir}.PutJSON(map[string]any{"not": "a state manifest"}, "application/json")
	if err != nil {
		t.Fatalf("PutJSON bad manifest: %v", err)
	}
	body, err := json.MarshalIndent(map[string]any{
		"schema_version": SchemaVersion,
		"manifest":       badManifest,
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest pointer: %v", err)
	}
	body = append(body, '\n')
	if err := os.WriteFile(filepath.Join(stateDir, "manifests", "state.json"), body, 0o644); err != nil {
		t.Fatalf("rewrite manifest pointer: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatal("expected invalid manifest object validation failure")
	}
	requireIssue(t, validation, "unsupported_manifest_object_schema")
	requireIssue(t, validation, "manifest_state_mismatch")
}

func TestValidateReportsMissingReferencedObject(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	initResult, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	path, err := objectPath(stateDir, initResult.Manifest.Digest)
	if err != nil {
		t.Fatalf("objectPath: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove referenced object: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatalf("expected missing object validation failure")
	}
	requireIssue(t, validation, "object_read_failed")
}

func TestValidateReportsUninitializedState(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(filepath.Join(stateDir, "objects", "sha256"), 0o755); err != nil {
		t.Fatalf("mkdir objects: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "manifests"), 0o755); err != nil {
		t.Fatalf("mkdir manifests: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "ledger.jsonl"), nil, 0o644); err != nil {
		t.Fatalf("write empty ledger: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatal("expected uninitialized state validation failure")
	}
	requireIssue(t, validation, "missing_manifest")
	requireIssue(t, validation, "empty_ledger")
}

func TestValidateReportsInvalidEventTime(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := Init(InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	prior, err := lastEventID(filepath.Join(stateDir, "ledger.jsonl"))
	if err != nil {
		t.Fatalf("lastEventID: %v", err)
	}
	event := Event{
		SchemaVersion: SchemaVersion,
		Time:          "not-a-time",
		Type:          "bad_time",
		PriorEventID:  prior,
	}
	event.EventID = eventID(event)
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "ledger.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open ledger: %v", err)
	}
	if _, err := f.Write(append(body, '\n')); err != nil {
		_ = f.Close()
		t.Fatalf("append event: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close ledger: %v", err)
	}
	validation := Validate(stateDir)
	if validation.OK {
		t.Fatalf("expected invalid event time failure")
	}
	requireIssue(t, validation, "invalid_event_time")
}

func requireIssue(t *testing.T, result ValidationResult, code string) {
	t.Helper()
	for _, issue := range result.Errors {
		if issue.Code == code {
			return
		}
	}
	t.Fatalf("missing issue %q in %+v", code, result.Errors)
}
