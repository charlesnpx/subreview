package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
