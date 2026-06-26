package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	EventTypeEvidenceRecorded = "gate.evidence_recorded"

	MediaTypeCatalog  = "application/vnd.subreview.gate-catalog+json"
	MediaTypeEvidence = "application/vnd.subreview.gate-evidence+json"

	ReplayContentPure      = "content_pure"
	ReplayEnvironmentBound = "environment_bound"
	ReplayObservational    = "observational"

	SideEffectsNone       = "none"
	SideEffectsTemporary  = "temporary"
	SideEffectsRepository = "repository"
	SideEffectsExternal   = "external"

	ProvenanceCLIWitnessed     = "cli_witnessed"
	ProvenanceExternalAsserted = "external_asserted"

	OutcomePass  = "pass"
	OutcomeFail  = "fail"
	OutcomeError = "error"

	defaultTimeoutSeconds = 30
	maxTimeoutSeconds     = 600
	maxDiagnosticBytes    = 4096
)

var commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type CheckOptions struct {
	CatalogPath string
	RepoPath    string
}

type RunOptions struct {
	StateDir     string
	CatalogPath  string
	CommandID    string
	SnapshotKind string
	Now          time.Time
}

type RecordOptions struct {
	StateDir     string
	CatalogPath  string
	CommandID    string
	SnapshotKind string
	Outcome      string
	Provenance   string
	Diagnostic   string
	ExitCode     *int
	Now          time.Time
}

type CheckResult struct {
	SchemaVersion int              `json:"schema_version"`
	OK            bool             `json:"ok"`
	Catalog       string           `json:"catalog"`
	Repo          string           `json:"repo"`
	Commands      []CommandSummary `json:"commands"`
}

type EvidenceResult struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	Repo          string          `json:"repo"`
	CommandID     string          `json:"command_id"`
	CommandDigest string          `json:"command_digest"`
	PolicyDigest  string          `json:"policy_digest,omitempty"`
	InputSnapshot string          `json:"input_snapshot"`
	Outcome       string          `json:"outcome"`
	Provenance    string          `json:"provenance"`
	Catalog       state.ObjectRef `json:"catalog"`
	Evidence      state.ObjectRef `json:"evidence"`
	EventID       string          `json:"event_id"`
}

type Catalog struct {
	SchemaVersion int                 `json:"schema_version"`
	Commands      []CommandDefinition `json:"commands"`
}

type CommandDefinition struct {
	ID                string            `json:"id"`
	Description       string            `json:"description,omitempty"`
	Argv              []string          `json:"argv"`
	WorkingDir        string            `json:"working_dir,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
	ReplayClass       string            `json:"replay_class"`
	EnvironmentPinned bool              `json:"environment_pinned"`
	ExecutesRepoCode  bool              `json:"executes_repo_code"`
	SideEffects       string            `json:"side_effects"`
	TimeoutSeconds    int               `json:"timeout_seconds,omitempty"`
	AllowedExitCodes  []int             `json:"allowed_exit_codes,omitempty"`
}

type CommandSummary struct {
	ID                string   `json:"id"`
	CommandDigest     string   `json:"command_digest"`
	ReplayClass       string   `json:"replay_class"`
	EnvironmentPinned bool     `json:"environment_pinned"`
	ExecutesRepoCode  bool     `json:"executes_repo_code"`
	SideEffects       string   `json:"side_effects"`
	Argv              []string `json:"argv"`
}

type EvidenceRecord struct {
	SchemaVersion     int                 `json:"schema_version"`
	Repo              string              `json:"repo"`
	CommandID         string              `json:"command_id"`
	CommandDigest     string              `json:"command_digest"`
	Command           CommandDefinition   `json:"command"`
	Catalog           state.ObjectRef     `json:"catalog"`
	Policy            *PolicyRef          `json:"policy,omitempty"`
	InputSnapshot     SnapshotRef         `json:"input_snapshot"`
	ReplayClass       string              `json:"replay_class"`
	EnvironmentPinned bool                `json:"environment_pinned"`
	ExecutesRepoCode  bool                `json:"executes_repo_code"`
	SideEffects       string              `json:"side_effects"`
	Provenance        string              `json:"provenance"`
	Outcome           string              `json:"outcome"`
	ExitCode          *int                `json:"exit_code,omitempty"`
	StartedAt         string              `json:"started_at,omitempty"`
	EndedAt           string              `json:"ended_at,omitempty"`
	DurationMS        int64               `json:"duration_ms,omitempty"`
	Diagnostics       EvidenceDiagnostics `json:"diagnostics"`
}

type EvidenceObservation struct {
	Record  EvidenceRecord `json:"record"`
	Digest  string         `json:"digest"`
	EventID string         `json:"event_id"`
}

type PolicyRef struct {
	Profile  string `json:"profile"`
	PolicyID string `json:"policy_id"`
	Digest   string `json:"digest"`
}

type SnapshotRef struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
}

type EvidenceDiagnostics struct {
	Summary    string `json:"summary,omitempty"`
	StdoutTail string `json:"stdout_tail,omitempty"`
	StderrTail string `json:"stderr_tail,omitempty"`
}

type stateBinding struct {
	State string
	Repo  string
}

type snapshotBinding struct {
	Kind   string
	Digest string
}

type policyBinding struct {
	Ref PolicyRef
}

func CheckCatalog(opts CheckOptions) (CheckResult, error) {
	repo, err := explicitRepoPath(opts.RepoPath)
	if err != nil {
		return CheckResult{}, err
	}
	catalogPath, catalog, err := LoadCatalog(opts.CatalogPath)
	if err != nil {
		return CheckResult{}, err
	}
	return CheckResult{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Catalog:       catalogPath,
		Repo:          repo,
		Commands:      commandSummaries(catalog.Commands),
	}, nil
}

func Run(opts RunOptions) (EvidenceResult, error) {
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return EvidenceResult{}, err
	}
	catalogPath, catalog, err := LoadCatalog(opts.CatalogPath)
	if err != nil {
		return EvidenceResult{}, err
	}
	_ = catalogPath
	command, err := resolveCommand(catalog, opts.CommandID)
	if err != nil {
		return EvidenceResult{}, err
	}
	if err := validateSnapshotKind(opts.SnapshotKind); err != nil {
		return EvidenceResult{}, err
	}
	if err := ensureWorkingDirInsideRepo(binding.Repo, command.WorkingDir); err != nil {
		return EvidenceResult{}, err
	}
	store, err := state.Open(binding.State)
	if err != nil {
		return EvidenceResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return EvidenceResult{}, err
	}
	inputSnapshot, err := latestSnapshotBinding(events, opts.SnapshotKind, binding.Repo)
	if err != nil {
		return EvidenceResult{}, err
	}
	policyRef, err := latestPolicyBinding(events, store, binding.Repo)
	if err != nil {
		return EvidenceResult{}, err
	}
	catalogRef, err := store.PutJSON(catalog, MediaTypeCatalog)
	if err != nil {
		return EvidenceResult{}, err
	}
	start := opts.Now.UTC()
	if start.IsZero() {
		start = time.Now().UTC()
	}
	runRoot, cleanup, err := restoredSnapshotRoot(binding.State, opts.SnapshotKind, inputSnapshot.Digest)
	if err != nil {
		return EvidenceResult{}, err
	}
	defer cleanup()
	run := executeCommand(runRoot, command, start)
	record := evidenceRecord(binding.Repo, command, catalogRef, policyRef, inputSnapshot, ProvenanceCLIWitnessed, run.Outcome, run.ExitCode, EvidenceDiagnostics{
		Summary:    run.Summary,
		StdoutTail: run.StdoutTail,
		StderrTail: run.StderrTail,
	}, start, run.EndedAt)
	return writeEvidence(binding.State, binding.Repo, store, record)
}

func Record(opts RecordOptions) (EvidenceResult, error) {
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return EvidenceResult{}, err
	}
	_, catalog, err := LoadCatalog(opts.CatalogPath)
	if err != nil {
		return EvidenceResult{}, err
	}
	command, err := resolveCommand(catalog, opts.CommandID)
	if err != nil {
		return EvidenceResult{}, err
	}
	if err := validateSnapshotKind(opts.SnapshotKind); err != nil {
		return EvidenceResult{}, err
	}
	if err := validateOutcome(opts.Outcome); err != nil {
		return EvidenceResult{}, err
	}
	if opts.ExitCode != nil {
		if *opts.ExitCode < 0 || *opts.ExitCode > 255 {
			return EvidenceResult{}, errors.New("--exit-code must be 0-255")
		}
		expected := outcomeForExitCode(command, *opts.ExitCode)
		if opts.Outcome != expected {
			return EvidenceResult{}, fmt.Errorf("gate outcome %s does not match exit code %d for catalog command %s; expected %s", opts.Outcome, *opts.ExitCode, command.ID, expected)
		}
	}
	provenance := strings.TrimSpace(opts.Provenance)
	if provenance == "" {
		provenance = ProvenanceExternalAsserted
	}
	if provenance != ProvenanceExternalAsserted {
		return EvidenceResult{}, fmt.Errorf("recorded gate evidence provenance must be %s", ProvenanceExternalAsserted)
	}
	store, err := state.Open(binding.State)
	if err != nil {
		return EvidenceResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return EvidenceResult{}, err
	}
	snapshot, err := latestSnapshotBinding(events, opts.SnapshotKind, binding.Repo)
	if err != nil {
		return EvidenceResult{}, err
	}
	policyRef, err := latestPolicyBinding(events, store, binding.Repo)
	if err != nil {
		return EvidenceResult{}, err
	}
	catalogRef, err := store.PutJSON(catalog, MediaTypeCatalog)
	if err != nil {
		return EvidenceResult{}, err
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	record := evidenceRecord(binding.Repo, command, catalogRef, policyRef, snapshot, provenance, opts.Outcome, opts.ExitCode, EvidenceDiagnostics{
		Summary: truncateDiagnostic(opts.Diagnostic),
	}, now, now)
	return writeEvidence(binding.State, binding.Repo, store, record)
}

func LoadCatalog(path string) (string, Catalog, error) {
	if strings.TrimSpace(path) == "" {
		return "", Catalog{}, errors.New("--catalog is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", Catalog{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", Catalog{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", Catalog{}, fmt.Errorf("gate catalog must be a regular file: %s", abs)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return "", Catalog{}, err
	}
	var catalog Catalog
	if err := decodeStrict(body, &catalog); err != nil {
		return "", Catalog{}, err
	}
	normalized, err := normalizeCatalog(catalog)
	if err != nil {
		return "", Catalog{}, err
	}
	return abs, normalized, nil
}

func LatestEvidenceByCommand(store state.Store, events []state.Event, repo string) (map[string]EvidenceObservation, error) {
	result := map[string]EvidenceObservation{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != EventTypeEvidenceRecorded {
			continue
		}
		if event.Repo != repo {
			return nil, errors.New("malformed gate.evidence_recorded event: repo mismatch")
		}
		commandID := event.Details["command_id"]
		if strings.TrimSpace(commandID) == "" {
			return nil, errors.New("malformed gate.evidence_recorded event: missing command_id")
		}
		if _, exists := result[commandID]; exists {
			continue
		}
		digest := event.Details["evidence"]
		if strings.TrimSpace(digest) == "" {
			return nil, errors.New("malformed gate.evidence_recorded event: missing evidence")
		}
		if !containsDigest(event.ObjectDigests, digest) {
			return nil, errors.New("malformed gate.evidence_recorded event: object_digests missing evidence")
		}
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var record EvidenceRecord
		if err := decodeStrict(body, &record); err != nil {
			return nil, err
		}
		if err := validateEvidenceRecord(record, repo, commandID); err != nil {
			return nil, err
		}
		result[commandID] = EvidenceObservation{Record: record, Digest: digest, EventID: event.EventID}
	}
	return result, nil
}

func normalizeCatalog(catalog Catalog) (Catalog, error) {
	if catalog.SchemaVersion != SchemaVersion {
		return Catalog{}, fmt.Errorf("unsupported gate catalog schema_version: %d", catalog.SchemaVersion)
	}
	if len(catalog.Commands) == 0 {
		return Catalog{}, errors.New("gate catalog requires at least one command")
	}
	commands := make([]CommandDefinition, len(catalog.Commands))
	ids := map[string]struct{}{}
	for i, command := range catalog.Commands {
		normalized, err := normalizeCommand(command)
		if err != nil {
			return Catalog{}, err
		}
		if _, ok := ids[normalized.ID]; ok {
			return Catalog{}, fmt.Errorf("duplicate gate command id: %s", normalized.ID)
		}
		ids[normalized.ID] = struct{}{}
		commands[i] = normalized
	}
	sort.Slice(commands, func(i, j int) bool { return commands[i].ID < commands[j].ID })
	return Catalog{SchemaVersion: SchemaVersion, Commands: commands}, nil
}

func normalizeCommand(command CommandDefinition) (CommandDefinition, error) {
	command.ID = strings.TrimSpace(command.ID)
	if !commandIDPattern.MatchString(command.ID) {
		return CommandDefinition{}, fmt.Errorf("invalid gate command id: %s", command.ID)
	}
	if len(command.Argv) == 0 {
		return CommandDefinition{}, fmt.Errorf("gate command %s requires argv", command.ID)
	}
	for i, arg := range command.Argv {
		if strings.ContainsRune(arg, '\x00') {
			return CommandDefinition{}, fmt.Errorf("gate command %s argv[%d] contains NUL", command.ID, i)
		}
		if i == 0 && strings.TrimSpace(arg) == "" {
			return CommandDefinition{}, fmt.Errorf("gate command %s argv[0] is required", command.ID)
		}
	}
	if command.EnvironmentPinned && !argv0HasPathSeparator(command.Argv[0]) {
		return CommandDefinition{}, fmt.Errorf("gate command %s environment_pinned argv[0] must include a path separator", command.ID)
	}
	if command.WorkingDir == "" {
		command.WorkingDir = "."
	}
	if _, err := cleanRepoPath(command.WorkingDir); err != nil && command.WorkingDir != "." {
		return CommandDefinition{}, fmt.Errorf("gate command %s has invalid working_dir: %w", command.ID, err)
	}
	if command.ReplayClass == "" {
		return CommandDefinition{}, fmt.Errorf("gate command %s requires replay_class", command.ID)
	}
	if !validReplayClass(command.ReplayClass) {
		return CommandDefinition{}, fmt.Errorf("gate command %s has invalid replay_class: %s", command.ID, command.ReplayClass)
	}
	if command.SideEffects == "" {
		return CommandDefinition{}, fmt.Errorf("gate command %s requires side_effects", command.ID)
	}
	if !validSideEffects(command.SideEffects) {
		return CommandDefinition{}, fmt.Errorf("gate command %s has invalid side_effects: %s", command.ID, command.SideEffects)
	}
	if command.TimeoutSeconds == 0 {
		command.TimeoutSeconds = defaultTimeoutSeconds
	}
	if command.TimeoutSeconds < 1 || command.TimeoutSeconds > maxTimeoutSeconds {
		return CommandDefinition{}, fmt.Errorf("gate command %s timeout_seconds must be 1-%d", command.ID, maxTimeoutSeconds)
	}
	if len(command.AllowedExitCodes) == 0 {
		command.AllowedExitCodes = []int{0}
	}
	seenExitCodes := map[int]struct{}{}
	for _, code := range command.AllowedExitCodes {
		if code < 0 || code > 255 {
			return CommandDefinition{}, fmt.Errorf("gate command %s allowed_exit_codes must be 0-255", command.ID)
		}
		seenExitCodes[code] = struct{}{}
	}
	command.AllowedExitCodes = command.AllowedExitCodes[:0]
	for code := range seenExitCodes {
		command.AllowedExitCodes = append(command.AllowedExitCodes, code)
	}
	sort.Ints(command.AllowedExitCodes)
	if command.Env != nil {
		for key, value := range command.Env {
			if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\x00=\n") || strings.ContainsRune(value, '\x00') {
				return CommandDefinition{}, fmt.Errorf("gate command %s has invalid env entry", command.ID)
			}
		}
	}
	return command, nil
}

func commandSummaries(commands []CommandDefinition) []CommandSummary {
	summaries := make([]CommandSummary, 0, len(commands))
	for _, command := range commands {
		summaries = append(summaries, CommandSummary{
			ID:                command.ID,
			CommandDigest:     CommandDigest(command),
			ReplayClass:       command.ReplayClass,
			EnvironmentPinned: command.EnvironmentPinned,
			ExecutesRepoCode:  command.ExecutesRepoCode,
			SideEffects:       command.SideEffects,
			Argv:              append([]string(nil), command.Argv...),
		})
	}
	return summaries
}

func resolveCommand(catalog Catalog, id string) (CommandDefinition, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return CommandDefinition{}, errors.New("--command-id is required")
	}
	for _, command := range catalog.Commands {
		if command.ID == id {
			return command, nil
		}
	}
	return CommandDefinition{}, fmt.Errorf("gate command id is not present in catalog: %s", id)
}

func CommandDigest(command CommandDefinition) string {
	body, err := json.Marshal(command)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type commandRun struct {
	Outcome    string
	ExitCode   *int
	Summary    string
	StdoutTail string
	StderrTail string
	EndedAt    time.Time
}

func executeCommand(repo string, command CommandDefinition, startedAt time.Time) commandRun {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(command.TimeoutSeconds)*time.Second)
	defer cancel()
	if command.EnvironmentPinned && !argv0HasPathSeparator(command.Argv[0]) {
		endedAt := time.Now().UTC()
		return commandRun{Outcome: OutcomeError, Summary: "environment-pinned gate argv[0] must include a path separator", EndedAt: endedAt}
	}
	cmd := exec.Command(command.Argv[0], command.Argv[1:]...)
	cmd.Dir = filepath.Join(repo, filepath.FromSlash(command.WorkingDir))
	cmd.Env = commandEnv(command)
	configureCommandProcess(cmd)
	var stdout, stderr tailBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		endedAt := time.Now().UTC()
		return commandRun{Outcome: OutcomeError, Summary: truncateDiagnostic(err.Error()), EndedAt: endedAt}
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Wait()
	}()
	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
		_ = terminateCommandProcess(cmd)
		<-errCh
		err = ctx.Err()
	}
	endedAt := time.Now().UTC()
	stdoutTail := stdout.String()
	stderrTail := stderr.String()
	if ctx.Err() == context.DeadlineExceeded {
		return commandRun{Outcome: OutcomeError, Summary: "gate command timed out", StdoutTail: stdoutTail, StderrTail: stderrTail, EndedAt: endedAt}
	}
	if err == nil {
		code := 0
		return commandRun{Outcome: outcomeForExitCode(command, code), ExitCode: &code, Summary: "gate command completed", StdoutTail: stdoutTail, StderrTail: stderrTail, EndedAt: endedAt}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 0 || code > 255 {
			return commandRun{Outcome: OutcomeError, Summary: truncateDiagnostic(exitErr.Error()), StdoutTail: stdoutTail, StderrTail: stderrTail, EndedAt: endedAt}
		}
		return commandRun{Outcome: outcomeForExitCode(command, code), ExitCode: &code, Summary: fmt.Sprintf("gate command exited with code %d", code), StdoutTail: stdoutTail, StderrTail: stderrTail, EndedAt: endedAt}
	}
	return commandRun{Outcome: OutcomeError, Summary: truncateDiagnostic(err.Error()), StdoutTail: stdoutTail, StderrTail: stderrTail, EndedAt: endedAt}
}

func restoredSnapshotRoot(stateDir, kind, expectedDigest string) (string, func(), error) {
	root, err := os.MkdirTemp("", "subreview-gate-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	output := filepath.Join(root, "snapshot")
	restored, err := snapshot.Restore(snapshot.RestoreOptions{StateDir: stateDir, Kind: kind, Output: output})
	if err != nil {
		cleanup()
		return "", nil, err
	}
	if restored.SnapshotDigest != expectedDigest {
		cleanup()
		return "", nil, fmt.Errorf("restored snapshot changed before gate run: %s != %s", restored.SnapshotDigest, expectedDigest)
	}
	return output, cleanup, nil
}

type tailBuffer struct {
	buf []byte
}

func (w *tailBuffer) Write(p []byte) (int, error) {
	if len(p) >= maxDiagnosticBytes {
		w.buf = append(w.buf[:0], p[len(p)-maxDiagnosticBytes:]...)
		return len(p), nil
	}
	total := len(w.buf) + len(p)
	if total > maxDiagnosticBytes {
		trim := total - maxDiagnosticBytes
		w.buf = append(w.buf[:0], w.buf[trim:]...)
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *tailBuffer) String() string {
	return strings.TrimSpace(string(w.buf))
}

func evidenceRecord(repo string, command CommandDefinition, catalog state.ObjectRef, policyRef *PolicyRef, snapshot snapshotBinding, provenance, outcome string, exitCode *int, diagnostics EvidenceDiagnostics, startedAt, endedAt time.Time) EvidenceRecord {
	duration := endedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return EvidenceRecord{
		SchemaVersion:     SchemaVersion,
		Repo:              repo,
		CommandID:         command.ID,
		CommandDigest:     CommandDigest(command),
		Command:           command,
		Catalog:           catalog,
		Policy:            policyRef,
		InputSnapshot:     SnapshotRef{Kind: snapshot.Kind, Digest: snapshot.Digest},
		ReplayClass:       command.ReplayClass,
		EnvironmentPinned: command.EnvironmentPinned,
		ExecutesRepoCode:  command.ExecutesRepoCode,
		SideEffects:       command.SideEffects,
		Provenance:        provenance,
		Outcome:           outcome,
		ExitCode:          exitCode,
		StartedAt:         startedAt.Format(time.RFC3339Nano),
		EndedAt:           endedAt.Format(time.RFC3339Nano),
		DurationMS:        duration,
		Diagnostics: EvidenceDiagnostics{
			Summary:    truncateDiagnostic(diagnostics.Summary),
			StdoutTail: truncateDiagnostic(diagnostics.StdoutTail),
			StderrTail: truncateDiagnostic(diagnostics.StderrTail),
		},
	}
}

func writeEvidence(stateDir, repo string, store state.Store, record EvidenceRecord) (EvidenceResult, error) {
	evidenceRef, err := store.PutJSON(record, MediaTypeEvidence)
	if err != nil {
		return EvidenceResult{}, err
	}
	objectDigests := []string{evidenceRef.Digest}
	if record.Catalog.Digest != "" {
		objectDigests = append(objectDigests, record.Catalog.Digest)
	}
	details := map[string]string{
		"evidence":           evidenceRef.Digest,
		"catalog":            record.Catalog.Digest,
		"command_id":         record.CommandID,
		"command_digest":     record.CommandDigest,
		"snapshot_kind":      record.InputSnapshot.Kind,
		"input_snapshot":     record.InputSnapshot.Digest,
		"outcome":            record.Outcome,
		"provenance":         record.Provenance,
		"replay_class":       record.ReplayClass,
		"side_effects":       record.SideEffects,
		"executes_repo_code": strconv.FormatBool(record.ExecutesRepoCode),
		"environment_pinned": strconv.FormatBool(record.EnvironmentPinned),
	}
	if record.Policy != nil {
		details["policy"] = record.Policy.Digest
		details["profile"] = record.Policy.Profile
		details["policy_id"] = record.Policy.PolicyID
	}
	event, err := state.AppendEvent(stateDir, state.Event{
		Type:          EventTypeEvidenceRecorded,
		ObjectDigests: objectDigests,
		Repo:          repo,
		Details:       details,
	})
	if err != nil {
		return EvidenceResult{}, err
	}
	result := EvidenceResult{
		SchemaVersion: SchemaVersion,
		State:         stateDir,
		Repo:          repo,
		CommandID:     record.CommandID,
		CommandDigest: record.CommandDigest,
		InputSnapshot: record.InputSnapshot.Digest,
		Outcome:       record.Outcome,
		Provenance:    record.Provenance,
		Catalog:       record.Catalog,
		Evidence:      evidenceRef,
		EventID:       event.EventID,
	}
	if record.Policy != nil {
		result.PolicyDigest = record.Policy.Digest
	}
	return result, nil
}

func latestSnapshotBinding(events []state.Event, kind, repo string) (snapshotBinding, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Details["kind"] != kind {
			continue
		}
		if event.Repo != repo {
			return snapshotBinding{}, fmt.Errorf("malformed snapshot.captured event for kind %s: repo mismatch", kind)
		}
		digest := event.Details["snapshot"]
		tree := event.Details["tree"]
		if strings.TrimSpace(digest) == "" || strings.TrimSpace(tree) == "" {
			return snapshotBinding{}, fmt.Errorf("malformed snapshot.captured event for kind %s", kind)
		}
		if len(event.ObjectDigests) != 2 || !containsDigest(event.ObjectDigests, digest) || !containsDigest(event.ObjectDigests, tree) {
			return snapshotBinding{}, fmt.Errorf("malformed snapshot.captured event for kind %s: object_digests must contain only snapshot and tree", kind)
		}
		return snapshotBinding{Kind: kind, Digest: digest}, nil
	}
	return snapshotBinding{}, fmt.Errorf("snapshot kind is not captured in state: %s", kind)
}

func latestPolicyBinding(events []state.Event, store state.Store, repo string) (*PolicyRef, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "policy.bound" {
			continue
		}
		if event.Repo != repo {
			return nil, errors.New("malformed policy.bound event: repo mismatch")
		}
		digest := event.Details["policy"]
		profile := event.Details["profile"]
		policyID := event.Details["policy_id"]
		if strings.TrimSpace(digest) == "" || strings.TrimSpace(profile) == "" || strings.TrimSpace(policyID) == "" {
			return nil, errors.New("malformed policy.bound event: missing policy, profile, or policy_id")
		}
		if len(event.ObjectDigests) != 1 || event.ObjectDigests[0] != digest {
			return nil, errors.New("malformed policy.bound event: object_digests must contain only policy digest")
		}
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var effective policy.EffectivePolicy
		if err := decodeStrict(body, &effective); err != nil {
			return nil, err
		}
		if effective.SchemaVersion != policy.SchemaVersion || effective.Repo != repo || effective.Profile != profile || effective.PolicyID != policyID {
			return nil, errors.New("bound policy object does not match policy.bound event")
		}
		return &PolicyRef{Profile: profile, PolicyID: policyID, Digest: digest}, nil
	}
	return nil, nil
}

func validateEvidenceRecord(record EvidenceRecord, repo, commandID string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported gate evidence schema_version: %d", record.SchemaVersion)
	}
	if record.Repo != repo {
		return fmt.Errorf("gate evidence repo mismatch: %s != %s", record.Repo, repo)
	}
	if record.CommandID != commandID {
		return fmt.Errorf("gate evidence command id mismatch: %s != %s", record.CommandID, commandID)
	}
	if record.CommandDigest == "" || record.CommandDigest != CommandDigest(record.Command) {
		return errors.New("gate evidence command digest mismatch")
	}
	if err := validateOutcome(record.Outcome); err != nil {
		return err
	}
	if record.Provenance != ProvenanceCLIWitnessed && record.Provenance != ProvenanceExternalAsserted {
		return fmt.Errorf("invalid gate evidence provenance: %s", record.Provenance)
	}
	return nil
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
	return abs, nil
}

func ensureWorkingDirInsideRepo(repo, workingDir string) error {
	clean := "."
	if workingDir != "" {
		var err error
		clean, err = cleanRepoPath(workingDir)
		if err != nil && workingDir != "." {
			return err
		}
	}
	workdir := filepath.Join(repo, filepath.FromSlash(clean))
	rel, err := filepath.Rel(repo, workdir)
	if err != nil {
		return err
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." && !filepath.IsAbs(rel)) {
		return nil
	}
	return fmt.Errorf("gate working_dir escapes repo: %s", workingDir)
}

func cleanRepoPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty repository path")
	}
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	slash := strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
	clean := filepath.Clean(slash)
	clean = filepath.ToSlash(clean)
	if clean == "." {
		return ".", nil
	}
	if strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	if clean != slash {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	return clean, nil
}

func commandEnv(command CommandDefinition) []string {
	env := []string{}
	if !command.EnvironmentPinned {
		env = append(env, os.Environ()...)
	}
	keys := make([]string, 0, len(command.Env))
	for key := range command.Env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+command.Env[key])
	}
	return env
}

func argv0HasPathSeparator(argv0 string) bool {
	return strings.ContainsAny(argv0, `/\`)
}

func outcomeForExitCode(command CommandDefinition, code int) string {
	for _, allowed := range command.AllowedExitCodes {
		if allowed == code {
			return OutcomePass
		}
	}
	return OutcomeFail
}

func validReplayClass(value string) bool {
	return value == ReplayContentPure || value == ReplayEnvironmentBound || value == ReplayObservational
}

func validSideEffects(value string) bool {
	return value == SideEffectsNone || value == SideEffectsTemporary || value == SideEffectsRepository || value == SideEffectsExternal
}

func validateOutcome(value string) error {
	switch value {
	case OutcomePass, OutcomeFail, OutcomeError:
		return nil
	default:
		return fmt.Errorf("invalid gate outcome: %s", value)
	}
}

func validateSnapshotKind(kind string) error {
	switch kind {
	case "base", "proposal", "final":
		return nil
	default:
		return fmt.Errorf("invalid snapshot kind: %s", kind)
	}
}

func truncateDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= maxDiagnosticBytes {
		return value
	}
	return value[len(value)-maxDiagnosticBytes:]
}

func containsDigest(values []string, digest string) bool {
	for _, value := range values {
		if value == digest {
			return true
		}
	}
	return false
}

func decodeStrict(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
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
