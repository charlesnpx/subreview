package artifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	EventTypeImported = "artifact.imported"

	KindPlan = "plan"

	MediaTypeArtifact = "application/vnd.subreview.artifact+json"
	MediaTypePlanText = "text/plain; charset=utf-8"

	DefaultMaxArtifactBytes = 1 << 20
)

type ImportOptions struct {
	StateDir         string
	Kind             string
	Path             string
	Title            string
	Revises          string
	Now              time.Time
	MaxArtifactBytes int64
}

type ImportResult struct {
	SchemaVersion   int             `json:"schema_version"`
	State           string          `json:"state"`
	Repo            string          `json:"repo"`
	ArtifactID      string          `json:"artifact_id"`
	Kind            string          `json:"kind"`
	Title           string          `json:"title"`
	SourcePath      string          `json:"source_path"`
	Revises         string          `json:"revises,omitempty"`
	Content         state.ObjectRef `json:"content"`
	ContentDigest   string          `json:"content_digest"`
	Artifact        state.ObjectRef `json:"artifact"`
	EventID         string          `json:"event_id"`
	CreatedAt       string          `json:"created_at"`
	AlreadyImported bool            `json:"already_imported,omitempty"`
}

type StatusOptions struct {
	StateDir   string
	ArtifactID string
}

type StatusResult struct {
	SchemaVersion       int              `json:"schema_version"`
	State               string           `json:"state"`
	Repo                string           `json:"repo"`
	RequestedArtifactID string           `json:"requested_artifact_id"`
	ArtifactID          string           `json:"artifact_id"`
	LatestArtifactID    string           `json:"latest_artifact_id"`
	IsLatest            bool             `json:"is_latest"`
	Successor           string           `json:"successor,omitempty"`
	Status              string           `json:"status"`
	ReviewRequired      bool             `json:"review_required"`
	Outcome             string           `json:"outcome,omitempty"`
	Clean               bool             `json:"clean"`
	FindingCount        int              `json:"finding_count"`
	AcceptedFindings    int              `json:"accepted_finding_count"`
	DuplicateFindings   int              `json:"duplicate_finding_count"`
	RejectedStructural  int              `json:"rejected_structural_count"`
	NeedsContextCount   int              `json:"needs_context_count"`
	Artifact            ArtifactSummary  `json:"artifact"`
	LatestPacket        *PacketSummary   `json:"latest_packet,omitempty"`
	LatestResult        *ResultSummary   `json:"latest_result,omitempty"`
	SupersededBy        []string         `json:"superseded_by,omitempty"`
	SupersededFindings  []FindingSummary `json:"superseded_findings,omitempty"`
	Blockers            []Blocker        `json:"blockers,omitempty"`
}

type Blocker struct {
	Code    string   `json:"code"`
	Message string   `json:"message"`
	IDs     []string `json:"ids,omitempty"`
}

type ArtifactSummary struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	SourcePath    string          `json:"source_path"`
	Repo          string          `json:"repo"`
	CreatedAt     string          `json:"created_at"`
	Revises       string          `json:"revises,omitempty"`
	Content       state.ObjectRef `json:"content"`
	ContentDigest string          `json:"content_digest"`
	Artifact      state.ObjectRef `json:"artifact"`
	EventID       string          `json:"event_id"`
}

type PacketSummary struct {
	Packet  string `json:"packet"`
	EventID string `json:"event_id"`
	Route   string `json:"route"`
	Kind    string `json:"kind"`
	RunKind string `json:"run_kind"`
}

type ResultSummary struct {
	Result             string `json:"result"`
	EventID            string `json:"event_id"`
	Packet             string `json:"packet"`
	Outcome            string `json:"outcome"`
	Clean              bool   `json:"clean"`
	FindingCount       int    `json:"finding_count"`
	AcceptedFindings   int    `json:"accepted_finding_count"`
	DuplicateFindings  int    `json:"duplicate_finding_count"`
	RejectedStructural int    `json:"rejected_structural_count"`
	NeedsContextCount  int    `json:"needs_context_count"`
}

type FindingSummary struct {
	ArtifactID string `json:"artifact_id"`
	FindingID  string `json:"finding_id"`
	State      string `json:"state"`
	Severity   string `json:"severity"`
	Class      string `json:"class"`
	Claim      string `json:"claim"`
	Result     string `json:"result"`
	EventID    string `json:"event_id"`
}

type ArtifactRecord struct {
	SchemaVersion int             `json:"schema_version"`
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	SourcePath    string          `json:"source_path"`
	Repo          string          `json:"repo"`
	CreatedAt     string          `json:"created_at"`
	Revises       string          `json:"revises,omitempty"`
	Content       state.ObjectRef `json:"content"`
	ContentDigest string          `json:"content_digest"`
	Text          TextMetadata    `json:"text"`
}

type TextMetadata struct {
	Encoding    string `json:"encoding"`
	UTF8        bool   `json:"utf8"`
	ContainsNUL bool   `json:"contains_nul"`
}

type Observation struct {
	Record   ArtifactRecord  `json:"record"`
	Artifact state.ObjectRef `json:"artifact"`
	EventID  string          `json:"event_id"`
}

type stateBinding struct {
	State string
	Repo  string
}

func Import(opts ImportOptions) (ImportResult, error) {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return ImportResult{}, err
	}
	kind, err := normalizeKind(opts.Kind)
	if err != nil {
		return ImportResult{}, err
	}
	title := strings.TrimSpace(opts.Title)
	if title == "" {
		return ImportResult{}, errors.New("--title is required")
	}
	sourcePath, body, err := readBoundedArtifactFile(opts.Path, maxArtifactBytes(opts.MaxArtifactBytes))
	if err != nil {
		return ImportResult{}, err
	}
	if kind == KindPlan {
		if err := validatePlanText(body); err != nil {
			return ImportResult{}, err
		}
	}
	store, err := state.Open(binding.State)
	if err != nil {
		return ImportResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return ImportResult{}, err
	}
	observations, err := Observations(store, events, binding.Repo)
	if err != nil {
		return ImportResult{}, err
	}
	revises := strings.TrimSpace(opts.Revises)
	contentDigest := digestBytes(body)
	artifactID := artifactID(kind, title, contentDigest, revises)
	if existing, ok := observationByID(observations, artifactID); ok {
		if sameImport(existing.Record, kind, title, revises, contentDigest, binding.Repo) {
			return importResultFromObservation(binding, existing, true), nil
		}
		return ImportResult{}, fmt.Errorf("artifact id collision: %s", artifactID)
	}
	if revises != "" {
		if err := validateRevisionTarget(observations, binding.Repo, kind, artifactID, revises); err != nil {
			return ImportResult{}, err
		}
	}
	contentRef, err := store.PutBytes(body, MediaTypePlanText)
	if err != nil {
		return ImportResult{}, err
	}
	record := ArtifactRecord{
		SchemaVersion: SchemaVersion,
		ID:            artifactID,
		Kind:          kind,
		Title:         title,
		SourcePath:    sourcePath,
		Repo:          binding.Repo,
		CreatedAt:     now.Format(time.RFC3339Nano),
		Revises:       revises,
		Content:       contentRef,
		ContentDigest: contentRef.Digest,
		Text: TextMetadata{
			Encoding:    "utf-8",
			UTF8:        true,
			ContainsNUL: false,
		},
	}
	artifactRef, err := store.PutJSON(record, MediaTypeArtifact)
	if err != nil {
		return ImportResult{}, err
	}
	details := map[string]string{
		"artifact":       artifactRef.Digest,
		"artifact_id":    artifactID,
		"kind":           kind,
		"title":          title,
		"content":        contentRef.Digest,
		"content_digest": contentRef.Digest,
	}
	if revises != "" {
		details["revises"] = revises
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          EventTypeImported,
		ObjectDigests: []string{artifactRef.Digest, contentRef.Digest},
		Repo:          binding.Repo,
		Details:       details,
	})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		SchemaVersion: SchemaVersion,
		State:         binding.State,
		Repo:          binding.Repo,
		ArtifactID:    artifactID,
		Kind:          kind,
		Title:         title,
		SourcePath:    sourcePath,
		Revises:       revises,
		Content:       contentRef,
		ContentDigest: contentRef.Digest,
		Artifact:      artifactRef,
		EventID:       event.EventID,
		CreatedAt:     record.CreatedAt,
	}, nil
}

func Status(opts StatusOptions) (StatusResult, error) {
	artifactID := strings.TrimSpace(opts.ArtifactID)
	if artifactID == "" {
		return StatusResult{}, errors.New("--artifact is required")
	}
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return StatusResult{}, err
	}
	store, err := state.Open(binding.State)
	if err != nil {
		return StatusResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return StatusResult{}, err
	}
	observations, err := Observations(store, events, binding.Repo)
	if err != nil {
		return StatusResult{}, err
	}
	observation, ok := observationByID(observations, artifactID)
	if !ok {
		return StatusResult{}, fmt.Errorf("artifact not found in state: %s", artifactID)
	}
	children := childrenByParent(observations)
	component := revisionComponent(observations, artifactID, children)
	blockers := revisionBlockers(observations, children, component)
	supersededBy := append([]string(nil), children[artifactID]...)
	sort.Strings(supersededBy)
	latestArtifactID := latestArtifactInComponent(component, children)
	if latestArtifactID == "" {
		latestArtifactID = artifactID
	}
	isLatest := artifactID == latestArtifactID
	successor := ""
	if len(supersededBy) > 0 {
		successor = supersededBy[0]
	}
	latestPacket := latestPacketForArtifact(events, binding.Repo, latestArtifactID)
	resultObservations, err := artifactResultObservations(store, events, binding.Repo)
	if err != nil {
		return StatusResult{}, err
	}
	latestResultObservation := latestResultForArtifact(resultObservations, latestArtifactID)
	var latestResult *ResultSummary
	var currentResult *ResultSummary
	outcome := ""
	clean := false
	findingCount := 0
	acceptedFindings := 0
	duplicateFindings := 0
	rejectedStructural := 0
	needsContextCount := 0
	if latestResultObservation != nil {
		summary := latestResultObservation.summary()
		latestResult = &summary
		if latestPacket != nil && summary.Packet == latestPacket.Packet {
			currentResult = latestResult
		}
	}
	if currentResult != nil {
		summary := *currentResult
		outcome = summary.Outcome
		clean = summary.Clean
		findingCount = summary.FindingCount
		acceptedFindings = summary.AcceptedFindings
		duplicateFindings = summary.DuplicateFindings
		rejectedStructural = summary.RejectedStructural
		needsContextCount = summary.NeedsContextCount
	}
	status := "no_review_packet"
	reviewRequired := true
	if len(blockers) > 0 {
		status = "blocked"
		reviewRequired = false
	} else if !isLatest {
		status = "superseded"
		reviewRequired = false
	} else if currentResult != nil {
		switch currentResult.Outcome {
		case "clean":
			status = "clean"
			reviewRequired = false
		case "needs_context":
			status = "needs_context"
			reviewRequired = true
		case "findings":
			status = "findings"
			reviewRequired = true
		default:
			status = currentResult.Outcome
			reviewRequired = true
		}
	} else if latestPacket != nil {
		status = "waiting_for_result"
	}
	return StatusResult{
		SchemaVersion:       SchemaVersion,
		State:               binding.State,
		Repo:                binding.Repo,
		RequestedArtifactID: artifactID,
		ArtifactID:          artifactID,
		LatestArtifactID:    latestArtifactID,
		IsLatest:            isLatest,
		Successor:           successor,
		Status:              status,
		ReviewRequired:      reviewRequired,
		Outcome:             outcome,
		Clean:               clean,
		FindingCount:        findingCount,
		AcceptedFindings:    acceptedFindings,
		DuplicateFindings:   duplicateFindings,
		RejectedStructural:  rejectedStructural,
		NeedsContextCount:   needsContextCount,
		Artifact:            artifactSummary(observation),
		LatestPacket:        latestPacket,
		LatestResult:        latestResult,
		SupersededBy:        supersededBy,
		SupersededFindings:  supersededFindings(resultObservations, component, latestArtifactID),
		Blockers:            blockers,
	}, nil
}

func Observations(store state.Store, events []state.Event, repo string) ([]Observation, error) {
	observations := []Observation{}
	for _, event := range events {
		if event.Type != EventTypeImported {
			continue
		}
		if event.Repo != repo {
			return nil, errors.New("malformed artifact.imported event: repo mismatch")
		}
		digest := strings.TrimSpace(event.Details["artifact"])
		if digest == "" {
			return nil, errors.New("malformed artifact.imported event: missing artifact")
		}
		if !containsDigest(event.ObjectDigests, digest) {
			return nil, errors.New("malformed artifact.imported event: object_digests missing artifact")
		}
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var record ArtifactRecord
		if err := json.Unmarshal(body, &record); err != nil {
			return nil, err
		}
		if err := validateArtifactRecord(record, repo); err != nil {
			return nil, err
		}
		if !containsDigest(event.ObjectDigests, record.ContentDigest) {
			return nil, errors.New("malformed artifact.imported event: object_digests missing content")
		}
		if event.Details["artifact_id"] != "" && event.Details["artifact_id"] != record.ID {
			return nil, errors.New("malformed artifact.imported event: artifact_id mismatch")
		}
		observations = append(observations, Observation{
			Record:   record,
			Artifact: state.ObjectRef{Digest: digest, MediaType: MediaTypeArtifact, Size: int64(len(body)), Path: recordPathBestEffort(record.Content.Path, digest)},
			EventID:  event.EventID,
		})
	}
	return observations, nil
}

func normalizeKind(kind string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(kind))
	switch value {
	case KindPlan:
		return value, nil
	case "":
		return "", errors.New("--kind is required")
	default:
		return "", fmt.Errorf("unsupported artifact kind: %s", value)
	}
}

func maxArtifactBytes(value int64) int64 {
	if value > 0 {
		return value
	}
	return DefaultMaxArtifactBytes
}

func readBoundedArtifactFile(path string, maxBytes int64) (string, []byte, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil, errors.New("--path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("artifact path must be a regular file: %s", abs)
	}
	if info.Size() == 0 {
		return "", nil, errors.New("artifact file is empty")
	}
	if info.Size() > maxBytes {
		return "", nil, fmt.Errorf("artifact exceeds %d byte limit", maxBytes)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return "", nil, err
	}
	if len(body) == 0 {
		return "", nil, errors.New("artifact file is empty")
	}
	if int64(len(body)) > maxBytes {
		return "", nil, fmt.Errorf("artifact exceeds %d byte limit", maxBytes)
	}
	return abs, body, nil
}

func validatePlanText(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("plan artifact must be valid UTF-8")
	}
	if bytes.IndexByte(body, 0) >= 0 {
		return errors.New("plan artifact must not contain NUL bytes")
	}
	return nil
}

func validateRevisionTarget(observations []Observation, repo, kind, artifactID, revises string) error {
	target, ok := observationByID(observations, revises)
	if !ok {
		return fmt.Errorf("revises artifact not found: %s", revises)
	}
	if target.Record.Repo != repo {
		return fmt.Errorf("revises artifact repo mismatch: %s != %s", target.Record.Repo, repo)
	}
	if target.Record.Kind != kind {
		return fmt.Errorf("revises artifact kind mismatch: %s != %s", target.Record.Kind, kind)
	}
	if chainContains(observations, revises, artifactID) {
		return fmt.Errorf("artifact revision cycle detected for %s", artifactID)
	}
	for _, existing := range observations {
		if existing.Record.Revises == revises && existing.Record.ID != artifactID {
			return fmt.Errorf("forked_revision: %s already revises %s", existing.Record.ID, revises)
		}
	}
	return nil
}

func validateArtifactRecord(record ArtifactRecord, repo string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported artifact schema_version: %d", record.SchemaVersion)
	}
	if record.ID == "" {
		return errors.New("artifact missing id")
	}
	if record.Repo != repo {
		return errors.New("artifact repo mismatch")
	}
	if record.Kind != KindPlan {
		return fmt.Errorf("unsupported artifact kind: %s", record.Kind)
	}
	if strings.TrimSpace(record.Title) == "" {
		return errors.New("artifact missing title")
	}
	if record.ContentDigest == "" || record.Content.Digest == "" || record.ContentDigest != record.Content.Digest {
		return errors.New("artifact content digest mismatch")
	}
	if record.CreatedAt == "" {
		return errors.New("artifact missing created_at")
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CreatedAt); err != nil {
		return fmt.Errorf("artifact invalid created_at: %w", err)
	}
	return nil
}

func artifactID(kind, title, contentDigest, revises string) string {
	parts := strings.Join([]string{
		"subreview-artifact-v1",
		strings.ToLower(strings.TrimSpace(kind)),
		strings.TrimSpace(title),
		strings.TrimSpace(contentDigest),
		strings.TrimSpace(revises),
	}, "\x00")
	sum := sha256.Sum256([]byte(parts))
	return "artifact-" + hex.EncodeToString(sum[:])[:16]
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func observationByID(observations []Observation, id string) (Observation, bool) {
	for i := len(observations) - 1; i >= 0; i-- {
		if observations[i].Record.ID == id {
			return observations[i], true
		}
	}
	return Observation{}, false
}

func sameImport(observation ArtifactRecord, kind, title, revises, contentDigest, repo string) bool {
	return observation.Kind == kind &&
		observation.Title == title &&
		observation.Revises == revises &&
		observation.ContentDigest == contentDigest &&
		observation.Repo == repo
}

func importResultFromObservation(binding stateBinding, observation Observation, duplicate bool) ImportResult {
	record := observation.Record
	return ImportResult{
		SchemaVersion:   SchemaVersion,
		State:           binding.State,
		Repo:            binding.Repo,
		ArtifactID:      record.ID,
		Kind:            record.Kind,
		Title:           record.Title,
		SourcePath:      record.SourcePath,
		Revises:         record.Revises,
		Content:         record.Content,
		ContentDigest:   record.ContentDigest,
		Artifact:        observation.Artifact,
		EventID:         observation.EventID,
		CreatedAt:       record.CreatedAt,
		AlreadyImported: duplicate,
	}
}

func artifactSummary(observation Observation) ArtifactSummary {
	record := observation.Record
	return ArtifactSummary{
		ID:            record.ID,
		Kind:          record.Kind,
		Title:         record.Title,
		SourcePath:    record.SourcePath,
		Repo:          record.Repo,
		CreatedAt:     record.CreatedAt,
		Revises:       record.Revises,
		Content:       record.Content,
		ContentDigest: record.ContentDigest,
		Artifact:      observation.Artifact,
		EventID:       observation.EventID,
	}
}

func childrenByParent(observations []Observation) map[string][]string {
	children := map[string][]string{}
	for _, observation := range observations {
		if observation.Record.Revises == "" {
			continue
		}
		children[observation.Record.Revises] = append(children[observation.Record.Revises], observation.Record.ID)
	}
	return children
}

func revisionBlockers(observations []Observation, children map[string][]string, component map[string]struct{}) []Blocker {
	blockers := []Blocker{}
	for parent, ids := range children {
		if _, relevant := component[parent]; !relevant {
			continue
		}
		unique := uniqueSorted(ids)
		if len(unique) > 1 {
			blockers = append(blockers, Blocker{
				Code:    "forked_revision",
				Message: fmt.Sprintf("artifact %s has multiple successors", parent),
				IDs:     unique,
			})
		}
	}
	for _, observation := range observations {
		if _, relevant := component[observation.Record.ID]; !relevant {
			continue
		}
		if observation.Record.Revises != "" {
			if _, ok := observationByID(observations, observation.Record.Revises); !ok {
				blockers = append(blockers, Blocker{
					Code:    "missing_revision_target",
					Message: fmt.Sprintf("artifact %s revises missing artifact %s", observation.Record.ID, observation.Record.Revises),
					IDs:     []string{observation.Record.ID, observation.Record.Revises},
				})
			}
		}
		if chainContains(observations, observation.Record.Revises, observation.Record.ID) {
			blockers = append(blockers, Blocker{
				Code:    "revision_cycle",
				Message: fmt.Sprintf("artifact %s participates in a revision cycle", observation.Record.ID),
				IDs:     []string{observation.Record.ID},
			})
		}
	}
	sort.Slice(blockers, func(i, j int) bool {
		if blockers[i].Code == blockers[j].Code {
			return strings.Join(blockers[i].IDs, ",") < strings.Join(blockers[j].IDs, ",")
		}
		return blockers[i].Code < blockers[j].Code
	})
	return blockers
}

func revisionComponent(observations []Observation, artifactID string, children map[string][]string) map[string]struct{} {
	component := map[string]struct{}{artifactID: {}}
	queue := []string{artifactID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if observation, ok := observationByID(observations, current); ok && observation.Record.Revises != "" {
			if _, seen := component[observation.Record.Revises]; !seen {
				component[observation.Record.Revises] = struct{}{}
				queue = append(queue, observation.Record.Revises)
			}
		}
		for _, child := range children[current] {
			if _, seen := component[child]; seen {
				continue
			}
			component[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	return component
}

func chainContains(observations []Observation, start, want string) bool {
	seen := map[string]struct{}{}
	for start != "" {
		if start == want {
			return true
		}
		if _, ok := seen[start]; ok {
			return true
		}
		seen[start] = struct{}{}
		observation, ok := observationByID(observations, start)
		if !ok {
			return false
		}
		start = observation.Record.Revises
	}
	return false
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func latestArtifactInComponent(component map[string]struct{}, children map[string][]string) string {
	leaves := []string{}
	for id := range component {
		childCount := 0
		for _, child := range children[id] {
			if _, ok := component[child]; ok {
				childCount++
			}
		}
		if childCount == 0 {
			leaves = append(leaves, id)
		}
	}
	sort.Strings(leaves)
	if len(leaves) == 0 {
		return ""
	}
	return leaves[0]
}

func latestPacketForArtifact(events []state.Event, repo, artifactID string) *PacketSummary {
	var latest *PacketSummary
	for _, event := range events {
		if event.Type != "packet.built" || event.Repo != repo || event.Details["artifact_id"] != artifactID {
			continue
		}
		packet := strings.TrimSpace(event.Details["packet"])
		if packet == "" {
			continue
		}
		latest = &PacketSummary{
			Packet:  packet,
			EventID: event.EventID,
			Route:   event.Details["route"],
			Kind:    event.Details["kind"],
			RunKind: event.Details["run_kind"],
		}
	}
	return latest
}

type artifactResultObservation struct {
	ArtifactID string
	Result     string
	EventID    string
	Record     reviewresult.ResultRecord
}

type artifactResultRecord struct {
	Packet       artifactResultPacketRef `json:"packet"`
	Route        string                  `json:"route"`
	Outcome      string                  `json:"outcome"`
	Findings     []artifactResultFinding `json:"findings"`
	NeedsContext []json.RawMessage       `json:"needs_context"`
}

type artifactResultPacketRef struct {
	Digest   string                        `json:"digest"`
	Kind     string                        `json:"kind"`
	RunKind  string                        `json:"run_kind"`
	Route    string                        `json:"route"`
	Artifact *artifactResultPacketArtifact `json:"artifact,omitempty"`
}

type artifactResultPacketArtifact struct {
	ID string `json:"id"`
}

type artifactResultFinding struct {
	ID           string `json:"id"`
	State        string `json:"state"`
	Severity     string `json:"severity"`
	Class        string `json:"class"`
	Claim        string `json:"claim"`
	Accepted     bool   `json:"accepted"`
	DuplicateOf  string `json:"duplicate_of,omitempty"`
	RejectReason string `json:"rejection_reason,omitempty"`
}

func artifactResultObservations(store state.Store, events []state.Event, repo string) ([]artifactResultObservation, error) {
	observations := []artifactResultObservation{}
	resultObservations, err := reviewresult.AllObservations(store, events, repo)
	if err != nil {
		return nil, err
	}
	for _, observation := range resultObservations {
		record := observation.Record
		if record.Route != reviewresult.RouteArtifactReview {
			continue
		}
		if record.Packet.Artifact == nil || strings.TrimSpace(record.Packet.Artifact.ID) == "" {
			return nil, errors.New("malformed artifact result record: missing artifact")
		}
		artifactID := record.Packet.Artifact.ID
		observations = append(observations, artifactResultObservation{
			ArtifactID: artifactID,
			Result:     observation.Digest,
			EventID:    observation.EventID,
			Record:     record,
		})
	}
	return observations, nil
}

func latestResultForArtifact(observations []artifactResultObservation, artifactID string) *artifactResultObservation {
	for i := range observations {
		if observations[i].ArtifactID == artifactID {
			return &observations[i]
		}
	}
	return nil
}

func (observation artifactResultObservation) summary() ResultSummary {
	return ResultSummary{
		Result:             observation.Result,
		EventID:            observation.EventID,
		Packet:             observation.Record.Packet.Digest,
		Outcome:            observation.Record.Outcome,
		Clean:              observation.Record.Outcome == "clean",
		FindingCount:       len(observation.Record.Findings),
		AcceptedFindings:   countArtifactFindings(observation.Record.Findings, "accepted"),
		DuplicateFindings:  countArtifactFindings(observation.Record.Findings, "duplicate"),
		RejectedStructural: countArtifactFindings(observation.Record.Findings, "rejected_structural"),
		NeedsContextCount:  len(observation.Record.NeedsContext),
	}
}

func countArtifactFindings(findings []reviewresult.FindingRecord, kind string) int {
	count := 0
	for _, finding := range findings {
		switch kind {
		case "accepted":
			if finding.Accepted {
				count++
			}
		case "duplicate":
			if finding.State == "duplicate" {
				count++
			}
		case "rejected_structural":
			if finding.State == "rejected_structural" {
				count++
			}
		}
	}
	return count
}

func supersededFindings(observations []artifactResultObservation, component map[string]struct{}, latestArtifactID string) []FindingSummary {
	out := []FindingSummary{}
	for _, observation := range observations {
		if observation.ArtifactID == latestArtifactID {
			continue
		}
		if _, ok := component[observation.ArtifactID]; !ok {
			continue
		}
		for _, finding := range observation.Record.Findings {
			if !finding.Accepted {
				continue
			}
			out = append(out, FindingSummary{
				ArtifactID: observation.ArtifactID,
				FindingID:  finding.ID,
				State:      finding.State,
				Severity:   finding.Severity,
				Class:      finding.Class,
				Claim:      finding.Claim,
				Result:     observation.Result,
				EventID:    observation.EventID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ArtifactID != out[j].ArtifactID {
			return out[i].ArtifactID < out[j].ArtifactID
		}
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].FindingID < out[j].FindingID
	})
	return out
}

func containsDigest(digests []string, digest string) bool {
	for _, item := range digests {
		if item == digest {
			return true
		}
	}
	return false
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
		return errors.New("state validation failed")
	}
	first := result.Errors[0]
	if first.Line > 0 {
		return fmt.Errorf("state validation failed: %s:%d: %s: %s", first.Path, first.Line, first.Code, first.Message)
	}
	return fmt.Errorf("state validation failed: %s: %s: %s", first.Path, first.Code, first.Message)
}

func recordPathBestEffort(contentPath, digest string) string {
	if contentPath == "" {
		return ""
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(contentPath))))
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return ""
	}
	path := filepath.Join(root, "objects", "sha256", hexDigest[:2], hexDigest)
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}
