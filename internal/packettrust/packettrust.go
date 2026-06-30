package packettrust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const EventTypePacketBuilt = "packet.built"

type Ref struct {
	Digest                 string          `json:"digest"`
	EventID                string          `json:"event_id"`
	Kind                   string          `json:"kind"`
	RunKind                string          `json:"run_kind"`
	Route                  string          `json:"route"`
	PromptDigest           string          `json:"prompt_digest"`
	StableDigest           string          `json:"stable_digest"`
	VolatileDigest         string          `json:"volatile_digest,omitempty"`
	SemanticDedupeDigest   string          `json:"semantic_dedupe_digest"`
	Policy                 *PolicyRef      `json:"policy,omitempty"`
	Artifact               *PacketArtifact `json:"artifact,omitempty"`
	CoverageManifest       state.ObjectRef `json:"coverage_manifest"`
	TargetState            SnapshotRef     `json:"target_state"`
	SourceCompleteness     string          `json:"source_completeness"`
	VerificationFindingID  string          `json:"verification_finding_id,omitempty"`
	VerificationFindingIDs []string        `json:"verification_finding_ids,omitempty"`
}

type PolicyRef struct {
	Profile  string `json:"profile"`
	PolicyID string `json:"policy_id"`
	Digest   string `json:"digest"`
}

type SnapshotRef struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	Tree   string `json:"tree,omitempty"`
}

type PacketArtifact struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	Revises       string          `json:"revises,omitempty"`
	Content       state.ObjectRef `json:"content"`
	ContentDigest string          `json:"content_digest"`
	Artifact      state.ObjectRef `json:"artifact"`
}

type packetRecord struct {
	SchemaVersion     int             `json:"schema_version"`
	Kind              string          `json:"kind"`
	RunKind           string          `json:"run_kind"`
	Route             string          `json:"route"`
	Repo              string          `json:"repo"`
	Policy            *PolicyRef      `json:"policy,omitempty"`
	Artifact          *PacketArtifact `json:"artifact,omitempty"`
	TargetState       SnapshotRef     `json:"target_state"`
	CoverageManifest  state.ObjectRef `json:"coverage_manifest"`
	StablePrefix      string          `json:"stable_prefix"`
	VolatileSuffix    string          `json:"volatile_suffix"`
	StableDigest      string          `json:"stable_digest"`
	VolatileDigest    string          `json:"volatile_digest"`
	PromptDigest      string          `json:"prompt_digest"`
	SemanticDedupeKey struct {
		Digest string `json:"digest"`
	} `json:"semantic_dedupe_key"`
	SourceCompleteness string              `json:"source_completeness"`
	Verification       *verificationRecord `json:"verification,omitempty"`
}

type verificationRecord struct {
	Finding    *verificationFinding  `json:"finding,omitempty"`
	Findings   []verificationFinding `json:"findings,omitempty"`
	FindingIDs []string              `json:"finding_ids,omitempty"`
}

type verificationFinding struct {
	ID string `json:"id"`
}

func Resolve(store state.Store, events []state.Event, stateDir, repo, packetID string) (Ref, error) {
	packetID = strings.TrimSpace(packetID)
	if packetID == "" {
		return Ref{}, errors.New("--packet is required")
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != EventTypePacketBuilt {
			continue
		}
		if event.Repo != repo {
			return Ref{}, errors.New("malformed packet.built event: repo mismatch")
		}
		candidates := []string{event.Details["packet"], event.Details["semantic_dedupe_digest"], event.EventID}
		if !contains(candidates, packetID) {
			continue
		}
		return ResolveEvent(store, stateDir, repo, event)
	}
	return Ref{}, fmt.Errorf("packet not found in state: %s", packetID)
}

func ResolveEvent(store state.Store, stateDir, repo string, event state.Event) (Ref, error) {
	if event.Type != EventTypePacketBuilt {
		return Ref{}, fmt.Errorf("event is not packet.built: %s", event.Type)
	}
	if event.Repo != repo {
		return Ref{}, errors.New("malformed packet.built event: repo mismatch")
	}
	digest := strings.TrimSpace(event.Details["packet"])
	if digest == "" {
		return Ref{}, errors.New("malformed packet.built event: missing packet")
	}
	if !contains(event.ObjectDigests, digest) {
		return Ref{}, errors.New("malformed packet.built event: object_digests missing packet")
	}
	body, err := store.Read(digest)
	if err != nil {
		return Ref{}, err
	}
	var record packetRecord
	if err := json.Unmarshal(body, &record); err != nil {
		return Ref{}, err
	}
	if err := validateRecord(record, repo); err != nil {
		return Ref{}, err
	}
	if err := validateEventConsistency(store, event, record); err != nil {
		return Ref{}, err
	}
	ref := refFromRecord(stateDir, digest, event.EventID, record)
	return ref, nil
}

func validateRecord(record packetRecord, repo string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported packet schema_version: %d", record.SchemaVersion)
	}
	if record.Repo != repo {
		return errors.New("packet repo mismatch")
	}
	if strings.TrimSpace(record.Kind) == "" || strings.TrimSpace(record.RunKind) == "" || strings.TrimSpace(record.Route) == "" {
		return errors.New("packet kind, run_kind, and route are required")
	}
	if record.StableDigest == "" || record.PromptDigest == "" || record.SemanticDedupeKey.Digest == "" {
		return errors.New("packet missing stable, prompt, or semantic digest")
	}
	if got := digestString(record.StablePrefix); got != record.StableDigest {
		return fmt.Errorf("packet stable_digest mismatch: %s != %s", got, record.StableDigest)
	}
	if record.VolatileDigest != "" {
		if got := digestString(record.VolatileSuffix); got != record.VolatileDigest {
			return fmt.Errorf("packet volatile_digest mismatch: %s != %s", got, record.VolatileDigest)
		}
	}
	if record.Kind == "artifact" || record.Route == "artifact_review" {
		if record.Kind != "artifact" || record.RunKind != "discovery" || record.Route != "artifact_review" {
			return errors.New("artifact packet route is malformed")
		}
		if record.Artifact == nil || strings.TrimSpace(record.Artifact.ID) == "" || record.Artifact.Artifact.Digest == "" || record.Artifact.Content.Digest == "" {
			return errors.New("artifact packet missing artifact reference")
		}
		return nil
	}
	if record.CoverageManifest.Digest == "" || record.TargetState.Digest == "" {
		return errors.New("packet missing coverage_manifest or target_state")
	}
	if record.RunKind == "verification" || record.Route == "targeted_verification" {
		ids := verificationIDs(record.Verification)
		if len(ids) == 0 {
			return errors.New("verification packet missing finding_ids")
		}
	}
	return nil
}

func validateEventConsistency(store state.Store, event state.Event, record packetRecord) error {
	if event.Details["kind"] != record.Kind {
		return fmt.Errorf("packet.built kind mismatch: %s != %s", event.Details["kind"], record.Kind)
	}
	if event.Details["run_kind"] != record.RunKind {
		return fmt.Errorf("packet.built run_kind mismatch: %s != %s", event.Details["run_kind"], record.RunKind)
	}
	if event.Details["route"] != record.Route {
		return fmt.Errorf("packet.built route mismatch: %s != %s", event.Details["route"], record.Route)
	}
	if event.Details["stable_digest"] != record.StableDigest {
		return errors.New("packet.built stable_digest mismatch")
	}
	if event.Details["prompt_digest"] != record.PromptDigest {
		return errors.New("packet.built prompt_digest mismatch")
	}
	if event.Details["semantic_dedupe_digest"] != record.SemanticDedupeKey.Digest {
		return errors.New("packet.built semantic_dedupe_digest mismatch")
	}
	if record.VolatileDigest != "" && event.Details["volatile_digest"] != record.VolatileDigest {
		return errors.New("packet.built volatile_digest mismatch")
	}
	if sourceCompleteness := strings.TrimSpace(event.Details["source_completeness"]); sourceCompleteness != "" && sourceCompleteness != record.SourceCompleteness {
		return errors.New("packet.built source_completeness mismatch")
	}
	markdownDigest := strings.TrimSpace(event.Details["markdown"])
	if markdownDigest == "" {
		return errors.New("malformed packet.built event: missing markdown")
	}
	if !contains(event.ObjectDigests, markdownDigest) {
		return errors.New("malformed packet.built event: object_digests missing markdown")
	}
	if markdownDigest != record.PromptDigest {
		return errors.New("packet markdown digest does not match prompt_digest")
	}
	if _, err := store.Read(markdownDigest); err != nil {
		return err
	}
	if record.CoverageManifest.Digest != "" && event.Details["coverage_manifest"] != record.CoverageManifest.Digest {
		return errors.New("packet.built coverage_manifest mismatch")
	}
	if record.TargetState.Digest != "" && event.Details["target_state"] != record.TargetState.Digest {
		return errors.New("packet.built target_state mismatch")
	}
	if record.Artifact != nil {
		if event.Details["artifact_id"] != record.Artifact.ID {
			return errors.New("packet.built artifact_id mismatch")
		}
		if event.Details["artifact"] != record.Artifact.Artifact.Digest {
			return errors.New("packet.built artifact digest mismatch")
		}
		if event.Details["artifact_content"] != record.Artifact.Content.Digest {
			return errors.New("packet.built artifact content mismatch")
		}
	}
	ids := verificationIDs(record.Verification)
	if len(ids) == 1 {
		if event.Details["finding_id"] != ids[0] {
			return errors.New("packet.built finding_id mismatch")
		}
	} else if len(ids) > 1 {
		if strings.TrimSpace(event.Details["finding_id"]) != "" {
			return errors.New("batch verification packet must not set legacy finding_id")
		}
		if splitIDs(event.Details["finding_ids"]) == nil || strings.Join(splitIDs(event.Details["finding_ids"]), ",") != strings.Join(ids, ",") {
			return errors.New("packet.built finding_ids mismatch")
		}
	}
	return nil
}

func refFromRecord(stateDir, digest, eventID string, record packetRecord) Ref {
	ids := verificationIDs(record.Verification)
	legacyID := ""
	if len(ids) == 1 {
		legacyID = ids[0]
	}
	ref := Ref{
		Digest:                 digest,
		EventID:                eventID,
		Kind:                   record.Kind,
		RunKind:                record.RunKind,
		Route:                  record.Route,
		PromptDigest:           record.PromptDigest,
		StableDigest:           record.StableDigest,
		VolatileDigest:         record.VolatileDigest,
		SemanticDedupeDigest:   record.SemanticDedupeKey.Digest,
		Policy:                 copyPolicy(record.Policy),
		Artifact:               copyArtifact(record.Artifact),
		TargetState:            record.TargetState,
		SourceCompleteness:     record.SourceCompleteness,
		VerificationFindingID:  legacyID,
		VerificationFindingIDs: ids,
	}
	if record.CoverageManifest.Digest != "" {
		ref.CoverageManifest = record.CoverageManifest
		ref.CoverageManifest.Path = ObjectPathBestEffort(stateDir, record.CoverageManifest.Digest)
	}
	return ref
}

func verificationIDs(record *verificationRecord) []string {
	if record == nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range record.FindingIDs {
		add(id)
	}
	if record.Finding != nil {
		add(record.Finding.ID)
	}
	for _, finding := range record.Findings {
		add(finding.ID)
	}
	sort.Strings(out)
	return out
}

func splitIDs(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		id := strings.TrimSpace(part)
		if id == "" {
			return nil
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func copyPolicy(policy *PolicyRef) *PolicyRef {
	if policy == nil {
		return nil
	}
	ref := *policy
	return &ref
}

func copyArtifact(artifact *PacketArtifact) *PacketArtifact {
	if artifact == nil {
		return nil
	}
	ref := *artifact
	return &ref
}

func ObjectPathBestEffort(stateDir, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return ""
	}
	path := filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest)
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func digestString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
