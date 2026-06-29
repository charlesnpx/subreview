package result

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	EventTypeImported = "result.imported"

	MediaTypeRaw    = "application/vnd.subreview.worker-result.raw+json"
	MediaTypeResult = "application/vnd.subreview.worker-result+json"

	RunKindDiscovery    = "discovery"
	RunKindVerification = "verification"

	RoutePrimaryReview        = "primary_review"
	RouteIndependentFinal     = "independent_final_review"
	RouteTargetedVerification = "targeted_verification"
	RouteCompactFreshVerify   = "compact_fresh_verification"
	RouteArtifactReview       = "artifact_review"

	OutcomeClean        = "clean"
	OutcomeFindings     = "findings"
	OutcomeNeedsContext = "needs_context"
	OutcomeVerification = "verification"

	VerificationResolved             = "resolved"
	VerificationNotResolved          = "not_resolved"
	VerificationRegressionIntroduced = "regression_introduced"
	VerificationInsufficientContext  = "insufficient_context"
	VerificationFindingInvalid       = "finding_invalid"
	VerificationUnexpectedScope      = "unexpected_scope"
	VerificationDeterministicRefuted = "deterministic_refuted"

	StateOpen               = "open"
	StateResolved           = "resolved"
	StateVerified           = "verified"
	StateInvalidated        = "invalidated"
	StateNeedsContext       = "needs_context"
	StateNeedsConfirmation  = "needs_confirmation"
	StateRejectedStructural = "rejected_structural"
	StateDuplicate          = "duplicate"
	StateUnknown            = "unknown"

	BasisDeterministicRefutation = "deterministic_refutation"
	BasisExecutableRefutation    = "executable_refutation"
	BasisFreshSemantic           = "fresh_semantic_verification"
	BasisFixVerification         = "fix_verification"

	RelationFreshBlinded = "fresh_blinded"

	RelationEvidenceCLIWitnessed   = "cli_witnessed"
	RelationEvidenceCallerAssert   = "caller_asserted"
	RelationEvidenceExternalAssert = "external_asserted"

	SatisfactionPrimaryReviewEvidence = "primary_review_evidence"
	SatisfactionDeterministicRefute   = "deterministic_refutation"

	maxResultBytes          = 256 * 1024
	maxFindings             = 64
	maxContextRequests      = 16
	maxVerifierOutcomes     = 64
	maxRefutations          = 64
	maxRequiredChecks       = 32
	maxRefsPerFinding       = 12
	maxFixSurfaceEntries    = 12
	maxClaimBytes           = 500
	maxFailureScenarioBytes = 1000
	maxSummaryBytes         = 1000
	maxQuestionBytes        = 500
	maxReasonBytes          = 700
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type ImportOptions struct {
	StateDir   string
	PacketID   string
	ResultPath string
	Now        time.Time
}

type ImportResult struct {
	SchemaVersion                   int             `json:"schema_version"`
	State                           string          `json:"state"`
	Repo                            string          `json:"repo"`
	PacketID                        string          `json:"packet_id"`
	ArtifactID                      string          `json:"artifact_id,omitempty"`
	Outcome                         string          `json:"outcome"`
	RawResult                       state.ObjectRef `json:"raw_result"`
	Result                          state.ObjectRef `json:"result"`
	EventID                         string          `json:"event_id"`
	FindingCount                    int             `json:"finding_count"`
	AcceptedFindingCount            int             `json:"accepted_finding_count"`
	DuplicateFindingCount           int             `json:"duplicate_finding_count"`
	RejectedStructuralCount         int             `json:"rejected_structural_count"`
	NeedsContextCount               int             `json:"needs_context_count"`
	VerifierOutcomeCount            int             `json:"verifier_outcome_count"`
	DeterministicRefutationCount    int             `json:"deterministic_refutation_count"`
	PrimaryReviewEvidence           bool            `json:"primary_review_evidence"`
	IndependentFinalReviewEvidence  bool            `json:"independent_final_review_evidence"`
	DeterministicRefutationEvidence bool            `json:"deterministic_refutation_evidence"`
}

type WorkerResult struct {
	SchemaVersion            int                            `json:"schema_version"`
	Packet                   string                         `json:"packet"`
	RunKind                  string                         `json:"run_kind"`
	Route                    string                         `json:"route"`
	Outcome                  string                         `json:"outcome"`
	Summary                  string                         `json:"summary,omitempty"`
	Findings                 []FindingInput                 `json:"findings,omitempty"`
	NeedsContext             []ContextRequest               `json:"needs_context,omitempty"`
	RequiredChecks           []RequiredCheck                `json:"required_checks,omitempty"`
	VerifierOutcomes         []VerifierOutcomeInput         `json:"verifier_outcomes,omitempty"`
	DeterministicRefutations []DeterministicRefutationInput `json:"deterministic_refutations,omitempty"`
	Telemetry                TokenTelemetry                 `json:"telemetry,omitempty"`
}

type FindingInput struct {
	ID                 string        `json:"id,omitempty"`
	State              string        `json:"state,omitempty"`
	Severity           string        `json:"severity"`
	Class              string        `json:"class"`
	Claim              string        `json:"claim"`
	FailureScenario    string        `json:"failure_scenario"`
	Citations          []LineRef     `json:"citations,omitempty"`
	Anchors            []AnchorRef   `json:"anchors,omitempty"`
	ArtifactRefs       []ArtifactRef `json:"artifact_refs,omitempty"`
	ExpectedFixSurface []FixSurface  `json:"expected_fix_surface,omitempty"`
}

type LineRef struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Quote     string `json:"quote,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type AnchorRef struct {
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	StartLine    int    `json:"start_line,omitempty"`
	EndLine      int    `json:"end_line,omitempty"`
	ObligationID string `json:"obligation_id,omitempty"`
}

type FixSurface struct {
	Kind      string `json:"kind,omitempty"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type ArtifactRef struct {
	ArtifactID  string `json:"artifact_id"`
	Section     string `json:"section,omitempty"`
	StoryID     string `json:"story_id,omitempty"`
	MergeUnitID string `json:"merge_unit_id,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	Quote       string `json:"quote,omitempty"`
}

type ContextRequest struct {
	Question string   `json:"question"`
	Reason   string   `json:"reason,omitempty"`
	Paths    []string `json:"paths,omitempty"`
}

type RequiredCheck struct {
	CommandID string `json:"command_id"`
	Reason    string `json:"reason,omitempty"`
}

type VerifierOutcomeInput struct {
	FindingID        string `json:"finding_id"`
	Outcome          string `json:"outcome,omitempty"`
	State            string `json:"state"`
	Basis            string `json:"basis"`
	Summary          string `json:"summary"`
	VerifierRelation string `json:"verifier_relation,omitempty"`
	RelationEvidence string `json:"relation_evidence,omitempty"`
}

type DeterministicRefutationInput struct {
	ID            string        `json:"id,omitempty"`
	FindingID     string        `json:"finding_id,omitempty"`
	ObligationIDs []string      `json:"obligation_ids,omitempty"`
	Basis         string        `json:"basis"`
	EvidenceKind  string        `json:"evidence_kind"`
	Summary       string        `json:"summary"`
	Citations     []LineRef     `json:"citations,omitempty"`
	EvidenceRefs  []EvidenceRef `json:"evidence_refs,omitempty"`
}

type EvidenceRef struct {
	Kind      string `json:"kind"`
	Digest    string `json:"digest,omitempty"`
	EventID   string `json:"event_id,omitempty"`
	CommandID string `json:"command_id,omitempty"`
}

type TokenTelemetry struct {
	SchemaVersion                 int    `json:"schema_version,omitempty"`
	GrossDiscoveryTokens          int    `json:"gross_discovery_tokens,omitempty"`
	IncrementalDiscoveryTokens    int    `json:"incremental_discovery_tokens,omitempty"`
	GrossVerificationTokens       int    `json:"gross_verification_tokens,omitempty"`
	IncrementalVerificationTokens int    `json:"incremental_verification_tokens,omitempty"`
	GrossInputTokens              int    `json:"gross_input_tokens,omitempty"`
	IncrementalInputTokens        int    `json:"incremental_input_tokens,omitempty"`
	CachedInputTokens             int    `json:"cached_input_tokens,omitempty"`
	OutputTokens                  int    `json:"output_tokens,omitempty"`
	ReasoningTokens               int    `json:"reasoning_tokens,omitempty"`
	LatencyMS                     int64  `json:"latency_ms,omitempty"`
	Backend                       string `json:"backend,omitempty"`
	Model                         string `json:"model,omitempty"`
	Effort                        string `json:"effort,omitempty"`
	TokenMeasurement              string `json:"token_measurement,omitempty"`
}

type ResultRecord struct {
	SchemaVersion            int                       `json:"schema_version"`
	Repo                     string                    `json:"repo"`
	ImportedAt               string                    `json:"imported_at"`
	Packet                   PacketRef                 `json:"packet"`
	RunKind                  string                    `json:"run_kind"`
	Route                    string                    `json:"route"`
	Outcome                  string                    `json:"outcome"`
	Summary                  string                    `json:"summary,omitempty"`
	RawResult                state.ObjectRef           `json:"raw_result"`
	Findings                 []FindingRecord           `json:"findings"`
	NeedsContext             []ContextRequest          `json:"needs_context"`
	RequiredChecks           []RequiredCheck           `json:"required_checks"`
	VerifierOutcomes         []VerifierOutcome         `json:"verifier_outcomes"`
	DeterministicRefutations []DeterministicRefutation `json:"deterministic_refutations"`
	Telemetry                TokenTelemetry            `json:"telemetry"`
	Evidence                 EvidenceSummary           `json:"evidence"`
}

type PacketRef struct {
	Digest                string          `json:"digest"`
	EventID               string          `json:"event_id"`
	Kind                  string          `json:"kind"`
	RunKind               string          `json:"run_kind"`
	Route                 string          `json:"route"`
	PromptDigest          string          `json:"prompt_digest"`
	StableDigest          string          `json:"stable_digest"`
	SemanticDedupeDigest  string          `json:"semantic_dedupe_digest"`
	Policy                *PolicyRef      `json:"policy,omitempty"`
	Artifact              *PacketArtifact `json:"artifact,omitempty"`
	CoverageManifest      state.ObjectRef `json:"coverage_manifest"`
	TargetState           SnapshotRef     `json:"target_state"`
	SourceCompleteness    string          `json:"source_completeness"`
	VerificationFindingID string          `json:"verification_finding_id,omitempty"`
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

type FindingRecord struct {
	ID                 string        `json:"id"`
	SourceID           string        `json:"source_id,omitempty"`
	DedupeDigest       string        `json:"dedupe_digest"`
	State              string        `json:"state"`
	Severity           string        `json:"severity"`
	Class              string        `json:"class"`
	Claim              string        `json:"claim"`
	FailureScenario    string        `json:"failure_scenario"`
	Citations          []LineRef     `json:"citations"`
	Anchors            []AnchorRef   `json:"anchors"`
	ArtifactRefs       []ArtifactRef `json:"artifact_refs,omitempty"`
	ExpectedFixSurface []FixSurface  `json:"expected_fix_surface"`
	Accepted           bool          `json:"accepted"`
	Blocking           bool          `json:"blocking"`
	DuplicateOf        string        `json:"duplicate_of,omitempty"`
	RejectionReason    string        `json:"rejection_reason,omitempty"`
}

type VerifierOutcome struct {
	FindingID        string `json:"finding_id"`
	Outcome          string `json:"outcome"`
	State            string `json:"state"`
	Basis            string `json:"basis"`
	Summary          string `json:"summary"`
	VerifierRelation string `json:"verifier_relation,omitempty"`
	RelationEvidence string `json:"relation_evidence,omitempty"`
}

type DeterministicRefutation struct {
	ID            string        `json:"id"`
	FindingID     string        `json:"finding_id,omitempty"`
	ObligationIDs []string      `json:"obligation_ids,omitempty"`
	Basis         string        `json:"basis"`
	EvidenceKind  string        `json:"evidence_kind"`
	Summary       string        `json:"summary"`
	Citations     []LineRef     `json:"citations"`
	EvidenceRefs  []EvidenceRef `json:"evidence_refs"`
}

type EvidenceSummary struct {
	PrimaryReviewEvidence           bool     `json:"primary_review_evidence"`
	IndependentFinalReviewEvidence  bool     `json:"independent_final_review_evidence"`
	DeterministicRefutationEvidence bool     `json:"deterministic_refutation_evidence"`
	SatisfactionKinds               []string `json:"satisfaction_kinds"`
	OpenBlockingFindings            int      `json:"open_blocking_findings"`
}

type EvidenceObservation struct {
	Record  ResultRecord `json:"record"`
	Digest  string       `json:"digest"`
	EventID string       `json:"event_id"`
}

type FindingBlocker struct {
	FindingID string `json:"finding_id"`
	State     string `json:"state"`
	Severity  string `json:"severity"`
	Class     string `json:"class"`
	Claim     string `json:"claim"`
	EventID   string `json:"event_id"`
	Digest    string `json:"digest"`
}

type packetRecord struct {
	SchemaVersion     int             `json:"schema_version"`
	Kind              string          `json:"kind"`
	RunKind           string          `json:"run_kind"`
	Route             string          `json:"route"`
	Repo              string          `json:"repo"`
	Policy            *PolicyRef      `json:"policy,omitempty"`
	Artifact          *PacketArtifact `json:"artifact,omitempty"`
	CoverageManifest  state.ObjectRef `json:"coverage_manifest"`
	TargetState       SnapshotRef     `json:"target_state"`
	StableDigest      string          `json:"stable_digest"`
	PromptDigest      string          `json:"prompt_digest"`
	SemanticDedupeKey struct {
		Digest string `json:"digest"`
	} `json:"semantic_dedupe_key"`
	Verification struct {
		Finding struct {
			ID string `json:"id"`
		} `json:"finding"`
	} `json:"verification"`
	SourceCompleteness string `json:"source_completeness"`
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
	store, err := state.Open(binding.State)
	if err != nil {
		return ImportResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return ImportResult{}, err
	}
	packetRef, err := resolvePacket(store, events, binding.State, binding.Repo, opts.PacketID)
	if err != nil {
		return ImportResult{}, err
	}
	raw, err := readBoundedRegularFile(opts.ResultPath)
	if err != nil {
		return ImportResult{}, err
	}
	var input WorkerResult
	if err := decodeStrict(raw, &input); err != nil {
		return ImportResult{}, fmt.Errorf("malformed worker result: %w", err)
	}
	existingDigests, existingIDs, err := existingFindingIdentity(store, events, binding.Repo, packetRef)
	if err != nil {
		return ImportResult{}, err
	}
	record, err := normalizeWorkerResult(input, packetRef, binding.Repo, now, existingDigests, existingIDs)
	if err != nil {
		return ImportResult{}, err
	}
	rawRef, err := store.PutBytes(raw, MediaTypeRaw)
	if err != nil {
		return ImportResult{}, err
	}
	record.RawResult = rawRef
	resultRef, err := store.PutJSON(record, MediaTypeResult)
	if err != nil {
		return ImportResult{}, err
	}
	details := map[string]string{
		"result":                            resultRef.Digest,
		"raw_result":                        rawRef.Digest,
		"packet":                            packetRef.Digest,
		"run_kind":                          record.RunKind,
		"route":                             record.Route,
		"outcome":                           record.Outcome,
		"clean":                             strconv.FormatBool(record.Outcome == OutcomeClean),
		"findings":                          strconv.Itoa(len(record.Findings)),
		"accepted_findings":                 strconv.Itoa(countAcceptedFindings(record.Findings)),
		"duplicate_findings":                strconv.Itoa(countFindingState(record.Findings, StateDuplicate)),
		"rejected_structural":               strconv.Itoa(countFindingState(record.Findings, StateRejectedStructural)),
		"needs_context":                     strconv.FormatBool(len(record.NeedsContext) > 0),
		"needs_context_count":               strconv.Itoa(len(record.NeedsContext)),
		"primary_review_evidence":           strconv.FormatBool(record.Evidence.PrimaryReviewEvidence),
		"deterministic_refutation_evidence": strconv.FormatBool(record.Evidence.DeterministicRefutationEvidence),
	}
	if packetRef.CoverageManifest.Digest != "" {
		details["coverage_manifest"] = packetRef.CoverageManifest.Digest
	}
	if packetRef.TargetState.Digest != "" {
		details["target_state"] = packetRef.TargetState.Digest
	}
	artifactID := ""
	if packetRef.Artifact != nil {
		artifactID = packetRef.Artifact.ID
		details["artifact_id"] = packetRef.Artifact.ID
		details["artifact"] = packetRef.Artifact.Artifact.Digest
		details["artifact_content"] = packetRef.Artifact.Content.Digest
	}
	if record.Evidence.IndependentFinalReviewEvidence {
		details["independent_final_review_evidence"] = "true"
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          EventTypeImported,
		ObjectDigests: []string{rawRef.Digest, resultRef.Digest},
		Repo:          binding.Repo,
		Details:       details,
	})
	if err != nil {
		return ImportResult{}, err
	}
	return ImportResult{
		SchemaVersion:                   SchemaVersion,
		State:                           binding.State,
		Repo:                            binding.Repo,
		PacketID:                        packetRef.Digest,
		ArtifactID:                      artifactID,
		Outcome:                         record.Outcome,
		RawResult:                       rawRef,
		Result:                          resultRef,
		EventID:                         event.EventID,
		FindingCount:                    len(record.Findings),
		AcceptedFindingCount:            countAcceptedFindings(record.Findings),
		DuplicateFindingCount:           countFindingState(record.Findings, StateDuplicate),
		RejectedStructuralCount:         countFindingState(record.Findings, StateRejectedStructural),
		NeedsContextCount:               len(record.NeedsContext),
		VerifierOutcomeCount:            len(record.VerifierOutcomes),
		DeterministicRefutationCount:    len(record.DeterministicRefutations),
		PrimaryReviewEvidence:           record.Evidence.PrimaryReviewEvidence,
		IndependentFinalReviewEvidence:  record.Evidence.IndependentFinalReviewEvidence,
		DeterministicRefutationEvidence: record.Evidence.DeterministicRefutationEvidence,
	}, nil
}

func Observations(store state.Store, events []state.Event, repo string) ([]EvidenceObservation, error) {
	return observations(store, events, repo, false)
}

func observations(store state.Store, events []state.Event, repo string, includeArtifact bool) ([]EvidenceObservation, error) {
	observations := []EvidenceObservation{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != EventTypeImported {
			continue
		}
		if event.Repo != repo {
			return nil, errors.New("malformed result.imported event: repo mismatch")
		}
		digest := event.Details["result"]
		if strings.TrimSpace(digest) == "" {
			return nil, errors.New("malformed result.imported event: missing result")
		}
		if !containsDigest(event.ObjectDigests, digest) {
			return nil, errors.New("malformed result.imported event: object_digests missing result")
		}
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var record ResultRecord
		if err := decodeStrict(body, &record); err != nil {
			return nil, err
		}
		if err := validateRecord(record, repo, event.Details["packet"]); err != nil {
			return nil, err
		}
		if !includeArtifact && record.Route == RouteArtifactReview {
			continue
		}
		observations = append(observations, EvidenceObservation{Record: record, Digest: digest, EventID: event.EventID})
	}
	return observations, nil
}

func LatestPrimaryReviewForManifest(observations []EvidenceObservation, manifestDigest string) (EvidenceObservation, bool) {
	for _, observation := range observations {
		record := observation.Record
		if record.Packet.CoverageManifest.Digest != manifestDigest {
			continue
		}
		if record.Evidence.PrimaryReviewEvidence {
			return observation, true
		}
	}
	return EvidenceObservation{}, false
}

func LatestPrimaryReviewForTargetState(observations []EvidenceObservation, targetDigest, policyDigest string) (EvidenceObservation, bool) {
	observation, ok := LatestDiscoveryForTargetState(observations, targetDigest, policyDigest)
	if !ok || !observation.Record.Evidence.PrimaryReviewEvidence {
		return EvidenceObservation{}, false
	}
	return observation, true
}

func LatestDiscoveryForTargetState(observations []EvidenceObservation, targetDigest, policyDigest string) (EvidenceObservation, bool) {
	for _, observation := range observations {
		record := observation.Record
		if record.RunKind != RunKindDiscovery || record.Route != RoutePrimaryReview {
			continue
		}
		if record.Packet.TargetState.Kind != "proposal" || record.Packet.TargetState.Digest != targetDigest {
			continue
		}
		if !packetPolicyMatches(record.Packet.Policy, policyDigest) {
			continue
		}
		return observation, true
	}
	return EvidenceObservation{}, false
}

func LatestIndependentFinalReviewForManifest(observations []EvidenceObservation, manifestDigest string) (EvidenceObservation, bool) {
	for _, observation := range observations {
		record := observation.Record
		if record.Packet.CoverageManifest.Digest != manifestDigest {
			continue
		}
		if record.Evidence.IndependentFinalReviewEvidence {
			return observation, true
		}
	}
	return EvidenceObservation{}, false
}

func DeterministicRefutationsForObligation(observations []EvidenceObservation, manifestDigest, obligationID string) []EvidenceObservation {
	matches := []EvidenceObservation{}
	for _, observation := range observations {
		if observation.Record.Packet.CoverageManifest.Digest != manifestDigest {
			continue
		}
		for _, refutation := range observation.Record.DeterministicRefutations {
			if containsString(refutation.ObligationIDs, obligationID) {
				matches = append(matches, observation)
				break
			}
		}
	}
	return matches
}

func ActiveFindingBlockers(observations []EvidenceObservation, manifestDigest string) []FindingBlocker {
	return findingBlockers(observations, func(record ResultRecord) bool {
		return record.Packet.CoverageManifest.Digest == manifestDigest
	})
}

func ClosureFindingBlockers(observations []EvidenceObservation, manifestDigest, proposalDigest, policyDigest string) []FindingBlocker {
	return findingBlockers(observations, func(record ResultRecord) bool {
		if record.Packet.CoverageManifest.Digest == manifestDigest {
			return true
		}
		return record.Evidence.PrimaryReviewEvidence &&
			record.Packet.TargetState.Kind == "proposal" &&
			record.Packet.TargetState.Digest == proposalDigest &&
			packetPolicyMatches(record.Packet.Policy, policyDigest)
	})
}

func findingBlockers(observations []EvidenceObservation, applies func(ResultRecord) bool) []FindingBlocker {
	type lifecycle struct {
		finding FindingRecord
		state   string
		eventID string
		digest  string
	}
	byID := map[string]lifecycle{}
	for i := len(observations) - 1; i >= 0; i-- {
		observation := observations[i]
		record := observation.Record
		if !applies(record) {
			continue
		}
		for _, finding := range record.Findings {
			if !finding.Accepted {
				continue
			}
			byID[finding.ID] = lifecycle{finding: finding, state: finding.State, eventID: observation.EventID, digest: observation.Digest}
		}
		for _, outcome := range record.VerifierOutcomes {
			current, ok := byID[outcome.FindingID]
			if !ok {
				continue
			}
			current.state = outcome.State
			current.eventID = observation.EventID
			current.digest = observation.Digest
			byID[outcome.FindingID] = current
		}
		for _, refutation := range record.DeterministicRefutations {
			if refutation.FindingID == "" {
				continue
			}
			current, ok := byID[refutation.FindingID]
			if !ok {
				continue
			}
			current.state = StateInvalidated
			current.eventID = observation.EventID
			current.digest = observation.Digest
			byID[refutation.FindingID] = current
		}
	}
	blockers := []FindingBlocker{}
	for id, item := range byID {
		if !blocksClosure(item.state) {
			continue
		}
		blockers = append(blockers, FindingBlocker{
			FindingID: id,
			State:     item.state,
			Severity:  item.finding.Severity,
			Class:     item.finding.Class,
			Claim:     item.finding.Claim,
			EventID:   item.eventID,
			Digest:    item.digest,
		})
	}
	sort.Slice(blockers, func(i, j int) bool {
		if blockers[i].Severity == blockers[j].Severity {
			return blockers[i].FindingID < blockers[j].FindingID
		}
		return severityRank(blockers[i].Severity) > severityRank(blockers[j].Severity)
	})
	return blockers
}

func packetPolicyMatches(policy *PolicyRef, policyDigest string) bool {
	policyDigest = strings.TrimSpace(policyDigest)
	if policyDigest == "" {
		return policy == nil || strings.TrimSpace(policy.Digest) == ""
	}
	return policy != nil && policy.Digest == policyDigest
}

func normalizeWorkerResult(input WorkerResult, packet PacketRef, repo string, now time.Time, existingDigests map[string]struct{}, existingIDs map[string]string) (ResultRecord, error) {
	if input.SchemaVersion != SchemaVersion {
		return ResultRecord{}, fmt.Errorf("unsupported worker result schema_version: %d", input.SchemaVersion)
	}
	if input.Packet != packet.Digest && input.Packet != packet.EventID && input.Packet != packet.SemanticDedupeDigest {
		return ResultRecord{}, fmt.Errorf("worker result packet %q does not match --packet %s", input.Packet, packet.Digest)
	}
	runKind := strings.TrimSpace(input.RunKind)
	if runKind == "" {
		runKind = packet.RunKind
	}
	if !validRunKind(runKind) {
		return ResultRecord{}, fmt.Errorf("invalid run_kind: %s", input.RunKind)
	}
	route := strings.TrimSpace(input.Route)
	if route == "" {
		route = packet.Route
	}
	if !validRoute(route) {
		return ResultRecord{}, fmt.Errorf("invalid route: %s", input.Route)
	}
	if route == RouteArtifactReview {
		if packet.Kind != "artifact" || packet.Route != RouteArtifactReview || packet.Artifact == nil || strings.TrimSpace(packet.Artifact.ID) == "" {
			return ResultRecord{}, errors.New("artifact_review result requires an artifact packet")
		}
		if runKind != RunKindDiscovery || packet.RunKind != RunKindDiscovery {
			return ResultRecord{}, errors.New("artifact_review result requires discovery run_kind")
		}
	} else if packet.Kind == "artifact" || packet.Route == RouteArtifactReview {
		return ResultRecord{}, errors.New("artifact packets only accept artifact_review results")
	}
	if runKind == RunKindDiscovery && (packet.RunKind != runKind || packet.Route != route) {
		return ResultRecord{}, fmt.Errorf("discovery result route %s/%s does not match packet route %s/%s", runKind, route, packet.RunKind, packet.Route)
	}
	outcome := strings.TrimSpace(input.Outcome)
	if outcome == "" {
		outcome = inferOutcome(input)
	}
	if !validOutcome(outcome) {
		return ResultRecord{}, fmt.Errorf("invalid outcome: %s", input.Outcome)
	}
	hasFindingRefutation := false
	for _, refutation := range input.DeterministicRefutations {
		if strings.TrimSpace(refutation.FindingID) != "" {
			hasFindingRefutation = true
			break
		}
	}
	isTargetedVerificationPacket := packet.RunKind == RunKindVerification && packet.Route == RouteTargetedVerification
	if isTargetedVerificationPacket && outcome != OutcomeVerification {
		return ResultRecord{}, errors.New("targeted verification packet requires verification outcome")
	}
	if len(input.VerifierOutcomes) > 0 || hasFindingRefutation || isTargetedVerificationPacket {
		if packet.RunKind != runKind || packet.Route != route {
			return ResultRecord{}, fmt.Errorf("verification result route %s/%s does not match packet route %s/%s", runKind, route, packet.RunKind, packet.Route)
		}
		if packet.VerificationFindingID == "" {
			return ResultRecord{}, errors.New("finding-level verification evidence requires a targeted verification packet")
		}
		for _, refutation := range input.DeterministicRefutations {
			for _, obligationID := range refutation.ObligationIDs {
				if strings.TrimSpace(obligationID) != "" {
					return ResultRecord{}, errors.New("targeted verification packets cannot import obligation-level deterministic refutations")
				}
			}
		}
		seenOutcome := false
		for _, outcome := range input.VerifierOutcomes {
			if strings.TrimSpace(outcome.FindingID) != packet.VerificationFindingID {
				return ResultRecord{}, fmt.Errorf("verifier outcome finding_id %q does not match packet finding_id %q", outcome.FindingID, packet.VerificationFindingID)
			}
			if seenOutcome {
				return ResultRecord{}, fmt.Errorf("targeted verification packet accepts at most one verifier outcome for finding_id %q", packet.VerificationFindingID)
			}
			seenOutcome = true
		}
		for _, refutation := range input.DeterministicRefutations {
			if findingID := strings.TrimSpace(refutation.FindingID); findingID != "" && findingID != packet.VerificationFindingID {
				return ResultRecord{}, fmt.Errorf("deterministic refutation finding_id %q does not match packet finding_id %q", refutation.FindingID, packet.VerificationFindingID)
			}
		}
	}
	if len(input.Findings) > maxFindings {
		return ResultRecord{}, fmt.Errorf("worker result has too many findings: %d > %d", len(input.Findings), maxFindings)
	}
	if len(input.NeedsContext) > maxContextRequests {
		return ResultRecord{}, fmt.Errorf("worker result has too many context requests: %d > %d", len(input.NeedsContext), maxContextRequests)
	}
	if len(input.RequiredChecks) > maxRequiredChecks {
		return ResultRecord{}, fmt.Errorf("worker result has too many required checks: %d > %d", len(input.RequiredChecks), maxRequiredChecks)
	}
	if len(input.VerifierOutcomes) > maxVerifierOutcomes {
		return ResultRecord{}, fmt.Errorf("worker result has too many verifier outcomes: %d > %d", len(input.VerifierOutcomes), maxVerifierOutcomes)
	}
	if len(input.DeterministicRefutations) > maxRefutations {
		return ResultRecord{}, fmt.Errorf("worker result has too many deterministic refutations: %d > %d", len(input.DeterministicRefutations), maxRefutations)
	}
	if err := validateOutcomeShape(runKind, outcome, input); err != nil {
		return ResultRecord{}, err
	}
	summary, err := normalizeBoundedString(input.Summary, maxSummaryBytes, "summary", false)
	if err != nil {
		return ResultRecord{}, err
	}
	findings := make([]FindingRecord, 0, len(input.Findings))
	seenDigests := map[string]struct{}{}
	seenIDs := map[string]string{}
	for i, finding := range input.Findings {
		normalized := normalizeFinding(finding, i, packet)
		if normalized.Accepted {
			if priorDigest, exists := existingIDs[normalized.ID]; exists && priorDigest != normalized.DedupeDigest {
				normalized.Accepted = false
				normalized.Blocking = false
				normalized.State = StateRejectedStructural
				normalized.RejectionReason = "duplicate finding id with different finding content"
			} else if priorDigest, exists := seenIDs[normalized.ID]; exists && priorDigest != normalized.DedupeDigest {
				normalized.Accepted = false
				normalized.Blocking = false
				normalized.State = StateRejectedStructural
				normalized.RejectionReason = "duplicate finding id with different finding content"
			} else if _, exists := existingDigests[normalized.DedupeDigest]; exists {
				normalized.Accepted = false
				normalized.Blocking = false
				normalized.State = StateDuplicate
				normalized.DuplicateOf = normalized.DedupeDigest
			} else if _, exists := seenDigests[normalized.DedupeDigest]; exists {
				normalized.Accepted = false
				normalized.Blocking = false
				normalized.State = StateDuplicate
				normalized.DuplicateOf = normalized.DedupeDigest
			} else {
				seenIDs[normalized.ID] = normalized.DedupeDigest
				seenDigests[normalized.DedupeDigest] = struct{}{}
			}
		}
		findings = append(findings, normalized)
	}
	contextRequests, err := normalizeContextRequests(input.NeedsContext)
	if err != nil {
		return ResultRecord{}, err
	}
	requiredChecks, err := normalizeRequiredChecks(input.RequiredChecks)
	if err != nil {
		return ResultRecord{}, err
	}
	verifierOutcomes, err := normalizeVerifierOutcomes(input.VerifierOutcomes)
	if err != nil {
		return ResultRecord{}, err
	}
	refutations, err := normalizeDeterministicRefutations(input.DeterministicRefutations)
	if err != nil {
		return ResultRecord{}, err
	}
	if err := validateVerifierOutcomeEvidence(verifierOutcomes, refutations); err != nil {
		return ResultRecord{}, err
	}
	telemetry, err := normalizeTelemetry(input.Telemetry)
	if err != nil {
		return ResultRecord{}, err
	}
	evidence := evidenceSummary(runKind, route, outcome, findings, refutations)
	return ResultRecord{
		SchemaVersion:            SchemaVersion,
		Repo:                     repo,
		ImportedAt:               now.Format(time.RFC3339Nano),
		Packet:                   packet,
		RunKind:                  runKind,
		Route:                    route,
		Outcome:                  outcome,
		Summary:                  summary,
		Findings:                 findings,
		NeedsContext:             contextRequests,
		RequiredChecks:           requiredChecks,
		VerifierOutcomes:         verifierOutcomes,
		DeterministicRefutations: refutations,
		Telemetry:                telemetry,
		Evidence:                 evidence,
	}, nil
}

func normalizeFinding(input FindingInput, index int, packet PacketRef) FindingRecord {
	if packet.Route == RouteArtifactReview {
		return normalizeArtifactFinding(input, index, packet)
	}
	sourceID := strings.TrimSpace(input.ID)
	stateValue := strings.TrimSpace(input.State)
	if stateValue == "" {
		stateValue = StateOpen
	}
	severity := strings.ToLower(strings.TrimSpace(input.Severity))
	class := strings.ToLower(strings.TrimSpace(input.Class))
	claim := strings.TrimSpace(input.Claim)
	failureScenario := strings.TrimSpace(input.FailureScenario)
	reasons := []string{}
	if sourceID != "" && !idPattern.MatchString(sourceID) {
		reasons = append(reasons, "invalid finding id")
	}
	if !validLifecycleState(stateValue) {
		reasons = append(reasons, "invalid lifecycle state")
	} else if !blocksClosure(stateValue) {
		stateValue = StateNeedsConfirmation
	}
	if !validSeverity(severity) {
		reasons = append(reasons, "invalid severity")
	}
	if !validFindingClass(class) {
		reasons = append(reasons, "invalid class")
	}
	if len(claim) == 0 || len([]byte(claim)) > maxClaimBytes {
		reasons = append(reasons, "claim is required and must be concise")
	}
	if len(failureScenario) == 0 || len([]byte(failureScenario)) > maxFailureScenarioBytes {
		reasons = append(reasons, "failure_scenario is required and must be concise")
	}
	if len(input.ArtifactRefs) > 0 {
		reasons = append(reasons, "artifact_refs are not allowed for code review routes")
	}
	citations, citationErrs := normalizeLineRefs(input.Citations, true)
	reasons = append(reasons, citationErrs...)
	anchors, anchorErrs := normalizeAnchors(input.Anchors, true)
	reasons = append(reasons, anchorErrs...)
	fixSurface, fixErrs := normalizeFixSurface(input.ExpectedFixSurface)
	reasons = append(reasons, fixErrs...)
	dedupe := findingDedupeDigest(severity, class, claim, failureScenario, citations, anchors)
	id := sourceID
	if id == "" {
		id = "finding_" + strings.TrimPrefix(dedupe, "sha256:")[:16]
	}
	record := FindingRecord{
		ID:                 id,
		SourceID:           sourceID,
		DedupeDigest:       dedupe,
		State:              stateValue,
		Severity:           severity,
		Class:              class,
		Claim:              claim,
		FailureScenario:    failureScenario,
		Citations:          citations,
		Anchors:            anchors,
		ExpectedFixSurface: fixSurface,
		Accepted:           true,
		Blocking:           blocksClosure(stateValue),
	}
	if len(reasons) > 0 {
		record.ID = fallbackFindingID(record.ID, dedupe, index)
		record.State = StateRejectedStructural
		record.Accepted = false
		record.Blocking = false
		record.RejectionReason = strings.Join(reasons, "; ")
	}
	return record
}

func normalizeArtifactFinding(input FindingInput, index int, packet PacketRef) FindingRecord {
	sourceID := strings.TrimSpace(input.ID)
	stateValue := strings.TrimSpace(input.State)
	if stateValue == "" {
		stateValue = StateOpen
	}
	severity := strings.ToLower(strings.TrimSpace(input.Severity))
	class := strings.ToLower(strings.TrimSpace(input.Class))
	claim := strings.TrimSpace(input.Claim)
	failureScenario := strings.TrimSpace(input.FailureScenario)
	reasons := []string{}
	if sourceID != "" && !idPattern.MatchString(sourceID) {
		reasons = append(reasons, "invalid finding id")
	}
	if !validLifecycleState(stateValue) {
		reasons = append(reasons, "invalid lifecycle state")
	} else if !blocksClosure(stateValue) {
		stateValue = StateNeedsConfirmation
	}
	if !validSeverity(severity) {
		reasons = append(reasons, "invalid severity")
	}
	if !validFindingClass(class) {
		reasons = append(reasons, "invalid class")
	}
	if len(claim) == 0 || len([]byte(claim)) > maxClaimBytes {
		reasons = append(reasons, "claim is required and must be concise")
	}
	if len(failureScenario) == 0 || len([]byte(failureScenario)) > maxFailureScenarioBytes {
		reasons = append(reasons, "failure_scenario is required and must be concise")
	}
	if len(input.Citations) > 0 {
		reasons = append(reasons, "citations are not allowed for artifact_review findings")
	}
	if len(input.Anchors) > 0 {
		reasons = append(reasons, "anchors are not allowed for artifact_review findings")
	}
	if len(input.ExpectedFixSurface) > 0 {
		reasons = append(reasons, "expected_fix_surface is not allowed for artifact_review findings")
	}
	artifactID := ""
	if packet.Artifact != nil {
		artifactID = packet.Artifact.ID
	}
	artifactRefs, artifactRefErrs := normalizeArtifactRefs(input.ArtifactRefs, true, artifactID)
	reasons = append(reasons, artifactRefErrs...)
	dedupe := artifactFindingDedupeDigest(severity, class, claim, failureScenario, artifactRefs)
	id := sourceID
	if id == "" {
		id = "finding_" + strings.TrimPrefix(dedupe, "sha256:")[:16]
	}
	record := FindingRecord{
		ID:              id,
		SourceID:        sourceID,
		DedupeDigest:    dedupe,
		State:           stateValue,
		Severity:        severity,
		Class:           class,
		Claim:           claim,
		FailureScenario: failureScenario,
		ArtifactRefs:    artifactRefs,
		Accepted:        true,
		Blocking:        blocksClosure(stateValue),
	}
	if len(reasons) > 0 {
		record.ID = fallbackFindingID(record.ID, dedupe, index)
		record.State = StateRejectedStructural
		record.Accepted = false
		record.Blocking = false
		record.RejectionReason = strings.Join(reasons, "; ")
	}
	return record
}

func normalizeLineRefs(input []LineRef, required bool) ([]LineRef, []string) {
	reasons := []string{}
	if required && len(input) == 0 {
		return []LineRef{}, []string{"at least one citation is required"}
	}
	if len(input) > maxRefsPerFinding {
		reasons = append(reasons, fmt.Sprintf("too many citations: %d > %d", len(input), maxRefsPerFinding))
	}
	out := make([]LineRef, 0, min(len(input), maxRefsPerFinding))
	for i, ref := range input {
		if i >= maxRefsPerFinding {
			break
		}
		path, err := cleanRepoPath(ref.Path)
		if err != nil {
			reasons = append(reasons, "invalid citation path")
			continue
		}
		if ref.StartLine < 0 || ref.EndLine < 0 || (ref.EndLine > 0 && ref.StartLine > ref.EndLine) {
			reasons = append(reasons, "invalid citation line range")
			continue
		}
		if ref.Digest != "" && !isDigest(ref.Digest) {
			reasons = append(reasons, "invalid citation digest")
			continue
		}
		out = append(out, LineRef{
			Path:      path,
			StartLine: ref.StartLine,
			EndLine:   ref.EndLine,
			Quote:     trimToByteLimit(ref.Quote, maxSummaryBytes),
			Digest:    ref.Digest,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].Path < out[j].Path
	})
	return out, reasons
}

func normalizeAnchors(input []AnchorRef, required bool) ([]AnchorRef, []string) {
	reasons := []string{}
	if required && len(input) == 0 {
		return []AnchorRef{}, []string{"at least one anchor is required"}
	}
	if len(input) > maxRefsPerFinding {
		reasons = append(reasons, fmt.Sprintf("too many anchors: %d > %d", len(input), maxRefsPerFinding))
	}
	out := make([]AnchorRef, 0, min(len(input), maxRefsPerFinding))
	for i, anchor := range input {
		if i >= maxRefsPerFinding {
			break
		}
		kind := strings.ToLower(strings.TrimSpace(anchor.Kind))
		if kind != "path" && kind != "file" && kind != "hunk" {
			reasons = append(reasons, "invalid anchor kind")
			continue
		}
		path, err := cleanRepoPath(anchor.Path)
		if err != nil {
			reasons = append(reasons, "invalid anchor path")
			continue
		}
		if anchor.StartLine < 0 || anchor.EndLine < 0 || (anchor.EndLine > 0 && anchor.StartLine > anchor.EndLine) {
			reasons = append(reasons, "invalid anchor line range")
			continue
		}
		out = append(out, AnchorRef{
			Kind:         kind,
			Path:         path,
			StartLine:    anchor.StartLine,
			EndLine:      anchor.EndLine,
			ObligationID: strings.TrimSpace(anchor.ObligationID),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			if out[i].Kind == out[j].Kind {
				return out[i].StartLine < out[j].StartLine
			}
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out, reasons
}

func normalizeFixSurface(input []FixSurface) ([]FixSurface, []string) {
	reasons := []string{}
	if len(input) > maxFixSurfaceEntries {
		reasons = append(reasons, fmt.Sprintf("too many expected_fix_surface entries: %d > %d", len(input), maxFixSurfaceEntries))
	}
	out := make([]FixSurface, 0, min(len(input), maxFixSurfaceEntries))
	for i, surface := range input {
		if i >= maxFixSurfaceEntries {
			break
		}
		path, err := cleanRepoPath(surface.Path)
		if err != nil {
			reasons = append(reasons, "invalid expected_fix_surface path")
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(surface.Kind))
		if kind == "" {
			kind = "file"
		}
		if kind != "file" && kind != "hunk" && kind != "test" && kind != "docs" && kind != "config" {
			reasons = append(reasons, "invalid expected_fix_surface kind")
			continue
		}
		if surface.StartLine < 0 || surface.EndLine < 0 || (surface.EndLine > 0 && surface.StartLine > surface.EndLine) {
			reasons = append(reasons, "invalid expected_fix_surface line range")
			continue
		}
		out = append(out, FixSurface{Kind: kind, Path: path, StartLine: surface.StartLine, EndLine: surface.EndLine})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].StartLine < out[j].StartLine
		}
		return out[i].Path < out[j].Path
	})
	return out, reasons
}

func normalizeArtifactRefs(input []ArtifactRef, required bool, packetArtifactID string) ([]ArtifactRef, []string) {
	reasons := []string{}
	if required && len(input) == 0 {
		return []ArtifactRef{}, []string{"at least one artifact_ref is required"}
	}
	if len(input) > maxRefsPerFinding {
		reasons = append(reasons, fmt.Sprintf("too many artifact_refs: %d > %d", len(input), maxRefsPerFinding))
	}
	out := make([]ArtifactRef, 0, min(len(input), maxRefsPerFinding))
	for i, ref := range input {
		if i >= maxRefsPerFinding {
			break
		}
		artifactID := strings.TrimSpace(ref.ArtifactID)
		if artifactID == "" {
			reasons = append(reasons, "artifact_ref artifact_id is required")
			continue
		}
		if artifactID != packetArtifactID {
			reasons = append(reasons, "artifact_ref artifact_id does not match packet artifact")
			continue
		}
		section, err := normalizeBoundedString(ref.Section, 200, "artifact_ref section", false)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		storyID := strings.TrimSpace(ref.StoryID)
		if storyID != "" && !idPattern.MatchString(storyID) {
			reasons = append(reasons, "invalid artifact_ref story_id")
			continue
		}
		mergeUnitID := strings.TrimSpace(ref.MergeUnitID)
		if mergeUnitID != "" && !idPattern.MatchString(mergeUnitID) {
			reasons = append(reasons, "invalid artifact_ref merge_unit_id")
			continue
		}
		if ref.StartLine < 0 || ref.EndLine < 0 || (ref.EndLine > 0 && ref.StartLine > ref.EndLine) || (ref.EndLine > 0 && ref.StartLine == 0) {
			reasons = append(reasons, "invalid artifact_ref line range")
			continue
		}
		quote, err := normalizeBoundedString(ref.Quote, maxSummaryBytes, "artifact_ref quote", false)
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		out = append(out, ArtifactRef{
			ArtifactID:  artifactID,
			Section:     section,
			StoryID:     storyID,
			MergeUnitID: mergeUnitID,
			StartLine:   ref.StartLine,
			EndLine:     ref.EndLine,
			Quote:       quote,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ArtifactID != out[j].ArtifactID {
			return out[i].ArtifactID < out[j].ArtifactID
		}
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		if out[i].StoryID != out[j].StoryID {
			return out[i].StoryID < out[j].StoryID
		}
		if out[i].MergeUnitID != out[j].MergeUnitID {
			return out[i].MergeUnitID < out[j].MergeUnitID
		}
		if out[i].StartLine != out[j].StartLine {
			return out[i].StartLine < out[j].StartLine
		}
		if out[i].EndLine != out[j].EndLine {
			return out[i].EndLine < out[j].EndLine
		}
		return out[i].Quote < out[j].Quote
	})
	deduped := out[:0]
	seen := map[string]struct{}{}
	for _, ref := range out {
		key := digestJSON(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, ref)
	}
	return deduped, reasons
}

func normalizeContextRequests(input []ContextRequest) ([]ContextRequest, error) {
	out := make([]ContextRequest, 0, len(input))
	for _, request := range input {
		question, err := normalizeBoundedString(request.Question, maxQuestionBytes, "context request question", true)
		if err != nil {
			return nil, err
		}
		reason, err := normalizeBoundedString(request.Reason, maxReasonBytes, "context request reason", false)
		if err != nil {
			return nil, err
		}
		paths := make([]string, 0, len(request.Paths))
		if len(request.Paths) > maxRefsPerFinding {
			return nil, fmt.Errorf("context request has too many paths: %d > %d", len(request.Paths), maxRefsPerFinding)
		}
		for _, rawPath := range request.Paths {
			path, err := cleanRepoPath(rawPath)
			if err != nil {
				return nil, fmt.Errorf("invalid context request path: %w", err)
			}
			paths = append(paths, path)
		}
		sort.Strings(paths)
		out = append(out, ContextRequest{Question: question, Reason: reason, Paths: paths})
	}
	return out, nil
}

func normalizeRequiredChecks(input []RequiredCheck) ([]RequiredCheck, error) {
	out := make([]RequiredCheck, 0, len(input))
	seen := map[string]struct{}{}
	for _, check := range input {
		commandID := strings.TrimSpace(check.CommandID)
		if !idPattern.MatchString(commandID) {
			return nil, fmt.Errorf("invalid required check command_id: %s", check.CommandID)
		}
		if _, exists := seen[commandID]; exists {
			continue
		}
		seen[commandID] = struct{}{}
		reason, err := normalizeBoundedString(check.Reason, maxReasonBytes, "required check reason", false)
		if err != nil {
			return nil, err
		}
		out = append(out, RequiredCheck{CommandID: commandID, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CommandID < out[j].CommandID })
	return out, nil
}

func normalizeVerifierOutcomes(input []VerifierOutcomeInput) ([]VerifierOutcome, error) {
	out := make([]VerifierOutcome, 0, len(input))
	for _, outcome := range input {
		findingID := strings.TrimSpace(outcome.FindingID)
		if !idPattern.MatchString(findingID) {
			return nil, fmt.Errorf("invalid verifier outcome finding_id: %s", outcome.FindingID)
		}
		outcomeValue := strings.TrimSpace(outcome.Outcome)
		if outcomeValue != "" && !validVerificationOutcome(outcomeValue) {
			return nil, fmt.Errorf("invalid verification outcome: %s", outcome.Outcome)
		}
		stateValue := strings.TrimSpace(outcome.State)
		basis := strings.TrimSpace(outcome.Basis)
		if outcomeValue != "" {
			if stateValue == "" {
				stateValue = stateForVerificationOutcome(outcomeValue)
			}
			if basis == "" {
				basis = basisForVerificationOutcome(outcomeValue)
			}
		}
		if !validLifecycleState(stateValue) || stateValue == StateOpen || stateValue == StateRejectedStructural || stateValue == StateDuplicate {
			return nil, fmt.Errorf("invalid verifier outcome state: %s", outcome.State)
		}
		if !validVerifierBasis(basis) {
			return nil, fmt.Errorf("invalid verifier outcome basis: %s", outcome.Basis)
		}
		summary, err := normalizeBoundedString(outcome.Summary, maxSummaryBytes, "verifier outcome summary", true)
		if err != nil {
			return nil, err
		}
		relation := strings.TrimSpace(outcome.VerifierRelation)
		relationEvidence := strings.TrimSpace(outcome.RelationEvidence)
		if stateValue == StateInvalidated && basis == BasisFreshSemantic {
			if relation != RelationFreshBlinded {
				return nil, errors.New("fresh semantic invalidation requires verifier_relation fresh_blinded")
			}
			if !validRelationEvidence(relationEvidence) {
				return nil, errors.New("fresh semantic invalidation requires admissible relation_evidence")
			}
		}
		if stateValue == StateInvalidated && basis != BasisFreshSemantic && basis != BasisDeterministicRefutation && basis != BasisExecutableRefutation {
			return nil, fmt.Errorf("invalidated finding requires deterministic, executable, or fresh semantic basis: %s", basis)
		}
		if outcomeValue == "" {
			outcomeValue = verificationOutcomeForState(stateValue, basis)
		}
		if stateValue != stateForVerificationOutcome(outcomeValue) {
			return nil, fmt.Errorf("verification outcome %s conflicts with state %s", outcomeValue, stateValue)
		}
		if !basisAllowedForVerificationOutcome(outcomeValue, basis) {
			return nil, fmt.Errorf("verification outcome %s conflicts with basis %s", outcomeValue, basis)
		}
		out = append(out, VerifierOutcome{
			FindingID:        findingID,
			Outcome:          outcomeValue,
			State:            stateValue,
			Basis:            basis,
			Summary:          summary,
			VerifierRelation: relation,
			RelationEvidence: relationEvidence,
		})
	}
	return out, nil
}

func normalizeDeterministicRefutations(input []DeterministicRefutationInput) ([]DeterministicRefutation, error) {
	out := make([]DeterministicRefutation, 0, len(input))
	for i, refutation := range input {
		basis := strings.TrimSpace(refutation.Basis)
		if basis == "" {
			basis = BasisDeterministicRefutation
		}
		if basis != BasisDeterministicRefutation && basis != BasisExecutableRefutation {
			return nil, fmt.Errorf("invalid deterministic refutation basis: %s", refutation.Basis)
		}
		evidenceKind := strings.ToLower(strings.TrimSpace(refutation.EvidenceKind))
		if !validEvidenceKind(evidenceKind) {
			return nil, fmt.Errorf("invalid deterministic refutation evidence_kind: %s", refutation.EvidenceKind)
		}
		summary, err := normalizeBoundedString(refutation.Summary, maxSummaryBytes, "deterministic refutation summary", true)
		if err != nil {
			return nil, err
		}
		findingID := strings.TrimSpace(refutation.FindingID)
		if findingID != "" && !idPattern.MatchString(findingID) {
			return nil, fmt.Errorf("invalid deterministic refutation finding_id: %s", refutation.FindingID)
		}
		obligationIDs := uniqueTrimmed(refutation.ObligationIDs)
		for _, obligationID := range obligationIDs {
			if strings.ContainsRune(obligationID, '\x00') || len(obligationID) > 160 {
				return nil, fmt.Errorf("invalid obligation id in deterministic refutation: %s", obligationID)
			}
		}
		if findingID == "" && len(obligationIDs) == 0 {
			return nil, errors.New("deterministic refutation requires finding_id or obligation_ids")
		}
		citations, citationReasons := normalizeLineRefs(refutation.Citations, false)
		if len(citationReasons) > 0 {
			return nil, fmt.Errorf("invalid deterministic refutation citation: %s", strings.Join(citationReasons, "; "))
		}
		evidenceRefs, err := normalizeEvidenceRefs(refutation.EvidenceRefs)
		if err != nil {
			return nil, err
		}
		if len(citations) == 0 && len(evidenceRefs) == 0 {
			return nil, errors.New("deterministic refutation requires citation or evidence_ref")
		}
		id := strings.TrimSpace(refutation.ID)
		if id != "" && !idPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid deterministic refutation id: %s", refutation.ID)
		}
		if id == "" {
			id = "refutation_" + digestJSON(map[string]any{
				"index":          i,
				"finding_id":     findingID,
				"obligation_ids": obligationIDs,
				"basis":          basis,
				"evidence_kind":  evidenceKind,
				"summary":        summary,
			})[7:23]
		}
		out = append(out, DeterministicRefutation{
			ID:            id,
			FindingID:     findingID,
			ObligationIDs: obligationIDs,
			Basis:         basis,
			EvidenceKind:  evidenceKind,
			Summary:       summary,
			Citations:     citations,
			EvidenceRefs:  evidenceRefs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func validateVerifierOutcomeEvidence(outcomes []VerifierOutcome, refutations []DeterministicRefutation) error {
	refutedFindings := map[string]struct{}{}
	for _, refutation := range refutations {
		if refutation.FindingID == "" {
			continue
		}
		refutedFindings[refutation.FindingID] = struct{}{}
	}
	for _, outcome := range outcomes {
		_, hasRefutation := refutedFindings[outcome.FindingID]
		deterministicOutcome := outcome.State == StateInvalidated && (outcome.Basis == BasisDeterministicRefutation || outcome.Basis == BasisExecutableRefutation)
		if deterministicOutcome && !hasRefutation {
			return fmt.Errorf("deterministic verifier outcome for %s requires matching deterministic refutation evidence", outcome.FindingID)
		}
		if hasRefutation && !deterministicOutcome {
			return fmt.Errorf("deterministic refutation for %s conflicts with verifier outcome %s/%s", outcome.FindingID, outcome.Outcome, outcome.Basis)
		}
	}
	return nil
}

func normalizeEvidenceRefs(input []EvidenceRef) ([]EvidenceRef, error) {
	if len(input) > maxRefsPerFinding {
		return nil, fmt.Errorf("too many evidence_refs: %d > %d", len(input), maxRefsPerFinding)
	}
	out := make([]EvidenceRef, 0, len(input))
	for _, ref := range input {
		kind := strings.ToLower(strings.TrimSpace(ref.Kind))
		if kind == "" {
			return nil, errors.New("evidence_ref kind is required")
		}
		digest := strings.TrimSpace(ref.Digest)
		if digest != "" && !isDigest(digest) {
			return nil, fmt.Errorf("invalid evidence_ref digest: %s", digest)
		}
		eventID := strings.TrimSpace(ref.EventID)
		commandID := strings.TrimSpace(ref.CommandID)
		if digest == "" && eventID == "" && commandID == "" {
			return nil, errors.New("evidence_ref requires digest, event_id, or command_id")
		}
		out = append(out, EvidenceRef{Kind: kind, Digest: digest, EventID: eventID, CommandID: commandID})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind == out[j].Kind {
			if out[i].Digest == out[j].Digest {
				return out[i].EventID < out[j].EventID
			}
			return out[i].Digest < out[j].Digest
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}

func normalizeTelemetry(input TokenTelemetry) (TokenTelemetry, error) {
	values := []struct {
		name  string
		value int
	}{
		{"gross_discovery_tokens", input.GrossDiscoveryTokens},
		{"incremental_discovery_tokens", input.IncrementalDiscoveryTokens},
		{"gross_verification_tokens", input.GrossVerificationTokens},
		{"incremental_verification_tokens", input.IncrementalVerificationTokens},
		{"gross_input_tokens", input.GrossInputTokens},
		{"incremental_input_tokens", input.IncrementalInputTokens},
		{"cached_input_tokens", input.CachedInputTokens},
		{"output_tokens", input.OutputTokens},
		{"reasoning_tokens", input.ReasoningTokens},
	}
	for _, item := range values {
		if item.value < 0 {
			return TokenTelemetry{}, fmt.Errorf("telemetry %s cannot be negative", item.name)
		}
	}
	if input.LatencyMS < 0 {
		return TokenTelemetry{}, errors.New("telemetry latency_ms cannot be negative")
	}
	input.Backend = trimToByteLimit(input.Backend, 128)
	input.Model = trimToByteLimit(input.Model, 128)
	input.Effort = trimToByteLimit(input.Effort, 64)
	input.TokenMeasurement = trimToByteLimit(input.TokenMeasurement, 128)
	if input.SchemaVersion == 0 {
		input.SchemaVersion = SchemaVersion
	}
	return input, nil
}

func evidenceSummary(runKind, route, outcome string, findings []FindingRecord, refutations []DeterministicRefutation) EvidenceSummary {
	satisfactionKinds := []string{}
	primary := runKind == RunKindDiscovery && route == RoutePrimaryReview && outcome != OutcomeNeedsContext
	independent := runKind == RunKindDiscovery && route == RouteIndependentFinal && outcome != OutcomeNeedsContext
	deterministic := len(refutations) > 0
	if primary || independent {
		satisfactionKinds = append(satisfactionKinds, SatisfactionPrimaryReviewEvidence)
	}
	if deterministic {
		satisfactionKinds = append(satisfactionKinds, SatisfactionDeterministicRefute)
	}
	sort.Strings(satisfactionKinds)
	open := 0
	for _, finding := range findings {
		if finding.Accepted && blocksClosure(finding.State) {
			open++
		}
	}
	return EvidenceSummary{
		PrimaryReviewEvidence:           primary,
		IndependentFinalReviewEvidence:  independent,
		DeterministicRefutationEvidence: deterministic,
		SatisfactionKinds:               satisfactionKinds,
		OpenBlockingFindings:            open,
	}
}

func resolvePacket(store state.Store, events []state.Event, stateDir, repo, packetID string) (PacketRef, error) {
	packetID = strings.TrimSpace(packetID)
	if packetID == "" {
		return PacketRef{}, errors.New("--packet is required")
	}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "packet.built" {
			continue
		}
		if event.Repo != repo {
			return PacketRef{}, errors.New("malformed packet.built event: repo mismatch")
		}
		candidates := []string{event.Details["packet"], event.Details["semantic_dedupe_digest"], event.EventID}
		if !containsString(candidates, packetID) {
			continue
		}
		digest := event.Details["packet"]
		if strings.TrimSpace(digest) == "" {
			return PacketRef{}, errors.New("malformed packet.built event: missing packet")
		}
		if !containsDigest(event.ObjectDigests, digest) {
			return PacketRef{}, errors.New("malformed packet.built event: object_digests missing packet")
		}
		body, err := store.Read(digest)
		if err != nil {
			return PacketRef{}, err
		}
		var record packetRecord
		if err := json.Unmarshal(body, &record); err != nil {
			return PacketRef{}, err
		}
		if record.SchemaVersion != SchemaVersion {
			return PacketRef{}, fmt.Errorf("unsupported packet schema_version: %d", record.SchemaVersion)
		}
		if record.Repo != repo {
			return PacketRef{}, errors.New("packet repo mismatch")
		}
		if record.Kind == "artifact" || record.Route == RouteArtifactReview {
			if record.Kind != "artifact" || record.RunKind != RunKindDiscovery || record.Route != RouteArtifactReview {
				return PacketRef{}, errors.New("artifact packet route is malformed")
			}
			if record.Artifact == nil || strings.TrimSpace(record.Artifact.ID) == "" || strings.TrimSpace(record.Artifact.Artifact.Digest) == "" || strings.TrimSpace(record.Artifact.Content.Digest) == "" {
				return PacketRef{}, errors.New("artifact packet missing artifact reference")
			}
			artifact := *record.Artifact
			return PacketRef{
				Digest:               digest,
				EventID:              event.EventID,
				Kind:                 record.Kind,
				RunKind:              record.RunKind,
				Route:                record.Route,
				PromptDigest:         record.PromptDigest,
				StableDigest:         record.StableDigest,
				SemanticDedupeDigest: record.SemanticDedupeKey.Digest,
				Artifact:             &artifact,
				SourceCompleteness:   record.SourceCompleteness,
			}, nil
		}
		if record.CoverageManifest.Digest == "" || record.TargetState.Digest == "" {
			return PacketRef{}, errors.New("packet missing coverage_manifest or target_state")
		}
		return PacketRef{
			Digest:                digest,
			EventID:               event.EventID,
			Kind:                  record.Kind,
			RunKind:               record.RunKind,
			Route:                 record.Route,
			PromptDigest:          record.PromptDigest,
			StableDigest:          record.StableDigest,
			SemanticDedupeDigest:  record.SemanticDedupeKey.Digest,
			Policy:                copyPolicyRef(record.Policy),
			VerificationFindingID: strings.TrimSpace(record.Verification.Finding.ID),
			CoverageManifest: state.ObjectRef{
				Digest:    record.CoverageManifest.Digest,
				MediaType: record.CoverageManifest.MediaType,
				Size:      record.CoverageManifest.Size,
				Path:      objectPathBestEffort(stateDir, record.CoverageManifest.Digest),
			},
			TargetState:        record.TargetState,
			SourceCompleteness: record.SourceCompleteness,
		}, nil
	}
	return PacketRef{}, fmt.Errorf("packet not found in state: %s", packetID)
}

func copyPolicyRef(policy *PolicyRef) *PolicyRef {
	if policy == nil {
		return nil
	}
	ref := *policy
	return &ref
}

func readBoundedRegularFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--result is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("result must be a regular file: %s", abs)
	}
	if info.Size() > maxResultBytes {
		return nil, fmt.Errorf("worker result exceeds %d byte limit", maxResultBytes)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if len(body) > maxResultBytes {
		return nil, fmt.Errorf("worker result exceeds %d byte limit", maxResultBytes)
	}
	return body, nil
}

func existingFindingIdentity(store state.Store, events []state.Event, repo string, packet PacketRef) (map[string]struct{}, map[string]string, error) {
	observations, err := observations(store, events, repo, true)
	if err != nil {
		return nil, nil, err
	}
	digests := map[string]struct{}{}
	ids := map[string]string{}
	for _, observation := range observations {
		if !findingIdentityScopeMatches(observation.Record, packet) {
			continue
		}
		for _, finding := range observation.Record.Findings {
			if finding.Accepted && finding.DedupeDigest != "" {
				digests[finding.DedupeDigest] = struct{}{}
				ids[finding.ID] = finding.DedupeDigest
			}
		}
	}
	return digests, ids, nil
}

func findingIdentityScopeMatches(record ResultRecord, packet PacketRef) bool {
	if packet.Route == RouteArtifactReview {
		return record.Route == RouteArtifactReview &&
			record.Packet.Artifact != nil &&
			packet.Artifact != nil &&
			record.Packet.Artifact.ID == packet.Artifact.ID
	}
	return record.Route != RouteArtifactReview && record.Packet.CoverageManifest.Digest == packet.CoverageManifest.Digest
}

func validateRecord(record ResultRecord, repo, packetDigest string) error {
	if record.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported result schema_version: %d", record.SchemaVersion)
	}
	if record.Repo != repo {
		return errors.New("result repo mismatch")
	}
	if packetDigest != "" && record.Packet.Digest != packetDigest {
		return errors.New("result packet mismatch")
	}
	if !validRunKind(record.RunKind) || !validRoute(record.Route) || !validOutcome(record.Outcome) {
		return errors.New("result run_kind, route, or outcome is invalid")
	}
	if record.Route == RouteArtifactReview {
		if record.RunKind != RunKindDiscovery || record.Packet.Kind != "artifact" || record.Packet.Route != RouteArtifactReview {
			return errors.New("artifact result packet reference is invalid")
		}
		if record.Packet.Artifact == nil || strings.TrimSpace(record.Packet.Artifact.ID) == "" {
			return errors.New("artifact result packet reference is incomplete")
		}
		for _, finding := range record.Findings {
			if len(finding.Citations) > 0 || len(finding.Anchors) > 0 || len(finding.ExpectedFixSurface) > 0 {
				return errors.New("artifact result contains code-review finding references")
			}
		}
		return nil
	}
	if record.Packet.CoverageManifest.Digest == "" || record.Packet.TargetState.Digest == "" {
		return errors.New("result packet reference is incomplete")
	}
	for _, finding := range record.Findings {
		if len(finding.ArtifactRefs) > 0 {
			return errors.New("code-review result contains artifact_refs")
		}
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

func inferOutcome(input WorkerResult) string {
	if len(input.NeedsContext) > 0 {
		return OutcomeNeedsContext
	}
	if len(input.Findings) > 0 {
		return OutcomeFindings
	}
	if len(input.VerifierOutcomes) > 0 || len(input.DeterministicRefutations) > 0 {
		return OutcomeVerification
	}
	return OutcomeClean
}

func validateOutcomeShape(runKind, outcome string, input WorkerResult) error {
	switch outcome {
	case OutcomeClean:
		if len(input.Findings) > 0 {
			return errors.New("outcome clean cannot include findings")
		}
		if len(input.NeedsContext) > 0 {
			return errors.New("outcome clean cannot include context requests")
		}
		if len(input.VerifierOutcomes) > 0 || len(input.DeterministicRefutations) > 0 {
			return errors.New("outcome clean cannot include verification evidence")
		}
	case OutcomeFindings:
		if len(input.Findings) == 0 {
			return errors.New("outcome findings requires at least one finding")
		}
		if len(input.VerifierOutcomes) > 0 || len(input.DeterministicRefutations) > 0 {
			return errors.New("findings result cannot include verification evidence")
		}
	case OutcomeNeedsContext:
		if len(input.NeedsContext) == 0 {
			return errors.New("outcome needs_context requires at least one context request")
		}
		if len(input.VerifierOutcomes) > 0 || len(input.DeterministicRefutations) > 0 {
			return errors.New("needs_context result cannot include verification evidence")
		}
	case OutcomeVerification:
		if runKind != RunKindVerification {
			return errors.New("verification outcome requires verification run_kind")
		}
		if len(input.VerifierOutcomes) == 0 && len(input.DeterministicRefutations) == 0 {
			return errors.New("verification outcome requires verifier outcome or refutation")
		}
		if len(input.Findings) > 0 || len(input.NeedsContext) > 0 {
			return errors.New("verification result cannot introduce findings or context requests")
		}
	}
	return nil
}

func validRunKind(value string) bool {
	return value == RunKindDiscovery || value == RunKindVerification
}

func validRoute(value string) bool {
	switch value {
	case RoutePrimaryReview, RouteIndependentFinal, RouteTargetedVerification, RouteCompactFreshVerify, RouteArtifactReview:
		return true
	default:
		return false
	}
}

func validOutcome(value string) bool {
	switch value {
	case OutcomeClean, OutcomeFindings, OutcomeNeedsContext, OutcomeVerification:
		return true
	default:
		return false
	}
}

func validLifecycleState(value string) bool {
	switch value {
	case StateOpen, StateResolved, StateVerified, StateInvalidated, StateNeedsContext, StateNeedsConfirmation, StateRejectedStructural, StateDuplicate, StateUnknown:
		return true
	default:
		return false
	}
}

func validSeverity(value string) bool {
	switch value {
	case "blocker", "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func validFindingClass(value string) bool {
	switch value {
	case "correctness", "security", "reliability", "performance", "compatibility", "test", "maintainability", "usability", "docs", "config", "bug", "other":
		return true
	default:
		return false
	}
}

func validVerifierBasis(value string) bool {
	switch value {
	case BasisDeterministicRefutation, BasisExecutableRefutation, BasisFreshSemantic, BasisFixVerification:
		return true
	default:
		return false
	}
}

func validVerificationOutcome(value string) bool {
	switch value {
	case VerificationResolved, VerificationNotResolved, VerificationRegressionIntroduced, VerificationInsufficientContext, VerificationFindingInvalid, VerificationUnexpectedScope, VerificationDeterministicRefuted:
		return true
	default:
		return false
	}
}

func stateForVerificationOutcome(value string) string {
	switch value {
	case VerificationResolved:
		return StateVerified
	case VerificationFindingInvalid, VerificationDeterministicRefuted:
		return StateInvalidated
	case VerificationInsufficientContext:
		return StateNeedsContext
	case VerificationNotResolved, VerificationRegressionIntroduced, VerificationUnexpectedScope:
		return StateNeedsConfirmation
	default:
		return StateNeedsConfirmation
	}
}

func basisForVerificationOutcome(value string) string {
	switch value {
	case VerificationResolved, VerificationNotResolved, VerificationRegressionIntroduced, VerificationInsufficientContext, VerificationUnexpectedScope:
		return BasisFixVerification
	case VerificationFindingInvalid:
		return BasisFreshSemantic
	case VerificationDeterministicRefuted:
		return BasisDeterministicRefutation
	default:
		return BasisFixVerification
	}
}

func basisAllowedForVerificationOutcome(outcome, basis string) bool {
	switch outcome {
	case VerificationResolved, VerificationNotResolved, VerificationRegressionIntroduced, VerificationInsufficientContext, VerificationUnexpectedScope:
		return basis == BasisFixVerification
	case VerificationFindingInvalid:
		return basis == BasisFreshSemantic
	case VerificationDeterministicRefuted:
		return basis == BasisDeterministicRefutation || basis == BasisExecutableRefutation
	default:
		return false
	}
}

func verificationOutcomeForState(stateValue, basis string) string {
	if stateValue == StateVerified {
		return VerificationResolved
	}
	if stateValue == StateNeedsContext {
		return VerificationInsufficientContext
	}
	if stateValue == StateInvalidated && (basis == BasisDeterministicRefutation || basis == BasisExecutableRefutation) {
		return VerificationDeterministicRefuted
	}
	if stateValue == StateInvalidated {
		return VerificationFindingInvalid
	}
	return VerificationNotResolved
}

func validRelationEvidence(value string) bool {
	switch value {
	case RelationEvidenceCLIWitnessed, RelationEvidenceCallerAssert, RelationEvidenceExternalAssert:
		return true
	default:
		return false
	}
}

func validEvidenceKind(value string) bool {
	switch value {
	case "gate", "test", "typecheck", "schema", "api_contract", "static_analysis", "runtime_check", "other":
		return true
	default:
		return false
	}
}

func blocksClosure(stateValue string) bool {
	switch stateValue {
	case StateOpen, StateResolved, StateNeedsContext, StateNeedsConfirmation, StateUnknown:
		return true
	default:
		return false
	}
}

func severityRank(severity string) int {
	switch severity {
	case "blocker":
		return 5
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func normalizeBoundedString(value string, maxBytes int, label string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	if len([]byte(value)) > maxBytes {
		return "", fmt.Errorf("%s exceeds %d bytes", label, maxBytes)
	}
	if strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("%s contains NUL", label)
	}
	return value, nil
}

func trimToByteLimit(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if len([]byte(value)) <= maxBytes {
		return value
	}
	body := []byte(value)
	return strings.TrimSpace(string(body[:maxBytes]))
}

func fallbackFindingID(current, dedupe string, index int) string {
	if idPattern.MatchString(current) {
		return current
	}
	prefix := strings.TrimPrefix(dedupe, "sha256:")
	if len(prefix) >= 16 {
		return "finding_" + prefix[:16]
	}
	return fmt.Sprintf("finding_%d", index)
}

func findingDedupeDigest(severity, class, claim, failureScenario string, citations []LineRef, anchors []AnchorRef) string {
	return digestJSON(map[string]any{
		"severity":         severity,
		"class":            class,
		"claim":            claim,
		"failure_scenario": failureScenario,
		"citations":        citations,
		"anchors":          anchors,
	})
}

func artifactFindingDedupeDigest(severity, class, claim, failureScenario string, refs []ArtifactRef) string {
	return digestJSON(map[string]any{
		"severity":         severity,
		"class":            class,
		"claim":            claim,
		"failure_scenario": failureScenario,
		"artifact_refs":    refs,
	})
}

func digestJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func uniqueTrimmed(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	if clean != slash {
		return "", fmt.Errorf("invalid repository-relative path: %q", path)
	}
	return clean, nil
}

func isDigest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) != 64 {
		return false
	}
	for _, r := range hexDigest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func objectPathBestEffort(stateDir, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return ""
	}
	return filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest)
}

func countAcceptedFindings(findings []FindingRecord) int {
	count := 0
	for _, finding := range findings {
		if finding.Accepted {
			count++
		}
	}
	return count
}

func countFindingState(findings []FindingRecord, stateValue string) int {
	count := 0
	for _, finding := range findings {
		if finding.State == stateValue {
			count++
		}
	}
	return count
}

func hasFindingState(findings []FindingRecord, stateValue string) bool {
	for _, finding := range findings {
		if finding.State == stateValue {
			return true
		}
	}
	return false
}

func containsDigest(values []string, digest string) bool {
	for _, value := range values {
		if value == digest {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
