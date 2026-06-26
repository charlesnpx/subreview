package closure

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/state"
)

const (
	SchemaVersion = 1

	EventTypeEvaluated = "closure.evaluated"
	MediaTypeReport    = "application/vnd.subreview.closure-report+json"
)

type EvaluateOptions struct {
	StateDir      string
	PolicyProfile string
	Now           time.Time
}

type Result struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	Repo          string          `json:"repo"`
	PolicyProfile string          `json:"policy_profile"`
	PolicyDigest  string          `json:"policy_digest,omitempty"`
	Closed        bool            `json:"closed"`
	Report        state.ObjectRef `json:"report"`
	EventID       string          `json:"event_id"`
	Facts         Facts           `json:"facts"`
	Blockers      []Blocker       `json:"blockers"`
	Obligations   ObligationFacts `json:"obligations"`
	Gates         GateFacts       `json:"gates"`
	Findings      FindingFacts    `json:"findings"`
	Runs          RunFacts        `json:"runs"`
	Tokens        TokenFacts      `json:"tokens"`
	Scheduler     SchedulerFacts  `json:"scheduler"`
}

type Report struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	Repo          string          `json:"repo"`
	PolicyProfile string          `json:"policy_profile"`
	PolicyDigest  string          `json:"policy_digest,omitempty"`
	Coverage      state.ObjectRef `json:"coverage_manifest"`
	EvaluatedAt   string          `json:"evaluated_at"`
	Closed        bool            `json:"closed"`
	Facts         Facts           `json:"facts"`
	Blockers      []Blocker       `json:"blockers"`
	Obligations   ObligationFacts `json:"obligations"`
	Gates         GateFacts       `json:"gates"`
	Findings      FindingFacts    `json:"findings"`
	Runs          RunFacts        `json:"runs"`
	Tokens        TokenFacts      `json:"tokens"`
	Scheduler     SchedulerFacts  `json:"scheduler"`
}

type Facts struct {
	PolicyBound                    bool `json:"policy_bound"`
	RequiredGatesSatisfied         bool `json:"required_gates_satisfied"`
	PrimaryReviewCompleted         bool `json:"primary_review_completed"`
	BlockingFindingsVerified       bool `json:"blocking_findings_verified"`
	CoverageObligationsSatisfied   bool `json:"coverage_obligations_satisfied"`
	ContextRequestsResolved        bool `json:"context_requests_resolved"`
	IndependentFinalCompleted      bool `json:"independent_final_completed"`
	FreshBlindedReview             bool `json:"fresh_blinded_review"`
	CLIWitnessed                   bool `json:"cli_witnessed"`
	BasisClean                     bool `json:"basis_clean"`
	BasisFixed                     bool `json:"basis_fixed"`
	BasisAcceptedRisk              bool `json:"basis_accepted_risk"`
	BasisDeterministicRefutation   bool `json:"basis_deterministic_refutation"`
	PolicyFinalPredicatesSatisfied bool `json:"policy_final_predicates_satisfied"`
}

type Blocker struct {
	Code         string `json:"code"`
	Message      string `json:"message"`
	ObligationID string `json:"obligation_id,omitempty"`
	AnchorID     string `json:"anchor_id,omitempty"`
	Status       string `json:"status,omitempty"`
	Transition   string `json:"transition,omitempty"`
	Path         string `json:"path,omitempty"`
}

type ObligationFacts struct {
	ManifestDigest      string            `json:"manifest_digest"`
	Total               int               `json:"total"`
	Satisfied           int               `json:"satisfied"`
	Unsatisfied         int               `json:"unsatisfied"`
	ByKind              map[string]Counts `json:"by_kind"`
	UnsatisfiedKinds    []string          `json:"unsatisfied_satisfaction_kinds"`
	RequiredGateCount   int               `json:"required_gate_count"`
	CoverageCount       int               `json:"coverage_count"`
	PolicyFinalRequired bool              `json:"policy_final_required"`
}

type Counts struct {
	Total       int `json:"total"`
	Satisfied   int `json:"satisfied"`
	Unsatisfied int `json:"unsatisfied"`
}

type GateFacts struct {
	ObservationCount int               `json:"observation_count"`
	RequiredCount    int               `json:"required_count"`
	PassCount        int               `json:"pass_count"`
	FailCount        int               `json:"fail_count"`
	ErrorCount       int               `json:"error_count"`
	LatestByCommand  []GateObservation `json:"latest_by_command"`
}

type GateObservation struct {
	CommandID     string `json:"command_id"`
	Outcome       string `json:"outcome"`
	Provenance    string `json:"provenance"`
	InputSnapshot string `json:"input_snapshot"`
	EventID       string `json:"event_id"`
	Digest        string `json:"digest"`
}

type FindingFacts struct {
	AcceptedCount          int              `json:"accepted_count"`
	OpenBlockingCount      int              `json:"open_blocking_count"`
	VerifierOutcomeCount   int              `json:"verifier_outcome_count"`
	DeterministicRefutes   int              `json:"deterministic_refutation_count"`
	ActiveBlockingFindings []FindingBlocker `json:"active_blocking_findings"`
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

type RunFacts struct {
	DiscoveryRuns          int            `json:"discovery_runs"`
	VerificationRuns       int            `json:"verification_runs"`
	PrimaryRuns            int            `json:"primary_runs"`
	IndependentFinalRuns   int            `json:"independent_final_runs"`
	TargetedVerifications  int            `json:"targeted_verifications"`
	CompactFreshVerifies   int            `json:"compact_fresh_verifications"`
	ContextExpansionRounds int            `json:"context_expansion_rounds"`
	ByRoute                map[string]int `json:"by_route"`
}

type TokenFacts struct {
	Discovery    TokenTotals       `json:"discovery"`
	Verification TokenTotals       `json:"verification"`
	FullCycle    FullCycleEstimate `json:"full_cycle_estimate"`
}

type TokenTotals struct {
	GrossDiscoveryTokens          int   `json:"gross_discovery_tokens,omitempty"`
	IncrementalDiscoveryTokens    int   `json:"incremental_discovery_tokens,omitempty"`
	GrossVerificationTokens       int   `json:"gross_verification_tokens,omitempty"`
	IncrementalVerificationTokens int   `json:"incremental_verification_tokens,omitempty"`
	GrossInputTokens              int   `json:"gross_input_tokens,omitempty"`
	IncrementalInputTokens        int   `json:"incremental_input_tokens,omitempty"`
	CachedInputTokens             int   `json:"cached_input_tokens,omitempty"`
	OutputTokens                  int   `json:"output_tokens,omitempty"`
	ReasoningTokens               int   `json:"reasoning_tokens,omitempty"`
	LatencyMS                     int64 `json:"latency_ms,omitempty"`
}

type FullCycleEstimate struct {
	Available         bool   `json:"available"`
	IncrementalTokens int    `json:"incremental_tokens,omitempty"`
	GrossTokens       int    `json:"gross_tokens,omitempty"`
	Basis             string `json:"basis,omitempty"`
}

type SchedulerFacts struct {
	PolicyRouteLimits policy.RouteLimits `json:"policy_route_limits"`
	Observed          SchedulerObserved  `json:"observed"`
	OverLimit         bool               `json:"over_limit"`
	Violations        []string           `json:"violations"`
	AntiThrashOK      bool               `json:"anti_thrash_ok"`
}

type SchedulerObserved struct {
	PrimarySemanticReviews int `json:"primary_semantic_reviews"`
	TargetedVerifications  int `json:"targeted_verifications"`
	FreshFinalReviews      int `json:"fresh_final_reviews"`
	ContextExpansionRounds int `json:"context_expansion_rounds"`
}

type binding struct {
	State string
	Repo  string
}

func Evaluate(opts EvaluateOptions) (Result, error) {
	profile := strings.TrimSpace(opts.PolicyProfile)
	if profile == "" {
		return Result{}, errors.New("--policy-profile is required")
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	bind, err := stateBinding(opts.StateDir)
	if err != nil {
		return Result{}, err
	}
	store, err := state.Open(bind.State)
	if err != nil {
		return Result{}, err
	}
	events, err := state.ReadEvents(bind.State)
	if err != nil {
		return Result{}, err
	}
	status, err := obligation.Status(obligation.StatusOptions{StateDir: bind.State})
	if err != nil {
		return Result{}, err
	}
	manifest, err := readCoverageManifest(store, status.Manifest.Digest)
	if err != nil {
		return Result{}, err
	}
	effective, err := readEffectivePolicy(store, manifest)
	if err != nil {
		return Result{}, err
	}
	observations, err := reviewresult.Observations(store, events, bind.Repo)
	if err != nil {
		return Result{}, err
	}
	gateEvidence, err := gate.EvidenceByCommand(store, events, bind.Repo)
	if err != nil {
		return Result{}, err
	}

	blockers := copyBlockers(status.Blockers)
	policyDigest := ""
	if manifest.Policy == nil {
		blockers = append(blockers, Blocker{Code: "policy_bound_missing", Message: "latest coverage manifest is not bound to a policy profile"})
	} else {
		policyDigest = manifest.Policy.Digest
		if manifest.Policy.Profile != profile {
			blockers = append(blockers, Blocker{
				Code:    "policy_profile_mismatch",
				Message: fmt.Sprintf("requested policy profile %q does not match coverage manifest profile %q", profile, manifest.Policy.Profile),
			})
		}
	}

	proposalDigest := proposalTargetDigest(manifest)
	findingFacts := findingFacts(observations, status.Manifest.Digest, proposalDigest, policyDigest)
	runFacts, tokens := runAndTokenFacts(observations, status.Manifest.Digest, proposalDigest, policyDigest)
	obligationFacts := obligationFacts(status)
	gateFacts := gateFacts(gateEvidence, obligationFacts.RequiredGateCount)
	facts := factsFromEvidence(status, manifest, observations, status.Manifest.Digest, proposalDigest, policyDigest, findingFacts)
	scheduler := schedulerFacts(effective, runFacts)
	if scheduler.OverLimit {
		blockers = append(blockers, Blocker{
			Code:    "scheduler_route_limit_exceeded",
			Message: "policy route limits exceeded: " + strings.Join(scheduler.Violations, "; "),
		})
	}
	blockers = append(blockers, policyFactBlockers(effective, facts)...)
	blockers = append(blockers, closureBasisBlockers(effective.ClosureBasis, facts)...)
	closed := status.Closed && facts.PolicyBound && len(blockers) == 0

	sortBlockers(blockers)
	report := Report{
		SchemaVersion: SchemaVersion,
		State:         bind.State,
		Repo:          bind.Repo,
		PolicyProfile: profile,
		PolicyDigest:  policyDigest,
		Coverage:      status.Manifest,
		EvaluatedAt:   now.Format(time.RFC3339Nano),
		Closed:        closed,
		Facts:         facts,
		Blockers:      blockers,
		Obligations:   obligationFacts,
		Gates:         gateFacts,
		Findings:      findingFacts,
		Runs:          runFacts,
		Tokens:        tokens,
		Scheduler:     scheduler,
	}
	reportRef, err := store.PutJSON(report, MediaTypeReport)
	if err != nil {
		return Result{}, err
	}
	event, err := state.AppendEvent(bind.State, state.Event{
		Time:          now.Format(time.RFC3339Nano),
		Type:          EventTypeEvaluated,
		ObjectDigests: []string{reportRef.Digest},
		Repo:          bind.Repo,
		Details: map[string]string{
			"closure_report":    reportRef.Digest,
			"coverage_manifest": status.Manifest.Digest,
			"policy_profile":    profile,
			"closed":            strconv.FormatBool(closed),
			"blockers":          strconv.Itoa(len(blockers)),
			"discovery_runs":    strconv.Itoa(runFacts.DiscoveryRuns),
			"verification_runs": strconv.Itoa(runFacts.VerificationRuns),
		},
	})
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion: SchemaVersion,
		State:         bind.State,
		Repo:          bind.Repo,
		PolicyProfile: profile,
		PolicyDigest:  policyDigest,
		Closed:        closed,
		Report:        reportRef,
		EventID:       event.EventID,
		Facts:         facts,
		Blockers:      blockers,
		Obligations:   obligationFacts,
		Gates:         gateFacts,
		Findings:      findingFacts,
		Runs:          runFacts,
		Tokens:        tokens,
		Scheduler:     scheduler,
	}, nil
}

func stateBinding(stateDir string) (binding, error) {
	root, err := state.ResolveStateDir(stateDir)
	if err != nil {
		return binding{}, err
	}
	if result := state.Validate(root); !result.OK {
		return binding{}, stateValidationError(result)
	}
	events, err := state.ReadEvents(root)
	if err != nil {
		return binding{}, err
	}
	if len(events) == 0 || events[0].Type != "state.initialized" {
		return binding{}, errors.New("state first event is not state.initialized")
	}
	return binding{State: root, Repo: events[0].Repo}, nil
}

func readCoverageManifest(store state.Store, digest string) (obligation.CoverageManifest, error) {
	body, err := store.Read(digest)
	if err != nil {
		return obligation.CoverageManifest{}, err
	}
	var manifest obligation.CoverageManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return obligation.CoverageManifest{}, err
	}
	return manifest, nil
}

func readEffectivePolicy(store state.Store, manifest obligation.CoverageManifest) (policy.EffectivePolicy, error) {
	if manifest.Policy == nil || strings.TrimSpace(manifest.Policy.Digest) == "" {
		return policy.EffectivePolicy{}, nil
	}
	body, err := store.Read(manifest.Policy.Digest)
	if err != nil {
		return policy.EffectivePolicy{}, err
	}
	var effective policy.EffectivePolicy
	if err := json.Unmarshal(body, &effective); err != nil {
		return policy.EffectivePolicy{}, err
	}
	return effective, nil
}

func factsFromEvidence(status obligation.StatusResult, manifest obligation.CoverageManifest, observations []reviewresult.EvidenceObservation, manifestDigest, proposalDigest, policyDigest string, findings FindingFacts) Facts {
	_, hasPrimary := reviewresult.LatestPrimaryReviewForManifest(observations, manifestDigest)
	if !hasPrimary && proposalDigest != "" {
		_, hasPrimary = reviewresult.LatestPrimaryReviewForTargetState(observations, proposalDigest, policyDigest)
	}
	_, hasFinal := reviewresult.LatestIndependentFinalReviewForManifest(observations, manifestDigest)
	evidence := evidenceFacts(observations, manifestDigest, proposalDigest, policyDigest)
	facts := Facts{
		PolicyBound:                    manifest.Policy != nil,
		RequiredGatesSatisfied:         obligationsSatisfied(status, obligation.KindGateRequirement),
		PrimaryReviewCompleted:         hasPrimary,
		BlockingFindingsVerified:       findings.OpenBlockingCount == 0,
		CoverageObligationsSatisfied:   coverageSatisfied(status),
		ContextRequestsResolved:        contextRequestsResolved(observations, manifestDigest, proposalDigest, policyDigest),
		IndependentFinalCompleted:      hasFinal,
		FreshBlindedReview:             evidence.FreshBlindedReview,
		CLIWitnessed:                   evidence.CLIWitnessed,
		BasisClean:                     evidence.BasisClean,
		BasisFixed:                     evidence.BasisFixed,
		BasisAcceptedRisk:              evidence.BasisAcceptedRisk,
		BasisDeterministicRefutation:   evidence.BasisDeterministicRefutation,
		PolicyFinalPredicatesSatisfied: obligationsSatisfied(status, obligation.KindPolicyFinalReview),
	}
	return facts
}

func contextRequestsResolved(observations []reviewresult.EvidenceObservation, manifestDigest, proposalDigest, policyDigest string) bool {
	for _, observation := range observations {
		record := observation.Record
		if record.Packet.CoverageManifest.Digest != manifestDigest || record.RunKind != reviewresult.RunKindDiscovery {
			continue
		}
		return record.Outcome != reviewresult.OutcomeNeedsContext && len(record.NeedsContext) == 0
	}
	if proposalDigest != "" {
		observation, ok := reviewresult.LatestDiscoveryForTargetState(observations, proposalDigest, policyDigest)
		if ok {
			record := observation.Record
			return record.Outcome != reviewresult.OutcomeNeedsContext && len(record.NeedsContext) == 0
		}
	}
	return true
}

func evidenceFacts(observations []reviewresult.EvidenceObservation, manifestDigest, proposalDigest, policyDigest string) Facts {
	facts := Facts{}
	for _, observation := range observations {
		record := observation.Record
		if !closureObservationApplies(record, manifestDigest, proposalDigest, policyDigest) {
			continue
		}
		if record.RunKind == reviewresult.RunKindDiscovery && record.Route == reviewresult.RoutePrimaryReview && record.Outcome == reviewresult.OutcomeClean {
			facts.BasisClean = true
		}
		for _, outcome := range record.VerifierOutcomes {
			if outcome.State == reviewresult.StateVerified && outcome.Basis == reviewresult.BasisFixVerification {
				facts.BasisFixed = true
			}
			if outcome.VerifierRelation == reviewresult.RelationFreshBlinded {
				facts.FreshBlindedReview = true
			}
			if outcome.RelationEvidence == reviewresult.RelationEvidenceCLIWitnessed {
				facts.CLIWitnessed = true
			}
		}
		for _, refutation := range record.DeterministicRefutations {
			if refutation.Basis == reviewresult.BasisDeterministicRefutation || refutation.Basis == reviewresult.BasisExecutableRefutation {
				facts.BasisDeterministicRefutation = true
			}
		}
	}
	return facts
}

func closureObservationApplies(record reviewresult.ResultRecord, manifestDigest, proposalDigest, policyDigest string) bool {
	if record.Packet.CoverageManifest.Digest == manifestDigest {
		return true
	}
	return record.Evidence.PrimaryReviewEvidence &&
		proposalDigest != "" &&
		record.Packet.TargetState.Kind == "proposal" &&
		record.Packet.TargetState.Digest == proposalDigest &&
		packetPolicyMatches(record.Packet.Policy, policyDigest)
}

func proposalTargetDigest(manifest obligation.CoverageManifest) string {
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == "base" && diff.ToKind == "proposal" {
			return diff.ToSnapshot
		}
	}
	return ""
}

func packetPolicyMatches(policy *reviewresult.PolicyRef, policyDigest string) bool {
	policyDigest = strings.TrimSpace(policyDigest)
	if policyDigest == "" {
		return policy == nil || strings.TrimSpace(policy.Digest) == ""
	}
	return policy != nil && policy.Digest == policyDigest
}

func policyFactBlockers(effective policy.EffectivePolicy, facts Facts) []Blocker {
	blockers := []Blocker{}
	for _, fact := range effective.RequiredEvidenceFacts {
		if factSatisfied(fact, facts) {
			continue
		}
		blockers = append(blockers, Blocker{
			Code:    "unsatisfied_policy_fact",
			Message: "required policy evidence fact is not satisfied: " + fact,
			Status:  fact,
		})
	}
	return blockers
}

func closureBasisBlockers(basis policy.ClosureBasis, facts Facts) []Blocker {
	allowed := map[string]struct{}{}
	for _, item := range basis.AllowedBasis {
		allowed[strings.TrimSpace(item)] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	for item := range allowed {
		if basisSatisfied(item, facts) {
			return nil
		}
	}
	return []Blocker{{
		Code:    "unsatisfied_closure_basis",
		Message: "no allowed closure basis is satisfied: " + strings.Join(sortedBasis(allowed), ", "),
	}}
}

func basisSatisfied(basis string, facts Facts) bool {
	switch basis {
	case "clean":
		return facts.BasisClean
	case "fixed":
		return facts.BasisFixed
	case "accepted_risk":
		return facts.BasisAcceptedRisk
	case "deterministic_refutation":
		return facts.BasisDeterministicRefutation
	default:
		return false
	}
}

func sortedBasis(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func factSatisfied(fact string, facts Facts) bool {
	switch fact {
	case "policy_bound":
		return facts.PolicyBound
	case "required_gates_satisfied":
		return facts.RequiredGatesSatisfied
	case "primary_review_completed":
		return facts.PrimaryReviewCompleted
	case "blocking_findings_verified":
		return facts.BlockingFindingsVerified
	case "coverage_obligations_satisfied":
		return facts.CoverageObligationsSatisfied
	case "context_requests_resolved":
		return facts.ContextRequestsResolved
	case "independent_final_completed":
		return facts.IndependentFinalCompleted
	case "fresh_blinded_review":
		return facts.FreshBlindedReview
	case "cli_witnessed":
		return facts.CLIWitnessed
	case "basis_clean":
		return facts.BasisClean
	case "basis_fixed":
		return facts.BasisFixed
	case "basis_accepted_risk":
		return facts.BasisAcceptedRisk
	case "basis_deterministic_refutation":
		return facts.BasisDeterministicRefutation
	default:
		return false
	}
}

func obligationFacts(status obligation.StatusResult) ObligationFacts {
	byKind := map[string]Counts{}
	requiredGateCount := 0
	coverageCount := 0
	policyFinalRequired := false
	for _, item := range status.Obligations {
		kind := item.Obligation.Kind
		counts := byKind[kind]
		counts.Total++
		if item.Satisfied {
			counts.Satisfied++
		} else {
			counts.Unsatisfied++
		}
		byKind[kind] = counts
		switch kind {
		case obligation.KindGateRequirement:
			if item.Obligation.Required {
				requiredGateCount++
			}
		case obligation.KindChangedPath, obligation.KindChangedFile, obligation.KindChangedHunk:
			if item.Obligation.Required {
				coverageCount++
			}
		case obligation.KindPolicyFinalReview:
			if item.Obligation.Required {
				policyFinalRequired = true
			}
		}
	}
	return ObligationFacts{
		ManifestDigest:      status.Manifest.Digest,
		Total:               len(status.Obligations),
		Satisfied:           status.SatisfiedCount,
		Unsatisfied:         status.UnsatisfiedCount,
		ByKind:              byKind,
		UnsatisfiedKinds:    append([]string(nil), status.UnsatisfiedSatisfactionKinds...),
		RequiredGateCount:   requiredGateCount,
		CoverageCount:       coverageCount,
		PolicyFinalRequired: policyFinalRequired,
	}
}

func gateFacts(evidence map[string][]gate.EvidenceObservation, requiredCount int) GateFacts {
	facts := GateFacts{RequiredCount: requiredCount, LatestByCommand: []GateObservation{}}
	commandIDs := make([]string, 0, len(evidence))
	for commandID := range evidence {
		commandIDs = append(commandIDs, commandID)
	}
	sort.Strings(commandIDs)
	for _, commandID := range commandIDs {
		observations := evidence[commandID]
		facts.ObservationCount += len(observations)
		for _, observation := range observations {
			switch observation.Record.Outcome {
			case gate.OutcomePass:
				facts.PassCount++
			case gate.OutcomeFail:
				facts.FailCount++
			case gate.OutcomeError:
				facts.ErrorCount++
			}
		}
		if len(observations) == 0 {
			continue
		}
		latest := observations[0]
		facts.LatestByCommand = append(facts.LatestByCommand, GateObservation{
			CommandID:     commandID,
			Outcome:       latest.Record.Outcome,
			Provenance:    latest.Record.Provenance,
			InputSnapshot: latest.Record.InputSnapshot.Kind,
			EventID:       latest.EventID,
			Digest:        latest.Digest,
		})
	}
	return facts
}

func findingFacts(observations []reviewresult.EvidenceObservation, manifestDigest, proposalDigest, policyDigest string) FindingFacts {
	facts := FindingFacts{ActiveBlockingFindings: []FindingBlocker{}}
	for _, observation := range observations {
		record := observation.Record
		if !closureObservationApplies(record, manifestDigest, proposalDigest, policyDigest) {
			continue
		}
		for _, finding := range record.Findings {
			if finding.Accepted {
				facts.AcceptedCount++
			}
		}
		facts.VerifierOutcomeCount += len(record.VerifierOutcomes)
		facts.DeterministicRefutes += len(record.DeterministicRefutations)
	}
	blockers := reviewresult.ClosureFindingBlockers(observations, manifestDigest, proposalDigest, policyDigest)
	facts.OpenBlockingCount = len(blockers)
	for _, blocker := range blockers {
		facts.ActiveBlockingFindings = append(facts.ActiveBlockingFindings, FindingBlocker{
			FindingID: blocker.FindingID,
			State:     blocker.State,
			Severity:  blocker.Severity,
			Class:     blocker.Class,
			Claim:     blocker.Claim,
			EventID:   blocker.EventID,
			Digest:    blocker.Digest,
		})
	}
	return facts
}

func runAndTokenFacts(observations []reviewresult.EvidenceObservation, manifestDigest, proposalDigest, policyDigest string) (RunFacts, TokenFacts) {
	runs := RunFacts{ByRoute: map[string]int{}}
	tokens := TokenFacts{}
	for _, observation := range observations {
		record := observation.Record
		if !closureObservationApplies(record, manifestDigest, proposalDigest, policyDigest) {
			continue
		}
		runs.ByRoute[record.Route]++
		switch record.RunKind {
		case reviewresult.RunKindDiscovery:
			runs.DiscoveryRuns++
			addTelemetry(&tokens.Discovery, record.Telemetry)
		case reviewresult.RunKindVerification:
			runs.VerificationRuns++
			addTelemetry(&tokens.Verification, record.Telemetry)
		}
		switch record.Route {
		case reviewresult.RoutePrimaryReview:
			runs.PrimaryRuns++
			if record.RunKind == reviewresult.RunKindDiscovery && record.Outcome == reviewresult.OutcomeNeedsContext {
				runs.ContextExpansionRounds++
			}
		case reviewresult.RouteIndependentFinal:
			runs.IndependentFinalRuns++
		case reviewresult.RouteTargetedVerification:
			runs.TargetedVerifications++
		case reviewresult.RouteCompactFreshVerify:
			runs.CompactFreshVerifies++
		}
	}
	discoveryIncremental := preferredIncremental(tokens.Discovery.IncrementalDiscoveryTokens, tokens.Discovery.IncrementalInputTokens)
	verificationIncremental := preferredIncremental(tokens.Verification.IncrementalVerificationTokens, tokens.Verification.IncrementalInputTokens)
	discoveryGross := preferredGross(tokens.Discovery.GrossDiscoveryTokens, tokens.Discovery.GrossInputTokens)
	verificationGross := preferredGross(tokens.Verification.GrossVerificationTokens, tokens.Verification.GrossInputTokens)
	if discoveryIncremental > 0 || verificationIncremental > 0 || discoveryGross > 0 || verificationGross > 0 {
		tokens.FullCycle = FullCycleEstimate{
			Available:         true,
			IncrementalTokens: discoveryIncremental + verificationIncremental,
			GrossTokens:       discoveryGross + verificationGross,
			Basis:             "sum of measured discovery and verification telemetry in the latest coverage manifest",
		}
	}
	return runs, tokens
}

func addTelemetry(total *TokenTotals, telemetry reviewresult.TokenTelemetry) {
	total.GrossDiscoveryTokens += telemetry.GrossDiscoveryTokens
	total.IncrementalDiscoveryTokens += telemetry.IncrementalDiscoveryTokens
	total.GrossVerificationTokens += telemetry.GrossVerificationTokens
	total.IncrementalVerificationTokens += telemetry.IncrementalVerificationTokens
	total.GrossInputTokens += telemetry.GrossInputTokens
	total.IncrementalInputTokens += telemetry.IncrementalInputTokens
	total.CachedInputTokens += telemetry.CachedInputTokens
	total.OutputTokens += telemetry.OutputTokens
	total.ReasoningTokens += telemetry.ReasoningTokens
	total.LatencyMS += telemetry.LatencyMS
}

func preferredIncremental(primary, fallback int) int {
	if primary > 0 {
		return primary
	}
	return fallback
}

func preferredGross(primary, fallback int) int {
	if primary > 0 {
		return primary
	}
	return fallback
}

func schedulerFacts(effective policy.EffectivePolicy, runs RunFacts) SchedulerFacts {
	observed := SchedulerObserved{
		PrimarySemanticReviews: runs.PrimaryRuns,
		TargetedVerifications:  runs.TargetedVerifications,
		FreshFinalReviews:      runs.IndependentFinalRuns,
		ContextExpansionRounds: runs.ContextExpansionRounds,
	}
	facts := SchedulerFacts{
		PolicyRouteLimits: effective.RouteLimits,
		Observed:          observed,
		AntiThrashOK:      true,
	}
	if effective.RouteLimits.PrimarySemanticReviews > 0 && observed.PrimarySemanticReviews > effective.RouteLimits.PrimarySemanticReviews {
		facts.Violations = append(facts.Violations, "primary semantic reviews exceed policy route limit")
	}
	if effective.RouteLimits.TargetedVerifications >= 0 && observed.TargetedVerifications > effective.RouteLimits.TargetedVerifications {
		facts.Violations = append(facts.Violations, "targeted verifications exceed policy route limit")
	}
	if effective.RouteLimits.FreshFinalReviews >= 0 && observed.FreshFinalReviews > effective.RouteLimits.FreshFinalReviews {
		facts.Violations = append(facts.Violations, "fresh final reviews exceed policy route limit")
	}
	if effective.RouteLimits.ContextExpansionRounds >= 0 && observed.ContextExpansionRounds > effective.RouteLimits.ContextExpansionRounds {
		facts.Violations = append(facts.Violations, "context expansion rounds exceed policy route limit")
	}
	facts.OverLimit = len(facts.Violations) > 0
	facts.AntiThrashOK = !facts.OverLimit
	return facts
}

func coverageSatisfied(status obligation.StatusResult) bool {
	for _, item := range status.Obligations {
		switch item.Obligation.Kind {
		case obligation.KindChangedPath, obligation.KindChangedFile, obligation.KindChangedHunk:
			if item.Obligation.Required && !item.Satisfied {
				return false
			}
		}
	}
	return true
}

func obligationsSatisfied(status obligation.StatusResult, kind string) bool {
	for _, item := range status.Obligations {
		if item.Obligation.Kind != kind || !item.Obligation.Required {
			continue
		}
		if !item.Satisfied {
			return false
		}
	}
	return true
}

func hasBlockerCode(blockers []Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}

func copyBlockers(input []obligation.Blocker) []Blocker {
	out := make([]Blocker, 0, len(input))
	for _, blocker := range input {
		out = append(out, Blocker{
			Code:         blocker.Code,
			Message:      blocker.Message,
			ObligationID: blocker.ObligationID,
			AnchorID:     blocker.AnchorID,
			Status:       blocker.Status,
			Transition:   blocker.Transition,
			Path:         blocker.Path,
		})
	}
	return out
}

func sortBlockers(blockers []Blocker) {
	sort.Slice(blockers, func(i, j int) bool {
		if blockers[i].Code == blockers[j].Code {
			if blockers[i].ObligationID == blockers[j].ObligationID {
				if blockers[i].Path == blockers[j].Path {
					return blockers[i].Message < blockers[j].Message
				}
				return blockers[i].Path < blockers[j].Path
			}
			return blockers[i].ObligationID < blockers[j].ObligationID
		}
		return blockers[i].Code < blockers[j].Code
	})
}

func stateValidationError(result state.ValidationResult) error {
	if len(result.Errors) == 0 {
		return fmt.Errorf("state validation failed: %s", result.State)
	}
	first := result.Errors[0]
	return fmt.Errorf("state validation failed: %s: %s: %s", result.State, first.Code, first.Message)
}
