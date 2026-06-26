package obligation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/charlesnpx/subreview/internal/anchor"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	KindChangedPath       = "changed_path"
	KindChangedFile       = "changed_file"
	KindChangedHunk       = "changed_hunk"
	KindContextRequest    = "context_request"
	KindGateRequirement   = "gate_requirement"
	KindPolicyFinalReview = "policy_final_review"

	SatisfactionGateEvidence          = "gate_evidence"
	SatisfactionPrimaryReviewEvidence = "primary_review_evidence"
	SatisfactionVerificationEvidence  = "verification_evidence"
	SatisfactionDeterministicRefute   = "deterministic_refutation"
	SatisfactionCarriedForward        = "carried_forward_evidence"
)

var hunkHeaderPattern = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)

type BuildOptions struct {
	StateDir string
}

type StatusOptions struct {
	StateDir string
}

type BuildResult struct {
	SchemaVersion   int             `json:"schema_version"`
	State           string          `json:"state"`
	Repo            string          `json:"repo"`
	Manifest        state.ObjectRef `json:"manifest"`
	ObligationCount int             `json:"obligation_count"`
	BlockerCount    int             `json:"blocker_count"`
	EventID         string          `json:"event_id"`
}

type StatusResult struct {
	SchemaVersion                int                `json:"schema_version"`
	State                        string             `json:"state"`
	Repo                         string             `json:"repo"`
	Manifest                     state.ObjectRef    `json:"manifest"`
	Closed                       bool               `json:"closed"`
	SatisfiedCount               int                `json:"satisfied_count"`
	UnsatisfiedCount             int                `json:"unsatisfied_count"`
	UnsatisfiedSatisfactionKinds []string           `json:"unsatisfied_satisfaction_kinds"`
	Blockers                     []Blocker          `json:"blockers"`
	Obligations                  []ObligationStatus `json:"obligations"`
}

type CoverageManifest struct {
	SchemaVersion int              `json:"schema_version"`
	Repo          string           `json:"repo"`
	Policy        *PolicyRef       `json:"policy,omitempty"`
	SourceDiffs   []TransitionDiff `json:"source_diffs"`
	Obligations   []Obligation     `json:"obligations"`
	Blockers      []Blocker        `json:"blockers"`
	SchemaCapture SchemaCapture    `json:"schema_capture"`
}

type PolicyRef struct {
	Profile  string `json:"profile"`
	PolicyID string `json:"policy_id"`
	Digest   string `json:"digest"`
}

type SchemaCapture struct {
	SymbolImpacts   []string `json:"symbol_impacts"`
	ContractImpacts []string `json:"contract_impacts"`
}

type TransitionDiff struct {
	Transition   string          `json:"transition"`
	FromKind     string          `json:"from_kind"`
	ToKind       string          `json:"to_kind"`
	FromSnapshot string          `json:"from_snapshot"`
	ToSnapshot   string          `json:"to_snapshot"`
	Diff         state.ObjectRef `json:"diff"`
	Patch        state.ObjectRef `json:"patch"`
	HasChanges   bool            `json:"has_changes"`
}

type Obligation struct {
	ID                        string            `json:"id"`
	Kind                      string            `json:"kind"`
	Required                  bool              `json:"required"`
	Transition                string            `json:"transition,omitempty"`
	Path                      string            `json:"path,omitempty"`
	OldPath                   string            `json:"old_path,omitempty"`
	StartLine                 int               `json:"start_line,omitempty"`
	EndLine                   int               `json:"end_line,omitempty"`
	CommandID                 string            `json:"command_id,omitempty"`
	Fact                      string            `json:"fact,omitempty"`
	Anchor                    *AnchorRef        `json:"anchor,omitempty"`
	RequiredSatisfactionKinds []string          `json:"required_satisfaction_kinds"`
	Metadata                  map[string]string `json:"metadata,omitempty"`
}

type AnchorRef struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
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

type ObligationStatus struct {
	Obligation                   Obligation    `json:"obligation"`
	Satisfied                    bool          `json:"satisfied"`
	SatisfiedBy                  []EvidenceRef `json:"satisfied_by"`
	UnsatisfiedSatisfactionKinds []string      `json:"unsatisfied_satisfaction_kinds"`
	Blockers                     []Blocker     `json:"blockers"`
}

type EvidenceRef struct {
	Kind    string `json:"kind"`
	EventID string `json:"event_id,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

type stateBinding struct {
	State string
	Repo  string
}

type boundPolicy struct {
	Ref       PolicyRef
	Effective policy.EffectivePolicy
}

type diffBinding struct {
	Transition   string
	FromKind     string
	ToKind       string
	FromSnapshot string
	ToSnapshot   string
	Diff         state.ObjectRef
	Patch        state.ObjectRef
	HasChanges   bool
	PatchBody    []byte
}

type filePatch struct {
	OldPath string
	NewPath string
	Hunks   []patchHunk
}

type patchHunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
}

type anchorMigrationRecord struct {
	SchemaVersion   int                     `json:"schema_version"`
	Repo            string                  `json:"repo"`
	FromKind        string                  `json:"from_kind"`
	ToKind          string                  `json:"to_kind"`
	FromSnapshot    string                  `json:"from_snapshot"`
	ToSnapshot      string                  `json:"to_snapshot"`
	Diff            state.ObjectRef         `json:"diff"`
	Patch           state.ObjectRef         `json:"patch"`
	AnchorManifest  state.ObjectRef         `json:"anchor_manifest"`
	Results         []anchor.AnchorResult   `json:"results"`
	ClosureBlockers []anchor.ClosureBlocker `json:"closure_blockers"`
}

func Build(opts BuildOptions) (BuildResult, error) {
	binding, err := stateBindingFromState(opts.StateDir)
	if err != nil {
		return BuildResult{}, err
	}
	store, err := state.Open(binding.State)
	if err != nil {
		return BuildResult{}, err
	}
	events, err := state.ReadEvents(binding.State)
	if err != nil {
		return BuildResult{}, err
	}
	policyBinding, err := latestBoundPolicy(store, events, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	blockers := []Blocker{}
	if policyBinding == nil {
		blockers = append(blockers, Blocker{
			Code:    "policy_bound_missing",
			Message: "no policy.bound event is available for obligation construction",
		})
	}

	baseProposal, err := latestDiffBinding(store, events, binding.State, "base", "proposal", binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	sourceDiffs := []TransitionDiff{transitionDiff(baseProposal)}
	obligations := obligationsFromDiff(baseProposal)

	if baseFinal, err := latestDiffBinding(store, events, binding.State, "base", "final", binding.Repo); err == nil {
		sourceDiffs = append(sourceDiffs, transitionDiff(baseFinal))
		obligations = append(obligations, obligationsFromDiff(baseFinal)...)
	} else {
		blockers = append(blockers, Blocker{
			Code:       "hidden_scope_uncertainty",
			Message:    "base->final diff is not captured; final-state coverage cannot be proven",
			Transition: "base->final",
		})
	}

	obligations = append(obligations, contextRequestPlaceholder())
	if policyBinding != nil {
		obligations = append(obligations, policyObligations(policyBinding.Effective)...)
	}
	sortObligations(obligations)
	sortBlockers(blockers)

	manifestRecord := CoverageManifest{
		SchemaVersion: SchemaVersion,
		Repo:          binding.Repo,
		SourceDiffs:   sourceDiffs,
		Obligations:   obligations,
		Blockers:      blockers,
		SchemaCapture: SchemaCapture{
			SymbolImpacts:   []string{},
			ContractImpacts: []string{},
		},
	}
	if policyBinding != nil {
		manifestRecord.Policy = &policyBinding.Ref
	}
	manifestRef, err := store.PutJSON(manifestRecord, "application/vnd.subreview.coverage-manifest+json")
	if err != nil {
		return BuildResult{}, err
	}
	details := map[string]string{
		"coverage_manifest": manifestRef.Digest,
		"obligations":       strconv.Itoa(len(obligations)),
		"blockers":          strconv.Itoa(len(blockers)),
	}
	if policyBinding != nil {
		details["policy"] = policyBinding.Ref.Digest
		details["profile"] = policyBinding.Ref.Profile
	}
	for _, diff := range sourceDiffs {
		details[diff.Transition+"_diff"] = diff.Diff.Digest
		details[diff.Transition+"_patch"] = diff.Patch.Digest
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          "obligations.built",
		ObjectDigests: []string{manifestRef.Digest},
		Repo:          binding.Repo,
		Details:       details,
	})
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		SchemaVersion:   SchemaVersion,
		State:           binding.State,
		Repo:            binding.Repo,
		Manifest:        manifestRef,
		ObligationCount: len(obligations),
		BlockerCount:    len(blockers),
		EventID:         event.EventID,
	}, nil
}

func Status(opts StatusOptions) (StatusResult, error) {
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
	manifestRef, manifest, err := latestCoverageManifest(store, events, binding.State, binding.Repo)
	if err != nil {
		return StatusResult{}, err
	}
	blockers := append([]Blocker(nil), manifest.Blockers...)
	freshnessBlockers, err := manifestFreshnessBlockers(store, events, binding.State, binding.Repo, manifest)
	if err != nil {
		return StatusResult{}, err
	}
	blockers = append(blockers, freshnessBlockers...)
	blockers = append(blockers, contextBlockers(events)...)
	anchorBlockers, err := unresolvedAnchorBlockers(store, events, binding.Repo, manifest.SourceDiffs)
	if err != nil {
		return StatusResult{}, err
	}
	blockers = append(blockers, anchorBlockers...)

	statuses := make([]ObligationStatus, 0, len(manifest.Obligations))
	unsatisfiedKinds := map[string]struct{}{}
	satisfied := 0
	for _, obligation := range manifest.Obligations {
		status := ObligationStatus{
			Obligation:                   obligation,
			Satisfied:                    false,
			SatisfiedBy:                  []EvidenceRef{},
			UnsatisfiedSatisfactionKinds: append([]string(nil), obligation.RequiredSatisfactionKinds...),
		}
		if !obligation.Required {
			status.Satisfied = true
			status.SatisfiedBy = append(status.SatisfiedBy, EvidenceRef{Kind: "not_required"})
			status.UnsatisfiedSatisfactionKinds = []string{}
		}
		if obligation.Kind == KindGateRequirement && obligation.Required {
			status.Blockers = append(status.Blockers, Blocker{
				Code:         "unsatisfied_required_check",
				Message:      "required gate evidence is not recorded yet",
				ObligationID: obligation.ID,
				Path:         obligation.Path,
			})
		}
		if isCoverageObligation(obligation) && obligation.Required {
			status.Blockers = append(status.Blockers, Blocker{
				Code:         "unsatisfied_coverage",
				Message:      "coverage obligation has no primary review, verification, deterministic refutation, or valid carry-forward evidence",
				ObligationID: obligation.ID,
				Transition:   obligation.Transition,
				Path:         obligation.Path,
			})
		}
		if obligation.Kind == KindPolicyFinalReview && obligation.Required {
			status.Blockers = append(status.Blockers, Blocker{
				Code:         "unsatisfied_policy_final_review",
				Message:      "policy-triggered final review evidence is not recorded yet",
				ObligationID: obligation.ID,
			})
		}
		if status.Satisfied {
			satisfied++
		}
		for _, kind := range status.UnsatisfiedSatisfactionKinds {
			unsatisfiedKinds[kind] = struct{}{}
		}
		blockers = append(blockers, status.Blockers...)
		statuses = append(statuses, status)
	}
	sortBlockers(blockers)
	kinds := sortedKeys(unsatisfiedKinds)
	return StatusResult{
		SchemaVersion:                SchemaVersion,
		State:                        binding.State,
		Repo:                         binding.Repo,
		Manifest:                     manifestRef,
		Closed:                       len(blockers) == 0 && satisfied == len(statuses),
		SatisfiedCount:               satisfied,
		UnsatisfiedCount:             len(statuses) - satisfied,
		UnsatisfiedSatisfactionKinds: kinds,
		Blockers:                     blockers,
		Obligations:                  statuses,
	}, nil
}

func transitionDiff(binding diffBinding) TransitionDiff {
	return TransitionDiff{
		Transition:   binding.Transition,
		FromKind:     binding.FromKind,
		ToKind:       binding.ToKind,
		FromSnapshot: binding.FromSnapshot,
		ToSnapshot:   binding.ToSnapshot,
		Diff:         binding.Diff,
		Patch:        binding.Patch,
		HasChanges:   binding.HasChanges,
	}
}

func obligationsFromDiff(binding diffBinding) []Obligation {
	files := parsePatch(binding.PatchBody)
	obligations := []Obligation{}
	for _, file := range files {
		path := file.NewPath
		if path == "" {
			path = file.OldPath
		}
		if path == "" {
			continue
		}
		pathKinds := []struct {
			kind       string
			anchorKind string
			kinds      []string
		}{
			{kind: KindChangedPath, anchorKind: anchor.KindPath, kinds: []string{SatisfactionPrimaryReviewEvidence, SatisfactionDeterministicRefute, SatisfactionCarriedForward}},
			{kind: KindChangedFile, anchorKind: anchor.KindFile, kinds: []string{SatisfactionPrimaryReviewEvidence, SatisfactionVerificationEvidence, SatisfactionDeterministicRefute, SatisfactionCarriedForward}},
		}
		for _, item := range pathKinds {
			obligations = append(obligations, Obligation{
				ID:                        obligationID(item.kind, binding.Transition, path, file.OldPath),
				Kind:                      item.kind,
				Required:                  true,
				Transition:                binding.Transition,
				Path:                      path,
				OldPath:                   file.OldPath,
				Anchor:                    &AnchorRef{Kind: item.anchorKind, Path: path},
				RequiredSatisfactionKinds: item.kinds,
			})
		}
		for _, hunk := range file.Hunks {
			start, end := finalHunkSpan(hunk)
			obligations = append(obligations, Obligation{
				ID:                        obligationID(KindChangedHunk, binding.Transition, path, fmt.Sprintf("%d:%d:%d:%d", hunk.OldStart, hunk.OldCount, hunk.NewStart, hunk.NewCount)),
				Kind:                      KindChangedHunk,
				Required:                  true,
				Transition:                binding.Transition,
				Path:                      path,
				OldPath:                   file.OldPath,
				StartLine:                 start,
				EndLine:                   end,
				Anchor:                    &AnchorRef{Kind: anchor.KindHunk, Path: path, StartLine: start, EndLine: end},
				RequiredSatisfactionKinds: []string{SatisfactionPrimaryReviewEvidence, SatisfactionVerificationEvidence, SatisfactionDeterministicRefute, SatisfactionCarriedForward},
				Metadata: map[string]string{
					"old_start": strconv.Itoa(hunk.OldStart),
					"old_count": strconv.Itoa(hunk.OldCount),
					"new_start": strconv.Itoa(hunk.NewStart),
					"new_count": strconv.Itoa(hunk.NewCount),
				},
			})
		}
	}
	return obligations
}

func contextRequestPlaceholder() Obligation {
	return Obligation{
		ID:                        "context_request_placeholder",
		Kind:                      KindContextRequest,
		Required:                  false,
		Fact:                      "context_requests_resolved",
		RequiredSatisfactionKinds: []string{SatisfactionPrimaryReviewEvidence, SatisfactionVerificationEvidence},
		Metadata: map[string]string{
			"placeholder": "true",
		},
	}
}

func policyObligations(effective policy.EffectivePolicy) []Obligation {
	obligations := []Obligation{}
	for _, gate := range effective.GateRequirements {
		if !gate.Required {
			continue
		}
		obligations = append(obligations, Obligation{
			ID:                        obligationID(KindGateRequirement, effective.Profile, gate.CommandID, ""),
			Kind:                      KindGateRequirement,
			Required:                  true,
			CommandID:                 gate.CommandID,
			Fact:                      "required_gates_satisfied",
			RequiredSatisfactionKinds: []string{SatisfactionGateEvidence},
		})
	}
	if policyRequiresIndependentFinal(effective) {
		obligations = append(obligations, Obligation{
			ID:                        obligationID(KindPolicyFinalReview, effective.Profile, "independent_final_completed", ""),
			Kind:                      KindPolicyFinalReview,
			Required:                  true,
			Fact:                      "independent_final_completed",
			RequiredSatisfactionKinds: []string{SatisfactionPrimaryReviewEvidence},
		})
	}
	return obligations
}

func policyRequiresIndependentFinal(effective policy.EffectivePolicy) bool {
	for _, fact := range effective.RequiredEvidenceFacts {
		if fact == "independent_final_completed" || fact == "fresh_blinded_review" || fact == "cli_witnessed" {
			return true
		}
	}
	for _, route := range effective.RiskRouting {
		if route.RequireIndependentFinal {
			return true
		}
	}
	return false
}

func isCoverageObligation(obligation Obligation) bool {
	return obligation.Kind == KindChangedPath || obligation.Kind == KindChangedFile || obligation.Kind == KindChangedHunk
}

func parsePatch(body []byte) []filePatch {
	lines := strings.Split(string(body), "\n")
	files := []filePatch{}
	var current *filePatch
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if current != nil {
				files = append(files, *current)
			}
			oldPath, newPath := parseDiffGitHeader(line)
			current = &filePatch{OldPath: oldPath, NewPath: newPath}
		case strings.HasPrefix(line, "--- ") && current != nil:
			current.OldPath = normalizeHeaderPath(strings.TrimSpace(strings.TrimPrefix(line, "--- ")), "from", "a")
		case strings.HasPrefix(line, "+++ ") && current != nil:
			current.NewPath = normalizeHeaderPath(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")), "to", "b")
		case strings.HasPrefix(line, "rename from ") && current != nil:
			current.OldPath = normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "rename from ")))
		case strings.HasPrefix(line, "rename to ") && current != nil:
			current.NewPath = normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "rename to ")))
		case strings.HasPrefix(line, "copy from ") && current != nil:
			current.OldPath = normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "copy from ")))
		case strings.HasPrefix(line, "copy to ") && current != nil:
			current.NewPath = normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "copy to ")))
		case strings.HasPrefix(line, "@@ ") && current != nil:
			if hunk, ok := parseHunkHeader(line); ok {
				current.Hunks = append(current.Hunks, hunk)
			}
		}
	}
	if current != nil {
		files = append(files, *current)
	}
	filtered := files[:0]
	for _, file := range files {
		if file.OldPath != "" || file.NewPath != "" || len(file.Hunks) > 0 {
			filtered = append(filtered, file)
		}
	}
	return filtered
}

func parseHunkHeader(line string) (patchHunk, bool) {
	match := hunkHeaderPattern.FindStringSubmatch(line)
	if match == nil {
		return patchHunk{}, false
	}
	oldStart, err := strconv.Atoi(match[1])
	if err != nil {
		return patchHunk{}, false
	}
	oldCount := 1
	if match[2] != "" {
		oldCount, err = strconv.Atoi(match[2])
		if err != nil {
			return patchHunk{}, false
		}
	}
	newStart, err := strconv.Atoi(match[3])
	if err != nil {
		return patchHunk{}, false
	}
	newCount := 1
	if match[4] != "" {
		newCount, err = strconv.Atoi(match[4])
		if err != nil {
			return patchHunk{}, false
		}
	}
	return patchHunk{OldStart: oldStart, OldCount: oldCount, NewStart: newStart, NewCount: newCount}, true
}

func finalHunkSpan(hunk patchHunk) (int, int) {
	if hunk.NewCount > 0 {
		return hunk.NewStart, hunk.NewStart + hunk.NewCount - 1
	}
	if hunk.OldCount > 0 {
		return hunk.OldStart, hunk.OldStart + hunk.OldCount - 1
	}
	return hunk.NewStart, hunk.NewStart
}

func normalizeDiffPath(path, prefix string) string {
	path, ok := decodeGitPathToken(path)
	if !ok {
		return ""
	}
	if prefix != "" {
		path = strings.TrimPrefix(path, prefix+"/")
	}
	return cleanDiffPath(path)
}

func cleanDiffPath(path string) string {
	if path == "/dev/null" || path == "" {
		return ""
	}
	clean, err := cleanRepoPath(path)
	if err != nil {
		return ""
	}
	return clean
}

func parseDiffGitHeader(line string) (string, string) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "diff --git "))
	left, right, ok := splitDiffGitArgs(rest)
	if !ok {
		return "", ""
	}
	return normalizeHeaderPath(left, "from", "a"), normalizeHeaderPath(right, "to", "b")
}

func splitDiffGitArgs(rest string) (string, string, bool) {
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "from/") {
		left, right, ok := splitKnownDiffPrefixes(rest, "from/", "to/")
		if !ok {
			return "", "", false
		}
		return left, right, true
	}
	if strings.HasPrefix(rest, "a/") {
		left, right, ok := splitKnownDiffPrefixes(rest, "a/", "b/")
		if !ok {
			return "", "", false
		}
		return left, right, true
	}
	first, remaining, ok := readDiffGitArg(rest)
	if !ok {
		return "", "", false
	}
	second, remaining, ok := readDiffGitArg(strings.TrimSpace(remaining))
	if !ok || strings.TrimSpace(remaining) != "" {
		return "", "", false
	}
	return first, second, true
}

func splitKnownDiffPrefixes(rest, leftPrefix, rightPrefix string) (string, string, bool) {
	if !strings.HasPrefix(rest, leftPrefix) {
		return "", "", false
	}
	marker := " " + rightPrefix
	indexes := []int{}
	searchStart := 0
	for {
		index := strings.Index(rest[searchStart:], marker)
		if index < 0 {
			break
		}
		index += searchStart
		if index > 0 {
			indexes = append(indexes, index)
		}
		searchStart = index + len(marker)
	}
	if len(indexes) == 0 {
		return "", "", false
	}
	var fallbackLeft, fallbackRight string
	for _, index := range indexes {
		left := rest[:index]
		right := rest[index+1:]
		if !strings.HasPrefix(right, rightPrefix) {
			continue
		}
		leftPath := normalizeHeaderPath(left, leftPrefix[:len(leftPrefix)-1], "")
		rightPath := normalizeHeaderPath(right, rightPrefix[:len(rightPrefix)-1], "")
		if leftPath != "" && rightPath != "" && leftPath == rightPath {
			return left, right, true
		}
		if fallbackLeft == "" && fallbackRight == "" {
			fallbackLeft, fallbackRight = left, right
		}
	}
	if fallbackLeft == "" && fallbackRight == "" {
		return "", "", false
	}
	if len(indexes) > 1 {
		return "", "", false
	}
	left, right := fallbackLeft, fallbackRight
	return left, right, true
}

func readDiffGitArg(rest string) (string, string, bool) {
	if rest == "" {
		return "", "", false
	}
	if rest[0] != '"' {
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return "", "", false
		}
		return fields[0], strings.TrimSpace(strings.TrimPrefix(rest, fields[0])), true
	}
	escaped := false
	for i := 1; i < len(rest); i++ {
		switch {
		case escaped:
			escaped = false
		case rest[i] == '\\':
			escaped = true
		case rest[i] == '"':
			return rest[:i+1], rest[i+1:], true
		}
	}
	return "", "", false
}

func normalizeHeaderPath(path string, primaryPrefix, alternatePrefix string) string {
	path, ok := decodeGitPathToken(path)
	if !ok {
		return ""
	}
	for _, prefix := range []string{primaryPrefix, alternatePrefix} {
		if prefix == "" {
			continue
		}
		if strings.HasPrefix(path, prefix+"/") {
			return cleanDiffPath(strings.TrimPrefix(path, prefix+"/"))
		}
	}
	return cleanDiffPath(path)
}

func normalizeMetadataPath(path string) string {
	path, ok := decodeGitPathToken(path)
	if !ok {
		return ""
	}
	return cleanDiffPath(path)
}

func decodeGitPathToken(path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" || path == "/dev/null" {
		return path, true
	}
	if strings.HasPrefix(path, `"`) {
		value, rest, ok := readDiffGitArg(path)
		if !ok {
			return "", false
		}
		if strings.TrimSpace(rest) != "" && !strings.HasPrefix(rest, "\t") {
			return "", false
		}
		unquoted, err := strconv.Unquote(value)
		if err != nil {
			return "", false
		}
		return unquoted, true
	}
	if tab := strings.IndexByte(path, '\t'); tab >= 0 {
		path = path[:tab]
	}
	return path, true
}

func latestCoverageManifest(store state.Store, events []state.Event, stateDir, repo string) (state.ObjectRef, CoverageManifest, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "obligations.built" {
			continue
		}
		if event.Repo != repo {
			return state.ObjectRef{}, CoverageManifest{}, errors.New("malformed obligations.built event: repo mismatch")
		}
		digest := event.Details["coverage_manifest"]
		if strings.TrimSpace(digest) == "" {
			return state.ObjectRef{}, CoverageManifest{}, errors.New("malformed obligations.built event: missing coverage_manifest")
		}
		if len(event.ObjectDigests) != 1 || event.ObjectDigests[0] != digest {
			return state.ObjectRef{}, CoverageManifest{}, errors.New("malformed obligations.built event: object_digests must contain only coverage manifest")
		}
		body, err := store.Read(digest)
		if err != nil {
			return state.ObjectRef{}, CoverageManifest{}, err
		}
		var manifest CoverageManifest
		if err := decodeStrict(body, &manifest); err != nil {
			return state.ObjectRef{}, CoverageManifest{}, err
		}
		if err := validateManifest(manifest, repo); err != nil {
			return state.ObjectRef{}, CoverageManifest{}, err
		}
		return state.ObjectRef{
			Digest:    digest,
			MediaType: "application/vnd.subreview.coverage-manifest+json",
			Size:      int64(len(body)),
			Path:      objectPathBestEffort(stateDir, digest),
		}, manifest, nil
	}
	return state.ObjectRef{}, CoverageManifest{}, errors.New("obligations have not been built in state")
}

func manifestFreshnessBlockers(store state.Store, events []state.Event, stateDir, repo string, manifest CoverageManifest) ([]Blocker, error) {
	blockers := []Blocker{}
	seenTransitions := map[string]struct{}{}
	for _, diff := range manifest.SourceDiffs {
		seenTransitions[diff.Transition] = struct{}{}
		latestFrom, err := latestSnapshotDigest(events, diff.FromKind, repo)
		if err != nil {
			return nil, err
		}
		latestTo, err := latestSnapshotDigest(events, diff.ToKind, repo)
		if err != nil {
			return nil, err
		}
		if diff.FromSnapshot != latestFrom || diff.ToSnapshot != latestTo {
			blockers = append(blockers, staleManifestBlocker(diff.Transition, "manifest source diff does not match latest snapshots"))
			continue
		}
		latestDiff, err := latestDiffBinding(store, events, stateDir, diff.FromKind, diff.ToKind, repo)
		if err != nil {
			blockers = append(blockers, staleManifestBlocker(diff.Transition, err.Error()))
			continue
		}
		if diff.Diff.Digest != latestDiff.Diff.Digest || diff.Patch.Digest != latestDiff.Patch.Digest {
			blockers = append(blockers, staleManifestBlocker(diff.Transition, "manifest source diff does not match latest captured diff"))
		}
	}
	if _, ok := seenTransitions["base->final"]; !ok {
		if _, err := latestDiffBinding(store, events, stateDir, "base", "final", repo); err == nil {
			blockers = append(blockers, staleManifestBlocker("base->final", "base->final diff was captured after this manifest was built"))
		}
	}
	currentPolicy, err := latestBoundPolicy(store, events, repo)
	if err != nil {
		return nil, err
	}
	switch {
	case manifest.Policy == nil && currentPolicy != nil:
		blockers = append(blockers, staleManifestBlocker("", "policy was bound after this manifest was built"))
	case manifest.Policy != nil && currentPolicy == nil:
		blockers = append(blockers, staleManifestBlocker("", "manifest references a policy but no policy is currently bound"))
	case manifest.Policy != nil && currentPolicy != nil && manifest.Policy.Digest != currentPolicy.Ref.Digest:
		blockers = append(blockers, staleManifestBlocker("", "manifest policy does not match latest bound policy"))
	}
	sortBlockers(blockers)
	return blockers, nil
}

func staleManifestBlocker(transition, message string) Blocker {
	return Blocker{
		Code:       "stale_coverage_manifest",
		Message:    message + "; rerun obligations build",
		Transition: transition,
	}
}

func validateManifest(manifest CoverageManifest, repo string) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported coverage manifest schema_version: %d", manifest.SchemaVersion)
	}
	if manifest.Repo != repo {
		return fmt.Errorf("coverage manifest repo mismatch: %s != %s", manifest.Repo, repo)
	}
	ids := map[string]struct{}{}
	for _, obligation := range manifest.Obligations {
		if strings.TrimSpace(obligation.ID) == "" {
			return errors.New("coverage manifest contains obligation without id")
		}
		if _, exists := ids[obligation.ID]; exists {
			return fmt.Errorf("coverage manifest contains duplicate obligation id: %s", obligation.ID)
		}
		ids[obligation.ID] = struct{}{}
	}
	return nil
}

func latestBoundPolicy(store state.Store, events []state.Event, repo string) (*boundPolicy, error) {
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
		return &boundPolicy{
			Ref:       PolicyRef{Profile: profile, PolicyID: policyID, Digest: digest},
			Effective: effective,
		}, nil
	}
	return nil, nil
}

func latestDiffBinding(store state.Store, events []state.Event, stateDir, fromKind, toKind, repo string) (diffBinding, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "diff.created" || event.Details["from_kind"] != fromKind || event.Details["to_kind"] != toKind {
			continue
		}
		if event.Repo != repo {
			return diffBinding{}, fmt.Errorf("malformed diff.created event for %s->%s: repo mismatch", fromKind, toKind)
		}
		diffDigest := event.Details["diff"]
		patchDigest := event.Details["patch"]
		fromSnapshot := event.Details["from_snapshot"]
		toSnapshot := event.Details["to_snapshot"]
		if strings.TrimSpace(diffDigest) == "" || strings.TrimSpace(patchDigest) == "" || strings.TrimSpace(fromSnapshot) == "" || strings.TrimSpace(toSnapshot) == "" {
			return diffBinding{}, fmt.Errorf("malformed diff.created event for %s->%s", fromKind, toKind)
		}
		latestFrom, err := latestSnapshotDigest(events, fromKind, repo)
		if err != nil {
			return diffBinding{}, err
		}
		latestTo, err := latestSnapshotDigest(events, toKind, repo)
		if err != nil {
			return diffBinding{}, err
		}
		if fromSnapshot != latestFrom || toSnapshot != latestTo {
			return diffBinding{}, fmt.Errorf("latest diff.created event for %s->%s does not match latest snapshots", fromKind, toKind)
		}
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
		transition := fromKind + "->" + toKind
		return diffBinding{
			Transition:   transition,
			FromKind:     fromKind,
			ToKind:       toKind,
			FromSnapshot: fromSnapshot,
			ToSnapshot:   toSnapshot,
			Diff: state.ObjectRef{
				Digest:    diffDigest,
				MediaType: "application/vnd.subreview.diff+json",
				Size:      int64(len(diffBody)),
				Path:      objectPathBestEffort(stateDir, diffDigest),
			},
			Patch: state.ObjectRef{
				Digest:    patchDigest,
				MediaType: "text/x-diff; charset=utf-8",
				Size:      int64(len(patchBody)),
				Path:      objectPathBestEffort(stateDir, patchDigest),
			},
			HasChanges: record.HasChanges,
			PatchBody:  patchBody,
		}, nil
	}
	return diffBinding{}, fmt.Errorf("diff %s->%s is not captured in state", fromKind, toKind)
}

func latestSnapshotDigest(events []state.Event, kind, repo string) (string, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Details["kind"] != kind {
			continue
		}
		if event.Repo != repo {
			return "", fmt.Errorf("malformed snapshot.captured event for kind %s: repo mismatch", kind)
		}
		digest := event.Details["snapshot"]
		tree := event.Details["tree"]
		if strings.TrimSpace(digest) == "" || strings.TrimSpace(tree) == "" {
			return "", fmt.Errorf("malformed snapshot.captured event for kind %s", kind)
		}
		if len(event.ObjectDigests) != 2 || !containsDigest(event.ObjectDigests, digest) || !containsDigest(event.ObjectDigests, tree) {
			return "", fmt.Errorf("malformed snapshot.captured event for kind %s: object_digests must contain only snapshot and tree", kind)
		}
		return digest, nil
	}
	return "", fmt.Errorf("snapshot kind is not captured in state: %s", kind)
}

func unresolvedAnchorBlockers(store state.Store, events []state.Event, repo string, activeDiffs []TransitionDiff) ([]Blocker, error) {
	blockers := []Blocker{}
	active := activeTransitionDiffs(activeDiffs)
	seen := map[string]struct{}{}
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "anchors.migrated" {
			continue
		}
		if event.Repo != repo {
			return nil, errors.New("malformed anchors.migrated event: repo mismatch")
		}
		key := transitionKey(event.Details["from_kind"], event.Details["to_kind"], event.Details["from_snapshot"], event.Details["to_snapshot"])
		if _, ok := active[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		digest := event.Details["migration"]
		if strings.TrimSpace(digest) == "" {
			return nil, errors.New("malformed anchors.migrated event: missing migration")
		}
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var migration anchorMigrationRecord
		if err := decodeStrict(body, &migration); err != nil {
			return nil, err
		}
		if migration.SchemaVersion != anchor.SchemaVersion || migration.Repo != repo {
			return nil, errors.New("anchor migration object does not match anchors.migrated event")
		}
		if migration.FromKind != event.Details["from_kind"] || migration.ToKind != event.Details["to_kind"] || migration.FromSnapshot != event.Details["from_snapshot"] || migration.ToSnapshot != event.Details["to_snapshot"] {
			return nil, errors.New("anchor migration object does not match anchors.migrated event")
		}
		for _, result := range migration.Results {
			anchorID := result.Anchor.ID
			if strings.TrimSpace(anchorID) == "" {
				continue
			}
			anchorKey := key + "\x00" + anchorID
			if _, ok := seen[anchorKey]; ok {
				continue
			}
			seen[anchorKey] = struct{}{}
			if !result.BlocksClosure {
				continue
			}
			code := "unresolved_anchor"
			if result.Status == anchor.StatusAmbiguous {
				code = "ambiguous_anchor"
			}
			blockers = append(blockers, Blocker{
				Code:       code,
				Message:    "carried-forward evidence is blocked by anchor migration status: " + result.Reason,
				AnchorID:   anchorID,
				Status:     result.Status,
				Transition: migration.FromKind + "->" + migration.ToKind,
			})
		}
	}
	sortBlockers(blockers)
	return blockers, nil
}

func activeTransitionDiffs(diffs []TransitionDiff) map[string]struct{} {
	active := map[string]struct{}{}
	for _, diff := range diffs {
		active[transitionKey(diff.FromKind, diff.ToKind, diff.FromSnapshot, diff.ToSnapshot)] = struct{}{}
	}
	return active
}

func transitionKey(fromKind, toKind, fromSnapshot, toSnapshot string) string {
	return fromKind + "\x00" + toKind + "\x00" + fromSnapshot + "\x00" + toSnapshot
}

func contextBlockers(events []state.Event) []Blocker {
	blockers := []Blocker{}
	for _, event := range events {
		if event.Type == "context.requested" || event.Type == "review.needs_context" || event.Details["needs_context"] == "true" {
			blockers = append(blockers, Blocker{
				Code:    "needs_context",
				Message: "a context request is recorded and must be resolved before closure",
			})
		}
	}
	return blockers
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

func obligationID(parts ...string) string {
	hash := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "obl_" + hex.EncodeToString(hash[:])[:16]
}

func sortObligations(obligations []Obligation) {
	sort.Slice(obligations, func(i, j int) bool {
		left, right := obligations[i], obligations[j]
		for _, cmp := range []int{
			strings.Compare(left.Transition, right.Transition),
			strings.Compare(left.Kind, right.Kind),
			strings.Compare(left.Path, right.Path),
			left.StartLine - right.StartLine,
			strings.Compare(left.ID, right.ID),
		} {
			if cmp < 0 {
				return true
			}
			if cmp > 0 {
				return false
			}
		}
		return false
	})
}

func sortBlockers(blockers []Blocker) {
	sort.Slice(blockers, func(i, j int) bool {
		left, right := blockers[i], blockers[j]
		for _, cmp := range []int{
			strings.Compare(left.Code, right.Code),
			strings.Compare(left.ObligationID, right.ObligationID),
			strings.Compare(left.AnchorID, right.AnchorID),
			strings.Compare(left.Transition, right.Transition),
			strings.Compare(left.Path, right.Path),
			strings.Compare(left.Message, right.Message),
		} {
			if cmp < 0 {
				return true
			}
			if cmp > 0 {
				return false
			}
		}
		return false
	})
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

func objectPathBestEffort(stateDir, digest string) string {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 2 {
		return ""
	}
	return filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest)
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
