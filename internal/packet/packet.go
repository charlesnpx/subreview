package packet

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
	"time"
	"unicode/utf8"

	"github.com/charlesnpx/subreview/internal/artifact"
	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	EventTypePacketBuilt = "packet.built"

	KindPrimary      = "primary"
	KindVerification = "verification"
	KindArtifact     = "artifact"

	RunKindDiscovery    = "discovery"
	RunKindVerification = "verification"
	RoutePrimary        = "primary_review"
	RouteVerification   = "targeted_verification"
	RouteArtifact       = "artifact_review"

	MediaTypePacket   = "application/vnd.subreview.packet+json"
	MediaTypeMarkdown = "text/markdown; charset=utf-8"

	defaultContextBytes = 24 * 1024
	defaultSnippetLines = 3
)

var (
	hunkHeaderPattern = regexp.MustCompile(`^@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@`)
	leakageTerms      = []string{
		"true_miss",
		"confirmed_non_miss",
		"missed-issue",
		"missed issue",
		"adjudication",
		"adjudicated",
		"gold label",
		"false_positive",
		"true_positive_new_issue",
	}
)

type BuildOptions struct {
	StateDir        string
	Kind            string
	Route           string
	FindingID       string
	ArtifactID      string
	Now             time.Time
	MaxContextBytes int
}

type BuildResult struct {
	SchemaVersion      int                  `json:"schema_version"`
	State              string               `json:"state"`
	Repo               string               `json:"repo"`
	Kind               string               `json:"kind"`
	RunKind            string               `json:"run_kind"`
	Route              string               `json:"route"`
	Packet             state.ObjectRef      `json:"packet"`
	Markdown           state.ObjectRef      `json:"markdown"`
	StableDigest       string               `json:"stable_digest"`
	VolatileDigest     string               `json:"volatile_digest"`
	PromptDigest       string               `json:"prompt_digest"`
	SemanticDedupeKey  SemanticDedupeKey    `json:"semantic_dedupe_key"`
	Context            ContextSummary       `json:"context"`
	Leakage            LeakageReport        `json:"leakage"`
	TokenTelemetry     TokenTelemetry       `json:"token_telemetry"`
	EventID            string               `json:"event_id"`
	GeneratedAt        string               `json:"generated_at"`
	CoverageManifest   state.ObjectRef      `json:"coverage_manifest"`
	Policy             *PolicyRef           `json:"policy,omitempty"`
	Artifact           *ArtifactRef         `json:"artifact,omitempty"`
	TargetState        SnapshotRef          `json:"target_state"`
	SourceCompleteness string               `json:"source_completeness"`
	Verification       *VerificationSummary `json:"verification,omitempty"`
}

type PacketRecord struct {
	SchemaVersion      int                 `json:"schema_version"`
	Kind               string              `json:"kind"`
	RunKind            string              `json:"run_kind"`
	Route              string              `json:"route"`
	Repo               string              `json:"repo"`
	GeneratedAt        string              `json:"generated_at"`
	Policy             *PolicyRef          `json:"policy,omitempty"`
	Artifact           *ArtifactRef        `json:"artifact,omitempty"`
	TargetState        SnapshotRef         `json:"target_state"`
	CoverageManifest   state.ObjectRef     `json:"coverage_manifest"`
	SourceDiffs        []SourceDiff        `json:"source_diffs"`
	Context            ContextBundle       `json:"context"`
	Gates              []GateSummary       `json:"gates"`
	StablePrefix       string              `json:"stable_prefix"`
	VolatileSuffix     string              `json:"volatile_suffix"`
	StableDigest       string              `json:"stable_digest"`
	VolatileDigest     string              `json:"volatile_digest"`
	PromptDigest       string              `json:"prompt_digest"`
	SemanticDedupeKey  SemanticDedupeKey   `json:"semantic_dedupe_key"`
	Leakage            LeakageReport       `json:"leakage"`
	TokenTelemetry     TokenTelemetry      `json:"token_telemetry"`
	SourceCompleteness string              `json:"source_completeness"`
	Verification       *VerificationRecord `json:"verification,omitempty"`
}

type PolicyRef struct {
	Profile  string `json:"profile"`
	PolicyID string `json:"policy_id"`
	Digest   string `json:"digest"`
}

type ArtifactRef struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Title         string          `json:"title"`
	Revises       string          `json:"revises,omitempty"`
	Content       state.ObjectRef `json:"content"`
	ContentDigest string          `json:"content_digest"`
	Artifact      state.ObjectRef `json:"artifact"`
}

type SnapshotRef struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	Tree   string `json:"tree,omitempty"`
}

type SourceDiff struct {
	Transition   string          `json:"transition"`
	FromKind     string          `json:"from_kind"`
	ToKind       string          `json:"to_kind"`
	FromSnapshot string          `json:"from_snapshot"`
	ToSnapshot   string          `json:"to_snapshot"`
	Diff         state.ObjectRef `json:"diff"`
	Patch        state.ObjectRef `json:"patch"`
	PatchDigest  string          `json:"patch_digest"`
	HasChanges   bool            `json:"has_changes"`
	ChangedPaths []string        `json:"changed_paths"`
	HunkCount    int             `json:"hunk_count"`
}

type ContextBundle struct {
	MaxBytes                   int            `json:"max_bytes"`
	UsedBytes                  int            `json:"used_bytes"`
	SnippetContextLines        int            `json:"snippet_context_lines"`
	Entries                    []ContextEntry `json:"entries"`
	Omissions                  []Omission     `json:"omissions"`
	ConfiguredRelationships    []string       `json:"configured_relationships"`
	ReviewerRequestedPaths     []string       `json:"reviewer_requested_paths"`
	BoundedContextRequestLimit int            `json:"bounded_context_request_limit"`
	AllowedContextDigest       string         `json:"allowed_context_digest"`
	ContentBundleHash          string         `json:"content_bundle_hash"`
}

type ContextSummary struct {
	MaxBytes             int        `json:"max_bytes"`
	UsedBytes            int        `json:"used_bytes"`
	EntryCount           int        `json:"entry_count"`
	Omissions            []Omission `json:"omissions"`
	AllowedContextDigest string     `json:"allowed_context_digest"`
	ContentBundleHash    string     `json:"content_bundle_hash"`
}

type ContextEntry struct {
	Kind         string `json:"kind"`
	Path         string `json:"path"`
	SnapshotKind string `json:"snapshot_kind"`
	Digest       string `json:"digest"`
	StartLine    int    `json:"start_line,omitempty"`
	EndLine      int    `json:"end_line,omitempty"`
	Bytes        int    `json:"bytes"`
	Content      string `json:"content"`
}

type Omission struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

type GateSummary struct {
	CommandID     string `json:"command_id"`
	CommandDigest string `json:"command_digest"`
	Outcome       string `json:"outcome"`
	Provenance    string `json:"provenance"`
	SnapshotKind  string `json:"snapshot_kind"`
	Snapshot      string `json:"snapshot"`
	PolicyDigest  string `json:"policy_digest,omitempty"`
	Evidence      string `json:"evidence"`
	EventID       string `json:"event_id"`
}

type VerificationSummary struct {
	FindingID          string   `json:"finding_id"`
	ProposalState      string   `json:"proposal_state"`
	FinalState         string   `json:"final_state"`
	ProposalFinalPatch string   `json:"proposal_final_patch"`
	Questions          []string `json:"questions"`
}

type VerificationRecord struct {
	Finding            reviewresult.FindingRecord `json:"finding"`
	ProposalState      SnapshotRef                `json:"proposal_state"`
	FinalState         SnapshotRef                `json:"final_state"`
	ProposalFinalDiff  SourceDiff                 `json:"proposal_final_diff"`
	ExpectedFixSurface []reviewresult.FixSurface  `json:"expected_fix_surface"`
	Questions          []VerificationQuestion     `json:"questions"`
}

type VerificationQuestion struct {
	ID       string `json:"id"`
	Question string `json:"question"`
}

type SemanticDedupeKey struct {
	SchemaVersion        int    `json:"schema_version"`
	PolicyID             string `json:"policy_id"`
	PolicyDigest         string `json:"policy_digest"`
	Route                string `json:"route"`
	TargetState          string `json:"target_state"`
	ContentBundleHash    string `json:"content_bundle_hash"`
	RunKind              string `json:"run_kind"`
	AllowedContextBundle string `json:"allowed_context_bundle"`
	Digest               string `json:"digest"`
}

type LeakageReport struct {
	OK             bool     `json:"ok"`
	ForbiddenTerms []string `json:"forbidden_terms"`
}

type TokenTelemetry struct {
	SchemaVersion                 int    `json:"schema_version"`
	RunKind                       string `json:"run_kind"`
	GrossDiscoveryTokens          int    `json:"gross_discovery_tokens"`
	IncrementalDiscoveryTokens    int    `json:"incremental_discovery_tokens"`
	GrossVerificationTokens       int    `json:"gross_verification_tokens"`
	IncrementalVerificationTokens int    `json:"incremental_verification_tokens"`
	GrossInputTokens              int    `json:"gross_input_tokens"`
	IncrementalInputTokens        int    `json:"incremental_input_tokens"`
	CachedInputTokens             int    `json:"cached_input_tokens"`
	OutputTokens                  int    `json:"output_tokens"`
	ReasoningTokens               int    `json:"reasoning_tokens"`
	LatencyMS                     int64  `json:"latency_ms"`
	Backend                       string `json:"backend,omitempty"`
	Model                         string `json:"model,omitempty"`
	Effort                        string `json:"effort,omitempty"`
	SourceCompleteness            string `json:"source_completeness"`
	ExecutionReusedFromPacketID   string `json:"execution_reused_from_packet_id,omitempty"`
	TokenMeasurement              string `json:"token_measurement"`
}

type stateBinding struct {
	State string
	Repo  string
}

type boundPolicy struct {
	Ref       PolicyRef
	Effective policy.EffectivePolicy
}

type snapshotBinding struct {
	Kind   string
	Digest string
	Tree   string
}

type patchFile struct {
	Path  string
	Patch string
	Hunks []patchHunk
}

type patchHunk struct {
	NewStart int
	NewCount int
	Patch    string
}

func Build(opts BuildOptions) (BuildResult, error) {
	if opts.Kind == "" {
		opts.Kind = KindPrimary
	}
	switch opts.Kind {
	case KindPrimary:
		return buildPrimary(opts)
	case KindVerification:
		return buildVerification(opts)
	case KindArtifact:
		return buildArtifact(opts)
	default:
		return BuildResult{}, fmt.Errorf("unsupported packet kind: %s", opts.Kind)
	}
}

func buildArtifact(opts BuildOptions) (BuildResult, error) {
	maxContextBytes := opts.MaxContextBytes
	if maxContextBytes <= 0 {
		maxContextBytes = defaultContextBytes
	}
	artifactID := strings.TrimSpace(opts.ArtifactID)
	if artifactID == "" {
		return BuildResult{}, errors.New("--artifact is required for artifact packets")
	}
	route := strings.TrimSpace(opts.Route)
	if route == "" {
		route = RouteArtifact
	}
	if route != RouteArtifact {
		return BuildResult{}, fmt.Errorf("unsupported artifact route: %s", route)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
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
	artifactObservation, err := artifactObservationByID(store, events, binding.Repo, artifactID)
	if err != nil {
		return BuildResult{}, err
	}
	artifactRef := packetArtifactRef(artifactObservation)
	context := buildArtifactContext(store, artifactObservation.Record, maxContextBytes)
	context.AllowedContextDigest = digestJSON(contextDigestMaterial(context))
	context.ContentBundleHash = digestJSON(map[string]any{
		"schema_version":         SchemaVersion,
		"packet_kind":            KindArtifact,
		"artifact_id":            artifactRef.ID,
		"artifact_kind":          artifactRef.Kind,
		"artifact_title":         artifactRef.Title,
		"artifact_revises":       artifactRef.Revises,
		"artifact_content":       canonicalObject(artifactRef.Content),
		"allowed_context_digest": context.AllowedContextDigest,
		"context_omissions":      omissionLeakageMaterial(context.Omissions),
	})
	dedupe := NewSemanticDedupeKey(SemanticDedupeFields{
		Route:                route,
		TargetState:          "artifact:" + artifactRef.ID,
		ContentBundleHash:    context.ContentBundleHash,
		RunKind:              RunKindDiscovery,
		AllowedContextBundle: context.AllowedContextDigest,
	})
	sourceCompleteness := sourceCompleteness(context)
	tokenTelemetry := NewTokenTelemetry(RunKindDiscovery, sourceCompleteness)
	stable := renderArtifactStablePrefix(artifactRenderData{
		Repo:           binding.Repo,
		Artifact:       artifactRef,
		Context:        context,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
	})
	volatile := renderVolatileSuffix(binding.State, now)
	stableDigest := digestString(stable)
	volatileDigest := digestString(volatile)
	markdown := stable + "\n\n" + volatile + "\n"
	promptDigest := digestString(markdown)
	leakage := CheckLeakage(artifactLeakageScanText(artifactLeakageMaterial{
		Repo:           binding.Repo,
		Artifact:       artifactRef,
		Context:        context,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
	}))
	if !leakage.OK {
		return BuildResult{}, fmt.Errorf("packet leakage check failed: %s", strings.Join(leakage.ForbiddenTerms, ", "))
	}
	record := PacketRecord{
		SchemaVersion:      SchemaVersion,
		Kind:               KindArtifact,
		RunKind:            RunKindDiscovery,
		Route:              route,
		Repo:               binding.Repo,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		Artifact:           &artifactRef,
		Context:            context,
		StablePrefix:       stable,
		VolatileSuffix:     volatile,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		SourceCompleteness: sourceCompleteness,
	}
	packetRef, err := store.PutJSON(record, MediaTypePacket)
	if err != nil {
		return BuildResult{}, err
	}
	markdownRef, err := store.PutBytes([]byte(markdown), MediaTypeMarkdown)
	if err != nil {
		return BuildResult{}, err
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          EventTypePacketBuilt,
		ObjectDigests: []string{packetRef.Digest, markdownRef.Digest},
		Repo:          binding.Repo,
		Details: map[string]string{
			"kind":                   KindArtifact,
			"run_kind":               RunKindDiscovery,
			"route":                  route,
			"packet":                 packetRef.Digest,
			"markdown":               markdownRef.Digest,
			"artifact_id":            artifactRef.ID,
			"artifact":               artifactRef.Artifact.Digest,
			"artifact_content":       artifactRef.Content.Digest,
			"stable_digest":          stableDigest,
			"volatile_digest":        volatileDigest,
			"prompt_digest":          promptDigest,
			"semantic_dedupe_digest": dedupe.Digest,
		},
	})
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		SchemaVersion:      SchemaVersion,
		State:              binding.State,
		Repo:               binding.Repo,
		Kind:               KindArtifact,
		RunKind:            RunKindDiscovery,
		Route:              route,
		Packet:             packetRef,
		Markdown:           markdownRef,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Context:            contextSummary(context),
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		EventID:            event.EventID,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		Artifact:           &artifactRef,
		SourceCompleteness: sourceCompleteness,
	}, nil
}

func buildPrimary(opts BuildOptions) (BuildResult, error) {
	maxContextBytes := opts.MaxContextBytes
	if maxContextBytes <= 0 {
		maxContextBytes = defaultContextBytes
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
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
	manifestRef, manifest, err := latestCoverageManifest(store, events, binding.State, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	policyBinding, err := latestBoundPolicy(store, events, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	if err := validateManifestFreshness(store, events, binding.State, binding.Repo, manifest, policyBinding); err != nil {
		return BuildResult{}, err
	}
	target, err := primaryTargetSnapshot(store, manifest, events, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	targetTree, err := readSnapshotTree(store, target)
	if err != nil {
		return BuildResult{}, err
	}
	sourceDiffs, patchFiles, err := sourceDiffSummaries(store, manifest.SourceDiffs)
	if err != nil {
		return BuildResult{}, err
	}
	context := buildContext(store, target, targetTree, patchFiles, maxContextBytes)
	gates, err := gateSummaries(store, events, binding.Repo, manifest)
	if err != nil {
		return BuildResult{}, err
	}
	context.AllowedContextDigest = digestJSON(contextDigestMaterial(context))
	contentBundleHash := digestJSON(contentBundleDigestMaterial(sourceDiffs, target, context.AllowedContextDigest, gates))
	context.ContentBundleHash = contentBundleHash
	var policyRef *PolicyRef
	policyID := ""
	policyDigest := ""
	if manifest.Policy != nil {
		ref := PolicyRef{Profile: manifest.Policy.Profile, PolicyID: manifest.Policy.PolicyID, Digest: manifest.Policy.Digest}
		policyRef = &ref
		policyID = ref.PolicyID
		policyDigest = ref.Digest
	}
	dedupe := NewSemanticDedupeKey(SemanticDedupeFields{
		PolicyID:             policyID,
		PolicyDigest:         policyDigest,
		Route:                RoutePrimary,
		TargetState:          targetDedupeID(target),
		ContentBundleHash:    contentBundleHash,
		RunKind:              RunKindDiscovery,
		AllowedContextBundle: context.AllowedContextDigest,
	})
	sourceCompleteness := sourceCompleteness(context)
	tokenTelemetry := NewTokenTelemetry(RunKindDiscovery, sourceCompleteness)
	stable := renderStablePrefix(stableRenderData{
		Repo:           binding.Repo,
		Policy:         policyRef,
		Target:         target,
		Manifest:       manifestRef,
		SourceDiffs:    sourceDiffs,
		Context:        context,
		Gates:          gates,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
	})
	volatile := renderVolatileSuffix(binding.State, now)
	stableDigest := digestString(stable)
	volatileDigest := digestString(volatile)
	markdown := stable + "\n\n" + volatile + "\n"
	promptDigest := digestString(markdown)
	leakage := CheckLeakage(leakageScanText(recordLeakageMaterial{
		Repo:           binding.Repo,
		Policy:         policyRef,
		Target:         target,
		Manifest:       manifestRef,
		SourceDiffs:    sourceDiffs,
		Context:        context,
		Gates:          gates,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
	}))
	if !leakage.OK {
		return BuildResult{}, fmt.Errorf("packet leakage check failed: %s", strings.Join(leakage.ForbiddenTerms, ", "))
	}
	record := PacketRecord{
		SchemaVersion:      SchemaVersion,
		Kind:               KindPrimary,
		RunKind:            RunKindDiscovery,
		Route:              RoutePrimary,
		Repo:               binding.Repo,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		Policy:             policyRef,
		TargetState:        target,
		CoverageManifest:   manifestRef,
		SourceDiffs:        sourceDiffs,
		Context:            context,
		Gates:              gates,
		StablePrefix:       stable,
		VolatileSuffix:     volatile,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		SourceCompleteness: sourceCompleteness,
	}
	packetRef, err := store.PutJSON(record, MediaTypePacket)
	if err != nil {
		return BuildResult{}, err
	}
	markdownRef, err := store.PutBytes([]byte(markdown), MediaTypeMarkdown)
	if err != nil {
		return BuildResult{}, err
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          EventTypePacketBuilt,
		ObjectDigests: []string{packetRef.Digest, markdownRef.Digest},
		Repo:          binding.Repo,
		Details: map[string]string{
			"kind":                   KindPrimary,
			"run_kind":               RunKindDiscovery,
			"route":                  RoutePrimary,
			"packet":                 packetRef.Digest,
			"markdown":               markdownRef.Digest,
			"coverage_manifest":      manifestRef.Digest,
			"stable_digest":          stableDigest,
			"volatile_digest":        volatileDigest,
			"prompt_digest":          promptDigest,
			"semantic_dedupe_digest": dedupe.Digest,
			"target_state":           target.Digest,
		},
	})
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		SchemaVersion:      SchemaVersion,
		State:              binding.State,
		Repo:               binding.Repo,
		Kind:               KindPrimary,
		RunKind:            RunKindDiscovery,
		Route:              RoutePrimary,
		Packet:             packetRef,
		Markdown:           markdownRef,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Context:            contextSummary(context),
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		EventID:            event.EventID,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		CoverageManifest:   manifestRef,
		Policy:             policyRef,
		TargetState:        target,
		SourceCompleteness: sourceCompleteness,
	}, nil
}

func buildVerification(opts BuildOptions) (BuildResult, error) {
	maxContextBytes := opts.MaxContextBytes
	if maxContextBytes <= 0 {
		maxContextBytes = defaultContextBytes
	}
	route := strings.TrimSpace(opts.Route)
	if route == "" {
		route = RouteVerification
	}
	if route != RouteVerification {
		return BuildResult{}, fmt.Errorf("unsupported verification route: %s", route)
	}
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
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
	manifestRef, manifest, err := latestCoverageManifest(store, events, binding.State, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	policyBinding, err := latestBoundPolicy(store, events, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	if err := validateManifestFreshness(store, events, binding.State, binding.Repo, manifest, policyBinding); err != nil {
		return BuildResult{}, err
	}
	var policyRef *PolicyRef
	policyID := ""
	policyDigest := ""
	if manifest.Policy != nil {
		ref := PolicyRef{Profile: manifest.Policy.Profile, PolicyID: manifest.Policy.PolicyID, Digest: manifest.Policy.Digest}
		policyRef = &ref
		policyID = ref.PolicyID
		policyDigest = ref.Digest
	}
	proposal, err := snapshotForManifestTransition(store, events, binding.Repo, manifest, "base", "proposal")
	if err != nil {
		return BuildResult{}, err
	}
	finding, err := latestFindingForVerification(store, events, binding.Repo, manifestRef.Digest, proposal.Digest, policyDigest, opts.FindingID)
	if err != nil {
		return BuildResult{}, err
	}
	final, err := snapshotForManifestTransition(store, events, binding.Repo, manifest, "base", "final")
	if err != nil {
		return BuildResult{}, err
	}
	finalTree, err := readSnapshotTree(store, final)
	if err != nil {
		return BuildResult{}, err
	}
	proposalFinal, err := proposalFinalSourceDiff(store, events, binding.State, binding.Repo, proposal.Digest, final.Digest)
	if err != nil {
		return BuildResult{}, err
	}
	patchFiles, err := patchFilesForDiff(store, proposalFinal)
	if err != nil {
		return BuildResult{}, err
	}
	context := buildContext(store, final, finalTree, patchFiles, maxContextBytes)
	gates, err := gateSummaries(store, events, binding.Repo, manifest)
	if err != nil {
		return BuildResult{}, err
	}
	context.AllowedContextDigest = digestJSON(contextDigestMaterial(context))
	questions := verificationQuestions(finding)
	verification := VerificationRecord{
		Finding:            finding,
		ProposalState:      proposal,
		FinalState:         final,
		ProposalFinalDiff:  proposalFinal,
		ExpectedFixSurface: append([]reviewresult.FixSurface(nil), finding.ExpectedFixSurface...),
		Questions:          questions,
	}
	contentBundleHash := digestJSON(verificationContentBundleDigestMaterial([]SourceDiff{proposalFinal}, final, context.AllowedContextDigest, gates, finding))
	context.ContentBundleHash = contentBundleHash
	dedupe := NewSemanticDedupeKey(SemanticDedupeFields{
		PolicyID:             policyID,
		PolicyDigest:         policyDigest,
		Route:                route,
		TargetState:          targetDedupeID(final),
		ContentBundleHash:    contentBundleHash,
		RunKind:              RunKindVerification,
		AllowedContextBundle: context.AllowedContextDigest,
	})
	sourceCompleteness := sourceCompleteness(context)
	tokenTelemetry := NewTokenTelemetry(RunKindVerification, sourceCompleteness)
	stable := renderVerificationStablePrefix(verificationRenderData{
		Repo:           binding.Repo,
		Policy:         policyRef,
		Target:         final,
		Manifest:       manifestRef,
		SourceDiffs:    []SourceDiff{proposalFinal},
		Context:        context,
		Gates:          gates,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
		Verification:   verification,
	})
	volatile := renderVolatileSuffix(binding.State, now)
	stableDigest := digestString(stable)
	volatileDigest := digestString(volatile)
	markdown := stable + "\n\n" + volatile + "\n"
	promptDigest := digestString(markdown)
	leakageMaterial := recordLeakageMaterial{
		Repo:           binding.Repo,
		Policy:         policyRef,
		Target:         final,
		Manifest:       manifestRef,
		SourceDiffs:    []SourceDiff{proposalFinal},
		Context:        context,
		Gates:          gates,
		Dedupe:         dedupe,
		SourceComplete: sourceCompleteness,
		TokenTelemetry: tokenTelemetry,
	}
	leakage := CheckLeakage(verificationLeakageScanText(leakageMaterial, verification))
	if !leakage.OK {
		return BuildResult{}, fmt.Errorf("packet leakage check failed: %s", strings.Join(leakage.ForbiddenTerms, ", "))
	}
	record := PacketRecord{
		SchemaVersion:      SchemaVersion,
		Kind:               KindVerification,
		RunKind:            RunKindVerification,
		Route:              route,
		Repo:               binding.Repo,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		Policy:             policyRef,
		TargetState:        final,
		CoverageManifest:   manifestRef,
		SourceDiffs:        []SourceDiff{proposalFinal},
		Context:            context,
		Gates:              gates,
		StablePrefix:       stable,
		VolatileSuffix:     volatile,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		SourceCompleteness: sourceCompleteness,
		Verification:       &verification,
	}
	packetRef, err := store.PutJSON(record, MediaTypePacket)
	if err != nil {
		return BuildResult{}, err
	}
	markdownRef, err := store.PutBytes([]byte(markdown), MediaTypeMarkdown)
	if err != nil {
		return BuildResult{}, err
	}
	event, err := state.AppendEvent(binding.State, state.Event{
		Type:          EventTypePacketBuilt,
		ObjectDigests: []string{packetRef.Digest, markdownRef.Digest},
		Repo:          binding.Repo,
		Details: map[string]string{
			"kind":                   KindVerification,
			"run_kind":               RunKindVerification,
			"route":                  route,
			"packet":                 packetRef.Digest,
			"markdown":               markdownRef.Digest,
			"coverage_manifest":      manifestRef.Digest,
			"stable_digest":          stableDigest,
			"volatile_digest":        volatileDigest,
			"prompt_digest":          promptDigest,
			"semantic_dedupe_digest": dedupe.Digest,
			"target_state":           final.Digest,
			"finding_id":             finding.ID,
			"proposal_state":         proposal.Digest,
			"final_state":            final.Digest,
			"proposal_final_patch":   proposalFinal.Patch.Digest,
		},
	})
	if err != nil {
		return BuildResult{}, err
	}
	return BuildResult{
		SchemaVersion:      SchemaVersion,
		State:              binding.State,
		Repo:               binding.Repo,
		Kind:               KindVerification,
		RunKind:            RunKindVerification,
		Route:              route,
		Packet:             packetRef,
		Markdown:           markdownRef,
		StableDigest:       stableDigest,
		VolatileDigest:     volatileDigest,
		PromptDigest:       promptDigest,
		SemanticDedupeKey:  dedupe,
		Context:            contextSummary(context),
		Leakage:            leakage,
		TokenTelemetry:     tokenTelemetry,
		EventID:            event.EventID,
		GeneratedAt:        now.Format(time.RFC3339Nano),
		CoverageManifest:   manifestRef,
		Policy:             policyRef,
		TargetState:        final,
		SourceCompleteness: sourceCompleteness,
		Verification: &VerificationSummary{
			FindingID:          finding.ID,
			ProposalState:      proposal.Digest,
			FinalState:         final.Digest,
			ProposalFinalPatch: proposalFinal.Patch.Digest,
			Questions:          questionStrings(questions),
		},
	}, nil
}

type SemanticDedupeFields struct {
	PolicyID             string
	PolicyDigest         string
	Route                string
	TargetState          string
	ContentBundleHash    string
	RunKind              string
	AllowedContextBundle string
}

func NewSemanticDedupeKey(fields SemanticDedupeFields) SemanticDedupeKey {
	key := SemanticDedupeKey{
		SchemaVersion:        SchemaVersion,
		PolicyID:             fields.PolicyID,
		PolicyDigest:         fields.PolicyDigest,
		Route:                fields.Route,
		TargetState:          fields.TargetState,
		ContentBundleHash:    fields.ContentBundleHash,
		RunKind:              fields.RunKind,
		AllowedContextBundle: fields.AllowedContextBundle,
	}
	key.Digest = digestJSON(map[string]string{
		"policy_id":              key.PolicyID,
		"policy_digest":          key.PolicyDigest,
		"route":                  key.Route,
		"target_state":           key.TargetState,
		"content_bundle_hash":    key.ContentBundleHash,
		"run_kind":               key.RunKind,
		"allowed_context_bundle": key.AllowedContextBundle,
	})
	return key
}

func NewTokenTelemetry(runKind, sourceCompleteness string) TokenTelemetry {
	return TokenTelemetry{
		SchemaVersion:      SchemaVersion,
		RunKind:            runKind,
		SourceCompleteness: sourceCompleteness,
		TokenMeasurement:   "not_measured",
	}
}

func validateManifestFreshness(store state.Store, events []state.Event, stateDir, repo string, manifest obligation.CoverageManifest, currentPolicy *boundPolicy) error {
	for _, diff := range manifest.SourceDiffs {
		latestFrom, err := latestSnapshotDigest(events, diff.FromKind, repo)
		if err != nil {
			return err
		}
		latestTo, err := latestSnapshotDigest(events, diff.ToKind, repo)
		if err != nil {
			return err
		}
		if diff.FromSnapshot != latestFrom || diff.ToSnapshot != latestTo {
			return fmt.Errorf("coverage manifest is stale: source diff %s does not match latest snapshots; rerun obligations build", diff.Transition)
		}
		latestDiff, ok, err := latestTransitionDiff(events, stateDir, repo, diff.FromKind, diff.ToKind)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("coverage manifest is stale: source diff %s is missing latest captured diff; rerun obligations build", diff.Transition)
		}
		if latestDiff.FromSnapshot != latestFrom || latestDiff.ToSnapshot != latestTo {
			return fmt.Errorf("coverage manifest is stale: latest diff %s does not match latest snapshots; rerun obligations build", diff.Transition)
		}
		if diff.Diff.Digest != latestDiff.Diff.Digest || diff.Patch.Digest != latestDiff.Patch.Digest {
			return fmt.Errorf("coverage manifest is stale: source diff %s does not match latest captured diff; rerun obligations build", diff.Transition)
		}
		if _, err := store.Read(diff.Diff.Digest); err != nil {
			return fmt.Errorf("coverage manifest is stale: source diff %s object is unreadable: %w", diff.Transition, err)
		}
		if _, err := store.Read(diff.Patch.Digest); err != nil {
			return fmt.Errorf("coverage manifest is stale: source patch %s object is unreadable: %w", diff.Transition, err)
		}
	}
	if !manifestHasTransition(manifest, "base", "final") {
		if _, ok, err := latestTransitionDiff(events, stateDir, repo, "base", "final"); err != nil {
			return err
		} else if ok {
			return errors.New("coverage manifest is stale: base->final diff was captured after this manifest was built; rerun obligations build")
		}
	}
	switch {
	case manifest.Policy == nil && currentPolicy != nil:
		return errors.New("coverage manifest is stale after policy bind; rerun obligations build")
	case manifest.Policy != nil && currentPolicy == nil:
		return errors.New("coverage manifest references a policy but no policy is currently bound; rerun obligations build")
	case manifest.Policy != nil && currentPolicy != nil && manifest.Policy.Digest != currentPolicy.Ref.Digest:
		return errors.New("coverage manifest is stale after policy rebind; rerun obligations build")
	default:
		return nil
	}
}

type latestDiffBinding struct {
	FromKind     string
	ToKind       string
	FromSnapshot string
	ToSnapshot   string
	Diff         state.ObjectRef
	Patch        state.ObjectRef
}

func latestSnapshotDigest(events []state.Event, kind, repo string) (string, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Details["kind"] != kind {
			continue
		}
		if event.Repo != repo {
			return "", errors.New("malformed snapshot.captured event: repo mismatch")
		}
		digest := event.Details["snapshot"]
		if strings.TrimSpace(digest) == "" {
			return "", fmt.Errorf("malformed snapshot.captured event: missing snapshot for %s", kind)
		}
		return digest, nil
	}
	return "", fmt.Errorf("%s snapshot is not captured", kind)
}

func latestTransitionDiff(events []state.Event, stateDir, repo, fromKind, toKind string) (latestDiffBinding, bool, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "diff.created" || event.Details["from_kind"] != fromKind || event.Details["to_kind"] != toKind {
			continue
		}
		if event.Repo != repo {
			return latestDiffBinding{}, false, fmt.Errorf("malformed diff.created event for %s->%s: repo mismatch", fromKind, toKind)
		}
		diffDigest := event.Details["diff"]
		patchDigest := event.Details["patch"]
		fromSnapshot := event.Details["from_snapshot"]
		toSnapshot := event.Details["to_snapshot"]
		if strings.TrimSpace(diffDigest) == "" || strings.TrimSpace(patchDigest) == "" || strings.TrimSpace(fromSnapshot) == "" || strings.TrimSpace(toSnapshot) == "" {
			return latestDiffBinding{}, false, fmt.Errorf("malformed diff.created event for %s->%s", fromKind, toKind)
		}
		diffPath, err := objectPath(stateDir, diffDigest)
		if err != nil {
			return latestDiffBinding{}, false, err
		}
		patchPath, err := objectPath(stateDir, patchDigest)
		if err != nil {
			return latestDiffBinding{}, false, err
		}
		return latestDiffBinding{
			FromKind:     fromKind,
			ToKind:       toKind,
			FromSnapshot: fromSnapshot,
			ToSnapshot:   toSnapshot,
			Diff:         state.ObjectRef{Digest: diffDigest, Path: diffPath},
			Patch:        state.ObjectRef{Digest: patchDigest, Path: patchPath},
		}, true, nil
	}
	return latestDiffBinding{}, false, nil
}

func manifestHasTransition(manifest obligation.CoverageManifest, fromKind, toKind string) bool {
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == fromKind && diff.ToKind == toKind {
			return true
		}
	}
	return false
}

func ReusedTokenTelemetry(runKind, sourceCompleteness, reusedFrom string, grossInputTokens int) TokenTelemetry {
	t := NewTokenTelemetry(runKind, sourceCompleteness)
	t.ExecutionReusedFromPacketID = reusedFrom
	t.GrossInputTokens = grossInputTokens
	t.IncrementalInputTokens = 0
	if runKind == RunKindDiscovery {
		t.GrossDiscoveryTokens = grossInputTokens
		t.IncrementalDiscoveryTokens = 0
	} else {
		t.GrossVerificationTokens = grossInputTokens
		t.IncrementalVerificationTokens = 0
	}
	return t
}

func CheckLeakage(text string) LeakageReport {
	lower := strings.ToLower(text)
	terms := []string{}
	for _, term := range leakageTerms {
		if strings.Contains(lower, term) {
			terms = append(terms, term)
		}
	}
	sort.Strings(terms)
	return LeakageReport{OK: len(terms) == 0, ForbiddenTerms: terms}
}

type recordLeakageMaterial struct {
	Repo           string
	Policy         *PolicyRef
	Target         SnapshotRef
	Manifest       state.ObjectRef
	SourceDiffs    []SourceDiff
	Context        ContextBundle
	Gates          []GateSummary
	Dedupe         SemanticDedupeKey
	SourceComplete string
	TokenTelemetry TokenTelemetry
}

type artifactLeakageMaterial struct {
	Repo           string
	Artifact       ArtifactRef
	Context        ContextBundle
	Dedupe         SemanticDedupeKey
	SourceComplete string
	TokenTelemetry TokenTelemetry
}

func leakageScanText(data recordLeakageMaterial) string {
	type contextEntryMetadata struct {
		Kind         string `json:"kind"`
		SnapshotKind string `json:"snapshot_kind"`
		Digest       string `json:"digest"`
		StartLine    int    `json:"start_line,omitempty"`
		EndLine      int    `json:"end_line,omitempty"`
		Bytes        int    `json:"bytes"`
	}
	entries := make([]contextEntryMetadata, 0, len(data.Context.Entries))
	for _, entry := range data.Context.Entries {
		entries = append(entries, contextEntryMetadata{
			Kind:         entry.Kind,
			SnapshotKind: entry.SnapshotKind,
			Digest:       entry.Digest,
			StartLine:    entry.StartLine,
			EndLine:      entry.EndLine,
			Bytes:        entry.Bytes,
		})
	}
	body, err := json.Marshal(map[string]any{
		"repo":              data.Repo,
		"policy":            data.Policy,
		"target":            data.Target,
		"manifest":          canonicalObject(data.Manifest),
		"source_diffs":      sourceDiffLeakageMaterial(data.SourceDiffs),
		"context_metadata":  entries,
		"context_omissions": omissionLeakageMaterial(data.Context.Omissions),
		"gates":             gateDigestMaterial(data.Gates),
		"dedupe":            data.Dedupe,
		"source_complete":   data.SourceComplete,
		"token_telemetry":   data.TokenTelemetry,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func artifactLeakageScanText(data artifactLeakageMaterial) string {
	type contextEntryMetadata struct {
		Kind   string `json:"kind"`
		Digest string `json:"digest"`
		Bytes  int    `json:"bytes"`
	}
	entries := make([]contextEntryMetadata, 0, len(data.Context.Entries))
	for _, entry := range data.Context.Entries {
		entries = append(entries, contextEntryMetadata{Kind: entry.Kind, Digest: entry.Digest, Bytes: entry.Bytes})
	}
	body, err := json.Marshal(map[string]any{
		"repo":              data.Repo,
		"artifact_id":       data.Artifact.ID,
		"artifact_kind":     data.Artifact.Kind,
		"artifact_title":    data.Artifact.Title,
		"artifact_content":  canonicalObject(data.Artifact.Content),
		"context_metadata":  entries,
		"context_omissions": omissionLeakageMaterial(data.Context.Omissions),
		"dedupe":            data.Dedupe,
		"source_complete":   data.SourceComplete,
		"token_telemetry":   data.TokenTelemetry,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

func verificationLeakageScanText(data recordLeakageMaterial, verification VerificationRecord) string {
	questionText := make([]string, 0, len(verification.Questions))
	for _, question := range verification.Questions {
		questionText = append(questionText, question.Question)
	}
	body, err := json.Marshal(map[string]any{
		"base": leakageScanText(data),
		"finding": map[string]string{
			"claim":            verification.Finding.Claim,
			"failure_scenario": verification.Finding.FailureScenario,
			"severity":         verification.Finding.Severity,
			"class":            verification.Finding.Class,
		},
		"questions": questionText,
	})
	if err != nil {
		panic(err)
	}
	return string(body)
}

type sourceDiffLeakageMetadata struct {
	Transition  string             `json:"transition"`
	FromKind    string             `json:"from_kind"`
	ToKind      string             `json:"to_kind"`
	Patch       canonicalObjectRef `json:"patch"`
	PatchDigest string             `json:"patch_digest"`
	HasChanges  bool               `json:"has_changes"`
	HunkCount   int                `json:"hunk_count"`
}

func sourceDiffLeakageMaterial(sourceDiffs []SourceDiff) []sourceDiffLeakageMetadata {
	material := make([]sourceDiffLeakageMetadata, 0, len(sourceDiffs))
	for _, diff := range sourceDiffs {
		material = append(material, sourceDiffLeakageMetadata{
			Transition:  diff.Transition,
			FromKind:    diff.FromKind,
			ToKind:      diff.ToKind,
			Patch:       canonicalObject(diff.Patch),
			PatchDigest: diff.PatchDigest,
			HasChanges:  diff.HasChanges,
			HunkCount:   diff.HunkCount,
		})
	}
	sort.Slice(material, func(i, j int) bool { return material[i].Transition < material[j].Transition })
	return material
}

type omissionLeakageMetadata struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func omissionLeakageMaterial(omissions []Omission) []omissionLeakageMetadata {
	material := make([]omissionLeakageMetadata, 0, len(omissions))
	for _, omission := range omissions {
		material = append(material, omissionLeakageMetadata{Code: omission.Code, Message: omission.Message})
	}
	sort.Slice(material, func(i, j int) bool {
		if material[i].Code == material[j].Code {
			return material[i].Message < material[j].Message
		}
		return material[i].Code < material[j].Code
	})
	return material
}

func markdownJSONString(value string) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(body)
}

type stableRenderData struct {
	Repo           string
	Policy         *PolicyRef
	Target         SnapshotRef
	Manifest       state.ObjectRef
	SourceDiffs    []SourceDiff
	Context        ContextBundle
	Gates          []GateSummary
	Dedupe         SemanticDedupeKey
	SourceComplete string
	TokenTelemetry TokenTelemetry
}

type artifactRenderData struct {
	Repo           string
	Artifact       ArtifactRef
	Context        ContextBundle
	Dedupe         SemanticDedupeKey
	SourceComplete string
	TokenTelemetry TokenTelemetry
}

func renderArtifactStablePrefix(data artifactRenderData) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Subreview Artifact Review Packet")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Review Contract")
	fmt.Fprintln(&b, "- Review the included artifact for decision completeness, feasibility, contradictions, missing tests, and actionable issues.")
	fmt.Fprintln(&b, "- Use only the artifact content, artifact metadata, and explicit omissions in this packet.")
	fmt.Fprintln(&b, "- Return structured artifact_review results with artifact_refs that cite artifact sections, stories, merge units, or line ranges.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Identity")
	fmt.Fprintf(&b, "- route: %s\n", RouteArtifact)
	fmt.Fprintf(&b, "- run_kind: %s\n", RunKindDiscovery)
	fmt.Fprintf(&b, "- repo: %s\n", data.Repo)
	fmt.Fprintf(&b, "- artifact_id: %s\n", data.Artifact.ID)
	fmt.Fprintf(&b, "- artifact_kind: %s\n", data.Artifact.Kind)
	fmt.Fprintf(&b, "- artifact_title: %s\n", markdownJSONString(data.Artifact.Title))
	if data.Artifact.Revises != "" {
		fmt.Fprintf(&b, "- artifact_revises: %s\n", data.Artifact.Revises)
	}
	fmt.Fprintf(&b, "- artifact_digest: %s\n", data.Artifact.Artifact.Digest)
	fmt.Fprintf(&b, "- content_digest: %s\n", data.Artifact.ContentDigest)
	fmt.Fprintf(&b, "- semantic_dedupe_digest: %s\n", data.Dedupe.Digest)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Context Budget")
	fmt.Fprintf(&b, "- max_bytes: %d\n", data.Context.MaxBytes)
	fmt.Fprintf(&b, "- used_bytes: %d\n", data.Context.UsedBytes)
	fmt.Fprintf(&b, "- source_completeness: %s\n", data.SourceComplete)
	fmt.Fprintf(&b, "- allowed_context_digest: %s\n", data.Context.AllowedContextDigest)
	fmt.Fprintf(&b, "- content_bundle_hash: %s\n", data.Context.ContentBundleHash)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Artifact Content")
	if len(data.Context.Entries) == 0 {
		fmt.Fprintln(&b, "- no artifact content selected")
	}
	for _, entry := range data.Context.Entries {
		fmt.Fprintf(&b, "### %s %s\n", entry.Kind, markdownJSONString(entry.Path))
		fmt.Fprintf(&b, "digest: %s\n\n", entry.Digest)
		fence := markdownFence(entry.Content)
		fmt.Fprintln(&b, fence)
		fmt.Fprintln(&b, entry.Content)
		fmt.Fprintln(&b, fence)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Explicit Omissions")
	if len(data.Context.Omissions) == 0 {
		fmt.Fprintln(&b, "- none")
	} else {
		for _, omission := range data.Context.Omissions {
			if omission.Path != "" {
				fmt.Fprintf(&b, "- %s %s: %s\n", omission.Code, markdownJSONString(omission.Path), omission.Message)
			} else {
				fmt.Fprintf(&b, "- %s: %s\n", omission.Code, omission.Message)
			}
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Expected Result Shape")
	fmt.Fprintln(&b, "- schema_version: 1")
	fmt.Fprintf(&b, "- run_kind: %s\n", RunKindDiscovery)
	fmt.Fprintf(&b, "- route: %s\n", RouteArtifact)
	fmt.Fprintln(&b, "- outcome: clean | findings | needs_context")
	fmt.Fprintln(&b, "- findings[].artifact_refs[]: artifact_id, section, story_id, merge_unit_id, start_line, end_line, quote")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Token Telemetry Schema")
	fmt.Fprintln(&b, "- gross_discovery_tokens, incremental_discovery_tokens, gross_verification_tokens, incremental_verification_tokens")
	fmt.Fprintln(&b, "- gross_input_tokens, incremental_input_tokens, cached_input_tokens, output_tokens, reasoning_tokens")
	fmt.Fprintln(&b, "- latency_ms, backend, model, effort, source_completeness")
	return strings.TrimSpace(b.String())
}

func renderStablePrefix(data stableRenderData) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Subreview Primary Review Packet")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Review Contract")
	fmt.Fprintln(&b, "- Review the target state for actionable defects introduced by the proposal.")
	fmt.Fprintln(&b, "- Use only the included context and explicitly listed omissions when forming findings.")
	fmt.Fprintln(&b, "- Report findings with path and anchor evidence suitable for later lifecycle import.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Identity")
	fmt.Fprintf(&b, "- route: %s\n", RoutePrimary)
	fmt.Fprintf(&b, "- run_kind: %s\n", RunKindDiscovery)
	fmt.Fprintf(&b, "- repo: %s\n", data.Repo)
	if data.Policy != nil {
		fmt.Fprintf(&b, "- policy_id: %s\n", data.Policy.PolicyID)
		fmt.Fprintf(&b, "- policy_digest: %s\n", data.Policy.Digest)
	}
	fmt.Fprintf(&b, "- target_state: %s %s\n", data.Target.Kind, data.Target.Digest)
	fmt.Fprintf(&b, "- coverage_manifest: %s\n", data.Manifest.Digest)
	fmt.Fprintf(&b, "- semantic_dedupe_digest: %s\n", data.Dedupe.Digest)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Source Diffs")
	for _, diff := range data.SourceDiffs {
		fmt.Fprintf(&b, "- %s: %s -> %s, patch=%s, changed_paths=%d, hunks=%d\n", diff.Transition, diff.FromSnapshot, diff.ToSnapshot, diff.Patch.Digest, len(diff.ChangedPaths), diff.HunkCount)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Gate Evidence")
	if len(data.Gates) == 0 {
		fmt.Fprintln(&b, "- none recorded")
	} else {
		for _, gate := range data.Gates {
			fmt.Fprintf(&b, "- %s: %s, snapshot=%s:%s, evidence=%s\n", gate.CommandID, gate.Outcome, gate.SnapshotKind, gate.Snapshot, gate.Evidence)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Context Budget")
	fmt.Fprintf(&b, "- max_bytes: %d\n", data.Context.MaxBytes)
	fmt.Fprintf(&b, "- used_bytes: %d\n", data.Context.UsedBytes)
	fmt.Fprintf(&b, "- source_completeness: %s\n", data.SourceComplete)
	fmt.Fprintf(&b, "- allowed_context_digest: %s\n", data.Context.AllowedContextDigest)
	fmt.Fprintf(&b, "- content_bundle_hash: %s\n", data.Context.ContentBundleHash)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Selected Context")
	if len(data.Context.Entries) == 0 {
		fmt.Fprintln(&b, "- no context entries selected")
	}
	for _, entry := range data.Context.Entries {
		fmt.Fprintf(&b, "### %s %s", entry.Kind, markdownJSONString(entry.Path))
		if entry.StartLine > 0 {
			fmt.Fprintf(&b, ":%d-%d", entry.StartLine, entry.EndLine)
		}
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "digest: %s\n\n", entry.Digest)
		fence := markdownFence(entry.Content)
		fmt.Fprintln(&b, fence)
		fmt.Fprintln(&b, entry.Content)
		fmt.Fprintln(&b, fence)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Explicit Omissions")
	if len(data.Context.Omissions) == 0 {
		fmt.Fprintln(&b, "- none")
	} else {
		for _, omission := range data.Context.Omissions {
			if omission.Path != "" {
				fmt.Fprintf(&b, "- %s %s: %s\n", omission.Code, markdownJSONString(omission.Path), omission.Message)
			} else {
				fmt.Fprintf(&b, "- %s: %s\n", omission.Code, omission.Message)
			}
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Token Telemetry Schema")
	fmt.Fprintln(&b, "- gross_discovery_tokens, incremental_discovery_tokens, gross_verification_tokens, incremental_verification_tokens")
	fmt.Fprintln(&b, "- gross_input_tokens, incremental_input_tokens, cached_input_tokens, output_tokens, reasoning_tokens")
	fmt.Fprintln(&b, "- latency_ms, backend, model, effort, source_completeness")
	return strings.TrimSpace(b.String())
}

type verificationRenderData struct {
	Repo           string
	Policy         *PolicyRef
	Target         SnapshotRef
	Manifest       state.ObjectRef
	SourceDiffs    []SourceDiff
	Context        ContextBundle
	Gates          []GateSummary
	Dedupe         SemanticDedupeKey
	SourceComplete string
	TokenTelemetry TokenTelemetry
	Verification   VerificationRecord
}

func renderVerificationStablePrefix(data verificationRenderData) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Subreview Verification Packet")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Verification Contract")
	fmt.Fprintln(&b, "- Verify whether the proposal-to-final changes resolved the referenced finding.")
	fmt.Fprintln(&b, "- Use only the included proposal-to-final diff, final-state context, gate evidence, and explicit omissions.")
	fmt.Fprintln(&b, "- Return exactly one verification outcome for the finding unless deterministic refutation evidence is supplied.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Identity")
	fmt.Fprintf(&b, "- route: %s\n", data.Dedupe.Route)
	fmt.Fprintf(&b, "- run_kind: %s\n", RunKindVerification)
	fmt.Fprintf(&b, "- repo: %s\n", data.Repo)
	if data.Policy != nil {
		fmt.Fprintf(&b, "- policy_id: %s\n", data.Policy.PolicyID)
		fmt.Fprintf(&b, "- policy_digest: %s\n", data.Policy.Digest)
	}
	fmt.Fprintf(&b, "- target_state: %s %s\n", data.Target.Kind, data.Target.Digest)
	fmt.Fprintf(&b, "- coverage_manifest: %s\n", data.Manifest.Digest)
	fmt.Fprintf(&b, "- semantic_dedupe_digest: %s\n", data.Dedupe.Digest)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Finding Under Verification")
	fmt.Fprintf(&b, "- finding_id: %s\n", data.Verification.Finding.ID)
	fmt.Fprintf(&b, "- severity: %s\n", data.Verification.Finding.Severity)
	fmt.Fprintf(&b, "- class: %s\n", data.Verification.Finding.Class)
	fmt.Fprintf(&b, "- claim: %s\n", markdownJSONString(data.Verification.Finding.Claim))
	fmt.Fprintf(&b, "- failure_scenario: %s\n", markdownJSONString(data.Verification.Finding.FailureScenario))
	renderLineRefs(&b, "citations", data.Verification.Finding.Citations)
	renderAnchorRefs(&b, "anchors", data.Verification.Finding.Anchors)
	if len(data.Verification.ExpectedFixSurface) > 0 {
		fmt.Fprintln(&b, "- expected_fix_surface:")
		for _, surface := range data.Verification.ExpectedFixSurface {
			fmt.Fprintf(&b, "  - %s", markdownJSONString(surface.Path))
			if surface.StartLine > 0 {
				fmt.Fprintf(&b, ":%d-%d", surface.StartLine, surface.EndLine)
			}
			if surface.Kind != "" {
				fmt.Fprintf(&b, " kind=%s", surface.Kind)
			}
			fmt.Fprintln(&b)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Verification Questions")
	for _, question := range data.Verification.Questions {
		fmt.Fprintf(&b, "- %s: %s\n", question.ID, question.Question)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Proposal To Final Diff")
	diff := data.Verification.ProposalFinalDiff
	fmt.Fprintf(&b, "- proposal: %s\n", data.Verification.ProposalState.Digest)
	fmt.Fprintf(&b, "- final: %s\n", data.Verification.FinalState.Digest)
	fmt.Fprintf(&b, "- patch: %s, changed_paths=%d, hunks=%d\n", diff.Patch.Digest, len(diff.ChangedPaths), diff.HunkCount)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Gate Evidence")
	if len(data.Gates) == 0 {
		fmt.Fprintln(&b, "- none recorded")
	} else {
		for _, gate := range data.Gates {
			fmt.Fprintf(&b, "- %s: %s, snapshot=%s:%s, evidence=%s\n", gate.CommandID, gate.Outcome, gate.SnapshotKind, gate.Snapshot, gate.Evidence)
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Context Budget")
	fmt.Fprintf(&b, "- max_bytes: %d\n", data.Context.MaxBytes)
	fmt.Fprintf(&b, "- used_bytes: %d\n", data.Context.UsedBytes)
	fmt.Fprintf(&b, "- source_completeness: %s\n", data.SourceComplete)
	fmt.Fprintf(&b, "- allowed_context_digest: %s\n", data.Context.AllowedContextDigest)
	fmt.Fprintf(&b, "- content_bundle_hash: %s\n", data.Context.ContentBundleHash)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Selected Context")
	if len(data.Context.Entries) == 0 {
		fmt.Fprintln(&b, "- no context entries selected")
	}
	for _, entry := range data.Context.Entries {
		fmt.Fprintf(&b, "### %s %s", entry.Kind, markdownJSONString(entry.Path))
		if entry.StartLine > 0 {
			fmt.Fprintf(&b, ":%d-%d", entry.StartLine, entry.EndLine)
		}
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "digest: %s\n\n", entry.Digest)
		fence := markdownFence(entry.Content)
		fmt.Fprintln(&b, fence)
		fmt.Fprintln(&b, entry.Content)
		fmt.Fprintln(&b, fence)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Explicit Omissions")
	if len(data.Context.Omissions) == 0 {
		fmt.Fprintln(&b, "- none")
	} else {
		for _, omission := range data.Context.Omissions {
			if omission.Path != "" {
				fmt.Fprintf(&b, "- %s %s: %s\n", omission.Code, markdownJSONString(omission.Path), omission.Message)
			} else {
				fmt.Fprintf(&b, "- %s: %s\n", omission.Code, omission.Message)
			}
		}
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Allowed Verification Outcomes")
	fmt.Fprintln(&b, "- resolved, not_resolved, regression_introduced, insufficient_context, finding_invalid, unexpected_scope, deterministic_refuted")
	fmt.Fprintln(&b, "- finding_invalid requires verifier_relation=fresh_blinded and relation_evidence=cli_witnessed|caller_asserted|external_asserted.")
	fmt.Fprintln(&b, "- deterministic_refuted requires matching deterministic_refutations evidence for the same finding_id.")
	return strings.TrimSpace(b.String())
}

func renderLineRefs(b *strings.Builder, label string, refs []reviewresult.LineRef) {
	if len(refs) == 0 {
		return
	}
	fmt.Fprintf(b, "- %s:\n", label)
	for _, ref := range refs {
		fmt.Fprintf(b, "  - %s", markdownJSONString(ref.Path))
		renderLineRange(b, ref.StartLine, ref.EndLine)
		if ref.Quote != "" {
			fmt.Fprintf(b, " quote=%s", markdownJSONString(ref.Quote))
		}
		if ref.Digest != "" {
			fmt.Fprintf(b, " digest=%s", ref.Digest)
		}
		fmt.Fprintln(b)
	}
}

func renderAnchorRefs(b *strings.Builder, label string, refs []reviewresult.AnchorRef) {
	if len(refs) == 0 {
		return
	}
	fmt.Fprintf(b, "- %s:\n", label)
	for _, ref := range refs {
		fmt.Fprintf(b, "  - %s", markdownJSONString(ref.Path))
		renderLineRange(b, ref.StartLine, ref.EndLine)
		if ref.Kind != "" {
			fmt.Fprintf(b, " kind=%s", ref.Kind)
		}
		if ref.ObligationID != "" {
			fmt.Fprintf(b, " obligation_id=%s", ref.ObligationID)
		}
		fmt.Fprintln(b)
	}
}

func renderLineRange(b *strings.Builder, startLine, endLine int) {
	if startLine <= 0 {
		return
	}
	if endLine <= 0 {
		fmt.Fprintf(b, ":%d", startLine)
		return
	}
	fmt.Fprintf(b, ":%d-%d", startLine, endLine)
}

func renderVolatileSuffix(stateDir string, now time.Time) string {
	var b strings.Builder
	fmt.Fprintln(&b, "## Volatile Invocation")
	fmt.Fprintf(&b, "- generated_at: %s\n", now.Format(time.RFC3339Nano))
	fmt.Fprintf(&b, "- state: %s\n", stateDir)
	return strings.TrimSpace(b.String())
}

func markdownFence(content string) string {
	maxRun := 0
	currentRun := 0
	for _, r := range content {
		if r == '`' {
			currentRun++
			if currentRun > maxRun {
				maxRun = currentRun
			}
			continue
		}
		currentRun = 0
	}
	if maxRun < 3 {
		return "```"
	}
	return strings.Repeat("`", maxRun+1)
}

func artifactObservationByID(store state.Store, events []state.Event, repo, artifactID string) (artifact.Observation, error) {
	observations, err := artifact.Observations(store, events, repo)
	if err != nil {
		return artifact.Observation{}, err
	}
	for i := len(observations) - 1; i >= 0; i-- {
		if observations[i].Record.ID == artifactID {
			return observations[i], nil
		}
	}
	return artifact.Observation{}, fmt.Errorf("artifact not found in state: %s", artifactID)
}

func packetArtifactRef(observation artifact.Observation) ArtifactRef {
	record := observation.Record
	return ArtifactRef{
		ID:            record.ID,
		Kind:          record.Kind,
		Title:         record.Title,
		Revises:       record.Revises,
		Content:       record.Content,
		ContentDigest: record.ContentDigest,
		Artifact:      observation.Artifact,
	}
}

func buildArtifactContext(store state.Store, record artifact.ArtifactRecord, maxBytes int) ContextBundle {
	context := ContextBundle{
		MaxBytes:                   maxBytes,
		Entries:                    []ContextEntry{},
		Omissions:                  []Omission{},
		ConfiguredRelationships:    []string{},
		ReviewerRequestedPaths:     []string{},
		BoundedContextRequestLimit: 0,
	}
	body, err := store.Read(record.ContentDigest)
	if err != nil {
		context.Omissions = append(context.Omissions, Omission{Code: "context_read_failed", Path: record.ID, Message: err.Error()})
		sortContext(context.Entries, context.Omissions)
		return context
	}
	if !isTextContextBody(body) {
		context.Omissions = append(context.Omissions, Omission{Code: "binary_context_omitted", Path: record.ID, Message: "artifact content is binary or not valid UTF-8"})
		sortContext(context.Entries, context.Omissions)
		return context
	}
	content := strings.TrimRight(string(body), "\n")
	bytesUsed := len([]byte(content))
	if bytesUsed > maxBytes {
		context.Omissions = append(context.Omissions, Omission{Code: "context_budget_exceeded", Path: record.ID, Message: "artifact content exceeded packet context budget"})
		sortContext(context.Entries, context.Omissions)
		return context
	}
	context.UsedBytes = bytesUsed
	context.Entries = append(context.Entries, ContextEntry{
		Kind:         "artifact_content",
		Path:         record.ID,
		SnapshotKind: "artifact",
		Digest:       record.ContentDigest,
		Bytes:        bytesUsed,
		Content:      content,
	})
	sortContext(context.Entries, context.Omissions)
	return context
}

func buildContext(store state.Store, target SnapshotRef, tree map[string]snapshot.TreeEntry, files []patchFile, maxBytes int) ContextBundle {
	context := ContextBundle{
		MaxBytes:                   maxBytes,
		SnippetContextLines:        defaultSnippetLines,
		Entries:                    []ContextEntry{},
		Omissions:                  []Omission{},
		ConfiguredRelationships:    []string{},
		ReviewerRequestedPaths:     []string{},
		BoundedContextRequestLimit: 1,
	}
	seen := map[string]struct{}{}
	addEntry := func(kind, path string, hunk *patchHunk) {
		key := kind + ":" + path
		if hunk != nil {
			key += fmt.Sprintf(":%d:%d", hunk.NewStart, hunk.NewCount)
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		entry, ok, omission := contextEntry(store, target, tree, kind, path, hunk)
		if !ok {
			context.Omissions = append(context.Omissions, omission)
			return
		}
		if context.UsedBytes+entry.Bytes > maxBytes {
			context.Omissions = append(context.Omissions, Omission{Code: "context_budget_exceeded", Path: path, Message: "selected context entry exceeded packet context budget"})
			return
		}
		context.UsedBytes += entry.Bytes
		context.Entries = append(context.Entries, entry)
	}
	for _, file := range files {
		if len(file.Hunks) == 0 {
			if file.Patch != "" {
				addEntry("patch_file", file.Path, &patchHunk{Patch: file.Patch})
			}
			if _, existsInTarget := tree[file.Path]; existsInTarget {
				addEntry("changed_file", file.Path, nil)
			}
			continue
		}
		for _, hunk := range file.Hunks {
			h := hunk
			addEntry("patch_hunk", file.Path, &h)
			if _, existsInTarget := tree[file.Path]; existsInTarget {
				addEntry("changed_hunk", file.Path, &h)
			}
		}
	}
	for _, path := range nearbyPaths(tree, files) {
		addEntry("nearby_path", path, nil)
	}
	if len(context.ConfiguredRelationships) == 0 {
		context.Omissions = append(context.Omissions, Omission{Code: "configured_relationships_not_configured", Message: "no configured path relationships are available in v1 state"})
	}
	if len(context.ReviewerRequestedPaths) == 0 {
		context.Omissions = append(context.Omissions, Omission{Code: "no_reviewer_requested_context", Message: "one bounded context request slot is reserved for later reviewer-requested context"})
	}
	sortContext(context.Entries, context.Omissions)
	return context
}

func contextEntry(store state.Store, target SnapshotRef, tree map[string]snapshot.TreeEntry, kind, path string, hunk *patchHunk) (ContextEntry, bool, Omission) {
	if (kind == "patch_hunk" || kind == "patch_file") && hunk != nil && hunk.Patch != "" {
		content := strings.TrimRight(hunk.Patch, "\n")
		return ContextEntry{
			Kind:         kind,
			Path:         path,
			SnapshotKind: "patch",
			Digest:       digestString(content),
			Bytes:        len([]byte(content)),
			Content:      content,
		}, true, Omission{}
	}
	entry, ok := tree[path]
	if !ok {
		return ContextEntry{}, false, Omission{Code: "path_not_in_target_snapshot", Path: path, Message: "changed path is absent from target snapshot"}
	}
	body, err := store.Read(entry.Digest)
	if err != nil {
		return ContextEntry{}, false, Omission{Code: "context_read_failed", Path: path, Message: err.Error()}
	}
	if !isTextContextBody(body) {
		return ContextEntry{}, false, Omission{Code: "binary_context_omitted", Path: path, Message: "target snapshot content is binary or not valid UTF-8; patch metadata is used instead"}
	}
	content := string(body)
	start := 0
	end := 0
	if hunk != nil {
		lineContent := strings.TrimSuffix(content, "\n")
		lines := strings.Split(lineContent, "\n")
		if hunk.NewStart > 0 {
			start = hunk.NewStart - defaultSnippetLines
			if start < 1 {
				start = 1
			}
			end = hunk.NewStart + hunk.NewCount + defaultSnippetLines - 1
			if end > len(lines) {
				end = len(lines)
			}
			if start <= end {
				content = strings.Join(lines[start-1:end], "\n")
			}
		}
	}
	content = strings.TrimRight(content, "\n")
	return ContextEntry{
		Kind:         kind,
		Path:         path,
		SnapshotKind: target.Kind,
		Digest:       entry.Digest,
		StartLine:    start,
		EndLine:      end,
		Bytes:        len([]byte(content)),
		Content:      content,
	}, true, Omission{}
}

func isTextContextBody(body []byte) bool {
	return utf8.Valid(body) && !bytes.Contains(body, []byte{0})
}

func nearbyPaths(tree map[string]snapshot.TreeEntry, files []patchFile) []string {
	wanted := map[string]struct{}{}
	changed := map[string]struct{}{}
	for _, file := range files {
		changed[file.Path] = struct{}{}
		dir := filepath.ToSlash(filepath.Dir(file.Path))
		base := filepath.Base(file.Path)
		ext := filepath.Ext(base)
		stem := strings.TrimSuffix(base, ext)
		if ext != "" {
			if strings.HasSuffix(stem, "_test") {
				wanted[filepath.ToSlash(filepath.Join(dir, strings.TrimSuffix(stem, "_test")+ext))] = struct{}{}
			} else {
				wanted[filepath.ToSlash(filepath.Join(dir, stem+"_test"+ext))] = struct{}{}
			}
		}
	}
	paths := []string{}
	for path := range wanted {
		if _, isChanged := changed[path]; isChanged {
			continue
		}
		if _, ok := tree[path]; ok {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths
}

func sourceDiffSummaries(store state.Store, diffs []obligation.TransitionDiff) ([]SourceDiff, []patchFile, error) {
	summaries := make([]SourceDiff, 0, len(diffs))
	allFiles := []patchFile{}
	for _, diff := range diffs {
		body, err := store.Read(diff.Patch.Digest)
		if err != nil {
			return nil, nil, err
		}
		files := parsePatch(body)
		paths := make([]string, 0, len(files))
		hunks := 0
		for _, file := range files {
			paths = append(paths, file.Path)
			hunks += len(file.Hunks)
			if diff.FromKind == "base" && diff.ToKind == "proposal" {
				allFiles = append(allFiles, file)
			}
		}
		sort.Strings(paths)
		summaries = append(summaries, SourceDiff{
			Transition:   diff.Transition,
			FromKind:     diff.FromKind,
			ToKind:       diff.ToKind,
			FromSnapshot: diff.FromSnapshot,
			ToSnapshot:   diff.ToSnapshot,
			Diff:         diff.Diff,
			Patch:        diff.Patch,
			PatchDigest:  diff.Patch.Digest,
			HasChanges:   diff.HasChanges,
			ChangedPaths: paths,
			HunkCount:    hunks,
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Transition < summaries[j].Transition })
	return summaries, allFiles, nil
}

func parsePatch(body []byte) []patchFile {
	lines := strings.Split(string(body), "\n")
	files := []patchFile{}
	var current *patchFile
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			if current != nil && current.Path != "" {
				files = append(files, *current)
			}
			current = &patchFile{Path: parseDiffPath(line), Patch: line}
		case strings.HasPrefix(line, "--- ") && current != nil:
			appendPatchFileLine(current, line)
			path := normalizeOldPatchPath(strings.TrimSpace(strings.TrimPrefix(line, "--- ")))
			if current.Path == "" && path != "" {
				current.Path = path
			}
		case strings.HasPrefix(line, "+++ ") && current != nil:
			appendPatchFileLine(current, line)
			path := normalizePatchPath(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")))
			if path != "" && path != "/dev/null" {
				current.Path = path
			}
		case strings.HasPrefix(line, "rename to ") && current != nil:
			appendPatchFileLine(current, line)
			path := normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "rename to ")))
			if path != "" {
				current.Path = path
			}
		case strings.HasPrefix(line, "@@ ") && current != nil:
			appendPatchFileLine(current, line)
			if hunk, ok := parseHunk(line); ok {
				current.Hunks = append(current.Hunks, hunk)
			}
		case current != nil && len(current.Hunks) > 0 && isPatchHunkLine(line):
			appendPatchFileLine(current, line)
			appendPatchHunkLine(current, line)
		case current != nil:
			appendPatchFileLine(current, line)
		}
	}
	if current != nil && current.Path != "" {
		files = append(files, *current)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func appendPatchFileLine(file *patchFile, line string) {
	if file.Patch == "" {
		file.Patch = line
		return
	}
	file.Patch += "\n" + line
}

func isPatchHunkLine(line string) bool {
	return strings.HasPrefix(line, " ") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") || strings.HasPrefix(line, "\\")
}

func appendPatchHunkLine(file *patchFile, line string) {
	index := len(file.Hunks) - 1
	file.Hunks[index].Patch += "\n" + line
}

func parseDiffPath(line string) string {
	oldPath, newPath := parseDiffGitHeader(line)
	if newPath != "" {
		return newPath
	}
	return oldPath
}

func normalizePatchPath(path string) string {
	return normalizeHeaderPath(path, "to", "b")
}

func normalizeOldPatchPath(path string) string {
	return normalizeHeaderPath(path, "from", "a")
}

func normalizeMetadataPath(path string) string {
	path, ok := decodeGitPathToken(path)
	if !ok {
		return ""
	}
	return cleanPatchPath(path)
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
	return fallbackLeft, fallbackRight, true
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
			return cleanPatchPath(strings.TrimPrefix(path, prefix+"/"))
		}
	}
	return cleanPatchPath(path)
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

func cleanPatchPath(path string) string {
	if path == "" || path == "/dev/null" {
		return ""
	}
	if strings.ContainsRune(path, '\x00') {
		return ""
	}
	slash := strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
	clean := filepath.Clean(slash)
	clean = filepath.ToSlash(clean)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.HasPrefix(clean, "/") || clean != slash {
		return ""
	}
	return clean
}

func parseHunk(line string) (patchHunk, bool) {
	matches := hunkHeaderPattern.FindStringSubmatch(line)
	if matches == nil {
		return patchHunk{}, false
	}
	start, err := strconv.Atoi(matches[3])
	if err != nil {
		return patchHunk{}, false
	}
	count := 1
	if matches[4] != "" {
		if parsed, err := strconv.Atoi(matches[4]); err == nil {
			count = parsed
		}
	}
	return patchHunk{NewStart: start, NewCount: count, Patch: line}, true
}

func primaryTargetSnapshot(store state.Store, manifest obligation.CoverageManifest, events []state.Event, repo string) (SnapshotRef, error) {
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == "base" && diff.ToKind == "proposal" {
			binding, err := snapshotBindingFromDigest(store, events, repo, diff.ToKind, diff.ToSnapshot)
			if err != nil {
				return SnapshotRef{}, err
			}
			return SnapshotRef{Kind: binding.Kind, Digest: binding.Digest, Tree: binding.Tree}, nil
		}
	}
	return SnapshotRef{}, errors.New("base->proposal diff is required for primary packet")
}

func snapshotForManifestTransition(store state.Store, events []state.Event, repo string, manifest obligation.CoverageManifest, fromKind, toKind string) (SnapshotRef, error) {
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == fromKind && diff.ToKind == toKind {
			binding, err := snapshotBindingFromDigest(store, events, repo, diff.ToKind, diff.ToSnapshot)
			if err != nil {
				return SnapshotRef{}, err
			}
			return SnapshotRef{Kind: binding.Kind, Digest: binding.Digest, Tree: binding.Tree}, nil
		}
	}
	return SnapshotRef{}, fmt.Errorf("%s->%s diff is required for verification packet", fromKind, toKind)
}

func latestFindingForVerification(store state.Store, events []state.Event, repo, manifestDigest, proposalDigest, policyDigest, findingID string) (reviewresult.FindingRecord, error) {
	findingID = strings.TrimSpace(findingID)
	if findingID == "" {
		return reviewresult.FindingRecord{}, errors.New("--finding is required for verification packets")
	}
	observations, err := reviewresult.Observations(store, events, repo)
	if err != nil {
		return reviewresult.FindingRecord{}, err
	}
	var carried *reviewresult.FindingRecord
	for _, observation := range observations {
		for _, finding := range observation.Record.Findings {
			if finding.ID != findingID || !finding.Accepted {
				continue
			}
			if observation.Record.Packet.CoverageManifest.Digest == manifestDigest {
				return finding, nil
			}
			if carried == nil && carriedFindingRecordApplies(observation.Record, proposalDigest, policyDigest) {
				value := finding
				carried = &value
			}
		}
	}
	if carried != nil {
		return *carried, nil
	}
	return reviewresult.FindingRecord{}, fmt.Errorf("accepted finding not found for verification: %s", findingID)
}

func carriedFindingRecordApplies(record reviewresult.ResultRecord, proposalDigest, policyDigest string) bool {
	return record.Evidence.PrimaryReviewEvidence &&
		proposalDigest != "" &&
		record.Packet.TargetState.Kind == "proposal" &&
		record.Packet.TargetState.Digest == proposalDigest &&
		resultPacketPolicyMatches(record.Packet.Policy, policyDigest)
}

func resultPacketPolicyMatches(policy *reviewresult.PolicyRef, policyDigest string) bool {
	policyDigest = strings.TrimSpace(policyDigest)
	if policyDigest == "" {
		return policy == nil || strings.TrimSpace(policy.Digest) == ""
	}
	return policy != nil && policy.Digest == policyDigest
}

func proposalFinalSourceDiff(store state.Store, events []state.Event, stateDir, repo, proposalDigest, finalDigest string) (SourceDiff, error) {
	binding, ok, err := latestTransitionDiff(events, stateDir, repo, "proposal", "final")
	if err != nil {
		return SourceDiff{}, err
	}
	if !ok {
		return SourceDiff{}, errors.New("proposal->final diff is required for verification packets")
	}
	if binding.FromSnapshot != proposalDigest || binding.ToSnapshot != finalDigest {
		return SourceDiff{}, errors.New("proposal->final diff does not match the current proposal and final snapshots")
	}
	patchBody, err := store.Read(binding.Patch.Digest)
	if err != nil {
		return SourceDiff{}, err
	}
	files := parsePatch(patchBody)
	paths := make([]string, 0, len(files))
	hunks := 0
	for _, file := range files {
		paths = append(paths, file.Path)
		hunks += len(file.Hunks)
	}
	sort.Strings(paths)
	return SourceDiff{
		Transition:   "proposal->final",
		FromKind:     "proposal",
		ToKind:       "final",
		FromSnapshot: binding.FromSnapshot,
		ToSnapshot:   binding.ToSnapshot,
		Diff:         state.ObjectRef{Digest: binding.Diff.Digest, MediaType: "application/vnd.subreview.diff+json", Path: binding.Diff.Path},
		Patch:        state.ObjectRef{Digest: binding.Patch.Digest, MediaType: "text/x-diff; charset=utf-8", Size: int64(len(patchBody)), Path: binding.Patch.Path},
		PatchDigest:  binding.Patch.Digest,
		HasChanges:   len(files) > 0,
		ChangedPaths: paths,
		HunkCount:    hunks,
	}, nil
}

func patchFilesForDiff(store state.Store, diff SourceDiff) ([]patchFile, error) {
	body, err := store.Read(diff.Patch.Digest)
	if err != nil {
		return nil, err
	}
	return parsePatch(body), nil
}

func verificationQuestions(finding reviewresult.FindingRecord) []VerificationQuestion {
	return []VerificationQuestion{
		{ID: "resolution", Question: "Did the proposal-to-final changes resolve the referenced finding in the final state?"},
		{ID: "regression", Question: "Did the fix introduce a new regression or unexpected scope change?"},
		{ID: "context", Question: "Is the included context sufficient to verify the outcome?"},
		{ID: "deterministic", Question: "Is there deterministic or executable evidence that refutes the finding?"},
	}
}

func questionStrings(questions []VerificationQuestion) []string {
	values := make([]string, 0, len(questions))
	for _, question := range questions {
		values = append(values, question.Question)
	}
	return values
}

func snapshotBindingFromDigest(store state.Store, events []state.Event, repo, kind, digest string) (snapshotBinding, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "snapshot.captured" || event.Repo != repo || event.Details["kind"] != kind || event.Details["snapshot"] != digest {
			continue
		}
		tree := event.Details["tree"]
		if tree == "" {
			return snapshotBinding{}, fmt.Errorf("snapshot %s missing tree digest", digest)
		}
		return snapshotBinding{Kind: kind, Digest: digest, Tree: tree}, nil
	}
	body, err := store.Read(digest)
	if err != nil {
		return snapshotBinding{}, err
	}
	var record snapshot.SnapshotRecord
	if err := decodeStrict(body, &record); err != nil {
		return snapshotBinding{}, err
	}
	return snapshotBinding{Kind: kind, Digest: digest, Tree: record.TreeDigest}, nil
}

func readSnapshotTree(store state.Store, target SnapshotRef) (map[string]snapshot.TreeEntry, error) {
	if target.Tree == "" {
		return nil, fmt.Errorf("target snapshot is missing tree digest: %s", target.Digest)
	}
	body, err := store.Read(target.Tree)
	if err != nil {
		return nil, err
	}
	var manifest snapshot.TreeManifest
	if err := decodeStrict(body, &manifest); err != nil {
		return nil, err
	}
	entries := map[string]snapshot.TreeEntry{}
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry
	}
	return entries, nil
}

func gateSummaries(store state.Store, events []state.Event, repo string, manifest obligation.CoverageManifest) ([]GateSummary, error) {
	observations, err := gate.EvidenceByCommand(store, events, repo)
	if err != nil {
		return nil, err
	}
	commandIDs := make([]string, 0, len(observations))
	for commandID := range observations {
		commandIDs = append(commandIDs, commandID)
	}
	sort.Strings(commandIDs)
	summaries := []GateSummary{}
	expectedDigests := expectedGateCommandDigests(manifest)
	for _, commandID := range commandIDs {
		observation, ok := latestMatchingGateEvidence(observations[commandID], manifest, expectedDigests[commandID])
		if !ok {
			continue
		}
		policyDigest := ""
		if observation.Record.Policy != nil {
			policyDigest = observation.Record.Policy.Digest
		}
		summaries = append(summaries, GateSummary{
			CommandID:     commandID,
			CommandDigest: observation.Record.CommandDigest,
			Outcome:       observation.Record.Outcome,
			Provenance:    observation.Record.Provenance,
			SnapshotKind:  observation.Record.InputSnapshot.Kind,
			Snapshot:      observation.Record.InputSnapshot.Digest,
			PolicyDigest:  policyDigest,
			Evidence:      observation.Digest,
			EventID:       observation.EventID,
		})
	}
	return summaries, nil
}

func latestMatchingGateEvidence(observations []gate.EvidenceObservation, manifest obligation.CoverageManifest, expectedCommandDigest string) (gate.EvidenceObservation, bool) {
	for _, observation := range observations {
		if expectedCommandDigest != "" && observation.Record.CommandDigest != expectedCommandDigest {
			continue
		}
		if !gateEvidenceMatchesSnapshot(observation.Record, manifest) || !gateEvidenceMatchesPolicy(observation.Record, manifest.Policy) {
			continue
		}
		return observation, true
	}
	return gate.EvidenceObservation{}, false
}

func expectedGateCommandDigests(manifest obligation.CoverageManifest) map[string]string {
	digests := map[string]string{}
	for _, item := range manifest.Obligations {
		if item.Kind != obligation.KindGateRequirement || item.CommandID == "" || item.Metadata == nil {
			continue
		}
		digest := item.Metadata["command_digest"]
		if digest != "" {
			digests[item.CommandID] = digest
		}
	}
	return digests
}

func gateEvidenceMatchesSnapshot(evidence gate.EvidenceRecord, manifest obligation.CoverageManifest) bool {
	kind, digest := requiredGateSnapshot(manifest)
	return kind != "" && evidence.InputSnapshot.Kind == kind && evidence.InputSnapshot.Digest == digest
}

func requiredGateSnapshot(manifest obligation.CoverageManifest) (string, string) {
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == "base" && diff.ToKind == "final" {
			return diff.ToKind, diff.ToSnapshot
		}
	}
	for _, diff := range manifest.SourceDiffs {
		if diff.FromKind == "base" && diff.ToKind == "proposal" {
			return diff.ToKind, diff.ToSnapshot
		}
	}
	for _, diff := range manifest.SourceDiffs {
		if diff.ToKind != "" && diff.ToSnapshot != "" {
			return diff.ToKind, diff.ToSnapshot
		}
	}
	return "", ""
}

func gateEvidenceMatchesPolicy(evidence gate.EvidenceRecord, manifestPolicy *obligation.PolicyRef) bool {
	if manifestPolicy == nil {
		return evidence.Policy == nil
	}
	return evidence.Policy != nil && evidence.Policy.Digest == manifestPolicy.Digest
}

func latestCoverageManifest(store state.Store, events []state.Event, stateDir, repo string) (state.ObjectRef, obligation.CoverageManifest, error) {
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "obligations.built" {
			continue
		}
		if event.Repo != repo {
			return state.ObjectRef{}, obligation.CoverageManifest{}, errors.New("malformed obligations.built event: repo mismatch")
		}
		digest := event.Details["coverage_manifest"]
		if digest == "" {
			return state.ObjectRef{}, obligation.CoverageManifest{}, errors.New("malformed obligations.built event: missing coverage_manifest")
		}
		body, err := store.Read(digest)
		if err != nil {
			return state.ObjectRef{}, obligation.CoverageManifest{}, err
		}
		var manifest obligation.CoverageManifest
		if err := decodeStrict(body, &manifest); err != nil {
			return state.ObjectRef{}, obligation.CoverageManifest{}, err
		}
		if manifest.Repo != repo {
			return state.ObjectRef{}, obligation.CoverageManifest{}, errors.New("coverage manifest repo mismatch")
		}
		path, err := objectPath(stateDir, digest)
		if err != nil {
			return state.ObjectRef{}, obligation.CoverageManifest{}, err
		}
		return state.ObjectRef{Digest: digest, MediaType: "application/vnd.subreview.coverage-manifest+json", Size: int64(len(body)), Path: path}, manifest, nil
	}
	return state.ObjectRef{}, obligation.CoverageManifest{}, errors.New("coverage manifest is not built")
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
		body, err := store.Read(digest)
		if err != nil {
			return nil, err
		}
		var effective policy.EffectivePolicy
		if err := decodeStrict(body, &effective); err != nil {
			return nil, err
		}
		if effective.Repo != repo || effective.Profile != profile || effective.PolicyID != policyID {
			return nil, errors.New("bound policy object does not match policy.bound event")
		}
		return &boundPolicy{Ref: PolicyRef{Profile: profile, PolicyID: policyID, Digest: digest}, Effective: effective}, nil
	}
	return nil, nil
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

func objectPath(stateDir, digest string) (string, error) {
	hexDigest := strings.TrimPrefix(digest, "sha256:")
	if len(hexDigest) < 3 {
		return "", fmt.Errorf("invalid digest: %s", digest)
	}
	return filepath.Abs(filepath.Join(stateDir, "objects", "sha256", hexDigest[:2], hexDigest))
}

func contextDigestMaterial(context ContextBundle) any {
	type entryDigest struct {
		Kind      string `json:"kind"`
		Path      string `json:"path"`
		Digest    string `json:"digest"`
		StartLine int    `json:"start_line,omitempty"`
		EndLine   int    `json:"end_line,omitempty"`
	}
	entries := make([]entryDigest, 0, len(context.Entries))
	for _, entry := range context.Entries {
		entries = append(entries, entryDigest{Kind: entry.Kind, Path: entry.Path, Digest: entry.Digest, StartLine: entry.StartLine, EndLine: entry.EndLine})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Path < entries[j].Path
	})
	return map[string]any{
		"entries":                  entries,
		"max_bytes":                context.MaxBytes,
		"snippet_context_lines":    context.SnippetContextLines,
		"configured_relationships": context.ConfiguredRelationships,
	}
}

type canonicalObjectRef struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Size      int64  `json:"size"`
}

type canonicalSourceDiff struct {
	Transition   string             `json:"transition"`
	FromKind     string             `json:"from_kind"`
	ToKind       string             `json:"to_kind"`
	Patch        canonicalObjectRef `json:"patch"`
	PatchDigest  string             `json:"patch_digest"`
	HasChanges   bool               `json:"has_changes"`
	ChangedPaths []string           `json:"changed_paths"`
	HunkCount    int                `json:"hunk_count"`
}

type canonicalGateSummary struct {
	CommandID     string `json:"command_id"`
	CommandDigest string `json:"command_digest"`
	Outcome       string `json:"outcome"`
	Provenance    string `json:"provenance"`
	SnapshotKind  string `json:"snapshot_kind"`
}

type canonicalTargetState struct {
	Kind string `json:"kind"`
	Tree string `json:"tree,omitempty"`
}

func contentBundleDigestMaterial(sourceDiffs []SourceDiff, target SnapshotRef, allowedContextDigest string, gates []GateSummary) any {
	return map[string]any{
		"source_diffs": sourceDiffDigestMaterial(sourceDiffs),
		"target_state": targetDigestMaterial(target),
		"context":      allowedContextDigest,
		"gates":        gateDigestMaterial(gates),
	}
}

func verificationContentBundleDigestMaterial(sourceDiffs []SourceDiff, target SnapshotRef, allowedContextDigest string, gates []GateSummary, finding reviewresult.FindingRecord) any {
	return map[string]any{
		"source_diffs": sourceDiffDigestMaterial(sourceDiffs),
		"target_state": targetDigestMaterial(target),
		"context":      allowedContextDigest,
		"gates":        gateDigestMaterial(gates),
		"finding": map[string]any{
			"id":                   finding.ID,
			"dedupe_digest":        finding.DedupeDigest,
			"severity":             finding.Severity,
			"class":                finding.Class,
			"expected_fix_surface": finding.ExpectedFixSurface,
		},
	}
}

func targetDigestMaterial(target SnapshotRef) canonicalTargetState {
	return canonicalTargetState{Kind: target.Kind, Tree: target.Tree}
}

func targetDedupeID(target SnapshotRef) string {
	if target.Tree != "" {
		return target.Kind + ":" + target.Tree
	}
	return target.Kind + ":" + target.Digest
}

func sourceDiffDigestMaterial(sourceDiffs []SourceDiff) []canonicalSourceDiff {
	canonical := make([]canonicalSourceDiff, 0, len(sourceDiffs))
	for _, diff := range sourceDiffs {
		changedPaths := append([]string(nil), diff.ChangedPaths...)
		sort.Strings(changedPaths)
		canonical = append(canonical, canonicalSourceDiff{
			Transition:   diff.Transition,
			FromKind:     diff.FromKind,
			ToKind:       diff.ToKind,
			Patch:        canonicalObject(diff.Patch),
			PatchDigest:  diff.PatchDigest,
			HasChanges:   diff.HasChanges,
			ChangedPaths: changedPaths,
			HunkCount:    diff.HunkCount,
		})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Transition < canonical[j].Transition })
	return canonical
}

func gateDigestMaterial(gates []GateSummary) []canonicalGateSummary {
	canonical := make([]canonicalGateSummary, 0, len(gates))
	for _, gate := range gates {
		canonical = append(canonical, canonicalGateSummary{
			CommandID:     gate.CommandID,
			CommandDigest: gate.CommandDigest,
			Outcome:       gate.Outcome,
			Provenance:    gate.Provenance,
			SnapshotKind:  gate.SnapshotKind,
		})
	}
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].CommandID == canonical[j].CommandID {
			if canonical[i].SnapshotKind == canonical[j].SnapshotKind {
				return canonical[i].CommandDigest < canonical[j].CommandDigest
			}
			return canonical[i].SnapshotKind < canonical[j].SnapshotKind
		}
		return canonical[i].CommandID < canonical[j].CommandID
	})
	return canonical
}

func canonicalObject(ref state.ObjectRef) canonicalObjectRef {
	return canonicalObjectRef{Digest: ref.Digest, MediaType: ref.MediaType, Size: ref.Size}
}

func contextSummary(context ContextBundle) ContextSummary {
	return ContextSummary{
		MaxBytes:             context.MaxBytes,
		UsedBytes:            context.UsedBytes,
		EntryCount:           len(context.Entries),
		Omissions:            context.Omissions,
		AllowedContextDigest: context.AllowedContextDigest,
		ContentBundleHash:    context.ContentBundleHash,
	}
}

func sourceCompleteness(context ContextBundle) string {
	for _, omission := range context.Omissions {
		if omission.Code == "context_budget_exceeded" || omission.Code == "context_read_failed" || omission.Code == "path_not_in_target_snapshot" || omission.Code == "binary_context_omitted" {
			return "partial"
		}
	}
	return "complete"
}

func sortContext(entries []ContextEntry, omissions []Omission) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			if entries[i].Kind == entries[j].Kind {
				return entries[i].StartLine < entries[j].StartLine
			}
			return entries[i].Kind < entries[j].Kind
		}
		return entries[i].Path < entries[j].Path
	})
	sort.Slice(omissions, func(i, j int) bool {
		if omissions[i].Code == omissions[j].Code {
			return omissions[i].Path < omissions[j].Path
		}
		return omissions[i].Code < omissions[j].Code
	})
}

func digestString(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func digestJSON(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeStrict(body []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return errors.New("multiple JSON values")
}
