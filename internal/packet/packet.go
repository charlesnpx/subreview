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

	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

const (
	EventTypePacketBuilt = "packet.built"

	KindPrimary = "primary"

	RunKindDiscovery = "discovery"
	RoutePrimary     = "primary_review"

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
	Now             time.Time
	MaxContextBytes int
}

type BuildResult struct {
	SchemaVersion      int               `json:"schema_version"`
	State              string            `json:"state"`
	Repo               string            `json:"repo"`
	Kind               string            `json:"kind"`
	RunKind            string            `json:"run_kind"`
	Route              string            `json:"route"`
	Packet             state.ObjectRef   `json:"packet"`
	Markdown           state.ObjectRef   `json:"markdown"`
	StableDigest       string            `json:"stable_digest"`
	VolatileDigest     string            `json:"volatile_digest"`
	PromptDigest       string            `json:"prompt_digest"`
	SemanticDedupeKey  SemanticDedupeKey `json:"semantic_dedupe_key"`
	Context            ContextSummary    `json:"context"`
	Leakage            LeakageReport     `json:"leakage"`
	TokenTelemetry     TokenTelemetry    `json:"token_telemetry"`
	EventID            string            `json:"event_id"`
	GeneratedAt        string            `json:"generated_at"`
	CoverageManifest   state.ObjectRef   `json:"coverage_manifest"`
	Policy             *PolicyRef        `json:"policy,omitempty"`
	TargetState        SnapshotRef       `json:"target_state"`
	SourceCompleteness string            `json:"source_completeness"`
}

type PacketRecord struct {
	SchemaVersion      int               `json:"schema_version"`
	Kind               string            `json:"kind"`
	RunKind            string            `json:"run_kind"`
	Route              string            `json:"route"`
	Repo               string            `json:"repo"`
	GeneratedAt        string            `json:"generated_at"`
	Policy             *PolicyRef        `json:"policy,omitempty"`
	TargetState        SnapshotRef       `json:"target_state"`
	CoverageManifest   state.ObjectRef   `json:"coverage_manifest"`
	SourceDiffs        []SourceDiff      `json:"source_diffs"`
	Context            ContextBundle     `json:"context"`
	Gates              []GateSummary     `json:"gates"`
	StablePrefix       string            `json:"stable_prefix"`
	VolatileSuffix     string            `json:"volatile_suffix"`
	StableDigest       string            `json:"stable_digest"`
	VolatileDigest     string            `json:"volatile_digest"`
	PromptDigest       string            `json:"prompt_digest"`
	SemanticDedupeKey  SemanticDedupeKey `json:"semantic_dedupe_key"`
	Leakage            LeakageReport     `json:"leakage"`
	TokenTelemetry     TokenTelemetry    `json:"token_telemetry"`
	SourceCompleteness string            `json:"source_completeness"`
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
	if opts.Kind != KindPrimary {
		return BuildResult{}, fmt.Errorf("unsupported packet kind: %s", opts.Kind)
	}
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
	gates, err := gateSummaries(store, events, binding.Repo)
	if err != nil {
		return BuildResult{}, err
	}
	context.AllowedContextDigest = digestJSON(contextDigestMaterial(context))
	contentBundleHash := digestJSON(contentBundleDigestMaterial(sourceDiffs, target, context.AllowedContextDigest, gates))
	context.ContentBundleHash = contentBundleHash
	var policyRef *PolicyRef
	policyID := ""
	policyDigest := ""
	if policyBinding != nil {
		ref := policyBinding.Ref
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
	leakage := CheckLeakage(markdown)
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
		fmt.Fprintf(&b, "### %s %s", entry.Kind, entry.Path)
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
				fmt.Fprintf(&b, "- %s %s: %s\n", omission.Code, omission.Path, omission.Message)
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
			addEntry("changed_file", file.Path, nil)
			continue
		}
		for _, hunk := range file.Hunks {
			h := hunk
			addEntry("changed_hunk", file.Path, &h)
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
	entry, ok := tree[path]
	if !ok {
		if hunk != nil && hunk.Patch != "" {
			content := strings.TrimRight(hunk.Patch, "\n")
			return ContextEntry{
				Kind:         "patch_hunk",
				Path:         path,
				SnapshotKind: "patch",
				Digest:       digestString(content),
				Bytes:        len([]byte(content)),
				Content:      content,
			}, true, Omission{}
		}
		return ContextEntry{}, false, Omission{Code: "path_not_in_target_snapshot", Path: path, Message: "changed path is absent from target snapshot"}
	}
	body, err := store.Read(entry.Digest)
	if err != nil {
		return ContextEntry{}, false, Omission{Code: "context_read_failed", Path: path, Message: err.Error()}
	}
	content := string(body)
	start := 0
	end := 0
	if hunk != nil {
		lines := strings.Split(content, "\n")
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
			current = &patchFile{Path: parseDiffPath(line)}
		case strings.HasPrefix(line, "--- ") && current != nil:
			path := normalizeOldPatchPath(strings.TrimSpace(strings.TrimPrefix(line, "--- ")))
			if current.Path == "" && path != "" {
				current.Path = path
			}
		case strings.HasPrefix(line, "+++ ") && current != nil:
			path := normalizePatchPath(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")))
			if path != "" && path != "/dev/null" {
				current.Path = path
			}
		case strings.HasPrefix(line, "rename to ") && current != nil:
			path := normalizeMetadataPath(strings.TrimSpace(strings.TrimPrefix(line, "rename to ")))
			if path != "" {
				current.Path = path
			}
		case strings.HasPrefix(line, "@@ ") && current != nil:
			if hunk, ok := parseHunk(line); ok {
				current.Hunks = append(current.Hunks, hunk)
			}
		case current != nil && len(current.Hunks) > 0 && isPatchHunkLine(line):
			appendPatchHunkLine(current, line)
		}
	}
	if current != nil && current.Path != "" {
		files = append(files, *current)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
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

func gateSummaries(store state.Store, events []state.Event, repo string) ([]GateSummary, error) {
	latest, err := gate.LatestEvidenceByCommand(store, events, repo)
	if err != nil {
		return nil, err
	}
	commandIDs := make([]string, 0, len(latest))
	for commandID := range latest {
		commandIDs = append(commandIDs, commandID)
	}
	sort.Strings(commandIDs)
	summaries := []GateSummary{}
	for _, commandID := range commandIDs {
		observation := latest[commandID]
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
		if omission.Code == "context_budget_exceeded" || omission.Code == "context_read_failed" || omission.Code == "path_not_in_target_snapshot" {
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
