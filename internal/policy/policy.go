package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/charlesnpx/subreview/internal/ident"
	"github.com/charlesnpx/subreview/internal/state"
)

const SchemaVersion = 1

var legacyCommandDescriptions = map[string]string{
	"go_test_all":              "Run go test ./...",
	"go_test_internal_state":   "Run go test ./internal/state",
	"go_test_race":             "Run go test -race ./...",
	"subreview_state_validate": "Run subreview state validate",
}

var knownFacts = map[string]struct{}{
	"required_gates_satisfied":       {},
	"primary_review_completed":       {},
	"blocking_findings_verified":     {},
	"coverage_obligations_satisfied": {},
	"context_requests_resolved":      {},
	"independent_final_completed":    {},
	"fresh_blinded_review":           {},
	"cli_witnessed":                  {},
	"policy_bound":                   {},
	"basis_clean":                    {},
	"basis_fixed":                    {},
	"basis_accepted_risk":            {},
	"basis_deterministic_refutation": {},
}

var knownBasis = map[string]struct{}{
	"clean":                    {},
	"fixed":                    {},
	"accepted_risk":            {},
	"deterministic_refutation": {},
}

var scalarGradeKeys = map[string]struct{}{
	"semantic_assurance": {},
	"assurance_grade":    {},
	"quality_grade":      {},
	"scalar_grade":       {},
	"grade":              {},
	"bound_grade":        {},
}

type Config struct {
	SchemaVersion int                `json:"schema_version"`
	PolicyID      string             `json:"policy_id"`
	Profiles      map[string]Profile `json:"profiles"`
}

type Profile struct {
	GateRequirements      []GateRequirement `json:"gate_requirements"`
	RouteLimits           RouteLimits       `json:"route_limits"`
	RequiredEvidenceFacts []string          `json:"required_evidence_facts"`
	RiskRouting           []RiskRoute       `json:"risk_routing"`
	ClosureBasis          ClosureBasis      `json:"closure_basis"`
}

type GateRequirement struct {
	CommandID     string `json:"command_id"`
	CommandDigest string `json:"command_digest,omitempty"`
	Required      bool   `json:"required"`
}

type RouteLimits struct {
	PrimarySemanticReviews int `json:"primary_semantic_reviews"`
	TargetedVerifications  int `json:"targeted_verifications"`
	FreshFinalReviews      int `json:"fresh_final_reviews"`
	ContextExpansionRounds int `json:"context_expansion_rounds"`
}

type RiskRoute struct {
	RiskTier                string `json:"risk_tier"`
	ReviewEffort            string `json:"review_effort"`
	RequireIndependentFinal bool   `json:"require_independent_final"`
}

type ClosureBasis struct {
	AllowedBasis              []string `json:"allowed_basis"`
	RequireBasisForUnresolved bool     `json:"require_basis_for_unresolved"`
}

type EffectivePolicy struct {
	SchemaVersion         int                 `json:"schema_version"`
	PolicyID              string              `json:"policy_id"`
	Profile               string              `json:"profile"`
	Repo                  string              `json:"repo"`
	GateRequirements      []GateRequirement   `json:"gate_requirements"`
	RouteLimits           RouteLimits         `json:"route_limits"`
	RequiredEvidenceFacts []string            `json:"required_evidence_facts"`
	RiskRouting           []RiskRoute         `json:"risk_routing"`
	ClosureBasis          ClosureBasis        `json:"closure_basis"`
	ClosurePredicates     []ClosurePredicate  `json:"closure_predicates"`
	CommandCatalog        []CommandDefinition `json:"command_catalog"`
}

type ClosurePredicate struct {
	Fact     string `json:"fact"`
	Required bool   `json:"required"`
	Reason   string `json:"reason"`
}

type CommandDefinition struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

type CheckResult struct {
	SchemaVersion int               `json:"schema_version"`
	OK            bool              `json:"ok"`
	Config        string            `json:"config"`
	Repo          string            `json:"repo"`
	PolicyID      string            `json:"policy_id"`
	Profiles      []EffectivePolicy `json:"profiles"`
}

type BindResult struct {
	SchemaVersion int             `json:"schema_version"`
	State         string          `json:"state"`
	Repo          string          `json:"repo"`
	Profile       string          `json:"profile"`
	Policy        state.ObjectRef `json:"policy"`
	EventID       string          `json:"event_id"`
}

type ExplainResult struct {
	SchemaVersion     int                `json:"schema_version"`
	State             string             `json:"state"`
	Profile           string             `json:"profile"`
	PolicyDigest      string             `json:"policy_digest"`
	ClosurePredicates []ClosurePredicate `json:"closure_predicates"`
	Policy            EffectivePolicy    `json:"policy"`
}

type CheckOptions struct {
	ConfigPath string
	RepoPath   string
}

type BindOptions struct {
	StateDir   string
	ConfigPath string
	Profile    string
}

type ExplainOptions struct {
	StateDir string
	Profile  string
}

func Check(opts CheckOptions) (CheckResult, error) {
	repo, err := explicitRepoPath(opts.RepoPath)
	if err != nil {
		return CheckResult{}, err
	}
	configPath, cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return CheckResult{}, err
	}
	profiles := make([]EffectivePolicy, 0, len(cfg.Profiles))
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		effective, err := Effective(cfg, name, repo)
		if err != nil {
			return CheckResult{}, err
		}
		profiles = append(profiles, effective)
	}
	return CheckResult{
		SchemaVersion: SchemaVersion,
		OK:            true,
		Config:        configPath,
		Repo:          repo,
		PolicyID:      cfg.PolicyID,
		Profiles:      profiles,
	}, nil
}

func Bind(opts BindOptions) (BindResult, error) {
	store, err := state.Open(opts.StateDir)
	if err != nil {
		return BindResult{}, err
	}
	_, cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return BindResult{}, err
	}
	stateDir, repo, err := stateManifestBinding(opts.StateDir)
	if err != nil {
		return BindResult{}, err
	}
	effective, err := Effective(cfg, opts.Profile, repo)
	if err != nil {
		return BindResult{}, err
	}
	ref, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		return BindResult{}, err
	}
	event, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{ref.Digest},
		Repo:          repo,
		Details: map[string]string{
			"profile":   opts.Profile,
			"policy":    ref.Digest,
			"policy_id": cfg.PolicyID,
		},
	})
	if err != nil {
		return BindResult{}, err
	}
	return BindResult{
		SchemaVersion: SchemaVersion,
		State:         stateDir,
		Repo:          repo,
		Profile:       opts.Profile,
		Policy:        ref,
		EventID:       event.EventID,
	}, nil
}

func Explain(opts ExplainOptions) (ExplainResult, error) {
	store, err := state.Open(opts.StateDir)
	if err != nil {
		return ExplainResult{}, err
	}
	stateDir, repo, err := stateManifestBinding(opts.StateDir)
	if err != nil {
		return ExplainResult{}, err
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		return ExplainResult{}, err
	}
	var binding boundPolicyBinding
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.Type != "policy.bound" || event.Details["profile"] != opts.Profile {
			continue
		}
		binding, err = parseBoundPolicyBinding(event, opts.Profile, repo)
		if err != nil {
			return ExplainResult{}, err
		}
		break
	}
	if binding.Digest == "" {
		return ExplainResult{}, fmt.Errorf("policy profile is not bound in state: %s", opts.Profile)
	}
	body, err := store.Read(binding.Digest)
	if err != nil {
		return ExplainResult{}, err
	}
	var effective EffectivePolicy
	if err := decodeStrict(body, &effective); err != nil {
		return ExplainResult{}, err
	}
	if err := ValidateBoundEffectivePolicy(effective, opts.Profile, repo, binding.PolicyID); err != nil {
		return ExplainResult{}, err
	}
	return ExplainResult{
		SchemaVersion:     SchemaVersion,
		State:             stateDir,
		Profile:           opts.Profile,
		PolicyDigest:      binding.Digest,
		ClosurePredicates: effective.ClosurePredicates,
		Policy:            effective,
	}, nil
}

func LoadConfig(path string) (string, Config, error) {
	if strings.TrimSpace(path) == "" {
		return "", Config{}, errors.New("--config is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", Config{}, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", Config{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", Config{}, fmt.Errorf("policy config must be a regular file: %s", abs)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return "", Config{}, err
	}
	if err := rejectScalarGrades(body); err != nil {
		return "", Config{}, err
	}
	var cfg Config
	if err := decodeStrict(body, &cfg); err != nil {
		return "", Config{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return "", Config{}, err
	}
	return abs, cfg, nil
}

func Effective(cfg Config, profileName, repo string) (EffectivePolicy, error) {
	if strings.TrimSpace(profileName) == "" {
		return EffectivePolicy{}, errors.New("--profile is required")
	}
	profile, ok := cfg.Profiles[profileName]
	if !ok {
		return EffectivePolicy{}, fmt.Errorf("unknown policy profile: %s", profileName)
	}
	facts := append([]string(nil), profile.RequiredEvidenceFacts...)
	sort.Strings(facts)
	predicates := make([]ClosurePredicate, 0, len(facts))
	for _, fact := range facts {
		predicates = append(predicates, ClosurePredicate{
			Fact:     fact,
			Required: true,
			Reason:   "required by policy profile " + profileName,
		})
	}
	gates, err := normalizedGateRequirements(profile.GateRequirements)
	if err != nil {
		return EffectivePolicy{}, err
	}
	return EffectivePolicy{
		SchemaVersion:         SchemaVersion,
		PolicyID:              cfg.PolicyID,
		Profile:               profileName,
		Repo:                  repo,
		GateRequirements:      gates,
		RouteLimits:           profile.RouteLimits,
		RequiredEvidenceFacts: facts,
		RiskRouting:           append([]RiskRoute(nil), profile.RiskRouting...),
		ClosureBasis: ClosureBasis{
			AllowedBasis:              append([]string(nil), profile.ClosureBasis.AllowedBasis...),
			RequireBasisForUnresolved: profile.ClosureBasis.RequireBasisForUnresolved,
		},
		ClosurePredicates: predicates,
		CommandCatalog:    commandCatalogFromGateRequirements(gates),
	}, nil
}

func normalizedGateRequirements(input []GateRequirement) ([]GateRequirement, error) {
	gates := make([]GateRequirement, 0, len(input))
	for _, gate := range input {
		commandID, err := ident.NormalizeCommandID(gate.CommandID)
		if err != nil {
			return nil, fmt.Errorf("invalid command_id: %s", gate.CommandID)
		}
		gates = append(gates, GateRequirement{
			CommandID:     commandID,
			CommandDigest: gate.CommandDigest,
			Required:      gate.Required,
		})
	}
	return gates, nil
}

func validateConfig(cfg Config) error {
	if cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported policy schema_version: %d", cfg.SchemaVersion)
	}
	if strings.TrimSpace(cfg.PolicyID) == "" {
		return errors.New("policy_id is required")
	}
	if len(cfg.Profiles) == 0 {
		return errors.New("at least one policy profile is required")
	}
	for name, profile := range cfg.Profiles {
		if strings.TrimSpace(name) == "" {
			return errors.New("policy profile name is required")
		}
		if len(profile.RequiredEvidenceFacts) == 0 {
			return fmt.Errorf("profile %s requires at least one evidence fact", name)
		}
		seenGateCommands := map[string]struct{}{}
		for _, gate := range profile.GateRequirements {
			commandID, err := ident.NormalizeCommandID(gate.CommandID)
			if err != nil {
				return fmt.Errorf("profile %s references invalid command_id: %s", name, gate.CommandID)
			}
			if _, exists := seenGateCommands[commandID]; exists {
				return fmt.Errorf("profile %s has duplicate gate requirement command_id: %s", name, commandID)
			}
			seenGateCommands[commandID] = struct{}{}
			if gate.Required && strings.TrimSpace(gate.CommandDigest) == "" {
				return fmt.Errorf("profile %s required gate %s requires command_digest", name, commandID)
			}
			if strings.TrimSpace(gate.CommandDigest) != "" && !validCommandDigest(gate.CommandDigest) {
				return fmt.Errorf("profile %s gate %s has invalid command_digest: %s", name, commandID, gate.CommandDigest)
			}
		}
		if err := validateRouteLimits(name, profile.RouteLimits); err != nil {
			return err
		}
		for _, fact := range profile.RequiredEvidenceFacts {
			if _, ok := knownFacts[fact]; !ok {
				return fmt.Errorf("profile %s references unknown evidence fact: %s", name, fact)
			}
		}
		for _, route := range profile.RiskRouting {
			if route.RiskTier != "low" && route.RiskTier != "medium" && route.RiskTier != "high" && route.RiskTier != "critical" {
				return fmt.Errorf("profile %s references invalid risk_tier: %s", name, route.RiskTier)
			}
			if route.ReviewEffort != "low" && route.ReviewEffort != "medium" && route.ReviewEffort != "high" {
				return fmt.Errorf("profile %s references invalid review_effort: %s", name, route.ReviewEffort)
			}
		}
		if len(profile.ClosureBasis.AllowedBasis) == 0 {
			return fmt.Errorf("profile %s requires at least one allowed closure basis", name)
		}
		for _, basis := range profile.ClosureBasis.AllowedBasis {
			if _, ok := knownBasis[basis]; !ok {
				return fmt.Errorf("profile %s references unknown closure basis: %s", name, basis)
			}
		}
	}
	return nil
}

func validCommandDigest(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, ch := range value[len(prefix):] {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func validateRouteLimits(profile string, limits RouteLimits) error {
	if limits.PrimarySemanticReviews < 1 {
		return fmt.Errorf("profile %s route_limits.primary_semantic_reviews must be at least 1", profile)
	}
	if limits.TargetedVerifications < 0 || limits.FreshFinalReviews < 0 || limits.ContextExpansionRounds < 0 {
		return fmt.Errorf("profile %s route limits must not be negative", profile)
	}
	if limits.TargetedVerifications > 1 {
		return fmt.Errorf("profile %s route_limits.targeted_verifications must be at most 1 in v1", profile)
	}
	return nil
}

func rejectScalarGrades(body []byte) error {
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(value any) error {
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, ok := scalarGradeKeys[key]; ok {
					return fmt.Errorf("scalar assurance grades are not supported in policy config: %s", key)
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range typed {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(raw)
}

func commandCatalogFromGateRequirements(gates []GateRequirement) []CommandDefinition {
	catalog := []CommandDefinition{}
	seen := map[string]struct{}{}
	for _, gate := range gates {
		id := strings.TrimSpace(gate.CommandID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		catalog = append(catalog, CommandDefinition{ID: id, Description: legacyCommandDescriptions[id]})
	}
	sort.Slice(catalog, func(i, j int) bool { return catalog[i].ID < catalog[j].ID })
	return catalog
}

func legacyCommandCatalog() []CommandDefinition {
	catalog := make([]CommandDefinition, 0, len(legacyCommandDescriptions))
	for id, description := range legacyCommandDescriptions {
		catalog = append(catalog, CommandDefinition{ID: id, Description: description})
	}
	sort.Slice(catalog, func(i, j int) bool { return catalog[i].ID < catalog[j].ID })
	return catalog
}

func stateManifestBinding(stateDir string) (string, string, error) {
	root, err := state.ResolveStateDir(stateDir)
	if err != nil {
		return "", "", err
	}
	if result := state.Validate(root); !result.OK {
		return "", "", stateValidationError(result)
	}
	events, err := state.ReadEvents(root)
	if err != nil {
		return "", "", err
	}
	if len(events) == 0 {
		return "", "", errors.New("state has no ledger events")
	}
	first := events[0]
	if first.Type != "state.initialized" {
		return "", "", fmt.Errorf("state first event is not state.initialized: %s", first.Type)
	}
	return root, first.Repo, nil
}

type boundPolicyBinding struct {
	Digest   string
	PolicyID string
}

func parseBoundPolicyBinding(event state.Event, profile, repo string) (boundPolicyBinding, error) {
	if event.Repo != repo {
		return boundPolicyBinding{}, fmt.Errorf("malformed policy.bound event for profile %s: repo mismatch", profile)
	}
	digest := event.Details["policy"]
	if strings.TrimSpace(digest) == "" {
		return boundPolicyBinding{}, fmt.Errorf("malformed policy.bound event for profile %s: missing policy digest", profile)
	}
	if len(event.ObjectDigests) != 1 || event.ObjectDigests[0] != digest {
		return boundPolicyBinding{}, fmt.Errorf("malformed policy.bound event for profile %s: object_digests must contain only policy digest %s", profile, digest)
	}
	policyID := event.Details["policy_id"]
	if strings.TrimSpace(policyID) == "" {
		return boundPolicyBinding{}, fmt.Errorf("malformed policy.bound event for profile %s: missing policy_id", profile)
	}
	return boundPolicyBinding{Digest: digest, PolicyID: policyID}, nil
}

func DecodeBoundEffectivePolicy(body []byte, profile, repo, policyID string) (EffectivePolicy, error) {
	var effective EffectivePolicy
	if err := decodeStrict(body, &effective); err != nil {
		return EffectivePolicy{}, err
	}
	if err := ValidateBoundEffectivePolicy(effective, profile, repo, policyID); err != nil {
		return EffectivePolicy{}, err
	}
	return effective, nil
}

func ValidateBoundEffectivePolicy(effective EffectivePolicy, profile, repo, policyID string) error {
	if effective.SchemaVersion != SchemaVersion {
		return fmt.Errorf("bound policy object does not match profile %s: unsupported schema_version %d", profile, effective.SchemaVersion)
	}
	if effective.Profile != profile {
		return fmt.Errorf("bound policy object does not match profile %s: object profile is %s", profile, effective.Profile)
	}
	if effective.Repo != repo {
		return fmt.Errorf("bound policy object does not match profile %s: object repo is %s", profile, effective.Repo)
	}
	if strings.TrimSpace(effective.PolicyID) == "" {
		return fmt.Errorf("bound policy object does not match profile %s: policy_id is required", profile)
	}
	if effective.PolicyID != policyID {
		return fmt.Errorf("bound policy object does not match profile %s: event policy_id is %s", profile, policyID)
	}
	cfg := Config{
		SchemaVersion: effective.SchemaVersion,
		PolicyID:      effective.PolicyID,
		Profiles: map[string]Profile{
			profile: {
				GateRequirements:      append([]GateRequirement(nil), effective.GateRequirements...),
				RouteLimits:           effective.RouteLimits,
				RequiredEvidenceFacts: append([]string(nil), effective.RequiredEvidenceFacts...),
				RiskRouting:           append([]RiskRoute(nil), effective.RiskRouting...),
				ClosureBasis: ClosureBasis{
					AllowedBasis:              append([]string(nil), effective.ClosureBasis.AllowedBasis...),
					RequireBasisForUnresolved: effective.ClosureBasis.RequireBasisForUnresolved,
				},
			},
		},
	}
	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("bound policy object does not match profile %s: %w", profile, err)
	}
	expected, err := Effective(cfg, profile, repo)
	if err != nil {
		return fmt.Errorf("bound policy object does not match profile %s: %w", profile, err)
	}
	if reflect.DeepEqual(effective, expected) {
		return nil
	}
	if legacyFixedCommandCatalogAllowed(effective, expected) {
		return nil
	}
	if !reflect.DeepEqual(effective, expected) {
		return fmt.Errorf("bound policy object does not match profile %s: object is not canonical", profile)
	}
	return nil
}

func legacyFixedCommandCatalogAllowed(effective, expected EffectivePolicy) bool {
	copyEffective := effective
	copyExpected := expected
	copyEffective.CommandCatalog = nil
	copyExpected.CommandCatalog = nil
	if !reflect.DeepEqual(copyEffective, copyExpected) {
		return false
	}
	for _, gate := range effective.GateRequirements {
		if _, ok := legacyCommandDescriptions[gate.CommandID]; !ok {
			return false
		}
	}
	return reflect.DeepEqual(effective.CommandCatalog, legacyCommandCatalog())
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

func decodeStrict(body []byte, dest any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
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
