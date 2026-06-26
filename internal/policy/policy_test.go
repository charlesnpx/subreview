package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/state"
)

const testCommandDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
const testSecondCommandDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestCheckExpandsValidConfig(t *testing.T) {
	root := t.TempDir()
	configPath := writePolicyConfig(t, root, validPolicyConfig())
	result, err := Check(CheckOptions{ConfigPath: configPath, RepoPath: root})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !result.OK || result.PolicyID != "v1-default" || len(result.Profiles) != 1 {
		t.Fatalf("unexpected check result: %+v", result)
	}
	profile := result.Profiles[0]
	if profile.Profile != "default" || profile.Repo != root {
		t.Fatalf("unexpected effective profile: %+v", profile)
	}
	if len(profile.ClosurePredicates) == 0 {
		t.Fatalf("expected closure predicates")
	}
	for _, predicate := range profile.ClosurePredicates {
		if !predicate.Required || predicate.Fact == "" {
			t.Fatalf("bad predicate: %+v", predicate)
		}
	}
}

func TestCheckRejectsUnknownCommand(t *testing.T) {
	root := t.TempDir()
	cfg := validPolicyConfig()
	profile := cfg["profiles"].(map[string]any)["default"].(map[string]any)
	profile["gate_requirements"] = []any{map[string]any{"command_id": "not_a_command", "required": true}}
	_, err := Check(CheckOptions{ConfigPath: writePolicyConfig(t, root, cfg), RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "unknown command_id") {
		t.Fatalf("expected unknown command error, got %v", err)
	}
}

func TestCheckRejectsMissingRequiredGateDigest(t *testing.T) {
	root := t.TempDir()
	cfg := validPolicyConfig()
	profile := cfg["profiles"].(map[string]any)["default"].(map[string]any)
	profile["gate_requirements"] = []any{map[string]any{"command_id": "go_test_all", "required": true}}
	_, err := Check(CheckOptions{ConfigPath: writePolicyConfig(t, root, cfg), RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "requires command_digest") {
		t.Fatalf("expected missing command digest error, got %v", err)
	}
}

func TestCheckRejectsInvalidGateDigest(t *testing.T) {
	root := t.TempDir()
	cfg := validPolicyConfig()
	profile := cfg["profiles"].(map[string]any)["default"].(map[string]any)
	profile["gate_requirements"] = []any{map[string]any{"command_id": "go_test_all", "command_digest": "sha256:not-hex", "required": true}}
	_, err := Check(CheckOptions{ConfigPath: writePolicyConfig(t, root, cfg), RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "invalid command_digest") {
		t.Fatalf("expected invalid command digest error, got %v", err)
	}
}

func TestCheckRejectsScalarGrade(t *testing.T) {
	root := t.TempDir()
	cfg := validPolicyConfig()
	profile := cfg["profiles"].(map[string]any)["default"].(map[string]any)
	profile["semantic_assurance"] = "delta_verified"
	_, err := Check(CheckOptions{ConfigPath: writePolicyConfig(t, root, cfg), RepoPath: root})
	if err == nil || !strings.Contains(err.Error(), "scalar assurance grades") {
		t.Fatalf("expected scalar grade rejection, got %v", err)
	}
}

func TestBindAndExplainRoundTrip(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	configPath := writePolicyConfig(t, root, validPolicyConfig())
	bound, err := Bind(BindOptions{StateDir: stateDir, ConfigPath: configPath, Profile: "default"})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Policy.Digest == "" || bound.EventID == "" {
		t.Fatalf("bad bind result: %+v", bound)
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	last := events[len(events)-1]
	if last.Type != "policy.bound" || last.Details["profile"] != "default" || last.Details["policy"] != bound.Policy.Digest {
		t.Fatalf("policy bind event not recorded: %+v", last)
	}
	explained, err := Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if explained.PolicyDigest != bound.Policy.Digest || explained.Policy.Profile != "default" {
		t.Fatalf("bad explain result: %+v", explained)
	}
	if len(explained.ClosurePredicates) == 0 {
		t.Fatalf("expected closure predicates")
	}
}

func TestBindRejectsUnknownProfile(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	configPath := writePolicyConfig(t, root, validPolicyConfig())
	_, err := Bind(BindOptions{StateDir: stateDir, ConfigPath: configPath, Profile: "missing"})
	if err == nil || !strings.Contains(err.Error(), "unknown policy profile") {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

func TestBindRejectsInvalidStateBeforeWritingPolicyEvent(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := os.Remove(filepath.Join(stateDir, "manifests", "state.json")); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}
	configPath := writePolicyConfig(t, root, validPolicyConfig())
	_, err := Bind(BindOptions{StateDir: stateDir, ConfigPath: configPath, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "state validation failed") {
		t.Fatalf("expected state validation error, got %v", err)
	}
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(events) != 1 || events[0].Type != "state.initialized" {
		t.Fatalf("bind wrote to invalid state: %+v", events)
	}
}

func TestExplainRejectsPolicyEventWithMismatchedObjectDigest(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := Config{
		SchemaVersion: SchemaVersion,
		PolicyID:      "v1-default",
		Profiles:      map[string]Profile{"default": validProfile()},
	}
	effective, err := Effective(cfg, "default", root)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	first, err := store.PutJSON(map[string]any{"kind": "first"}, "application/json")
	if err != nil {
		t.Fatalf("PutJSON first: %v", err)
	}
	policyObject, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		t.Fatalf("PutJSON policy: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{first.Digest},
		Repo:          root,
		Details: map[string]string{
			"profile":   "default",
			"policy":    policyObject.Digest,
			"policy_id": "v1-default",
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "malformed policy.bound event") {
		t.Fatalf("expected malformed policy.bound error, got %v", err)
	}
}

func TestExplainRejectsPolicyObjectForDifferentProfile(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := Config{
		SchemaVersion: SchemaVersion,
		PolicyID:      "v1-default",
		Profiles:      map[string]Profile{"default": validProfile()},
	}
	effective, err := Effective(cfg, "default", root)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	effective.Profile = "other"
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	policyObject, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		t.Fatalf("PutJSON policy: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{policyObject.Digest},
		Repo:          root,
		Details: map[string]string{
			"profile":   "default",
			"policy":    policyObject.Digest,
			"policy_id": "v1-default",
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "bound policy object does not match profile") {
		t.Fatalf("expected profile mismatch error, got %v", err)
	}
}

func TestExplainRejectsPolicyEventWithMismatchedRepo(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := Config{
		SchemaVersion: SchemaVersion,
		PolicyID:      "v1-default",
		Profiles:      map[string]Profile{"default": validProfile()},
	}
	effective, err := Effective(cfg, "default", root)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	policyObject, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		t.Fatalf("PutJSON policy: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{policyObject.Digest},
		Repo:          filepath.Join(root, "other-repo"),
		Details: map[string]string{
			"profile":   "default",
			"policy":    policyObject.Digest,
			"policy_id": "v1-default",
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "repo mismatch") {
		t.Fatalf("expected repo mismatch error, got %v", err)
	}
}

func TestExplainRejectsPolicyEventWithMismatchedPolicyID(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := Config{
		SchemaVersion: SchemaVersion,
		PolicyID:      "v1-default",
		Profiles:      map[string]Profile{"default": validProfile()},
	}
	effective, err := Effective(cfg, "default", root)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	policyObject, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		t.Fatalf("PutJSON policy: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{policyObject.Digest},
		Repo:          root,
		Details: map[string]string{
			"profile":   "default",
			"policy":    policyObject.Digest,
			"policy_id": "other-policy",
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "event policy_id") {
		t.Fatalf("expected policy_id mismatch error, got %v", err)
	}
}

func TestExplainRejectsNonCanonicalPolicyObject(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: root, Now: time.Unix(100, 0)}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	cfg := Config{
		SchemaVersion: SchemaVersion,
		PolicyID:      "v1-default",
		Profiles:      map[string]Profile{"default": validProfile()},
	}
	effective, err := Effective(cfg, "default", root)
	if err != nil {
		t.Fatalf("Effective: %v", err)
	}
	effective.ClosurePredicates[0].Required = false
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	policyObject, err := store.PutJSON(effective, "application/vnd.subreview.policy+json")
	if err != nil {
		t.Fatalf("PutJSON policy: %v", err)
	}
	if _, err := state.AppendEvent(stateDir, state.Event{
		Type:          "policy.bound",
		ObjectDigests: []string{policyObject.Digest},
		Repo:          root,
		Details: map[string]string{
			"profile":   "default",
			"policy":    policyObject.Digest,
			"policy_id": "v1-default",
		},
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	_, err = Explain(ExplainOptions{StateDir: stateDir, Profile: "default"})
	if err == nil || !strings.Contains(err.Error(), "object is not canonical") {
		t.Fatalf("expected non-canonical policy error, got %v", err)
	}
}

func validPolicyConfig() map[string]any {
	return map[string]any{
		"schema_version": float64(SchemaVersion),
		"policy_id":      "v1-default",
		"profiles": map[string]any{
			"default": validProfileConfig(),
		},
	}
}

func validProfile() Profile {
	return Profile{
		GateRequirements: []GateRequirement{
			{CommandID: "go_test_all", CommandDigest: testCommandDigest, Required: true},
			{CommandID: "subreview_state_validate", CommandDigest: testSecondCommandDigest, Required: true},
		},
		RouteLimits: RouteLimits{
			PrimarySemanticReviews: 1,
			TargetedVerifications:  1,
			FreshFinalReviews:      0,
			ContextExpansionRounds: 1,
		},
		RequiredEvidenceFacts: []string{
			"required_gates_satisfied",
			"primary_review_completed",
			"blocking_findings_verified",
			"coverage_obligations_satisfied",
			"policy_bound",
		},
		RiskRouting: []RiskRoute{
			{RiskTier: "high", ReviewEffort: "medium", RequireIndependentFinal: true},
		},
		ClosureBasis: ClosureBasis{
			AllowedBasis:              []string{"clean", "fixed", "deterministic_refutation"},
			RequireBasisForUnresolved: true,
		},
	}
}

func validProfileConfig() map[string]any {
	return map[string]any{
		"gate_requirements": []any{
			map[string]any{"command_id": "go_test_all", "command_digest": testCommandDigest, "required": true},
			map[string]any{"command_id": "subreview_state_validate", "command_digest": testSecondCommandDigest, "required": true},
		},
		"route_limits": map[string]any{
			"primary_semantic_reviews": float64(1),
			"targeted_verifications":   float64(1),
			"fresh_final_reviews":      float64(0),
			"context_expansion_rounds": float64(1),
		},
		"required_evidence_facts": []any{
			"required_gates_satisfied",
			"primary_review_completed",
			"blocking_findings_verified",
			"coverage_obligations_satisfied",
			"policy_bound",
		},
		"risk_routing": []any{
			map[string]any{"risk_tier": "high", "review_effort": "medium", "require_independent_final": true},
		},
		"closure_basis": map[string]any{
			"allowed_basis":                []any{"clean", "fixed", "deterministic_refutation"},
			"require_basis_for_unresolved": true,
		},
	}
}

func writePolicyConfig(t *testing.T, root string, cfg map[string]any) string {
	t.Helper()
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write policy config: %v", err)
	}
	return path
}
