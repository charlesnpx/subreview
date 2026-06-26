package closure_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesnpx/subreview/internal/closure"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/packet"
	"github.com/charlesnpx/subreview/internal/policy"
	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestEvaluateClosesFromLedgerFactsAndRejectsWrongProfile(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initClosureGitRepo(t, repo)
	writeClosureFile(t, repo, "alpha.txt", "one\n")
	runClosureGit(t, repo, "add", ".")
	runClosureGit(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writeClosurePolicy(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeClosureFile(t, repo, "alpha.txt", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	primary, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindPrimary})
	if err != nil {
		t.Fatalf("Build primary packet: %v", err)
	}
	beforeReview, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "default"})
	if err != nil {
		t.Fatalf("Evaluate before review: %v", err)
	}
	if beforeReview.Closed || !hasClosureBlocker(beforeReview.Blockers, "unsatisfied_policy_fact") {
		t.Fatalf("policy facts should block closure before primary evidence: %+v", beforeReview)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writeClosureWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings.",
			Telemetry: reviewresult.TokenTelemetry{
				GrossDiscoveryTokens:       100,
				IncrementalDiscoveryTokens: 80,
				CachedInputTokens:          20,
				OutputTokens:               12,
			},
		}),
	}); err != nil {
		t.Fatalf("Import clean result: %v", err)
	}

	closed, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "default"})
	if err != nil {
		t.Fatalf("Evaluate closure: %v", err)
	}
	if !closed.Closed || len(closed.Blockers) != 0 {
		t.Fatalf("expected closed state with no blockers: %+v", closed)
	}
	if !closed.Facts.PolicyBound || !closed.Facts.PrimaryReviewCompleted || !closed.Facts.CoverageObligationsSatisfied || !closed.Facts.BlockingFindingsVerified || !closed.Facts.ContextRequestsResolved || !closed.Facts.BasisClean {
		t.Fatalf("closure facts should reflect satisfied ledger evidence: %+v", closed.Facts)
	}
	if closed.Facts.IndependentFinalCompleted {
		t.Fatalf("independent final evidence should not be invented: %+v", closed.Facts)
	}
	if closed.Runs.DiscoveryRuns != 1 || closed.Runs.PrimaryRuns != 1 || closed.Runs.VerificationRuns != 0 {
		t.Fatalf("bad run summary: %+v", closed.Runs)
	}
	if !closed.Tokens.FullCycle.Available || closed.Tokens.Discovery.IncrementalDiscoveryTokens != 80 || closed.Tokens.FullCycle.IncrementalTokens != 80 {
		t.Fatalf("bad token summary: %+v", closed.Tokens)
	}
	if closed.Report.Digest == "" || closed.EventID == "" {
		t.Fatalf("closure report should be persisted and ledgered: %+v", closed)
	}

	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writeClosureWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "Second primary review should exceed the v1 route limit.",
		}),
	}); err != nil {
		t.Fatalf("Import second clean result: %v", err)
	}
	overLimit, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "default"})
	if err != nil {
		t.Fatalf("Evaluate over route limit: %v", err)
	}
	if overLimit.Closed || !overLimit.Scheduler.OverLimit || overLimit.Scheduler.AntiThrashOK || !hasClosureBlocker(overLimit.Blockers, "scheduler_route_limit_exceeded") {
		t.Fatalf("route-limit violation should block closure: %+v", overLimit)
	}

	wrongProfile, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "strict"})
	if err != nil {
		t.Fatalf("Evaluate wrong profile: %v", err)
	}
	if wrongProfile.Closed || !hasClosureBlocker(wrongProfile.Blockers, "policy_profile_mismatch") {
		t.Fatalf("wrong requested profile should block closure: %+v", wrongProfile)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate after closure reports: %+v", validation.Errors)
	}
}

func TestEvaluateEnforcesAllowedClosureBasis(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initClosureGitRepo(t, repo)
	writeClosureFile(t, repo, "alpha.txt", "one\n")
	runClosureGit(t, repo, "add", ".")
	runClosureGit(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writeClosurePolicyWithBasis(t, root, []string{"fixed"}), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeClosureFile(t, repo, "alpha.txt", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	primary, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindPrimary})
	if err != nil {
		t.Fatalf("Build primary packet: %v", err)
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writeClosureWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings.",
		}),
	}); err != nil {
		t.Fatalf("Import clean result: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build final obligations: %v", err)
	}
	blocked, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "default"})
	if err != nil {
		t.Fatalf("Evaluate closure: %v", err)
	}
	if blocked.Closed || !blocked.Facts.BasisClean || blocked.Facts.BasisFixed || !hasClosureBlocker(blocked.Blockers, "unsatisfied_closure_basis") {
		t.Fatalf("fixed-only closure basis should reject clean-only evidence: %+v", blocked)
	}
}

func TestEvaluateEnforcesContextExpansionRouteLimit(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initClosureGitRepo(t, repo)
	writeClosureFile(t, repo, "alpha.txt", "one\n")
	runClosureGit(t, repo, "add", ".")
	runClosureGit(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writeClosurePolicy(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeClosureFile(t, repo, "alpha.txt", "one\ntwo\n")
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build proposal obligations: %v", err)
	}
	primary, err := packet.Build(packet.BuildOptions{StateDir: stateDir, Kind: packet.KindPrimary})
	if err != nil {
		t.Fatalf("Build primary packet: %v", err)
	}
	for _, question := range []string{"Please include alpha_test.txt.", "Please include beta_test.txt."} {
		if _, err := reviewresult.Import(reviewresult.ImportOptions{
			StateDir: stateDir,
			PacketID: primary.Packet.Digest,
			ResultPath: writeClosureWorkerResult(t, reviewresult.WorkerResult{
				SchemaVersion: reviewresult.SchemaVersion,
				Packet:        primary.Packet.Digest,
				RunKind:       reviewresult.RunKindDiscovery,
				Route:         reviewresult.RoutePrimaryReview,
				Outcome:       reviewresult.OutcomeNeedsContext,
				NeedsContext: []reviewresult.ContextRequest{{
					Question: question,
					Reason:   "More context is required before closure.",
					Paths:    []string{"alpha.txt"},
				}},
			}),
		}); err != nil {
			t.Fatalf("Import needs-context result %q: %v", question, err)
		}
	}
	if _, err := reviewresult.Import(reviewresult.ImportOptions{
		StateDir: stateDir,
		PacketID: primary.Packet.Digest,
		ResultPath: writeClosureWorkerResult(t, reviewresult.WorkerResult{
			SchemaVersion: reviewresult.SchemaVersion,
			Packet:        primary.Packet.Digest,
			RunKind:       reviewresult.RunKindDiscovery,
			Route:         reviewresult.RoutePrimaryReview,
			Outcome:       reviewresult.OutcomeClean,
			Summary:       "No actionable findings after context expansion.",
		}),
	}); err != nil {
		t.Fatalf("Import clean result: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "final"}); err != nil {
		t.Fatalf("Capture final: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "final"}); err != nil {
		t.Fatalf("CreateDiff base->final: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build final obligations: %v", err)
	}
	blocked, err := closure.Evaluate(closure.EvaluateOptions{StateDir: stateDir, PolicyProfile: "default"})
	if err != nil {
		t.Fatalf("Evaluate closure: %v", err)
	}
	if blocked.Closed || !blocked.Scheduler.OverLimit || blocked.Scheduler.Observed.ContextExpansionRounds != 2 || !hasClosureBlocker(blocked.Blockers, "scheduler_route_limit_exceeded") {
		t.Fatalf("context expansion route limit should block closure: %+v", blocked)
	}
}

func writeClosurePolicy(t *testing.T, root string) string {
	return writeClosurePolicyWithBasis(t, root, []string{"clean", "fixed", "deterministic_refutation"})
}

func writeClosurePolicyWithBasis(t *testing.T, root string, allowed []string) string {
	t.Helper()
	allowedBody, err := json.Marshal(allowed)
	if err != nil {
		t.Fatalf("marshal allowed basis: %v", err)
	}
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
      "risk_routing": [],
      "closure_basis": {"allowed_basis": ` + string(allowedBody) + `, "require_basis_for_unresolved": true}
    }
  }
}`)
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func writeClosureWorkerResult(t *testing.T, value reviewresult.WorkerResult) string {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal worker result: %v", err)
	}
	path := filepath.Join(t.TempDir(), "worker-result.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write worker result: %v", err)
	}
	return path
}

func initClosureGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runClosureGit(t, repo, "init")
	runClosureGit(t, repo, "config", "user.email", "test@example.com")
	runClosureGit(t, repo, "config", "user.name", "Test User")
}

func runClosureGit(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeClosureFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func hasClosureBlocker(blockers []closure.Blocker, code string) bool {
	for _, blocker := range blockers {
		if blocker.Code == code {
			return true
		}
	}
	return false
}
