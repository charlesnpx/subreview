package packet

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestBuildPrimaryPacketStableDigestAndDedupeIgnoreVolatileTime(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", "one\ntwo\n")
	first, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0)})
	if err != nil {
		t.Fatalf("Build first: %v", err)
	}
	second, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(200, 0)})
	if err != nil {
		t.Fatalf("Build second: %v", err)
	}
	if first.StableDigest == "" || first.Packet.Digest == "" || first.Markdown.Digest == "" || first.Context.EntryCount == 0 {
		t.Fatalf("bad packet result: %+v", first)
	}
	if first.PromptDigest != first.Markdown.Digest {
		t.Fatalf("prompt digest should match stored markdown bytes: prompt=%s markdown=%s", first.PromptDigest, first.Markdown.Digest)
	}
	if first.StableDigest != second.StableDigest {
		t.Fatalf("stable digest should ignore generated time: %s != %s", first.StableDigest, second.StableDigest)
	}
	if first.SemanticDedupeKey.Digest != second.SemanticDedupeKey.Digest {
		t.Fatalf("dedupe key should ignore volatile generated time: %s != %s", first.SemanticDedupeKey.Digest, second.SemanticDedupeKey.Digest)
	}
	if first.VolatileDigest == second.VolatileDigest {
		t.Fatalf("volatile digest should include generated time")
	}
	store, err := state.Open(stateDir)
	if err != nil {
		t.Fatalf("Open state: %v", err)
	}
	markdown, err := store.Read(first.Markdown.Digest)
	if err != nil {
		t.Fatalf("Read markdown: %v", err)
	}
	for _, want := range []string{"# Subreview Primary Review Packet", "## Selected Context", "semantic_dedupe_digest"} {
		if !strings.Contains(string(markdown), want) {
			t.Fatalf("markdown missing %q:\n%s", want, markdown)
		}
	}
	packetBody, err := store.Read(first.Packet.Digest)
	if err != nil {
		t.Fatalf("Read packet: %v", err)
	}
	var record PacketRecord
	if err := json.Unmarshal(packetBody, &record); err != nil {
		t.Fatalf("Unmarshal packet: %v", err)
	}
	if record.StableDigest != first.StableDigest || record.SemanticDedupeKey.Digest != first.SemanticDedupeKey.Digest {
		t.Fatalf("packet record mismatch: %+v", record)
	}
	if validation := state.Validate(stateDir); !validation.OK {
		t.Fatalf("state should validate: %+v", validation.Errors)
	}
}

func TestBuildPrimaryPacketReportsContextBudgetOmissions(t *testing.T) {
	_, stateDir := initializedPacketState(t, "one\n", strings.Repeat("line\n", 50))
	result, err := Build(BuildOptions{StateDir: stateDir, Kind: KindPrimary, Now: time.Unix(100, 0), MaxContextBytes: 8})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if result.SourceCompleteness != "partial" {
		t.Fatalf("source completeness should be partial under budget pressure: %+v", result)
	}
	if !hasPacketOmission(result.Context.Omissions, "context_budget_exceeded") {
		t.Fatalf("expected context budget omission: %+v", result.Context.Omissions)
	}
}

func TestLeakageDetectionRejectsEvaluationLabels(t *testing.T) {
	report := CheckLeakage("this packet mentions a true_miss adjudication")
	if report.OK || len(report.ForbiddenTerms) == 0 {
		t.Fatalf("expected leakage terms, got %+v", report)
	}
}

func TestSemanticDedupeAndReusedTelemetryHelpers(t *testing.T) {
	fields := SemanticDedupeFields{
		PolicyID:             "policy",
		PolicyDigest:         "sha256:policy",
		Route:                RoutePrimary,
		TargetState:          "sha256:target",
		ContentBundleHash:    "sha256:content",
		RunKind:              RunKindDiscovery,
		AllowedContextBundle: "sha256:context",
	}
	first := NewSemanticDedupeKey(fields)
	second := NewSemanticDedupeKey(fields)
	if first.Digest == "" || first.Digest != second.Digest {
		t.Fatalf("dedupe key should be stable: %+v %+v", first, second)
	}
	telemetry := ReusedTokenTelemetry(RunKindDiscovery, "complete", "packet-1", 1234)
	if telemetry.ExecutionReusedFromPacketID != "packet-1" || telemetry.GrossDiscoveryTokens != 1234 || telemetry.IncrementalDiscoveryTokens != 0 {
		t.Fatalf("bad reused telemetry: %+v", telemetry)
	}
}

func TestParsePatchHandlesQuotedAndSeparatorPaths(t *testing.T) {
	files := parsePatch([]byte(`diff --git "from/a\tb.txt" "to/a\tb.txt"
--- "from/a\tb.txt"
+++ "to/a\tb.txt"
@@ -1 +1 @@
-old
+new
diff --git from/a to/file.txt to/a to/file.txt
old mode 100644
new mode 100755
diff --git from/old to/file.txt to/new to/file.txt
similarity index 100%
rename from old to/file.txt
rename to new to/file.txt
`))
	paths := make([]string, 0, len(files))
	hunksByPath := map[string]int{}
	for _, file := range files {
		paths = append(paths, file.Path)
		hunksByPath[file.Path] = len(file.Hunks)
	}
	if got, want := strings.Join(paths, "|"), "a\tb.txt|a to/file.txt|new to/file.txt"; got != want {
		t.Fatalf("unexpected parsed paths: got %q want %q", got, want)
	}
	if hunksByPath["a\tb.txt"] != 1 {
		t.Fatalf("quoted path should retain hunk, got %+v", files)
	}
}

func TestDecodeStrictRejectsTrailingJSON(t *testing.T) {
	var record struct {
		Name string `json:"name"`
	}
	if err := decodeStrict([]byte(`{"name":"one"} {"name":"two"}`), &record); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
	if err := decodeStrict([]byte(`{"name":"one"}`), &record); err != nil {
		t.Fatalf("valid JSON should pass: %v", err)
	}
}

func initializedPacketState(t *testing.T, baseBody, proposalBody string) (string, string) {
	t.Helper()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	stateDir := filepath.Join(root, "state")
	initGitRepo(t, repo)
	writeFile(t, repo, "alpha.txt", baseBody)
	writeFile(t, repo, "alpha_test.txt", "package fixture\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	if _, err := state.Init(state.InitOptions{StateDir: stateDir, RepoPath: repo, Now: time.Unix(10, 0)}); err != nil {
		t.Fatalf("Init state: %v", err)
	}
	if _, err := policy.Bind(policy.BindOptions{StateDir: stateDir, ConfigPath: writePolicyConfig(t, root), Profile: "default"}); err != nil {
		t.Fatalf("Bind policy: %v", err)
	}
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "base", Ref: "HEAD"}); err != nil {
		t.Fatalf("Capture base: %v", err)
	}
	writeFile(t, repo, "alpha.txt", proposalBody)
	if _, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: stateDir, RepoPath: repo, Kind: "proposal"}); err != nil {
		t.Fatalf("Capture proposal: %v", err)
	}
	if _, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: stateDir, FromKind: "base", ToKind: "proposal"}); err != nil {
		t.Fatalf("CreateDiff base->proposal: %v", err)
	}
	if _, err := obligation.Build(obligation.BuildOptions{StateDir: stateDir}); err != nil {
		t.Fatalf("Build obligations: %v", err)
	}
	return repo, stateDir
}

func writePolicyConfig(t *testing.T, root string) string {
	t.Helper()
	body := []byte(`{
  "schema_version": 1,
  "policy_id": "test-policy",
  "profiles": {
    "default": {
      "gate_requirements": [],
      "route_limits": {"primary_semantic_reviews": 1, "targeted_verifications": 1, "fresh_final_reviews": 0, "context_expansion_rounds": 1},
      "required_evidence_facts": ["primary_review_completed", "blocking_findings_verified", "coverage_obligations_satisfied", "policy_bound"],
      "risk_routing": [],
      "closure_basis": {"allowed_basis": ["clean", "fixed", "deterministic_refutation"], "require_basis_for_unresolved": true}
    }
  }
}
`)
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func hasPacketOmission(omissions []Omission, code string) bool {
	for _, omission := range omissions {
		if omission.Code == code {
			return true
		}
	}
	return false
}

func initGitRepo(t *testing.T, repo string) {
	t.Helper()
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	git(t, repo, "init")
	git(t, repo, "config", "user.email", "test@example.com")
	git(t, repo, "config", "user.name", "Test User")
}

func git(t *testing.T, repo string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeFile(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
