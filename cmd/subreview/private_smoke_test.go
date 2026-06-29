//go:build private_smoke

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	reviewresult "github.com/charlesnpx/subreview/internal/result"
	"github.com/charlesnpx/subreview/internal/state"
)

func TestPrivateArtifactCorpusSmoke(t *testing.T) {
	repoRoot := findRepoRootForSmoke(t)
	loadDotEnvForSmoke(t, filepath.Join(repoRoot, ".env"))

	privateRoot := expandSmokePath(t, os.Getenv("SUBREVIEW_PRIVATE_ARTIFACTS_DIR"))
	if strings.TrimSpace(privateRoot) == "" {
		t.Skip("SUBREVIEW_PRIVATE_ARTIFACTS_DIR is not set; copy .env.example to .env or export it")
	}
	info, err := os.Stat(privateRoot)
	if err != nil {
		t.Fatalf("SUBREVIEW_PRIVATE_ARTIFACTS_DIR is not readable: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("SUBREVIEW_PRIVATE_ARTIFACTS_DIR is not a directory: %s", privateRoot)
	}

	artifactPath := filepath.Join(privateRoot, "research", "codex-subagent-review-corpus", "README.md")
	if _, err := os.Stat(artifactPath); err != nil {
		t.Fatalf("private artifact corpus README is not readable at %s: %v", artifactPath, err)
	}

	bin := filepath.Join(t.TempDir(), "subreview")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build subreview: %v\n%s", err, out)
	}

	stateDir := filepath.Join(t.TempDir(), "state")
	runSmokeCommand(t, bin, "state", "init", "--state", stateDir, "--repo", privateRoot, "--json")

	importOut := runSmokeCommand(t, bin, "artifact", "import", "--state", stateDir, "--kind", "plan", "--path", artifactPath, "--title", "Private Corpus Smoke", "--json")
	var imported struct {
		ArtifactID string `json:"artifact_id"`
	}
	decodeSmokeJSON(t, importOut, &imported)
	if imported.ArtifactID == "" {
		t.Fatalf("artifact import did not return artifact_id: %s", importOut)
	}

	packetOut := runSmokeCommand(t, bin, "packet", "build", "--state", stateDir, "--kind", "artifact", "--artifact", imported.ArtifactID, "--json")
	var built struct {
		Packet struct {
			Digest string `json:"digest"`
		} `json:"packet"`
	}
	decodeSmokeJSON(t, packetOut, &built)
	if built.Packet.Digest == "" {
		t.Fatalf("artifact packet build did not return packet digest: %s", packetOut)
	}

	resultPath := writePrivateSmokeWorkerResult(t, built.Packet.Digest)
	runSmokeCommand(t, bin, "result", "import", "--state", stateDir, "--packet", built.Packet.Digest, "--result", resultPath, "--json")

	statusOut := runSmokeCommand(t, bin, "artifact", "status", "--state", stateDir, "--artifact", imported.ArtifactID, "--json")
	var status struct {
		Status         string `json:"status"`
		ReviewRequired bool   `json:"review_required"`
		Clean          bool   `json:"clean"`
		LatestResult   struct {
			Packet string `json:"packet"`
		} `json:"latest_result"`
	}
	decodeSmokeJSON(t, statusOut, &status)
	if status.Status != "clean" || status.ReviewRequired || !status.Clean || status.LatestResult.Packet != built.Packet.Digest {
		t.Fatalf("artifact status did not close cleanly: %s", statusOut)
	}

	runSmokeCommand(t, bin, "state", "validate", "--state", stateDir, "--json")
	assertNoCodeReviewEventsForSmoke(t, stateDir)
}

func writePrivateSmokeWorkerResult(t *testing.T, packetDigest string) string {
	t.Helper()
	body, err := json.MarshalIndent(reviewresult.WorkerResult{
		SchemaVersion: reviewresult.SchemaVersion,
		Packet:        packetDigest,
		RunKind:       reviewresult.RunKindDiscovery,
		Route:         reviewresult.RouteArtifactReview,
		Outcome:       reviewresult.OutcomeClean,
		Summary:       "Private artifact corpus smoke packet imported successfully.",
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal private smoke result: %v", err)
	}
	path := filepath.Join(t.TempDir(), "artifact-result.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write private smoke result: %v", err)
	}
	return path
}

func assertNoCodeReviewEventsForSmoke(t *testing.T, stateDir string) {
	t.Helper()
	events, err := state.ReadEvents(stateDir)
	if err != nil {
		t.Fatalf("read smoke state events: %v", err)
	}
	for _, event := range events {
		switch event.Type {
		case "snapshot.captured", "diff.created", "obligations.built", "policy.bound", "gate.checked", "gate.ran", "gate.recorded", "closure.evaluated":
			t.Fatalf("private artifact smoke should not require code-review event %s", event.Type)
		}
	}
}

func runSmokeCommand(t *testing.T, bin string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("subreview %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func decodeSmokeJSON(t *testing.T, body []byte, value any) {
	t.Helper()
	if err := json.Unmarshal(body, value); err != nil {
		t.Fatalf("decode smoke JSON: %v\n%s", err, body)
	}
}

func loadDotEnvForSmoke(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" || os.Getenv(key) != "" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		t.Setenv(key, value)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
}

func expandSmokePath(t *testing.T, value string) string {
	t.Helper()
	value = strings.TrimSpace(os.ExpandEnv(value))
	if value == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home directory: %v", err)
		}
		return home
	}
	if strings.HasPrefix(value, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("resolve home directory: %v", err)
		}
		return filepath.Join(home, value[2:])
	}
	return value
}

func findRepoRootForSmoke(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatalf("could not locate repo root from %s", wd)
		}
		wd = next
	}
}
