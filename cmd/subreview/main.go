package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/charlesnpx/subreview/internal/anchor"
	"github.com/charlesnpx/subreview/internal/gate"
	"github.com/charlesnpx/subreview/internal/install"
	"github.com/charlesnpx/subreview/internal/obligation"
	"github.com/charlesnpx/subreview/internal/policy"
	"github.com/charlesnpx/subreview/internal/snapshot"
	"github.com/charlesnpx/subreview/internal/state"
)

var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stdout)
		return
	}
	var err error
	switch os.Args[1] {
	case "anchors":
		err = anchorsCommand(os.Args[2:])
	case "diff":
		err = diffCommand(os.Args[2:])
	case "gates":
		err = gatesCommand(os.Args[2:])
	case "install-skills":
		err = installSkills(os.Args[2:])
	case "obligations":
		err = obligationsCommand(os.Args[2:])
	case "policy":
		err = policyCommand(os.Args[2:])
	case "snapshot":
		err = snapshotCommand(os.Args[2:])
	case "state":
		err = stateCommand(os.Args[2:])
	case "version":
		fmt.Println(Version)
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		err = fmt.Errorf("unknown command: %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview anchors migrate --state <dir> --from <base|proposal|final> --to <base|proposal|final> --anchors <path> [--json]
  subreview diff create --state <dir> --from <base|proposal|final> --to <base|proposal|final> [--json]
  subreview gates check-catalog --catalog <path> --repo <path> [--json]
  subreview gates run --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> [--json]
  subreview gates record --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> --outcome <pass|fail|error> [--diagnostic <text>] [--provenance external_asserted] [--json]
  subreview install-skills [--plan|--install|--uninstall] [--target tools|claude|codex|all] [--json] [--install-root <dir>]
  subreview obligations build --state <dir> [--json]
  subreview obligations status --state <dir> [--json]
  subreview policy check --config <path> --repo <path> [--json]
  subreview policy bind --state <dir> --config <path> --profile <name> [--json]
  subreview policy explain --state <dir> --profile <name> [--json]
  subreview snapshot capture --state <dir> --kind <base|proposal|final> --repo <path> [--ref <ref>] [--json]
  subreview snapshot restore --state <dir> --kind <base|proposal|final> --output <dir> [--json]
  subreview state init --state <dir> --repo <path> [--json]
  subreview state validate --state <dir> [--json]
  subreview version`)
}

func gatesCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("gates requires subcommand: check-catalog, run, or record")
	}
	if isHelpCommand(args[0]) {
		usageGates(os.Stdout)
		return nil
	}
	switch args[0] {
	case "check-catalog":
		return gatesCheckCatalog(args[1:])
	case "run":
		return gatesRun(args[1:])
	case "record":
		return gatesRecord(args[1:])
	default:
		return fmt.Errorf("gates requires subcommand: check-catalog, run, or record")
	}
}

func gatesCheckCatalog(args []string) error {
	if hasHelpFlag(args) {
		usageGatesCheckCatalog(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("gates check-catalog", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	catalogPath := fs.String("catalog", "", "Trusted gate catalog path")
	repoPath := fs.String("repo", "", "Repository path")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("gates check-catalog does not accept positional arguments")
	}
	result, err := gate.CheckCatalog(gate.CheckOptions{CatalogPath: *catalogPath, RepoPath: *repoPath})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("gate catalog valid: %s (%d commands)\n", result.Catalog, len(result.Commands))
	return nil
}

func gatesRun(args []string) error {
	if hasHelpFlag(args) {
		usageGatesRun(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("gates run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	catalogPath := fs.String("catalog", "", "Trusted gate catalog path")
	commandID := fs.String("command-id", "", "Gate catalog command id")
	snapshotKind := fs.String("snapshot", "", "Input snapshot kind")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("gates run does not accept positional arguments")
	}
	result, err := gate.Run(gate.RunOptions{StateDir: *stateDir, CatalogPath: *catalogPath, CommandID: *commandID, SnapshotKind: *snapshotKind})
	if err != nil {
		return err
	}
	if *asJSON {
		if err := writeJSON(result); err != nil {
			return err
		}
	} else {
		fmt.Printf("gate recorded: %s %s (%s)\n", result.CommandID, result.Evidence.Digest, result.Outcome)
	}
	if result.Outcome != gate.OutcomePass {
		return fmt.Errorf("gate %s finished with outcome %s", result.CommandID, result.Outcome)
	}
	return nil
}

func gatesRecord(args []string) error {
	if hasHelpFlag(args) {
		usageGatesRecord(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("gates record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	catalogPath := fs.String("catalog", "", "Trusted gate catalog path")
	commandID := fs.String("command-id", "", "Gate catalog command id")
	snapshotKind := fs.String("snapshot", "", "Input snapshot kind")
	outcome := fs.String("outcome", "", "Gate outcome: pass, fail, or error")
	provenance := fs.String("provenance", "external_asserted", "Evidence provenance")
	diagnostic := fs.String("diagnostic", "", "Concise diagnostic summary")
	exitCode := fs.Int("exit-code", -1, "Optional exit code")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("gates record does not accept positional arguments")
	}
	var exitCodePtr *int
	if *exitCode >= 0 {
		exitCodePtr = exitCode
	}
	result, err := gate.Record(gate.RecordOptions{StateDir: *stateDir, CatalogPath: *catalogPath, CommandID: *commandID, SnapshotKind: *snapshotKind, Outcome: *outcome, Provenance: *provenance, Diagnostic: *diagnostic, ExitCode: exitCodePtr})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("gate recorded: %s %s (%s)\n", result.CommandID, result.Evidence.Digest, result.Outcome)
	return nil
}

func usageGates(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview gates check-catalog --catalog <path> --repo <path> [--json]
  subreview gates run --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> [--json]
  subreview gates record --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> --outcome <pass|fail|error> [--diagnostic <text>] [--provenance external_asserted] [--json]`)
}

func usageGatesCheckCatalog(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview gates check-catalog --catalog <path> --repo <path> [--json]

Validates an operator-authored trusted gate catalog without executing commands.`)
}

func usageGatesRun(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview gates run --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> [--json]

Runs a catalog command by id, stores CLI-witnessed gate evidence, and never executes reviewer prose.`)
}

func usageGatesRecord(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview gates record --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> --outcome <pass|fail|error> [--diagnostic <text>] [--provenance external_asserted] [--json]

Records externally asserted gate evidence for a catalog command id without executing it.`)
}

func obligationsCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("obligations requires subcommand: build or status")
	}
	if isHelpCommand(args[0]) {
		usageObligations(os.Stdout)
		return nil
	}
	switch args[0] {
	case "build":
		return obligationsBuild(args[1:])
	case "status":
		return obligationsStatus(args[1:])
	default:
		return fmt.Errorf("obligations requires subcommand: build or status")
	}
}

func obligationsBuild(args []string) error {
	if hasHelpFlag(args) {
		usageObligationsBuild(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("obligations build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("obligations build does not accept positional arguments")
	}
	result, err := obligation.Build(obligation.BuildOptions{StateDir: *stateDir})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("obligations built: %s (%d obligations, %d blockers)\n", result.Manifest.Digest, result.ObligationCount, result.BlockerCount)
	return nil
}

func obligationsStatus(args []string) error {
	if hasHelpFlag(args) {
		usageObligationsStatus(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("obligations status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("obligations status does not accept positional arguments")
	}
	result, err := obligation.Status(obligation.StatusOptions{StateDir: *stateDir})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("obligations status: %d unsatisfied, %d blockers\n", result.UnsatisfiedCount, len(result.Blockers))
	return nil
}

func usageObligations(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview obligations build --state <dir> [--json]
  subreview obligations status --state <dir> [--json]`)
}

func usageObligationsBuild(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview obligations build --state <dir> [--json]

Builds a CAS-backed coverage manifest from captured base->proposal and base->final diffs.`)
}

func usageObligationsStatus(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview obligations status --state <dir> [--json]

Reports unsatisfied obligation evidence slots and closure blockers from the latest coverage manifest.`)
}

func anchorsCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("anchors requires subcommand: migrate")
	}
	if isHelpCommand(args[0]) {
		usageAnchors(os.Stdout)
		return nil
	}
	switch args[0] {
	case "migrate":
		return anchorsMigrate(args[1:])
	default:
		return fmt.Errorf("anchors requires subcommand: migrate")
	}
}

func anchorsMigrate(args []string) error {
	if hasHelpFlag(args) {
		usageAnchorsMigrate(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("anchors migrate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	fromKind := fs.String("from", "", "Snapshot kind to migrate from")
	toKind := fs.String("to", "", "Snapshot kind to migrate to")
	anchorsPath := fs.String("anchors", "", "JSON anchor manifest path")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("anchors migrate does not accept positional arguments")
	}
	result, err := anchor.Migrate(anchor.MigrateOptions{StateDir: *stateDir, FromKind: *fromKind, ToKind: *toKind, AnchorPath: *anchorsPath, WriteLedger: true})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("anchors migrated: %s->%s %s (%d blockers)\n", result.FromKind, result.ToKind, result.Migration.Digest, len(result.ClosureBlockers))
	return nil
}

func usageAnchors(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview anchors migrate --state <dir> --from <base|proposal|final> --to <base|proposal|final> --anchors <path> [--json]`)
}

func usageAnchorsMigrate(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview anchors migrate --state <dir> --from <base|proposal|final> --to <base|proposal|final> --anchors <path> [--json]

Migrates file, path, and hunk anchors across an already captured snapshot diff.`)
}

func diffCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("diff requires subcommand: create")
	}
	if isHelpCommand(args[0]) {
		usageDiff(os.Stdout)
		return nil
	}
	switch args[0] {
	case "create":
		return diffCreate(args[1:])
	default:
		return fmt.Errorf("diff requires subcommand: create")
	}
}

func diffCreate(args []string) error {
	if hasHelpFlag(args) {
		usageDiffCreate(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("diff create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	fromKind := fs.String("from", "", "Snapshot kind to diff from")
	toKind := fs.String("to", "", "Snapshot kind to diff to")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("diff create does not accept positional arguments")
	}
	result, err := snapshot.CreateDiff(snapshot.DiffOptions{StateDir: *stateDir, FromKind: *fromKind, ToKind: *toKind})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("diff created: %s->%s %s\n", result.FromKind, result.ToKind, result.Diff.Digest)
	return nil
}

func usageDiff(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview diff create --state <dir> --from <base|proposal|final> --to <base|proposal|final> [--json]`)
}

func usageDiffCreate(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview diff create --state <dir> --from <base|proposal|final> --to <base|proposal|final> [--json]

Restores the latest captured snapshots from CAS and stores a transition diff object.`)
}

func installSkills(args []string) error {
	if hasHelpFlag(args) {
		usageInstallSkills(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("install-skills", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	target := fs.String("target", "all", "tools | claude | codex | all")
	planFlag := fs.Bool("plan", false, "Print intended files without writing")
	doInstall := fs.Bool("install", false, "Install files")
	uninstall := fs.Bool("uninstall", false, "Remove files")
	asJSON := fs.Bool("json", false, "Emit mise-en-place delegated-installer JSON")
	installRoot := fs.String("install-root", "", "Stage install under this directory as if it were HOME")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("install-skills does not accept positional arguments")
	}
	selected := 0
	for _, value := range []bool{*planFlag, *doInstall, *uninstall} {
		if value {
			selected++
		}
	}
	if selected > 1 {
		return fmt.Errorf("--plan, --install, and --uninstall are mutually exclusive")
	}
	op := "install"
	if *planFlag {
		op = "plan"
	}
	if *uninstall {
		op = "uninstall"
	}
	result, err := install.Run(install.Options{
		Operation:   op,
		Target:      *target,
		InstallRoot: *installRoot,
		Version:     Version,
	})
	if err != nil {
		return err
	}
	if *asJSON || op != "install" {
		return writeJSON(result)
	}
	fmt.Printf("installed subreview %s\n", result.Version)
	return nil
}

func usageInstallSkills(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview install-skills [--plan|--install|--uninstall] [--target tools|claude|codex|all] [--json] [--install-root <dir>]

Delegated installer operations:
  --plan       Print intended files without writing
  --install    Install files; default when no operation flag is supplied
  --uninstall  Remove files owned by this delegated repo
  --json       Emit delegated-installer JSON to stdout
  --target     tools, codex, claude, or all

The installer stages the subreview CLI tool. Codex and Claude targets also install thin early-stage skill scaffolds.`)
}

func policyCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("policy requires subcommand: check, bind, or explain")
	}
	if isHelpCommand(args[0]) {
		usagePolicy(os.Stdout)
		return nil
	}
	switch args[0] {
	case "check":
		return policyCheck(args[1:])
	case "bind":
		return policyBind(args[1:])
	case "explain":
		return policyExplain(args[1:])
	default:
		return fmt.Errorf("policy requires subcommand: check, bind, or explain")
	}
}

func policyCheck(args []string) error {
	if hasHelpFlag(args) {
		usagePolicyCheck(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("policy check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "Trusted policy config path")
	repoPath := fs.String("repo", "", "Repository path")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy check does not accept positional arguments")
	}
	result, err := policy.Check(policy.CheckOptions{ConfigPath: *configPath, RepoPath: *repoPath})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("policy valid: %s (%d profiles)\n", result.PolicyID, len(result.Profiles))
	return nil
}

func policyBind(args []string) error {
	if hasHelpFlag(args) {
		usagePolicyBind(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("policy bind", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	configPath := fs.String("config", "", "Trusted policy config path")
	profile := fs.String("profile", "", "Policy profile name")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy bind does not accept positional arguments")
	}
	result, err := policy.Bind(policy.BindOptions{StateDir: *stateDir, ConfigPath: *configPath, Profile: *profile})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("policy bound: %s %s\n", result.Profile, result.Policy.Digest)
	return nil
}

func policyExplain(args []string) error {
	if hasHelpFlag(args) {
		usagePolicyExplain(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("policy explain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	profile := fs.String("profile", "", "Policy profile name")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("policy explain does not accept positional arguments")
	}
	result, err := policy.Explain(policy.ExplainOptions{StateDir: *stateDir, Profile: *profile})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("policy profile: %s (%d closure predicates)\n", result.Profile, len(result.ClosurePredicates))
	return nil
}

func usagePolicy(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview policy check --config <path> --repo <path> [--json]
  subreview policy bind --state <dir> --config <path> --profile <name> [--json]
  subreview policy explain --state <dir> --profile <name> [--json]`)
}

func usagePolicyCheck(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview policy check --config <path> --repo <path> [--json]

Validates trusted control-plane policy config without writing state.`)
}

func usagePolicyBind(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview policy bind --state <dir> --config <path> --profile <name> [--json]

Normalizes a policy profile, stores it in state CAS, and appends a policy.bound ledger event.`)
}

func usagePolicyExplain(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview policy explain --state <dir> --profile <name> [--json]

Reports closure predicates as required evidence facts for a bound policy profile.`)
}

func snapshotCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("snapshot requires subcommand: capture or restore")
	}
	if isHelpCommand(args[0]) {
		usageSnapshot(os.Stdout)
		return nil
	}
	switch args[0] {
	case "capture":
		return snapshotCapture(args[1:])
	case "restore":
		return snapshotRestore(args[1:])
	default:
		return fmt.Errorf("snapshot requires subcommand: capture or restore")
	}
}

func snapshotCapture(args []string) error {
	if hasHelpFlag(args) {
		usageSnapshotCapture(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("snapshot capture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	kind := fs.String("kind", "", "Snapshot kind: base, proposal, or final")
	repoPath := fs.String("repo", "", "Repository path")
	ref := fs.String("ref", "", "Optional git ref to capture")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("snapshot capture does not accept positional arguments")
	}
	result, err := snapshot.Capture(snapshot.CaptureOptions{StateDir: *stateDir, Kind: *kind, RepoPath: *repoPath, Ref: *ref})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("snapshot captured: %s %s\n", result.Kind, result.Snapshot.Digest)
	return nil
}

func snapshotRestore(args []string) error {
	if hasHelpFlag(args) {
		usageSnapshotRestore(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("snapshot restore", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	kind := fs.String("kind", "", "Snapshot kind: base, proposal, or final")
	output := fs.String("output", "", "Empty output directory")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("snapshot restore does not accept positional arguments")
	}
	result, err := snapshot.Restore(snapshot.RestoreOptions{StateDir: *stateDir, Kind: *kind, Output: *output})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("snapshot restored: %s %s\n", result.Kind, result.Output)
	return nil
}

func usageSnapshot(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview snapshot capture --state <dir> --kind <base|proposal|final> --repo <path> [--ref <ref>] [--json]
  subreview snapshot restore --state <dir> --kind <base|proposal|final> --output <dir> [--json]`)
}

func usageSnapshotCapture(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview snapshot capture --state <dir> --kind <base|proposal|final> --repo <path> [--ref <ref>] [--json]

Stores a reconstructable snapshot record, tree manifest, and file blobs in state CAS.`)
}

func usageSnapshotRestore(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview snapshot restore --state <dir> --kind <base|proposal|final> --output <dir> [--json]

Restores the latest captured snapshot of the requested kind from CAS into an empty directory.`)
}

func stateCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("state requires subcommand: init or validate")
	}
	if isHelpCommand(args[0]) {
		usageState(os.Stdout)
		return nil
	}
	switch args[0] {
	case "init":
		return stateInit(args[1:])
	case "validate":
		return stateValidate(args[1:])
	default:
		return fmt.Errorf("state requires subcommand: init or validate")
	}
}

func stateInit(args []string) error {
	if hasHelpFlag(args) {
		usageStateInit(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("state init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit non-hidden state directory")
	repoPath := fs.String("repo", "", "Repository path this state belongs to")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("state init does not accept positional arguments")
	}
	result, err := state.Init(state.InitOptions{StateDir: *stateDir, RepoPath: *repoPath})
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(result)
	}
	fmt.Printf("initialized subreview state at %s\n", result.State)
	return nil
}

func stateValidate(args []string) error {
	if hasHelpFlag(args) {
		usageStateValidate(os.Stdout)
		return nil
	}
	fs := flag.NewFlagSet("state validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stateDir := fs.String("state", "", "Explicit state directory")
	asJSON := fs.Bool("json", false, "Emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("state validate does not accept positional arguments")
	}
	if *stateDir == "" {
		return fmt.Errorf("--state is required")
	}
	result := state.Validate(*stateDir)
	if *asJSON {
		if err := writeJSON(result); err != nil {
			return err
		}
		if !result.OK {
			return fmt.Errorf("state validation failed")
		}
		return nil
	}
	if result.OK {
		fmt.Printf("state valid: %s\n", result.State)
		return nil
	}
	for _, issue := range result.Errors {
		if issue.Line > 0 {
			fmt.Fprintf(os.Stderr, "%s:%d: %s: %s\n", issue.Path, issue.Line, issue.Code, issue.Message)
			continue
		}
		fmt.Fprintf(os.Stderr, "%s: %s: %s\n", issue.Path, issue.Code, issue.Message)
	}
	return fmt.Errorf("state validation failed")
}

func usageState(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview state init --state <dir> --repo <path> [--json]
  subreview state validate --state <dir> [--json]`)
}

func usageStateInit(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview state init --state <dir> --repo <path> [--json]

Creates the supplied non-hidden state directory with objects/, manifests/, and ledger.jsonl.`)
}

func usageStateValidate(w io.Writer) {
	fmt.Fprintln(w, `Usage:
  subreview state validate --state <dir> [--json]

Validates ledger JSONL, prior-event linkage, referenced CAS objects, and object digests.`)
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func isHelpCommand(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "help"
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
