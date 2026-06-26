package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/charlesnpx/subreview/internal/install"
	"github.com/charlesnpx/subreview/internal/policy"
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
	case "install-skills":
		err = installSkills(os.Args[2:])
	case "policy":
		err = policyCommand(os.Args[2:])
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
  subreview install-skills [--plan|--install|--uninstall] [--target tools|claude|codex|all] [--json] [--install-root <dir>]
  subreview policy check --config <path> --repo <path> [--json]
  subreview policy bind --state <dir> --config <path> --profile <name> [--json]
  subreview policy explain --state <dir> --profile <name> [--json]
  subreview state init --state <dir> --repo <path> [--json]
  subreview state validate --state <dir> [--json]
  subreview version`)
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
		if arg == "-h" || arg == "--help" || arg == "help" {
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
