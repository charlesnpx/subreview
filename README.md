# subreview

`subreview` is a local-first controller for structured subagent review loops. The v1 runtime is a Go CLI that records explicit state supplied by the operator; it does not create hidden default state directories.

Current early commands:

```sh
subreview version
subreview install-skills --plan --target all --json
subreview install-skills --install --target all --json --install-root /tmp/subreview-stage
subreview install-skills --uninstall --target all --json --install-root /tmp/subreview-stage
```

The repository also exposes the delegated installer expected by `mise-en-place`:

```sh
./install-skill.sh --plan --target all --json
./install-skill.sh --install --target all --json --install-root /tmp/subreview-stage
./install-skill.sh --uninstall --target all --json --install-root /tmp/subreview-stage
```

The delegated installer stages the self-contained CLI under `.local/bin/subreview` relative to the selected install root. It also installs thin early-stage Codex and Claude skill scaffolds under `.codex/skills/subreview/SKILL.md` and `.claude/skills/subreview/SKILL.md`.

Real installs without `--install-root` target hidden home paths such as `~/.local`, `~/.codex`, and `~/.claude`. Environments that require explicit approval for hidden-file writes should obtain operator approval before running a real install. Tests and validation should use an explicit temporary install root.

The installed skills are intentionally thin. They tell agents to invoke the CLI, require explicit `--state <dir>` paths for any command that accepts state, avoid hidden default state creation, and avoid claiming closure from a clean reviewer response alone. Later stories add the actual v1 workflow commands behind the CLI.

The existing `research/` corpus and `scripts/` utilities are research inputs for policy design and evaluation. They are separate from the v1 runtime CLI and are not imported or executed by `subreview` commands.
