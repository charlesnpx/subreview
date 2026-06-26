# subreview

`subreview` is a local-first controller for structured subagent review loops. The v1 runtime is a Go CLI that records explicit state supplied by the operator; it does not create hidden default state directories.

Current early commands:

```sh
subreview version
subreview state init --state /tmp/subreview-state --repo . --json
subreview state validate --state /tmp/subreview-state --json
subreview policy check --config /tmp/subreview-policy.json --repo . --json
subreview policy bind --state /tmp/subreview-state --config /tmp/subreview-policy.json --profile default --json
subreview policy explain --state /tmp/subreview-state --profile default --json
subreview snapshot capture --state /tmp/subreview-state --kind base --repo . --ref HEAD --json
subreview snapshot capture --state /tmp/subreview-state --kind proposal --repo . --json
subreview snapshot restore --state /tmp/subreview-state --kind proposal --output /tmp/subreview-restore --json
subreview diff create --state /tmp/subreview-state --from base --to proposal --json
subreview anchors migrate --state /tmp/subreview-state --from base --to proposal --anchors /tmp/subreview-anchors.json --json
subreview obligations build --state /tmp/subreview-state --json
subreview obligations status --state /tmp/subreview-state --json
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

The delegated installer stages the self-contained CLI under `.local/bin/subreview` when the selected target includes `tools`, and it installs thin early-stage Codex and Claude skill scaffolds under `.codex/skills/subreview/SKILL.md` and `.claude/skills/subreview/SKILL.md` when those targets are selected.

Real installs without `--install-root` target hidden home paths such as `~/.local`, `~/.codex`, and `~/.claude`. Environments that require explicit approval for hidden-file writes should obtain operator approval before running a real install. Tests and validation should use an explicit temporary install root.

The installed skills are intentionally thin. They tell agents to invoke the CLI, require explicit `--state <dir>` paths for any command that accepts state, avoid hidden default state creation, and avoid claiming closure from a clean reviewer response alone. Later stories add the actual v1 workflow commands behind the CLI.

`subreview state init` creates local state only at the supplied non-hidden `--state` path. The state layout contains `objects/sha256/`, `manifests/`, and `ledger.jsonl`. `subreview state validate` checks ledger JSONL, event linkage, referenced CAS objects, and digest integrity.

`subreview policy check` validates strict JSON control-plane policy config without writing state. `subreview policy bind` normalizes a profile, stores it in state CAS, and records a `policy.bound` ledger event. `subreview policy explain` reads the bound profile and reports closure predicates as required evidence facts rather than scalar assurance grades.

`subreview snapshot capture` records base, proposal, or final snapshots as reconstructable CAS tree manifests and file blobs. Captures from `--ref` record commit/tree metadata when available; working-tree captures explicitly record dirty state and omit `commit_sha` when the snapshot is not committed. `subreview snapshot restore` reconstructs the latest captured snapshot of a kind from CAS into an empty output directory. `subreview diff create` stores transition diff objects for captured snapshot pairs such as base to proposal, proposal to final, and base to final.

`subreview anchors migrate` migrates JSON anchor manifests containing file, path, and hunk anchors across an already captured snapshot diff. Migration results are stored in CAS and ledgered as `anchors.migrated`; ambiguous and unresolved anchors are emitted as closure blockers rather than silently carried forward.

`subreview obligations build` creates a CAS-backed coverage manifest from captured base-to-proposal and base-to-final diffs plus the bound policy. The manifest records hunk, file, path, gate-requirement, context-request placeholder, and policy-final-review obligations. `subreview obligations status` reports unsatisfied evidence slots and explicit blockers for missing gate evidence, missing review evidence, unresolved context, unresolved anchors, hidden final-state scope, and unsatisfied required checks. Story 007 intentionally records future evidence slots without importing review, gate, verification, or refutation adapters yet.

The existing `research/` corpus and `scripts/` utilities are research inputs for policy design and evaluation. They are separate from the v1 runtime CLI and are not imported or executed by `subreview` commands.
