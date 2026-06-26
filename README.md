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
subreview gates check-catalog --catalog /tmp/subreview-gates.json --repo . --json
subreview gates run --state /tmp/subreview-state --catalog /tmp/subreview-gates.json --command-id go_test_all --snapshot proposal --json
subreview gates record --state /tmp/subreview-state --catalog /tmp/subreview-gates.json --command-id go_test_all --snapshot proposal --outcome pass --diagnostic "external CI passed" --json
subreview obligations build --state /tmp/subreview-state --json
subreview obligations status --state /tmp/subreview-state --json
subreview packet build --state /tmp/subreview-state --kind primary --json
subreview packet build --state /tmp/subreview-state --kind verification --finding finding-123 --json
subreview result import --state /tmp/subreview-state --packet sha256:... --result /tmp/worker-result.json --json
subreview close --state /tmp/subreview-state --policy-profile default --json
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

The installed skills are intentionally thin. They tell agents to invoke the CLI, require explicit `--state <dir>` paths for any command that accepts state, avoid hidden default state creation, and avoid claiming closure from a clean reviewer response alone.

`subreview state init` creates local state only at the supplied non-hidden `--state` path. The state layout contains `objects/sha256/`, `manifests/`, and `ledger.jsonl`. `subreview state validate` checks ledger JSONL, event linkage, referenced CAS objects, and digest integrity.

`subreview policy check` validates strict JSON control-plane policy config without writing state. `subreview policy bind` normalizes a profile, stores it in state CAS, and records a `policy.bound` ledger event. `subreview policy explain` reads the bound profile and reports closure predicates as required evidence facts rather than scalar assurance grades.

`subreview snapshot capture` records base, proposal, or final snapshots as reconstructable CAS tree manifests and file blobs. Captures from `--ref` record commit/tree metadata when available; working-tree captures explicitly record dirty state and omit `commit_sha` when the snapshot is not committed. `subreview snapshot restore` reconstructs the latest captured snapshot of a kind from CAS into an empty output directory. `subreview diff create` stores transition diff objects for captured snapshot pairs such as base to proposal, proposal to final, and base to final.

`subreview anchors migrate` migrates JSON anchor manifests containing file, path, and hunk anchors across an already captured snapshot diff. Migration results are stored in CAS and ledgered as `anchors.migrated`; ambiguous and unresolved anchors are emitted as closure blockers rather than silently carried forward.

`subreview gates check-catalog` validates an operator-authored trusted gate catalog and reports each command digest. Required policy gate requirements include the expected `command_digest`, so `subreview obligations status` only accepts evidence from the trusted command definition. `subreview gates run` executes only catalog command ids and stores CLI-witnessed gate evidence bound to the current policy and input snapshot. `subreview gates record` stores externally asserted gate evidence without executing commands. Gate evidence records replay class, environment pinning, repo-code execution, side-effect class, provenance, command digest, snapshot digest, outcome, and concise diagnostics. `subreview obligations status` consumes passing gate evidence for gate-requirement obligations and reports failed required gates as review blockers.

`subreview obligations build` creates a CAS-backed coverage manifest from captured base-to-proposal and base-to-final diffs plus the bound policy. The manifest records hunk, file, path, gate-requirement, context-request placeholder, and policy-final-review obligations. `subreview obligations status` reports unsatisfied evidence slots and explicit blockers for missing gate evidence, missing review evidence, unresolved context, unresolved anchors, hidden final-state scope, and unsatisfied required checks.

`subreview packet build --kind primary` creates a CAS-backed primary review packet and Markdown prompt from the latest coverage manifest. `subreview packet build --kind verification --finding <id>` creates a finding-targeted proposal-to-final verification packet when proposal and final snapshots plus a proposal-to-final diff are captured. Packets separate stable prefix and volatile suffix digests, include semantic dedupe keys, run-kind and route metadata, leakage checks for replay/evaluation labels, compact selected context, explicit omissions, and token telemetry fields for later worker result import.

`subreview result import` ingests a bounded structured worker result for a built packet. It normalizes clean reviews, findings, context requests, verifier outcomes, deterministic refutations, and token telemetry into CAS, deduplicates findings, records lifecycle states, and lets `subreview obligations status` consume primary-review and deterministic-refutation evidence without treating open findings as closed.

`subreview close` evaluates final-state closure from the latest ledger evidence and the requested bound policy profile. It persists a `closure.evaluated` report object and reports closure facts, blockers, gates, findings, discovery runs, verification runs, measured discovery/verification tokens, estimated full-cycle tokens when telemetry is available, and anti-thrash scheduler status. Closure succeeds only when the obligation engine has satisfied required gates, coverage obligations, context requests, active finding lifecycle requirements, and policy-triggered final review predicates; a clean primary reviewer response alone is not sufficient.

Generated/private research corpora and replay artifacts are intentionally not included in this public runtime repository. The generated corpus path is ignored so local research outputs are not tracked accidentally.
