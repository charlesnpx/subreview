---
name: "subreview"
description: Use the subreview CLI for explicit-state subagent review controller workflows as commands become available. Trigger on $subreview or requests to run subreview workflows.
---

# Subreview

Use `subreview` as the authority for durable records, policy checks, packet generation, verification, closure, and reports. This early skill is only a thin wrapper around the installed CLI.

Available now:

```sh
subreview version
subreview state init --state <dir> --repo <path> --json
subreview state validate --state <dir> --json
subreview policy check --config <path> --repo <path> --json
subreview policy bind --state <dir> --config <path> --profile <name> --json
subreview policy explain --state <dir> --profile <name> --json
subreview snapshot capture --state <dir> --kind <base|proposal|final> --repo <path> [--ref <ref>] --json
subreview snapshot restore --state <dir> --kind <base|proposal|final> --output <dir> --json
subreview diff create --state <dir> --from <base|proposal|final> --to <base|proposal|final> --json
subreview anchors migrate --state <dir> --from <base|proposal|final> --to <base|proposal|final> --anchors <path> --json
subreview gates check-catalog --catalog <path> --repo <path> --json
subreview gates run --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> --json
subreview gates record --state <dir> --catalog <path> --command-id <id> --snapshot <base|proposal|final> --outcome <pass|fail|error> --json
subreview obligations build --state <dir> --json
subreview obligations status --state <dir> --json
subreview artifact import --state <dir> --kind plan --path <file> --title <title> [--revises <artifact-id>] --json
subreview artifact status --state <dir> --artifact <id> --json
subreview packet build --state <dir> --kind primary --json
subreview packet build --state <dir> --kind verification --finding <id> [--finding <id> ...] [--max-context-bytes <n>] --json
subreview packet build --state <dir> --kind artifact --artifact <id> --json
subreview result validate --state <dir> --packet <id> --result <file> --json
subreview result import --state <dir> --packet <id> --result <file> --json
subreview close --state <dir> --policy-profile <name> --json
subreview install-skills --plan --target all --json
```

Do not simulate unsupported `subreview` commands in prose. If a requested command is not present in `subreview --help`, say that it is not implemented in this installed version and stop before making closure claims.

For any command that accepts state, require an explicit `--state <dir>` path supplied by the operator or current task. Do not create hidden default state directories, and do not use `~/.subreview` or any other implicit hidden state path.

For standalone plan review, use artifact commands as controller recordkeeping only: import the plan artifact, build an `artifact_review` packet, run the actual review with the external subagent runner available in the current environment, import that structured result, and use `subreview artifact status` as the loop gate. Artifact review does not require snapshots, diffs, obligations, policy binding, gates, coverage manifests, or `subreview close`.

Use `subreview result validate --json` when you need to check worker-result JSON before import. It uses the same strict result rules as import but writes no CAS objects and appends no ledger events. For verification packets, repeat `--finding` to target multiple findings in one packet; result JSON must provide exactly one logical verdict per packet finding. Use `--max-context-bytes <n>` when the default packet context budget is too small.

Do not claim that `subreview` spawns subagents. It records state and packets; the operator's orchestration tool performs the review.

Do not claim code-review closure from a clean reviewer response alone. Code-review closure must come from `subreview close`, which evaluates the latest policy-bound ledger evidence and reports facts, blockers, gates, findings, discovery/verification runs, token telemetry, and scheduler status.
