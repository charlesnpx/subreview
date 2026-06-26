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
subreview packet build --state <dir> --kind primary --json
subreview install-skills --plan --target all --json
```

V1 workflow commands are being implemented across later stories. Do not simulate unsupported `subreview` commands in prose. If a requested command is not present in `subreview --help`, say that it is not implemented in this installed version and stop before making closure claims.

For any command that accepts state, require an explicit `--state <dir>` path supplied by the operator or current task. Do not create hidden default state directories, and do not use `~/.subreview` or any other implicit hidden state path.

Do not claim review closure from a clean reviewer response alone. Closure must come from the CLI's evidence and policy evaluation once those commands are available.
