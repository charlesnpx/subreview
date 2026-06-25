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
subreview install-skills --plan --target all --json
```

V1 workflow commands are being implemented across later stories. Do not simulate unsupported `subreview` commands in prose. If a requested command is not present in `subreview --help`, say that it is not implemented in this installed version and stop before making closure claims.

For any command that accepts state, require an explicit `--state <dir>` path supplied by the operator or current task. Do not create hidden default state directories, and do not use `~/.subreview` or any other implicit hidden state path.

Do not claim review closure from a clean reviewer response alone. Closure must come from the CLI's evidence and policy evaluation once those commands are available.
