# Contributing

This repository implements an experimental storage-neutral organization and
membership policy API. The root is a prerequisite for the separately delivered
native PostgreSQL adapter, not a durable backend on its own or a stable release.
Read [AGENTS.md](AGENTS.md), [the full later scope](docs/goal.md) and
[SECURITY.md](SECURITY.md). Historical planning records do not establish runtime
or release qualification.

## Verification

Use Go 1.27.2; the module minimum remains Go 1.27.0. An isolated checkout
needs no sibling repositories or coordination goal files for these checks.
Install the public v2.5.1 binary archive for your platform from
[go-library-tools releases](https://github.com/faustbrian/go-library-tools/releases/tag/v2.5.1).
Verify `checksums.txt` against the digest in `.golib.yaml`, then verify the
archive against that checksum set. Put the extracted binary on `PATH` or
select its path through `GOLIB`; do not build Tools from source. CI uses the
immutable published setup action to install and attest this release.

Run one bounded disposable-cache session:

```bash
(
  set -eu
  planning_cache="$(mktemp -d)"
  trap 'chmod -R u+w "$planning_cache"; find "$planning_cache" -depth -delete' EXIT
  mkdir "$planning_cache/build" "$planning_cache/modules" "$planning_cache/tmp"
  export GOCACHE="$planning_cache/build"
  export GOMODCACHE="$planning_cache/modules"
  export GOTMPDIR="$planning_cache/tmp"
  GOWORK=off go test ./...
  GOWORK=off go vet ./...
  make check
)
```

`make check`, `make ci` and `make fast-check` run six ordered commands:
configuration, repository, cohesion, offline specification, local links and
unconditional full secret checking. Whole-tree/history checks cover local
dirty and untracked work; a changed-range scan must not replace them locally.
`make planning-check` omits secrets only to let CI add its separately validated
scan; it is not a complete verification claim.

Ordinary PR/push CI requires the exact event base commit, present in Git and
an ancestor of HEAD. No missing-range fallback exists. Changed-content secrets
run on every change, including documentation, with a fatal forty-second
deadline and five-second termination grace. They cover committed additions
and current contents of changed paths, not an arbitrary dirty workspace.
Required is the sole job, capped at five minutes for ordinary events; failures,
timeouts and cancellations cannot be converted into success. Public tooling,
scanner caches and temporary resources are task-owned and cleaned on failure.

Select broader planning checks explicitly:

```bash
make check-full
make specification-check-online
make secrets-check
```

Scheduled/manual Required retains online authority refresh and whole-tree/history
secrets with the existing twenty-minute outer cap. These structural checks do
not run the root behavior tests or input-validation fuzz target. Run affected
native tests separately; changed concurrency and hostile-input boundaries also
need focused race/fuzz evidence. Root unit tests prove policy and transaction
handoff, not native persistence. A green structural check does not establish
PostgreSQL delivery, full platform qualification or a stable module release.
