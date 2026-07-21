# ledger.py — Git-Backed Multi-Machine Run Ledger

The ledger lets a small team running CARO experiments on **different machines with
separate `arvo_loc_runs.db` files** see combined experiment coverage and
automatically queue up unrun experiments, without any hosted service.

Each machine appends minimal **run facts** — vuln id, experiment_tag, model, run
mode, outcome — to its own JSONL file in a small shared git repository, and reads
everyone else's files. Detailed results (agent logs, patches, token usage) never
enter the ledger; they stay in each machine's local DB, synced separately. The
ledger answers exactly one question well: *which (vuln × experiment_tag) cells
still need a run, team-wide?* — and feeds the answer to `run_experiments.py
enqueue --fill-gaps`.

Tests: `test_ledger.py` (`python -m pytest test_ledger.py`).

---

## One-time setup

**1. One person creates the shared repo** (private, e.g. `arvo-run-ledger` on
GitHub). It starts empty — no structure required.

**2. Every machine clones it and sets two env vars** (in `~/.bashrc` or similar):

```bash
python ledger.py init --ledger-dir ~/arvo-run-ledger \
    --remote git@github.com:<org>/arvo-run-ledger.git

export ARVO_LEDGER_DIR=~/arvo-run-ledger
export ARVO_LEDGER_MACHINE=splab        # optional; defaults to the hostname
```

Machine names must be unique across the team (each machine writes only to
`<machine>.jsonl`). Git identity (`user.name`/`user.email`) must be configured and
pushes to the shared repo must work non-interactively (SSH key) — the ledger
commits and pushes automatically.

**3. Backfill history.** The first `report` on each machine publishes every
tagged run already in its local DB:

```bash
python ledger.py report
```

---

## How facts flow

```
machine A:  runs table ──report──> A.jsonl ──commit/push──┐
machine B:  runs table ──report──> B.jsonl ──commit/push──┤──> shared git repo
machine C:                                                │        │
            enqueue --fill-gaps <──select gaps<──pull─────┴────────┘
                    └──> claims appended to C.jsonl ──commit/push──> (others skip those vulns)
```

- **Reporting is an idempotent outbox.** `report` compares the local `runs` table
  against what this machine's ledger file already contains (keyed on `run_id`)
  and appends only the difference. Safe to call after every run, from cron, or
  once a week — the result converges either way.
- **Runs with no `experiment_tag` are skipped by default** (legacy/manual runs
  tell you nothing about coverage). `--include-untagged` reports them anyway.
- **Offline tolerance is total.** Every git failure (no network, push race) is
  non-fatal: facts are committed locally and pushed on the next opportunity;
  even a commit failure is healed on the next call. Experiments are never
  blocked by ledger problems — when the runner reports automatically, a ledger
  failure is a logged warning, nothing more.

### Fact format

One JSON object per line in `<machine>.jsonl`:

```json
{"type": "run", "run_id": "arvo-101-vul-1784...-patch", "machine": "splab",
 "vuln_id": 101, "experiment_tag": "baseline-patch-envmd", "run_mode": "patch",
 "model": "claude-sonnet-4-6", "outcome": "success", "timestamp": "2026-07-18T10:00:00",
 "reported_at": "2026-07-19T09:00:00+00:00"}

{"type": "claim", "machine": "splab", "vuln_id": 102,
 "experiment_tag": "baseline-patch-envmd", "campaign": "fill-jul19",
 "timestamp": "2026-07-19T09:00:00+00:00"}
```

`outcome` is one of `success` (run finished without an error flag), `error`, or
`usage_limited` — the same classification the campaign runner uses. Note
`success` means *the run completed*, not that the patch fixed the crash
(`patch_data.is_crash_resolved` stays local).

---

## Commands

All commands take `--ledger-dir` (default `$ARVO_LEDGER_DIR`) and `--no-sync`
(skip the `git pull` before reading/writing).

### `report` — publish this machine's runs

```bash
python ledger.py report [--db arvo_loc_runs.db] [--machine NAME] [--include-untagged]
```

### `coverage` — team-wide coverage per experiment_tag

```bash
python ledger.py coverage                      # summary counts per tag
python ledger.py coverage --tag baseline-patch-envmd    # per-vuln cells
python ledger.py coverage --json               # machine-readable, for tooling
```

Cell status: **covered** (a successful run exists anywhere on the team) >
**claimed** (an active claim, no success yet) > **attempted** (only
failed/limited runs). Cells also list which models and machines have touched
them — this is how "which models ran what" stays visible even though model
isn't yet a controllable experiment parameter.

### `gaps` — preview what a gap-fill would pick

```bash
python ledger.py gaps --tag baseline-patch-envmd --count 20 \
    [--project ndpi --project libxml2] [--id-min N] [--id-max N] \
    [--reproduced-only] [--retry-failed] [--seed 7]
```

Dry-run twin of `enqueue --fill-gaps`: same selection, prints ids, changes
nothing. Candidates come from the **local** `arvo` table filtered by the flags;
coverage exclusions come from the ledger.

### `claim` — manually reserve vulns

```bash
python ledger.py claim --tag baseline-patch-envmd --ids 101 102
```

For work you're about to run outside gap-fill (gap-fill claims automatically).

### `init` — create or clone the ledger repo

```bash
python ledger.py init --ledger-dir ~/arvo-run-ledger [--remote <git-url>]
```

---

## Gap-fill enqueueing (the point of all this)

```bash
python run_experiments.py enqueue --campaign fill-jul19 \
    --experiment-tag baseline-patch-envmd --patch-mode \
    --fill-gaps 20 --project ndpi --reproduced-only [--seed 7]

python run_experiments.py run --campaign fill-jul19
```

`--fill-gaps N` replaces `--ids`: it pulls the ledger, selects up to N random
vulns matching the filters that **no machine** has successfully run (or actively
claimed) under this experiment_tag, enqueues them, and **claims them in the
ledger** so other machines' gap-fills skip them. By default cells whose only
runs failed are also skipped (a failure often signals an infra issue worth a
human look); add `--retry-failed` to re-attempt them.

During `run`, if `ARVO_LEDGER_DIR` is set (or `--ledger-dir` is passed), the
runner **reports facts to the ledger after every item automatically** — this is
what makes coverage "dynamic": teammates see your results within one run, not
whenever you remember to sync. Fully automatic operation is then:

```bash
# each machine, under nohup: queue 10 gaps, run them, repeat
nohup bash -c 'while python run_experiments.py enqueue \
      --campaign auto-$(date +%j) --experiment-tag baseline-patch-envmd \
      --patch-mode --fill-gaps 10 --reproduced-only --append; do
    python run_experiments.py run --campaign auto-$(date +%j)
  done' > autofill.log 2>&1 &
```

### Claims: semantics and honesty about races

- A claim means "a machine has queued this cell"; it expires after **7 days**
  (`--claim-ttl-days`) so an abandoned campaign can't block a cell forever.
- Claims narrow the double-run window from hours to seconds, but don't close it:
  two machines gap-filling in the same instant can both select the same vuln
  before either's claim propagates. At team size 2–4 this is rare and the cost
  is one redundant run, not corruption — coverage treats duplicate successes as
  one covered cell. Seeding different `--seed` values per machine (or different
  `--project` filters) makes collisions rarer still.
- A claim is released implicitly: either a run fact for the cell appears
  (covered/attempted takes over) or the claim expires.

---

## Operational notes

- **The ledger repo is append-only by convention.** Never hand-edit or rewrite
  history; per-machine files mean concurrent pushes rebase cleanly.
- **Don't share machine names.** Two machines writing one file is the only way
  to corrupt the outbox bookkeeping.
- **The local `arvo` table is the candidate universe** for gap-fill, so keep the
  arvo data present on machines that enqueue (it ships inside
  `arvo_loc_runs.db`).
- **Ledger vs. campaign DB:** campaigns/items (in each machine's DB) track
  *execution* on that machine; the ledger tracks *coverage* across all machines.
  The runner consults the ledger only at enqueue time and reports to it after
  runs — campaign mechanics (waiting, resuming, requeueing) never depend on it.
- Logs go to `ledger.log` next to the repo scripts.
