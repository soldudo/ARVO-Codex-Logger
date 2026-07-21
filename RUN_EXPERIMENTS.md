# run_experiments.py — Campaign Experiment Runner

`run_experiments.py` runs batches of CARO experiments with durable progress tracking,
automatic usage-limit detection, and automatic wait-and-resume of runs that were cut
off mid-session. It replaces the ad-hoc list-based runners (`experiments.py`,
`proto_run_experiments.py`).

This document describes the implementation as built (phases 1 and 2 of
`EXPERIMENT_RUNNER_PROPOSAL.md`). Random vulnerability selection (phase 3) is not yet
implemented.

Tests: `test_run_experiments.py` (`python -m pytest test_run_experiments.py`).

---

## Quick start

```bash
# 1. Create a campaign: pick an experiment_tag and the vulns to run
python run_experiments.py enqueue --campaign baseline-jul12 \
    --experiment-tag baseline-patch-envmd --patch-mode \
    --ids 42531212 42531502 437162340 419085594

# 2. Run it (waits out usage-limit resets and resumes automatically)
python run_experiments.py run --campaign baseline-jul12

# 3. Check progress (from another terminal, any time)
python run_experiments.py status --campaign baseline-jul12

# 4. Retry anything that errored
python run_experiments.py requeue --campaign baseline-jul12 --status error
python run_experiments.py run --campaign baseline-jul12
```

The runner is safe to kill and restart at any point: all state lives in
`arvo_loc_runs.db`, and re-invoking `run` continues exactly where it left off.

---

## Concepts

### Campaign

A **campaign** is one batch of experiments: an `experiment_tag` (which selects the
prompt template and agent markdowns via the existing `experiments` table), a base
config (mode flags, container, agent), and a set of arvo vulnerability ids. Run
variations are just new campaigns with a different tag — nothing else changes.

### Items and the status state machine

Each vulnerability in a campaign is an **item** with a status:

```
pending ──run──> running ──┬─> complete
                           ├─> usage_limited ──(reset time passes)──> running ...
                           │        └─(attempts >= --max-attempts)──> error
                           └─> error ──(requeue)──> pending
```

| status | meaning |
|---|---|
| `pending` | not yet attempted (or requeued) |
| `running` | a caro.py subprocess is executing it right now |
| `complete` | all runs finished without an error flag; `run_id` points at the final run |
| `usage_limited` | the agent run was cut off by a Claude usage limit; will auto-resume |
| `error` | caro/docker failed, the agent errored, the run timed out, or retries were exhausted |
| `skipped` | reserved for manual bookkeeping (nothing sets it automatically) |

### Design decisions that shape everything else

- **State lives in the database**, in two new tables (`campaigns`, `campaign_items`)
  in `arvo_loc_runs.db`, next to the `runs` data itself. The tables are created on
  first use (`CREATE TABLE IF NOT EXISTS`); no migration step is needed.
- **`caro.py` runs as a subprocess with a generated per-item config** passed via its
  existing `--config` flag. The shared `experiment_setup.json` is never touched, so
  manual one-off runs keep working unchanged. `caro.py` itself required no changes.
- **Outcomes are classified from the `runs` table, not exit codes.** caro exits 0
  even when the agent run fails (it catches and logs exceptions), so after each
  invocation the runner queries the run rows created for that vuln since the item
  started and classifies from `result_error_flag` / `result` text.
- **Execution is strictly serial.** caro uses fixed container names (`rootainer`,
  `vulnscan`) and a shared `caro.log`, so only one experiment can run at a time. A
  lockfile (`runs/.run_experiments.lock`) prevents accidentally starting two runners.

---

## Command reference

### `enqueue` — create a campaign / add items

```bash
python run_experiments.py enqueue --campaign <tag> --experiment-tag <tag> \
    (--ids <id> [<id> ...] | --ids-file <path>) \
    [--loc-mode] [--patch-mode] [--container rootainer] [--agent claude] [--append]
```

| flag | meaning |
|---|---|
| `--campaign` | campaign tag, e.g. `baseline-jul12` (unique; reused with `--append`) |
| `--experiment-tag` | must exist in the `experiments` table (validated); fixed at creation |
| `--ids` | arvo vulnerability ids, space-separated |
| `--ids-file` | file with one id per line; `#` comments and blank lines are ignored |
| `--loc-mode` / `--patch-mode` | at least one required; stored in the campaign's base config |
| `--container` | docker container caro should exec into (default `rootainer`) |
| `--agent` | coding agent (default `claude`) |
| `--append` | add ids to an existing campaign instead of failing |

Behavior notes:

- Ids not present in the `arvo` table are reported and skipped; ids already in the
  campaign are silently deduplicated. Both are safe to re-run.
- The mode flags, container, and agent are stored once per campaign and copied into
  every generated config. To run the same vulns with different settings, make a new
  campaign.
- `campaign_items.config_overrides` (a JSON column merged into the generated config
  per item) exists for per-item variation — e.g. a per-vuln `loc_run_id` or
  `additional_context` — but currently has no CLI; set it with SQL if needed.
  `experiment_tag` and `arvo_id` can never be overridden.

### `run` — execute the campaign

```bash
python run_experiments.py run --campaign <tag> \
    [--max-runs N] [--run-timeout 5400] [--no-wait] [--max-attempts 2]
```

| flag | meaning |
|---|---|
| `--max-runs N` | stop after N caro invocations this session (resumes count) — useful for pacing against the usage budget |
| `--run-timeout` | per-run timeout in seconds (default 5400 = 1.5 h); a hung run is killed and marked `error` |
| `--no-wait` | when a usage limit blocks progress, exit instead of sleeping until the reset |
| `--max-attempts` | give up on an item after this many usage-limited attempts (default 2); it is marked `error` |

Each loop iteration decides one of three things:

1. **Run something.** Usage-limited items whose reset time has passed are resumed
   *first* (they're partially done); then pending items, in enqueue order.
2. **Wait.** If any item is usage-limited with a reset still in the future, the
   runner sleeps until the earliest reset + a 5-minute buffer — including holding
   back pending items, because the limit is account-wide and running them would only
   burn no-op runs. With `--no-wait` it exits here instead, printing when to re-run.
3. **Done.** No runnable or waiting items remain; final status counts are logged.

For every executed item the runner writes a config to
`runs/campaign_<tag>/config_<vuln_id>.json` (resume attempts get
`config_<vuln_id>_attempt<N>.json` so earlier configs stay inspectable), marks the
item `running`, invokes `python caro.py --config <path>` (caro's live output stays
on your terminal), then classifies the outcome:

| observation in `runs` table | item status |
|---|---|
| no rows recorded | `error` (caro/docker failed before an agent run; stderr tail saved to `last_error`) |
| a row with `result_error_flag=1` and "hit your limit" in `result` | `usage_limited` (earliest such row wins; its `session_id`, `run_mode`, and parsed reset time are stored) |
| a row with `result_error_flag=1` (anything else) | `error` |
| otherwise | `complete` (`run_id` = last run of the invocation, e.g. the patch run of a loc+patch pair) |

Startup housekeeping: items left in `running` by a previously killed runner are
re-classified from the runs table before anything executes, so an interrupted
session self-heals on the next `run`.

### `status` — show campaign progress

```bash
python run_experiments.py status --campaign <tag>
```

Prints the campaign's base config, status counts, and a per-item table: vuln id,
status, attempt count, latest `run_id`, and a detail column (the resume time for
usage-limited items, the last error otherwise). Read-only; safe while a runner is
active.

### `requeue` — reset items back to pending

```bash
python run_experiments.py requeue --campaign <tag> \
    [--status error usage_limited ...] [--ids <id> ...]
```

Resets items in the given statuses (default: `error`) back to `pending`, clearing
`last_error` and any stale resume bookkeeping (`limited_stage`, `resume_after`) so
they run fresh. `--ids` limits the reset to specific vulns. Note a requeued
usage-limited item will **not** resume its old session — it starts over; the
automatic resume path only applies while the item is still in `usage_limited`.

### `list` — list all campaigns

```bash
python run_experiments.py list
```

One row per campaign: tag, experiment tag, creation time, and total/complete/pending
item counts.

---

## Usage-limit handling and auto-resume

This is the core phase-2 machinery, end to end:

1. **Detection.** A limited run is recognizable in the `runs` table by
   `result_error_flag=1` and a result like
   `You've hit your limit · resets 7pm (UTC)` (observed consistently across all
   historical limited runs).
2. **Reset-time parsing.** `resets <h>[:<mm>] <am|pm> (UTC)` is parsed and projected
   to the next occurrence of that wall-clock time in UTC, stored in
   `campaign_items.resume_after`. If the message format ever changes and parsing
   fails, the runner falls back to retrying after 30 minutes
   (`FALLBACK_RETRY_SECONDS`).
3. **Waiting.** The runner sleeps until `resume_after` + 300 s
   (`RESUME_BUFFER_SECONDS`), logging the wake time. Ctrl+C during the wait is safe —
   state is already persisted, and re-running the same `run` command re-enters the
   wait (or resumes immediately if the reset has passed).
4. **Resuming.** Every run's agent `session_id` is already stored in the `runs`
   table, and caro's config supports `is_resume` / `resume_id` (mapping to
   `claude --resume <session_id>` with the prompt "continue where you left off").
   The resume config depends on which stage was cut off (`limited_stage`, taken from
   the limited run's `run_mode`):

   | cut-off stage | generated resume config |
   |---|---|
   | `patch` | `is_loc_mode=false`, `is_patch_mode=true`, `is_resume=true`, `resume_id=<session>` — the localization already lives in the resumed conversation, so it is not redone |
   | `loc` | original mode flags + `is_resume=true`, `resume_id=<session>` — caro resumes the loc session, then chains a fresh patch run on the new loc result (existing caro behavior) |

   If no `session_id` was recorded for the limited run, the item reruns from scratch
   with a warning.
5. **Bounding.** Each caro invocation increments the item's `attempts`. An item still
   usage-limited after `--max-attempts` attempts is marked `error`
   (`"usage-limited; exceeded max attempts (N)"`) so a persistent failure can't loop
   forever.

The truncated run row and the resumed run row **both remain in the `runs` table**
(caro assigns each invocation a fresh `run_id`). They share a `session_id`; the
campaign item's `run_id` points at the resumed/final run. Truncated rows are
identifiable by `result_error_flag=1` + the limit message — evaluation scripts
should filter them.

### Caveats to know about

- Resume restores the **conversation, not the workspace**: `conduct_run` destroys
  the `vulnscan` container at the end of every run, so any edits the agent made
  before the cutoff are gone and the agent must re-apply its plan. Usually
  recoverable, but worth watching in the first resumed runs.
- `claude --resume` requires the session file to still exist inside `rootainer`
  (its `~/.claude` state). `rootainer` is persistent so this should hold, but verify
  one manual resume before trusting an unattended overnight campaign.

---

## Database schema

Both tables live in `arvo_loc_runs.db` and are created automatically on first use.

```sql
CREATE TABLE campaigns (
    campaign_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_tag   TEXT UNIQUE NOT NULL,
    experiment_id  INTEGER NOT NULL REFERENCES experiments(experiment_id),
    base_config    TEXT NOT NULL,     -- JSON: is_loc_mode, is_patch_mode, container_name, agent
    selection_desc TEXT,              -- reserved for phase 3 (random-selection provenance)
    created_at     TEXT
);

CREATE TABLE campaign_items (
    item_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id      INTEGER NOT NULL REFERENCES campaigns(campaign_id),
    vuln_id          INTEGER NOT NULL REFERENCES arvo(localId),
    status           TEXT NOT NULL DEFAULT 'pending',
    attempts         INTEGER NOT NULL DEFAULT 0,   -- caro invocations, incl. resumes
    run_id           TEXT,             -- latest run row produced for this item
    session_id       TEXT,             -- agent session, used for --resume
    limited_stage    TEXT,             -- 'loc' or 'patch': which run hit the limit
    resume_after     TEXT,             -- ISO UTC time to retry after
    config_overrides TEXT,             -- optional JSON merged into the generated config
    last_error       TEXT,
    started_at       TEXT,             -- when the current/last attempt began
    updated_at       TEXT,
    UNIQUE (campaign_id, vuln_id)
);
```

## Files the runner produces

| path | contents |
|---|---|
| `runs/campaign_<tag>/config_<vuln>.json` | generated caro config for the first attempt |
| `runs/campaign_<tag>/config_<vuln>_attempt<N>.json` | config for resume/retry attempt N |
| `runs/.run_experiments.lock` | holds the runner's PID while `run` is active; deleted on exit. If a runner was killed hard and the lock is stale, delete it by hand (the error message says so) |
| `run_experiments.log` | append-mode log of everything the runner did (also echoed to stdout) |

Individual agent run logs continue to land where caro puts them
(`runs/<run_id>/agent_<run_id>.log`), unchanged.

## Recovery cheat-sheet

| situation | what to do |
|---|---|
| runner killed mid-run (Ctrl+C, reboot) | just re-run `run` — stale `running` items are re-classified from the runs table on startup |
| "Another runner appears to be active" but none is | delete `runs/.run_experiments.lock` |
| items stuck in `error` | inspect with `status`, fix the cause, `requeue --status error`, re-run |
| limit hit while using `--no-wait` | re-run `run` after the printed reset time — the limited item resumes automatically |
| item exhausted `--max-attempts` | it's in `error`; `requeue` it to start that vuln over from scratch |
| want to re-run a completed vuln under the same experiment | `requeue --status complete --ids <id>` (the old run rows remain in `runs`) |

## Multi-machine coverage and gap-fill enqueueing

When several researchers run experiments on separate machines with separate DBs,
the git-backed **ledger** (`ledger.py`, documented in `LEDGER.md`) shares minimal
run facts so the team can see combined coverage and queue unrun experiments:

- `enqueue --fill-gaps N` selects up to N vulns that no machine has successfully
  run under the campaign's experiment_tag, filtered by `--project`, `--id-min/max`,
  `--reproduced-only`, sampled reproducibly with `--seed`, and claims them in the
  ledger so other machines skip them (`--retry-failed` re-attempts failed-only cells).
- `run` reports each item's outcome to the ledger automatically when
  `CARO_LEDGER_DIR` is set or `--ledger-dir` is passed; ledger failures never
  interrupt a campaign.

## Limitations / not yet implemented

- **Coverage-blind random selection** (the proposal's phase-3 `--random N`) was
  superseded by ledger-driven `--fill-gaps`, which does filtered, seeded sampling
  restricted to *unrun* vulns. There is no way to random-sample while ignoring
  coverage; if that's ever wanted, sample against an empty ledger.
- **No parallelism** — inherent to caro's fixed container names; also mostly
  pointless under a shared usage limit.
- **No CLI for `config_overrides`** — the column is honored when populated, but
  setting it currently requires SQL.
- Truncated (usage-limited) run rows are not tagged in the `runs` table itself;
  evaluation scripts must filter them by `result_error_flag=1` + the limit message.
