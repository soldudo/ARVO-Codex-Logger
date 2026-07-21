# Experiment Campaign Runner — Proposal

> **Status:** Phases 1 and 2 are implemented in `run_experiments.py`. See
> `RUN_EXPERIMENTS.md` for as-built documentation and usage instructions; this
> document is kept as the original design rationale. Phase 3 (random selection)
> was superseded by multi-machine, coverage-driven gap-fill selection backed by
> a shared git ledger — see `LEDGER.md`.

A replacement for `experiments.py` that runs batches of CARO experiments with durable
progress tracking, flexible vulnerability selection, and automatic detection/resume of
runs cut short by Claude usage limits.

## 1. Limitations of the current approach

`experiments.py` today:

- Hardcodes three parallel lists (`experiment_list`, `run_list`, `context_list`) that must
  be kept in sync by hand.
- Mutates the shared `experiment_setup.json` in place, so a crash mid-batch leaves the
  file in whatever state the last iteration wrote.
- Has no record of which vulns have been attempted — re-running the script re-runs
  everything.
- Treats every non-zero exit the same. In practice `caro.py` exits 0 even when the agent
  run failed (exceptions are caught and logged), so `subprocess.run(check=True)` catches
  almost nothing.
- Has no awareness of usage limits. A limit hit mid-batch burns through the remaining
  vulns, producing a string of 1-turn junk runs (visible in the DB: several runs with
  `result = "You've hit your limit · resets 7pm (UTC)"`, `num_turns = 1`).

## 2. Design overview

A single CLI script, `run_experiments.py`, with subcommands, backed by two new tables in
`arvo_loc_runs.db`. State lives in the DB (same place as everything else), not in the
script, so the runner can be killed and restarted at any point without losing progress.

```
run_experiments.py
├── enqueue   create a campaign: experiment_tag + list of vuln ids (explicit or random)
├── run       work through pending items serially; classify outcomes; wait/resume on limits
├── status    show campaign progress (pending / running / complete / usage_limited / error)
├── requeue   reset error/skipped items back to pending
└── list      list campaigns
```

A **campaign** is one batch: an `experiment_tag` (which selects prompt template +
markdowns via the existing `experiments` table), a base config (mode flags, container,
agent), and a set of vuln ids. Run variations are just new campaigns with a different
tag — nothing else changes.

Key mechanism decisions:

- **Per-run config files, not `experiment_setup.json`.** `caro.py` already accepts
  `--config <path>`. The runner writes a generated config to
  `runs/campaign_<tag>/config_<vuln_id>.json` per item and passes it explicitly.
  `experiment_setup.json` stays untouched for manual one-off runs.
- **`caro.py` stays a subprocess.** It calls `sys.exit`, reconfigures root logging, and
  truncates `caro.log` (`mode='w'`) — importing it would fight the runner. Subprocess
  isolation also means a hard crash in one item can't take down the batch.
- **Outcomes are classified from the DB, not the exit code.** After each `caro.py`
  invocation the runner queries the `runs` table for rows created for that vuln since the
  item started, and classifies from `result_error_flag` / `result` / row absence.

## 3. Schema additions

```sql
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_tag   TEXT UNIQUE NOT NULL,          -- e.g. 'baseline-jul02'
    experiment_id  INTEGER NOT NULL REFERENCES experiments(experiment_id),
    base_config    TEXT NOT NULL,                 -- JSON: is_loc_mode, is_patch_mode, container_name, agent
    selection_desc TEXT,                          -- how ids were chosen (filters, seed) for reproducibility
    created_at     TEXT
);

CREATE TABLE IF NOT EXISTS campaign_items (
    item_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id      INTEGER NOT NULL REFERENCES campaigns(campaign_id),
    vuln_id          INTEGER NOT NULL REFERENCES arvo(localId),
    status           TEXT NOT NULL DEFAULT 'pending',
                     -- pending | running | complete | usage_limited | error | skipped
    attempts         INTEGER NOT NULL DEFAULT 0,
    run_id           TEXT,                        -- latest run row produced for this item
    session_id       TEXT,                        -- agent session, for --resume
    limited_stage    TEXT,                        -- 'loc' or 'patch': which run hit the limit
    resume_after     TEXT,                        -- ISO UTC time parsed from the limit message
    config_overrides TEXT,                        -- optional JSON merged into generated config
    last_error       TEXT,
    updated_at       TEXT,
    UNIQUE (campaign_id, vuln_id)
);
```

State machine per item:

```
pending ──run──> running ──┬─> complete
                           ├─> usage_limited ──(resume_after passes)──> running ...
                           └─> error ──(requeue)──> pending
```

`config_overrides` covers per-item variation without new columns — e.g. a per-vuln
`loc_run_id` for patch-with-known-localization campaigns, or `additional_context`
(what the old `context_list` did).

## 4. Vulnerability selection

`enqueue` accepts either an explicit list or a random sample drawn from the `arvo` table:

```
# explicit
python run_experiments.py enqueue --campaign baseline-jul02 \
    --experiment-tag baseline-patch-envmd --patch-mode \
    --ids 42531212 42531502 437162340 419085594

# or from a file (one id per line)
python run_experiments.py enqueue ... --ids-file ids.txt

# random with filters
python run_experiments.py enqueue --campaign baseline-ndpi-sample \
    --experiment-tag baseline-patch-envmd --patch-mode \
    --random 20 --project ndpi --id-min 42000000 --id-max 43000000 \
    --crash-type "Heap-buffer-overflow" --language c \
    --reproduced-only --exclude-attempted --seed 7
```

Filter flags map directly to `arvo` columns: `--project` (repeatable),
`--id-min`/`--id-max` (`localId`), `--crash-type` (substring match), `--language`,
`--reproduced-only` (`reproduced = 1`), `--verified-only` (`verified = 1`).

- `--exclude-attempted` joins against `runs` and excludes any vuln that already has a run
  under the same `experiment_tag` — this is what makes "run the baselines I haven't run
  yet" a one-liner.
- `--seed` makes the sample reproducible; the seed and all filters are stored in
  `campaigns.selection_desc`.
- `--dry-run` prints the selected ids (with project/crash_type) without enqueueing.

Selection is a single parameterized query, roughly:

```sql
SELECT localId FROM arvo
WHERE (:project IS NULL OR project IN (...))
  AND localId BETWEEN :id_min AND :id_max
  AND (:crash_type IS NULL OR crash_type LIKE '%' || :crash_type || '%')
  AND reproduced = 1                              -- if --reproduced-only
  AND localId NOT IN (
      SELECT vuln_id FROM runs r
      JOIN experiments e ON r.experiment_id = e.experiment_id
      WHERE e.experiment_tag = :tag)              -- if --exclude-attempted
ORDER BY RANDOM()  -- seeded in Python instead: fetch matching ids, random.Random(seed).sample()
LIMIT :n
```

(Seeding happens in Python — SQLite's `RANDOM()` can't be seeded — by fetching matching
ids and sampling with `random.Random(seed)`.)

## 5. Execution loop

```
python run_experiments.py run --campaign baseline-jul02 [--max-runs N] [--no-wait] [--max-attempts 3]
```

Pseudocode:

```python
while True:
    item = next_runnable_item(campaign)   # pending, or usage_limited with resume_after <= now
    if item is None:
        if remaining_limited := earliest_resume_after(campaign):
            if no_wait: exit_with_status()
            sleep_until(remaining_limited + BUFFER)   # logged; BUFFER ≈ 5 min
            continue
        break                                          # campaign finished

    config = build_config(campaign, item)              # base_config + overrides (+ resume fields)
    config_path = write_config(config, item)
    mark(item, 'running'); started_at = utcnow()

    subprocess.run([sys.executable, 'caro.py', '--config', str(config_path)],
                   cwd=REPO_ROOT, timeout=RUN_TIMEOUT)

    outcome = classify(item.vuln_id, started_at)       # from the runs table, section 6
    apply(item, outcome)
```

Notes:

- **Strictly serial.** `conduct_run` uses fixed container names (`rootainer`,
  `vulnscan`) and `caro.log` is a shared file, so only one experiment can run at a time.
  Parallelism would require per-run container names — out of scope here.
- `--max-runs N` caps how many items execute in this invocation (useful for pacing
  against the usage budget).
- `RUN_TIMEOUT` (e.g., 2 h, configurable) guards against a hung agent/docker exec; on
  timeout the item is marked `error` with `last_error='timeout'`.
- Every status change updates `campaign_items` immediately, so `Ctrl+C` at any point
  loses at most the in-flight run, which `requeue` (or classification on next start —
  items stuck in `running` are re-classified) recovers.

## 6. Outcome classification

After `caro.py` returns, query the runs it produced:

```sql
SELECT run_id, run_mode, result, result_error_flag, session_id, num_turns
FROM runs
WHERE vuln_id = ? AND timestamp >= ?      -- item start time
ORDER BY timestamp
```

Classification rules, in order:

1. **No rows** → `error` (caro/docker failed before an agent run was recorded; stderr
   from the subprocess is saved to `last_error`).
2. **Any row with `result_error_flag = 1` and `result` matching the limit pattern** →
   `usage_limited`. Store that row's `session_id`, `run_mode` (as `limited_stage`), and
   the parsed reset time (section 7).
3. **Any row with `result_error_flag = 1`** (non-limit error) → `error`.
4. **Otherwise** → `complete`, store the final `run_id`.

The observed limit signature in the DB (8 existing runs) is consistent:
`result_type='success'`, `result_error_flag=1`, `return_code=1`, and
`result = "You've hit your limit · resets 7pm (UTC)"` (hour and am/pm vary).

For loc+patch campaigns, rule 2 distinguishes which stage was cut off via the run row's
`run_mode` — if the loc run hit the limit, the subsequent patch run in the same caro
invocation will also appear as a 1-turn limited row; the *earliest* limited row wins and
determines the resume strategy.

## 7. Usage-limit detection and auto-resume

**Parsing the reset time.** The result text is matched with:

```python
LIMIT_RE = re.compile(r"hit your limit.*?resets\s+(\d{1,2})(?::(\d{2}))?\s*(am|pm)\s*\((UTC)\)",
                      re.IGNORECASE)
```

The hour is projected to the next occurrence of that wall-clock time in UTC (if it's
already past, add a day), plus a small buffer. If the message format ever changes and
parsing fails, fall back to a fixed retry interval (default 30 min) — bounded by
`--max-attempts` so a persistent failure can't loop forever.

**Resuming.** The existing plumbing already supports this end to end:

- `runs.session_id` stores the agent session for every run.
- `caro.py` honors `is_resume` / `resume_id` in its config and sends
  `claude --resume <session_id>` with the prompt "continue where you left off".

The runner builds the resume config from `limited_stage`:

| limited stage | resume config |
|---|---|
| `patch` | `is_loc_mode=false, is_patch_mode=true, is_resume=true, resume_id=<session>` (skip re-localization; the conversation already has the loc context) |
| `loc` | original mode flags + `is_resume=true, resume_id=<session>` — caro already handles resume-loc-then-fresh-patch (it flips `is_resume` off after the loc run and chains the patch run on the new loc result) |

The resumed run gets a **new** `run_id` (caro generates it from the current timestamp),
so the DB keeps both the truncated and the resumed run. They are linkable via
`session_id`; the campaign item's `run_id` is updated to the resumed run, and analysis
scripts that count runs per experiment should be aware truncated rows exist (they are
identifiable by `result_error_flag=1` + the limit message, so they're easy to filter).

**Wait behavior.** Default is to sleep in-process until the earliest `resume_after`
across the campaign, logging the wake time, then continue. `--no-wait` instead exits
after marking items, printing when to re-invoke — the same `run` command picks up
exactly where it left off, so this composes with Task Scheduler / cron if preferred.

**Caveats to verify (flagged, not blocking):**

1. `claude --resume` inside `rootainer` requires the session file to still exist in the
   container's `~/.claude` and the working directory to match. `rootainer` is persistent
   so this should hold, but it should be confirmed with one manual resume before trusting
   the automation. (The existing `is_resume` config flag suggests this has been done
   manually already.)
2. Resume restores the **conversation**, not the workspace: `cleanup_dind('vulnscan')`
   at the end of `conduct_run` destroys the ARVO container, and `standby_dind` recreates
   it fresh on resume. Any edits the agent made inside `vulnscan` before the limit are
   gone. For patch runs that emit the diff in the final message this is usually
   recoverable (the agent re-applies its plan), but it can confuse the agent — worth
   watching in the first resumed runs.
3. A limit hit mid-run wastes the truncated run's tokens. An optional `--probe` flag
   could fire a minimal `claude -p "ok"` before each item and pre-emptively wait if the
   limit is already exhausted — cheap insurance when running near the budget edge.

## 8. Changes required to existing code

Almost none — that's the point of the design:

- `caro.py`: **no changes required.** (`--config` already exists.) One optional
  quality-of-life change: accept a `run_id` in the config so the runner knows the run id
  a priori instead of inferring it from `vuln_id + timestamp`. The timestamp query is
  reliable under serial execution, so this is optional.
- `queries.py`: add small helpers — `get_runs_for_vuln_since(vuln_id, ts)`,
  campaign/item CRUD. Table creation follows the `init_db()` pattern in `run_parser.py`
  (`CREATE TABLE IF NOT EXISTS`, so existing DBs upgrade transparently).
- `experiments.py`: retired (kept until the new runner has completed one real campaign).

## 9. Constraints and open questions

- **Serial only** (shared container names + shared `caro.log`). Fine for usage-limited
  workloads anyway — parallel runs would just hit the limit faster.
- **Reset-time format**: the parser handles `resets <h>(am|pm) (UTC)`; a minutes
  component is tolerated. If Anthropic changes the wording, the fixed-interval fallback
  keeps the campaign alive.
- **Multiple campaigns**: nothing prevents interleaving campaigns, but only one `run`
  process should execute at a time (enforced with a simple lockfile).
- Should truncated (usage-limited) run rows be tagged, e.g. a `superseded_by` column on
  `runs`, so evaluation scripts can exclude them mechanically instead of by result-text
  matching? Cheap to add while we're touching the schema — recommended.

## 10. Implementation plan

1. **Phase 1 — queue + serial runner** (core value): schema, `enqueue --ids`, `run`
   with DB-based outcome classification, `status`, `requeue`. Usage-limited items are
   detected and marked but the runner just exits (`--no-wait` behavior only).
2. **Phase 2 — auto-resume**: reset-time parsing, in-process wait, resume-config
   generation, `--max-attempts`. Verify one manual `--resume` in `rootainer` first
   (caveat 7.1).
3. **Phase 3 — random selection**: `--random` + filter flags + `--exclude-attempted` +
   `--seed` + `--dry-run`.

Phase 1 alone already replaces `experiments.py` with something restartable; phases 2–3
are independent of each other and can land in either order.
