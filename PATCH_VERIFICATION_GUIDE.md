# Patch Verification — Setup & Usage

Preparing a project that predates the `patch_verification` work, and running the
first verification on it. Design rationale lives in
`PATCH_VERIFICATION_PROPOSAL.md`; this is the operational side.

`diff_tools.py` takes one patch run, applies its diff to a fresh ARVO container,
recompiles, re-runs the POC, and records every stage to `patch_verification` so the
verdict is auditable afterwards.

---

## Prerequisites

| requirement | check | notes |
|---|---|---|
| Python 3.9+ | `python -c "import sys; print(sys.version)"` | builtin generics in annotations |
| no pip installs | — | the import chain is **stdlib only**; `pytest` is needed for the tests, nothing else |
| host docker | `docker ps` | see the warning below |
| `arvo_loc_runs.db` in the repo root | `ls arvo_loc_runs.db` | `DB_PATH` is relative, so **always run from the repo root** |
| disk headroom | `docker system df` | tens of GB per ffmpeg run; see Disk below |

> **`diff_tools.py` uses host docker directly, not the rootainer.**
> `standby_container` runs `docker run` on the host, while the campaign runner uses
> `standby_dind` inside `rootainer`. Two consequences: `docker` must work for the
> user invoking `diff_tools.py`, and the image pruning that keeps rootainer's
> storage in check **does not protect this path**. Watch host disk yourself.

---

## One-time setup

### 1. Get the code

```bash
cd ~/repos/ARVO-Codex-Logger
git pull
```

You need `diff_tools.py`, `schema.py`, `queries.py`, `run_parser.py`,
`patch_verification_upgrade.py` and `test_diff_tools.py` at their current versions.
`diff_tools_updated.py`, if present, is superseded — the workflow below is all in
`diff_tools.py`.

### 2. Migrate the database

Dry run first. It creates nothing and reports what the backfill would copy:

```bash
python patch_verification_upgrade.py --dry-run
```

Then for real:

```bash
python patch_verification_upgrade.py
```

Expect, on a database with existing adjudicated runs:

```
INFO - patch_verification table and index present
INFO - backfill: inserted 22 legacy rows as attempt=0
INFO - patch_verification rows: 22 {0: 22}
```

The migration is additive and rerunnable — `CREATE TABLE IF NOT EXISTS` plus a
backfill guarded on `(run_id, attempt=0)`. Running it twice is safe and reports
`backfill: nothing to do`. Nothing existing is dropped or altered, so the rollback
is `DROP TABLE patch_verification`.

Options: `--no-backfill` creates the table without copying legacy verdicts; `--db`
points at a different file.

**On a fresh database** with no `runs` table yet, use `init_db()` instead — it now
creates `patch_verification` along with everything else:

```bash
python -c "import run_parser; run_parser.init_db()"
```

Running the migration on a fresh database also works (it creates the table and logs
`backfill: no patch_data table, skipping`), but `init_db()` is the right entry
point. Either way, note that neither creates the **`arvo`** table — that is the
imported ARVO corpus, and `diff_tools.py` reads the project, crash type and
baseline log from it. A fresh database has the verification table but nothing to
verify until the corpus and some patch runs exist.

### 3. Verify the install

```bash
python -m pytest test_diff_tools.py -q        # expect: 26 passed
python diff_tools.py --help
```

Confirm the table and the backfill landed:

```bash
python - <<'EOF'
import sqlite3
c = sqlite3.connect('arvo_loc_runs.db')
print('columns:', len(c.execute('PRAGMA table_info(patch_verification)').fetchall()))
print('rows by attempt:', dict(c.execute(
    'SELECT attempt, COUNT(*) FROM patch_verification GROUP BY attempt')))
print('patch_data rows (must be unchanged):',
      c.execute('SELECT COUNT(*) FROM patch_data').fetchone()[0])
EOF
```

38 columns, `{0: <your adjudicated count>}`, and `patch_data` untouched.

Four test modules are already broken on `main` for reasons unrelated to this work,
and will keep failing — don't chase them. `test_queries.py`, `caro_inject_test.py`
and `test_agent_tools.py` import `get_crash_log` / `insert_crash_log`, which no
longer exist in `queries.py`; `test_experiments.py` calls `run_experiment_list`
with 2 of its 4 arguments. Run the rest as:

```bash
python -m pytest -q --ignore=test_queries.py --ignore=caro_inject_test.py \
    --ignore=test_agent_tools.py --ignore=test_experiments.py
```

Expect `81 passed`.

---

## Calibrate before the first real batch

**For ffmpeg this is already done** — the shipped defaults are measurement-backed:

| | measured (2 ffmpeg runs) | shipped default |
|---|---|---|
| `compile_duration_s` | 930, 932 | `--compile-timeout 3600` (3.9× headroom) |
| `compile_log_bytes` | 1,955,662 (1.87 MiB) | extract budget 256 KiB, full log on disk |

So you can go straight to a batch on ffmpeg. `arvo compile` still rebuilds **every**
decoder fuzzer in the project — 435 of them — because the narrowed build is
unverified (see the proposal's Deferred section); 932 s is what that costs.

Re-measure when you first verify a **project other than ffmpeg**, since nothing
here has been measured for libxml2, php-src, mruby and the rest. Pick any ready run
in that project and watch it:

```bash
python diff_tools.py --patch-run-id <a-ready-run-in-that-project> 2>&1 | tee calibrate.log
```

Progress is logged once a minute during the compile. When it finishes:

```bash
python - <<'EOF'
import sqlite3
c = sqlite3.connect('arvo_loc_runs.db'); c.row_factory = sqlite3.Row
r = c.execute('SELECT * FROM patch_verification ORDER BY verification_id DESC '
              'LIMIT 1').fetchone()
print('compile seconds :', r['compile_duration_s'])
print('compile log MiB :', round((r['compile_log_bytes'] or 0) / 1048576, 1))
print('log path        :', r['compile_log_path'])
EOF
```

Set `--compile-timeout` to roughly 3-4× the observed wall time, matching the ffmpeg
margin above. The `EXTRACT_*` constants need no adjustment for size — the full log
goes to disk and is fed to the LLM whole; the bounded extract is only the queryable
summary kept in the database.

### Disk

An ffmpeg rebuild materialises ~435 ASAN binaries at roughly 50–100 MB each.
Before a batch:

```bash
docker system df
docker exec <container> df -h /src /out     # during a run
```

A build that dies on `No space left on device` sets `compile_rc != 0`, and the run
stops before the POC rather than adjudicating a broken build — but you lose the
run, so check first.

---

## Usage

### Pick a run

The ready queue — completed runs that produced a diff and have no verdict:

```bash
python - <<'EOF'
import sqlite3
c = sqlite3.connect('arvo_loc_runs.db')
rows = c.execute('''
    SELECT r.run_id, a.project
    FROM runs r
    JOIN patch_data p ON p.run_id = r.run_id
    LEFT JOIN arvo a ON a.localId = r.vuln_id
    WHERE r.run_mode = 'patch' AND r.result_error_flag = 0
      AND r.result_json GLOB '*diff*' AND p.is_crash_resolved IS NULL
    ORDER BY a.project, r.run_id
''').fetchall()
print(len(rows), 'ready')
for run_id, project in rows[:10]:
    print(f'  {run_id}  {project}')
EOF
```

`RUN_DATA_MAP.md` has the same queue split by priority — P1 and P2 are the two arms
of the headline comparison, so those are the ones that unblock a result.

### Run it

```bash
python diff_tools.py --patch-run-id arvo-42540891-vul-1784232900-patch
```

| flag | default | |
|---|---|---|
| `--patch-run-id` | required | the run to verify |
| `--compile-timeout` | 3600 | seconds; raise for a slow project |
| `--poc-timeout` | 120 | seconds |

Output goes to both the terminal and `diff_tools.log`. The stages, in order:

1. **Baseline** — reads `arvo.crash_output`. Not re-executed; re-running `arvo` to
   regenerate it can itself break the build being tested.
2. **Apply** — each patch entry is recounted, its strip level derived from its
   headers, dry-run, then applied. Stops before the compile if anything fails.
3. **Compile** — `arvo compile`, streamed to `runs/<run_id>/compile_<id>.log`.
   Stops if `compile_rc != 0`, because a POC result after a failed compile does not
   reflect the patched code.
4. **POC** — re-runs `arvo`, then hands you the adjudication menu.

### Adjudicating

```
[r]e-run  |  [c]lassify  |  [q]uit:
```

- `r` re-runs the POC and replaces what will be stored, so the output you judge is
  the output that gets recorded.
- `c` then asks `[s]uccess` / `[u]nsuccessful` / `[b]ack`, then offers an optional
  free-text note.
- `q` exits without a verdict. The attempt is still fully recorded — everything
  except `is_crash_resolved` — so quitting costs you the classification, not the
  evidence.

### What gets written

Each stage is committed as it completes, so a run killed mid-compile still leaves
its baseline and patch-application evidence. One `patch_verification` row per
attempt, plus a mirror into `patch_data` (`is_crash_resolved`, `patch_crash_log`,
`compile_errors`) so `analysis/patch_eval.py` and `analysis/command_analysis.py`
keep working unchanged.

---

## Reading results back

```bash
python - <<'EOF'
from queries import get_patch_verification
r = get_patch_verification('arvo-42540891-vul-1784232900-patch')
for k in ('attempt', 'patch_rc', 'patch_recounted', 'patch_strip',
          'patch_hunks_ok', 'patch_hunks_failed', 'patch_max_fuzz',
          'compile_rc', 'compile_duration_s', 'compile_timed_out',
          'poc_rc', 'is_crash_resolved', 'adjudicated_at'):
    print(f'{k:22} {r[k]}')
print('compile log:', r['compile_log_path'])
EOF
```

Three fields decide whether a verdict is trustworthy:

| field | meaning |
|---|---|
| `compile_rc` | must be `0`. Anything else and the POC ran against a stale build. |
| `patch_max_fuzz` | `0` means every context line was verified. `1`–`2` means that many were discarded — the patch may have landed slightly off. |
| `patch_recounted` | headers this run had to rewrite. Non-zero means the agent's diff was malformed and would have failed, or silently applied truncated, before this change. |

A quick audit across everything verified so far:

```sql
SELECT run_id, attempt, compile_rc, patch_max_fuzz, patch_recounted,
       poc_rc, is_crash_resolved
FROM patch_verification WHERE attempt > 0 ORDER BY run_id, attempt;
```

`attempt = 0` rows are the pre-capture backfill: verdict, POC output and baseline
only, with every provenance and return-code column NULL because it was never
recorded. Exclude them from any claim that depends on compile evidence.

## Re-verifying

Just run the same command again. `attempt` increments, the earlier row is kept, and
`patch_data` reflects the newest attempt. Nothing is overwritten — that history is
the point, since a verdict is a property of (patch, applier, compiler, POC), not of
the agent's diff alone.

```sql
SELECT attempt, applier_sha256, compile_rc, is_crash_resolved, adjudicated_at
FROM patch_verification WHERE run_id = ? ORDER BY attempt;
```

`applier_sha256` identifies the exact `diff_tools.py` that produced each attempt,
which is what lets you tell whether two verdicts are comparable.

---

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `docker: command not found` | Run from a shell where host docker works. This path does not use `rootainer`. |
| `Conflict. The container name ... is already in use` | A previous run was killed before cleanup. The `finally` block removes it, so **just run the command again** — the retry succeeds. Or `docker rm -f <run_id>`. |
| Nothing happens for 10+ minutes after `patch (entry 1) (rc=0)` | Normal. That's the compile. A progress line lands each minute; `docker top <run_id>` should show `make` at high CPU. |
| `No run found for <id>` | Wrong run id, or you are not in the repo root — `DB_PATH` is relative. |
| `<id> has no patches in result_json` | The agent produced no diff. Nothing to verify; not a tooling fault. |
| `Patch did not apply cleanly` | Read `patch_stdout` on the attempt row. The dry run failed, so **nothing was written to the container** and the tree is clean. |
| `compile_timed_out = 1` | Raise `--compile-timeout`. Check `compile_log_path` for where it stopped and `docker system df` for disk. |
| `No space left on device` in the compile log | Host docker storage. `docker system df`, then `docker image prune -af`. |
| `No verification row found for id` in the log | The DB was replaced mid-run, or two processes are verifying the same run. Run one at a time. |
| Migration says `no such table: patch_data` | Fresh database — use `run_parser.init_db()` instead of the migration. |

---

## Batch workflow (unattended)

Runs a list of patch runs through `diff_tools.py` back to back, capturing all
artifacts and entering **no verdict**. Adjudication is a later pass over the saved
files. Design: `BATCH_VERIFICATION_PROPOSAL.md`.

### Setup on a database that already has `patch_verification`

If the table was created before `transcript_path` existed (38 columns), the same
migration adds it — no separate step, nothing to undo.

```bash
cd ~/repos/ARVO-Codex-Logger
git pull
python patch_verification_upgrade.py
```

```
INFO - added column patch_verification.transcript_path      <- only on the first run
INFO - patch_verification table and index present
INFO - backfill: nothing to do                              <- already backfilled
INFO - patch_verification rows: 22 {0: 22}
```

Existing rows are untouched and re-running is safe. Confirm and check the plan:

```bash
python -c "import sqlite3; print(len(sqlite3.connect('arvo_loc_runs.db').execute('PRAGMA table_info(patch_verification)').fetchall()), 'columns')"
python -m pytest test_diff_tools.py test_verify_batch.py -q
python verify_batch.py --ids-file phase1_batch.txt --dry-run
```

Expect `39 columns`, `69 passed`, and 98 runs across 55 vulns.

### Run it

Start with one vuln's pair — proves image reuse and the prune, ~35 min:

```bash
python verify_batch.py --ids arvo-42540891-vul-1784232900-patch \
                             arvo-42540891-vul-1785207325-patch
```

Then the batch, ~22-25 h:

```bash
nohup python verify_batch.py --ids-file phase1_batch.txt > batch.log 2>&1 &
```

Safe to kill and re-invoke at any point: completed runs are skipped on resume.

| flag | |
|---|---|
| `--ids-file` / `--ids` / `--from-queue` | run selection; `--from-queue` recomputes the filter from the database |
| `--max-runs N` | stop after N runs this session |
| `--abort-after N` | consecutive infrastructure failures before aborting (default 3) |
| `--force` | re-verify runs that already have artifacts, as a new attempt |
| `--no-prune` | keep arvo images between vulns (~14 GB each) |
| `--dry-run` / `--status` | plan / progress, run nothing |

### Check progress

```bash
python verify_batch.py --ids-file phase1_batch.txt --status
tail -f batch.log
```

Outcomes are read from the database, not exit codes. `patch_failed` and
`compile_failed` are **results**, not errors, and do not stop the batch; only
infrastructure faults (`no_row`, `driver_timeout`, `infra_failed` — disk full, dead
docker daemon) count toward `--abort-after`.

### Hand the artifacts to the LLM pass

```bash
python verify_batch.py --collect-artifacts ./for_llm
```

Two files per attempt, copied verbatim — nothing is truncated:

```
compile_<run_id>_a<attempt>.log    full arvo compile output (~1.9 MiB)
verify_<run_id>_a<attempt>.log     baseline POC, patch application, patched POC
```

Both filenames carry the run id, so they stay traceable in a flat directory. The
transcript opens with a header and a `SCALARS` block (`compile_rc`, `patch_rc`,
`patch_max_fuzz`, `patch_recounted`, `poc_rc`) so the model reads those as values
rather than inferring them.

A transcript is written for **every** attempt, including runs that stopped at a
failed apply or a failed compile — `stopped_after` in the header says where.

### Disk

One image at a time (~14.9 GB peak) because images are pruned when the vuln
changes. The container's writable layer is only ~780 MB and is reclaimed on
removal. Without pruning, 55 images would be ~780 GB.

---

## Not automated yet

Deliberately, per the proposal:

- **Apply failures are captured but not classified.** A run whose patch does not
  apply gets a full `patch_verification` row with rc, applier output and the exact
  patch bytes, but no verdict and no ledger report. `RUN_DATA_MAP.md` Class 7 stays
  open until the reporting policy is decided.
- **The compile is not narrowed to the single `fuzz_target`.** It would cut the
  measured 932 s per run to ~1–2 min, but only once a narrowed build is shown to produce a
  byte-identical target binary. Until then the full rebuild is the conservative
  choice.
- **`compile_verified` is always NULL.** That column is for the downstream LLM pass
  to write once it judges a compile trustworthy, which is a separate claim from
  `compile_rc = 0`.
