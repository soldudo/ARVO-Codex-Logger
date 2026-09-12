# Batch Patch Verification — Phased Proposal

> **Status:** Proposed. Nothing implemented. The diff_tools facts below are read
> from the current implementation; every count is queried from `arvo_loc_runs.db`
> and reconciled against `RUN_DATA_MAP.md`. The Phase 1 batch is written to
> `phase1_batch.txt`.

Three phases. **Phase 1** runs a fixed list of patch runs through `diff_tools.py`
unattended, capturing every artifact and entering **no verdict**. **Phase 2** narrows
the compile. **Phase 3** adds the asynchronous adjudication pass. Each phase is
independently useful and lands separately.

## Background — what blocks unattended running

Almost nothing. `diff_tools.py` has exactly three interactive calls, all inside
`handle_fuzzer_result`:

```
465:  choice = input('[r]e-run  |  [c]lassify  |  [q]uit: ')
471:  class_choice = input('Classify result: ...')
477:  note = input('Note (optional, Enter to skip): ')
```

Every earlier stage already runs unattended — the patch-failure path prints and
returns 1 with no prompt — and critically the POC output is persisted **before**
adjudication is offered:

```python
poc = run_poc(container_name, args.poc_timeout)
update_patch_verification(verification_id, poc)      # artifacts durable here
...
is_crash_resolved, note, poc = handle_fuzzer_result(poc, container_name)
```

So the artifacts Phase 1 exists to produce are already committed at the point the
prompt appears. Skipping the prompt costs the verdict and nothing else.

Verified by driving the function directly: fed `q` it returns `(None, None, poc)`,
`main`'s existing `if is_crash_resolved is not None:` guard skips both the verdict
write and the `patch_data` mirror, `finished_at` is still written, and `main`
returns **0**. The interactive path is unchanged (`c` → `s` → note still yields a
verdict).

---

# Phase 1 — unattended artifact capture

No build narrowing. Accepts the full ffmpeg rebuild — measured at 932 s — and makes
the batch survivable instead: resumable, killable, disk-bounded.

## Change 1.1 — `diff_tools.py`: `--no-adjudicate`

```python
    parser.add_argument('--no-adjudicate', action='store_true',
                        help='capture artifacts and exit without prompting for a '
                             'verdict; adjudicate later with adjudicate.py')
```

```python
        if args.no_adjudicate:
            logger.info('--no-adjudicate: artifacts captured, verdict deferred')
        else:
            print('\n--- Baseline Fuzzer Output ---')
            print(baseline_log)
            print('------------------------------')
            is_crash_resolved, note, poc = handle_fuzzer_result(poc, container_name)
            update_patch_verification(verification_id, poc)
            if is_crash_resolved is not None:
                ...            # unchanged
```

**A zero-change fallback exists** if you want to start before touching any code:

```bash
printf 'q\n' | python diff_tools.py --patch-run-id <id>
```

The flag is still worth the three lines — it does not dump the baseline and POC
output to the terminal for 98 runs, it does not depend on `q` remaining the quit
key, and a stray second prompt under a closed stdin would raise `EOFError` rather
than exiting cleanly.

## Change 1.2 — `arvo_tools.standby_container`: accept a timeout

`diff_tools.py:34` defines `PULL_TIMEOUT = 1800` and `:523` prints it, but
`standby_container` takes no timeout and calls `run_command(stby_cmd)` with the
default `None`. The multi-GB image pull is unbounded, and the log claims a bound
that does not exist.

```python
def standby_container(container_name: str, vuln_id: int, fix_flag: str = 'vul',
                      timeout: Optional[int] = None):
    ...
    run_command(stby_cmd, timeout=timeout)
```

Then pass `PULL_TIMEOUT` from `diff_tools.py`. An unbounded pull is the single most
likely way to stall a multi-day batch, so this is a prerequisite rather than a
nicety.

## Change 1.3 — artifacts the LLM pass can actually consume

The compile log and a second file carrying the baseline POC, the patch application
and the re-run POC are fed to an LLM to judge whether the container compiled and
whether the POC result genuinely reflects the patched code. Three problems with
what `diff_tools.py` writes today.

### 1.3a — Filenames must carry the run id

Current:

```
runs/<run_id>/compile_<verification_id>.log
```

The directory carries the run id; the file does not. Pool 98 of these into one
directory to hand to an LLM and `compile_1.log` … `compile_98.log` are untraceable.

Proposed, matching the existing `runs/<run_id>/agent_<run_id>.log` convention —
kind prefix, then run id:

```
runs/<run_id>/compile_<run_id>_a<attempt>.log
runs/<run_id>/verify_<run_id>_a<attempt>.log
```

Keyed on `attempt` rather than `verification_id` because `(run_id, attempt)` is
already the table's UNIQUE key, so the filename is a complete join key back to the
row, and `_a2` reads as a re-verification where `_37` does not.

**Extension stays `.log`.** Both files are plain UTF-8 text either way, so nothing
downstream cares; `.log` matches every other per-run artifact in `runs/`
(`agent_<run_id>.log`, `crash_<container>.log`) and keeps one rule for the
directory. Trivially reversible if a tool ever wants `.txt`.

**Renaming is free right now.** Zero rows hold a `compile_log_path` and zero
attempts exist above the backfill, so there is nothing to migrate. This is the
moment to fix it.

### 1.3b — A second artifact: the verification transcript

One file per attempt, assembled from the `patch_verification` row:

```
=== CARO PATCH VERIFICATION TRANSCRIPT ===
run_id            arvo-42540891-vul-1784232900-patch
vuln_id           42540891
project           ffmpeg
fuzz_target       ffmpeg_AV_CODEC_ID_JPEGLS_fuzzer
crash_type        Heap-buffer-overflow WRITE 2
attempt           1
started_at        2026-09-11T20:44:03+00:00
finished_at       2026-09-11T20:59:35+00:00
image_tag         n132/arvo:42540891-vul
applier_sha256    9b077bf8ff4c2d4d
container_workdir /src/ffmpeg
stopped_after     complete
compile_log_file  compile_arvo-42540891-vul-1784232900-patch_a1.log

--- SCALARS ---
patch_rc 0   patch_strip 1   patch_recounted 0
patch_hunks_ok 1   patch_hunks_failed 0   patch_max_fuzz 0
compile_rc 0   compile_duration_s 932.0   compile_timed_out 0
poc_rc 0   poc_duration_s 1.4   poc_timed_out 0

--- 1. BASELINE POC OUTPUT (unpatched) ---
source: arvo.crash_output
<baseline_log>

--- 2. PATCH APPLICATION ---
<patch_stdout, already carrying per-entry markers and dry-run/apply blocks>
<patch_stderr, if any>

--- 3. PATCHED POC OUTPUT ---
--- stdout ---
<poc_stdout>
--- stderr ---
<poc_stderr>

=== END ===
```

The header and `SCALARS` block exist so the LLM is not inferring from prose what is
already recorded as integers. `compile_rc` answers "did it compile" outright, and
`patch_max_fuzz` is the one that speaks to "does this truly represent the patched
code" — a hunk applied at fuzz 2 had that many context lines discarded and may have
landed off-target.

**Written at every exit path, not just the happy one.** A run whose patch fails to
apply has no compile and no POC, but its transcript — baseline, patch log,
`stopped_after: patch_failed` — is exactly what a reviewer needs. Same for a failed
compile. The current code returns early at three points and would produce nothing.
Emitting the transcript from a `finally`-style block makes it **the one artifact
that always exists for an attempt**, which in turn makes it the natural unit for
the LLM batch.

**The transcript carries no compile output.** The full compile log is a separate
file and is already fed to the LLM whole; duplicating an extract of it here would
waste context and invite the model to reason from the abridged copy. The transcript
names the compile file in its header and stops there. The bounded
`compile_output_extract` stays in the database as the queryable summary — that is a
different job from the LLM artifact.

### 1.3c — Sizing, now measured

Two ffmpeg runs, same vuln:

| | |
|---|---|
| `compile_log_bytes` | 1,955,662 (1.87 MiB) — identical across both |
| `compile_duration_s` | 930 and 932 |

That settles the three numbers Verification step 1 was there to fix, and corrects
an assumption I had wrong:

- **`COMPILE_TIMEOUT = 3600` is well calibrated** — 3.9× the observed 932 s. Keep
  it; the margin covers a slower project without letting a genuine stall run for
  hours.
- **No truncation anywhere in the LLM path.** I had assumed the log could reach
  hundreds of MB and designed a threshold around it. At 1.87 MiB that is simply
  not a problem, and it is already being consumed whole. Drop the idea — no
  `--full-compile-under`, no extract substitution. `--collect-artifacts <dir>`
  copies both files per attempt into a flat directory, verbatim.
- **Full log stays on disk, not in the database.** The reasoning changes but the
  decision does not: 98 full logs inline would add ~183 MiB to a 206 MiB database,
  an 89% increase, for content already on disk. The bounded extracts add ~24 MiB
  worst case. The split was right for the wrong reason.

The build also looks largely incremental — 932 s across 435 targets is ~2.1 s each,
and ~4.5 KB of log each, which is a `make` mostly finding things up to date rather
than 435 full ASAN links. Two data points from one vuln, so not a conclusion, but
it bears on how much Phase 2 actually saves.

### 1.3d — Schema: one new column

`transcript_path TEXT`, alongside the existing `compile_log_path`. Both are
derivable from `run_id` + `attempt` + the naming convention, which is exactly why
`compile_log_path` is stored — if the convention later changes, old rows still
point at the files they actually wrote.

Lands as an idempotent addendum to `patch_verification_upgrade.py`, guarded on a
`PRAGMA table_info` check so re-running stays safe:

```python
cols = {r[1] for r in conn.execute('PRAGMA table_info(patch_verification)')}
if 'transcript_path' not in cols:
    conn.execute('ALTER TABLE patch_verification ADD COLUMN transcript_path TEXT')
```

38 columns to 39. `schema.py`'s `PATCH_VERIFICATION_DDL` gains the column too, so a
freshly created database matches without the ALTER.

## Change 1.4 — `verify_batch.py`

Shells out to `diff_tools.py` once per run id. Subprocess rather than in-process so
a hang or hard crash in one run cannot take the batch down, and so the driver can
impose an outer bound that does not depend on diff_tools' internal timeouts holding.

```bash
python verify_batch.py --ids-file phase1_batch.txt
python verify_batch.py --ids-file phase1_batch.txt --max-runs 2
python verify_batch.py --ids-file phase1_batch.txt --dry-run
python verify_batch.py --from-queue                    # recompute the list from the DB
python verify_batch.py --status
```

| flag | meaning |
|---|---|
| `--ids-file` | one run id per line; blank lines and `#` comments skipped |
| `--ids` | ids on the command line |
| `--from-queue [N]` | recompute the Phase 1 filter from the database (see below) |
| `--max-runs N` | stop after N runs this session |
| `--compile-timeout` / `--poc-timeout` | passed through to `diff_tools.py` |
| `--run-timeout` | outer subprocess bound; default `compile_timeout + poc_timeout + 1800` |
| `--force` | re-verify runs that already have artifacts, as a new `attempt` |
| `--no-prune` | keep images between vulns |
| `--dry-run` / `--status` | plan / progress only |

### Serial, with a lockfile

One run at a time, using the `_acquire_lock` pattern from `run_experiments.py:377`
with its own path `runs/.verify_batch.lock` carrying the pid. Before each run the
driver issues `docker rm -f <run_id>` to clear an orphan left by a SIGKILLed
predecessor.

Serial is not caution. `arvo compile` writes ~435 ASAN binaries into the container's
writable layer — roughly 30 GB transient for ffmpeg, reclaimed when diff_tools'
`finally` removes the container. Two concurrent runs is ~60 GB of transient layer
plus two resident images, and a batch that dies on `No space left on device` loses
the run it was on. Parallelism needs the disk math done deliberately; it is not a
default.

### Order by vuln, prune when it changes

The batch is **98 runs across 55 vulns**. `docker run` pulls only when the image is
absent, so processing in vuln order means each image is pulled once and reused by
every run that shares it — 55 pulls instead of up to 98 — and the driver removes it
when the vuln changes, keeping one resident image at a time.

Same reasoning as `arvo_tools.prune_dind_images`' docstring, applied to host docker.
The prune lives in the driver, not in `diff_tools.py`, which should stay a
single-run tool with no opinion about what runs next.

### Resume

A run is finished for batch purposes when it has an `attempt > 0` row in a terminal
state:

```sql
SELECT 1 FROM patch_verification
WHERE run_id = ? AND attempt > 0
  AND (poc_rc IS NOT NULL          -- full artifacts captured
    OR poc_timed_out = 1           -- bounded out; partial but terminal
    OR patch_rc != 0               -- stopped before compile, by design
    OR (compile_rc IS NOT NULL AND compile_rc != 0))
```

Anything else — no row, or a row abandoned mid-stage — is retried. `--force`
ignores the predicate and opens a fresh attempt; nothing is ever overwritten.

The `attempt > 0` clause is load-bearing: all 22 backfilled rows carry `poc_stdout`
but no `poc_rc`, and would otherwise read as batch-completed work.

### Per-run outcome

Classified from the **database, not the exit code** — `diff_tools.py` returning 1
for a patch that does not apply is a legitimate recorded result, not a batch error,
and roughly 10 of the queue will land there.

| outcome | detected by |
|---|---|
| `artifacts_ready` | `poc_rc IS NOT NULL` |
| `patch_failed` | `patch_rc != 0` — stopped before compile, container tree untouched |
| `compile_failed` | `compile_rc != 0` or `compile_timed_out = 1` |
| `poc_timeout` | `poc_timed_out = 1` |
| `no_row` | died before opening a verification row (bad id, pull failure) |
| `driver_timeout` | outer `--run-timeout` fired; container force-removed |

## The Phase 1 batch — 98 runs

Written to **`phase1_batch.txt`**, grouped by project then vuln in execution order.
Filter:

```
run_mode = 'patch'
AND result_error_flag = 0                         -- completed, not limited or 401
AND result_json GLOB '*diff*'                     -- actually produced a patch
AND patch_data.is_crash_resolved IS NULL          -- no verdict
AND patch_data.patch_crash_log  IS NULL           -- no captured POC log
AND patch_data.compile_errors   IS NULL           -- no captured compile output
AND run_id NOT IN (patch runs paired with a Class 1 broken resume)
```

### Reconciliation against `RUN_DATA_MAP.md`

| step | runs |
|---|---|
| `RUN_DATA_MAP.md` adjudication queue | 107 |
| + `patch_crash_log IS NULL AND compile_errors IS NULL` | 107 — **no change** |
| − patch runs paired with a Class 1 broken resume | **98** |

The "no additional data in `patch_data`" requirement turns out to be already
implied: all 107 queued runs have all three verification columns NULL, because
`update_patch_crash_results` writes them together and nothing else writes them. The
condition is stated explicitly anyway so the filter stays correct if that ever
changes.

The 98 are P1 (32) + P2 (46) + 20 of the 29 P3 runs — the full headline comparison
plus the Class 5 and Class 8 remainder.

### The Class 1 exclusion

`RUN_DATA_MAP.md` Class 1 lists ten localization runs that failed to resume,
started fresh sessions and recorded `result_json = {}` as successes. Their paired
patch runs ran against a prompt announcing findings that were not there.

The pairing is unambiguous and confirmed two independent ways: the loc and patch
runs of one invocation share the stem `arvo-<vuln>-vul-<timestamp>-`, and
`patch_data.loc_source` on each paired patch run points at its Class 1 loc run
exactly. All ten check out on both.

**Nine** of the ten paired patch runs are dropped from the queue by this exclusion:

```
arvo-42537352-vul-1785353700-patch    arvo-42537772-vul-1786065300-patch
arvo-42537575-vul-1785389700-patch    arvo-42537828-vul-1786494900-patch
arvo-42537608-vul-1785371700-patch    arvo-42539789-vul-1787202900-patch
arvo-42537660-vul-1786029300-patch    arvo-42540556-vul-1785299700-patch
arvo-42537662-vul-1786047300-patch
```

The tenth, `arvo-42540880-vul-1785225300-patch`, was never in the queue: it has
`result_error_flag = 1` and a 2-byte `result_json`, so it is already excluded by
the completeness filters. That is why `RUN_DATA_MAP.md` P3 lists nine here and
Class 2 lists ten.

**The exclusion is derived, not hardcoded.** `RESUME_FIX_PROPOSAL.md`'s detector —
a loc run carrying the resume sentinel prompt with neither `--resume` nor
`--continue` in its recorded command and an empty result — reproduces the
documented Class 1 set **exactly, 10 for 10, with no false positives or
negatives**. The driver should use that query so the filter stays correct if more
broken resumes surface, rather than embedding a list that silently goes stale.

```sql
SELECT run_id FROM runs
WHERE run_mode = 'loc'
  AND prompt = 'continue where you left off'
  AND command NOT LIKE '%--resume%'
  AND command NOT LIKE '%--continue%'
  AND (result_json IS NULL OR TRIM(result_json) = '{}')
```

These nine are excluded for **provenance hygiene, not because the patch is
unverifiable**. Each produced a real diff and would yield a real crash-resolution
outcome. They are held back because attributing that outcome to the full-md arm
would be wrong, and because Class 1 repair may re-run them with real context. Add
them to a later batch once Class 1 is resolved, or verify them explicitly if an
apply-rate figure is wanted independent of arm.

## Budget

| | |
|---|---|
| runs | 98 |
| distinct vulns | 55 |
| project mix | ffmpeg 77, libxml2 7, php-src 3, geos 3, mruby 3, others 5 |
| compiles required | 98 — two runs on one vuln share the image but not the build |
| image pulls | 55 in vuln order |
| ffmpeg compile | **932 s measured** (was estimated at ~30 min) |
| wall time | 77 × 932 s ≈ 19.9 h, plus non-ffmpeg and pulls → **~22-25 hours** |
| compile log | 1.87 MiB each; ~183 MiB across the batch, on disk |
| transient disk | ~30 GB per container, reclaimed on removal (unmeasured) |
| resident disk | one image at a time with pruning |

The wall-time figure is measurement-backed for the 77 ffmpeg runs, which dominate
it. The 21 non-ffmpeg runs are smaller projects and should be well under 932 s
each, and the 55 image pulls are unmeasured — both are inside the 3-hour spread.

## Verification steps

1. `--dry-run --ids-file phase1_batch.txt` lists 98 runs in 55 vuln groups, touches
   nothing.
2. `printf 'q\n' | python diff_tools.py --patch-run-id <id>` on one run: exit 0, a
   row with `poc_rc` set and `is_crash_resolved` NULL. Confirms the fallback before
   any code moves.
3. Same run with `--no-adjudicate`: identical row, no output dump, exit 0.
4. `--max-runs 2` over two runs of the **same** vuln (e.g. the two `42540891`
   runs): one pull, two compiles, two `artifacts_ready` rows. This doubles as
   Verification step 1 of `PATCH_VERIFICATION_PROPOSAL.md` — it measures the
   compile wall time and log size that `--compile-timeout 3600` and the extract
   budget are still guessing at.
5. `--max-runs 2` over two runs of **different** vulns: the first image is removed
   when the vuln changes.
6. Re-invoke after step 4: both runs skipped by the resume predicate.
7. `--force` on one: a new `attempt` row, the earlier one intact.
8. Include a known apply-failure: outcome `patch_failed`, batch continues.
9. Ctrl-C mid-compile, re-invoke: that run retried, completed runs skipped.
10. `--run-timeout` below the compile time: outcome `driver_timeout`, container
    removed, batch continues.

---

# Phase 2 — build narrowing

Deferred until it is shown not to compromise experiment accuracy. `arvo compile`
currently rebuilds all 435 decoder fuzzers to reach the one the vuln needs — for
`arvo-42540891` it was observed building `target_dec_fraps_fuzzer` while that
vuln's target is `ffmpeg_AV_CODEC_ID_JPEGLS_fuzzer`.

At ~1-2 min per compile the Phase 1 batch drops from ~22-25 hours to roughly
**three**, and the transient disk mostly disappears. Still the single largest
improvement available in this workflow, though the measured 932 s makes it a ~7×
win rather than the ~20× the earlier estimate implied.

One measurement bears on whether even that holds. At 932 s across 435 targets —
~2.1 s and ~4.5 KB of log each — most of that time looks like `make` walking a
dependency graph it finds up to date, not 435 ASAN links. If so, narrowing removes
the walk rather than a pile of real compilation, and the floor is lower than 932 s
but the ceiling on savings is less certain. Measure a single-target `make` in the
container before committing to the rewrite.

The accuracy question to settle first, before writing anything:

1. Build one vuln both ways and compare the **target binary's hash**. Identical
   settles it.
2. Read `/src/build.sh` for any whole-set step a single-target `make` would skip —
   a shared archive relink, a copy into `/out`, a post-build check.
3. Confirm the narrowing mechanism exists: whether the decoder list is driven by an
   env var, an explicit list, or is computed and would need patching.

Phase 1's capture is what makes that comparison auditable — `applier_sha256`,
`compile_rc`, `compile_log_bytes` and the POC output give a before/after baseline on
real runs rather than a one-off manual check. So Phase 1 first is the right order
even though Phase 2 is where the time is.

If it does not hold, the fallback is a narrowing that keeps the full link set but
caches it: `docker commit` the post-compile container per vuln, so runs 2..n on the
same vuln start from a built tree and rebuild only what the patch touches. More
moving parts, and it changes what is tested, so it needs the same scrutiny.

---

# Phase 3 — `adjudicate.py`

The asynchronous review pass over Phase 1's artifacts. Walks attempts with
artifacts and no verdict:

```sql
SELECT * FROM patch_verification
WHERE attempt > 0 AND is_crash_resolved IS NULL AND poc_rc IS NOT NULL
ORDER BY run_id, attempt
```

For each: prints the baseline log, the patched POC output, `compile_rc`,
`patch_max_fuzz` and `patch_recounted`, then takes `[s]uccess` / `[u]nsuccessful` /
`[k]ip` / `[q]uit` plus an optional note. Writes exactly what interactive
`diff_tools.py` writes — `is_crash_resolved`, `adjudicated_by`, `adjudicated_at`,
`adjudication_note` — and mirrors to `patch_data` so the `analysis/` scripts keep
working.

Two flags it must surface per run, because they decide whether a verdict means
anything:

- `compile_rc != 0` — the POC ran against a stale build. Should be unreachable,
  since `diff_tools.py` stops before the POC in that case, but assert rather than
  assume.
- `patch_max_fuzz > 0` — that many context lines were discarded, so the patch may
  have landed slightly off. A verdict here is weaker than one at fuzz 0.

`--run-id` adjudicates one run; `--limit N` caps a session. No container and no
docker, so review happens anywhere the database is.

This is also where the LLM compile-verification pass fits: it can populate
`compile_verified` over Phase 1's artifacts independently, before or alongside human
adjudication, and `adjudicate.py` can then show its judgement as an input rather
than a substitute.

Until Phase 3 lands, `RUN_DATA_MAP.md` Class 7 stays open — Phase 1 produces
evidence, not verdicts, which is the stated intent.

---

# Changes not covered in this plan

Things Phase 1 will touch or cause that are not in the changes above, flagged for a
decision:

1. **No `.gitignore` exists.** Phase 1 creates 196 files under `runs/` — a compile
   log and a transcript per run — at ~1.87 MiB per compile log, so roughly 183 MiB
   total, on top of the 38 untracked entries already in `git status`. Either add a
   `.gitignore` covering `runs/*/`, `*.log`, `__pycache__/` and `*.db`, or accept
   that `git status` becomes unusable. This is
   the only change here that touches repository hygiene rather than the workflow,
   and it is worth doing first because it is cheap and irreversible decisions get
   made in its absence.
2. **Host-docker image pruning has no existing helper.**
   `arvo_tools.prune_dind_images` is rootainer-only. I propose putting the host
   variant in `verify_batch.py` rather than adding `prune_host_images` to
   `arvo_tools`, to keep the blast radius on a new file — but it is duplicated
   logic, and the alternative is a small addition to `arvo_tools` that the campaign
   runner could later share.
3. **Database growth.** 98 rows carrying `patch_text`, `poc_stdout`/`poc_stderr` and
   a ≤256 KiB compile extract — on the order of 20-30 MB against a 208 MB database.
   Not a problem, but it is the first time this table grows meaningfully, and the
   rollback is `DELETE FROM patch_verification WHERE attempt > 0`.
4. **`diff_tools.log` is a single append-only file** shared by all 98 runs, and now
   logs applier output and the baseline at INFO. A few MB, readable but awkward.
   Consider a per-run log path, or leave it — the per-run evidence is in the
   database and the compile log either way.
5. **`analysis/` output does not change during Phase 1.** No verdicts are written,
   so `patch_eval.py` and `command_analysis.py` report exactly what they do today
   until Phase 3 runs. Expected, not a regression — worth knowing before someone
   re-runs them mid-batch looking for movement.
6. **`test_diff_tools.py` gains no coverage for `--no-adjudicate`.** The flag is
   three lines in `main()`, which the suite does not exercise at all. A test would
   need `main` refactored or mocked; I would skip it and rely on Verification
   step 3.
7. **Do not run a campaign concurrently.** Different lockfiles and different docker
   targets — `diff_tools.py` uses host docker, `run_experiments.py` uses rootainer
   — so they will not fight over container names, but they will contend for CPU and
   disk for ~22-25 hours.
8. **Batch order carries no experimental meaning.** Grouping by project and vuln is
   a disk optimisation. Nothing downstream reads the order, but if a partial result
   is wanted sooner, a P1-only ids file drawn from `RUN_DATA_MAP.md` would drain the
   headline arm first at the cost of more image pulls.

## Related

- `PATCH_VERIFICATION_PROPOSAL.md` — the schema and single-run design this drives.
- `PATCH_VERIFICATION_GUIDE.md` — setup and the interactive single-run workflow.
- `RUN_DATA_MAP.md` — Class 1, Class 2 and the priority-split adjudication queue.
- `RESUME_FIX_PROPOSAL.md` — the resume regression, and the detector reused here.
- `run_experiments.py` — `_acquire_lock`, `--max-runs`, resumable-campaign
  conventions mirrored here.
