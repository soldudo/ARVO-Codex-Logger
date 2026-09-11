# Patch Verification Capture — Proposal

> **Status:** Implemented, offline verification passed, not yet exercised against a
> live container. Changes 1, 3, 4 and 5 are complete and the migration has run
> (22 legacy rows backfilled as `attempt = 0`). Change 2's timeouts and streamed
> compile are written but only the timeout values remain unmeasured — Verification
> step 1 still needs a real ffmpeg run. Steps 2, 3, 4, 10 and 11 pass; steps 5–9
> need docker.
>
> Two things changed during implementation, both recorded below: the compile output
> is captured as one merged stream (`compile_output_extract`) rather than split
> stdout/stderr, and the sweep turned up a silent-truncation failure mode that had
> not been visible in the rc-only outcome table.

A plan to persist the four artifacts a patch verification run produces — baseline
POC output, patch application record, compile output, patched POC output — into the
database with enough provenance to reproduce and audit the verdict, and to fix the
malformed-patch class that currently costs runs before any of those artifacts exist.

## Background — what the run produces and what survives it

`diff_tools_updated.py` executes four stages against a standby container:

| stage | source | code |
|---|---|---|
| baseline POC output | `arvo.crash_output` (DB read, **not** re-executed) | `:165`, `:187` |
| patch write + apply | `write_diff` then `patch -p0`, retry `-p1` | `:193`–`:213` |
| recompile | `arvo compile` | `:224` |
| patched POC | `arvo` | `:228` |

All four are written to `diff_tools.log`. Three of the four are then discarded, and
the one that reaches the database arrives incomplete:

- **Baseline POC output** — never persisted. It is read from `arvo.crash_output`
  and logged. Nothing records *which* baseline the verdict was made against.
- **Patch application** — never persisted. Not the patch bytes, not the argv, not
  the strip level, not the return code, not the fuzz factor applied.
- **Compile** — `patch_data.compile_errors` receives `arvo_compile_result.stderr`
  only (`:225`). `stdout` is dropped. **The return code is dropped.**
- **Patched POC** — `patch_data.patch_crash_log` receives `stdout + stderr`
  concatenated (`:96`). The return code is dropped.

Only `is_crash_resolved`, `patch_crash_log`, and `compile_errors` are written, all
via a single `update_patch_crash_results` call at `:236`.

## Evidence

### The compile verdict is not recorded anywhere

This is the central gap for the downstream LLM pass. The question that pass has to
answer — "did the compile complete, so is the POC result a reflection of the patched
code?" — has an authoritative answer in `arvo_compile_result.returncode`, and that
integer is logged by `run_and_report` at `:37` and then thrown away.

The LLM is currently being asked to infer from `compile_errors` text what a single
stored integer would state. Worse, `arvo compile` runs `bash -eux /src/build.sh`,
so its stderr is dominated by shell trace output rather than diagnostics — the
signal-to-noise ratio of the one field that *is* stored is poor by construction.

`arvo_tools.recompile_container` already notes the related trap at its own TODO:

```
# TODO: recompiling failure can still prodoce this successful recomiplation msg
```

### Current coverage

```
runs with run_mode='patch'                 170
patch_data rows                            170   (all present; run_parser.py:310)
  is_crash_resolved NOT NULL                22
  patch_crash_log   NOT NULL                22
  compile_errors    NOT NULL                21
```

148 rows are unadjudicated, consistent with `RUN_DATA_MAP.md` Class 7. One
adjudicated run has a verdict and a crash log but no compile output at all, so even
within the adjudicated set the compile evidence is not uniform.

### The malformed patch class

49 of 127 patch runs carrying a diff (39%) have at least one hunk whose `@@` header
line counts disagree with its body. Reproduced against GNU patch 2.7.6 with target
files synthesised so context matches perfectly — every outcome below is a parsing
result, not source drift:

| outcome | current `diff_tools.py` | `diff_tools_updated.py` (`-F 3`) |
|---|---|---|
| `ok` (clean apply) | 67 | 67 |
| `ok-fuzz` (context discarded) | 32 | 39 |
| `fail` | 14 | 8 |
| `malformed` | 14 | 13 |

The update moved one run out of `malformed` and zero runs into clean `ok`. Its two
new mitigations do not address the cause:

- **The blank-line separator** (`:93`) buys exactly one line of slack. An
  undercounted header makes `patch` over-read by the shortfall, consuming
  `--- b.c` as a removal and `+++ b.c` as an addition, then reading the next
  entry's `@@` as a further hunk *of the previous file*. Shortfall 1 is absorbed;
  shortfall 2 is not:

  | shortfall | no separator | with separator |
  |---|---|---|
  | 1 | hunk 1 FAILED, b.c hunk applied to a.c | clean, rc=0 |
  | 2 | `malformed`, rc=2 | hunk 1 FAILED, b.c hunk applied to a.c |
  | 3 | — | `malformed`, rc=2 |

- **The blank-context regex** (`:81`) targets a condition neither applier rejects.
  GNU `patch` and `git apply` both accept a bare empty line as a context line
  (verified, rc=0 from each, counts correct). Its negative lookahead also excludes
  the two positions a blank line most often occupies — immediately before a `-` or
  a `+` line — so it does not fire where it was aimed.

`-F 3` accounts for the entire measured movement, and it moves the wrong way. GNU
patch already defaults to fuzz 2 and caps fuzz at the available context. Measured
over 211 hunks in the stored diffs: **median 3 context lines per side, 86% with
3 or fewer leading and 96% with 3 or fewer trailing.** At `-F 3` the large majority
of hunks can have all context discarded, leaving the agent's claimed line number
unverified. Five runs now apply at fuzz 3 where none did before.

For a verification harness that converts a recordable experimental outcome ("the
agent emitted an unusable diff") into an unverified application that then compiles
and fuzzes and gets adjudicated as a result.

## Files affected

| file | change |
|---|---|
| `patch_verification_upgrade.py` | new — rerunnable migration, modelled on `db_experiment_upgrade.py` |
| `queries.py` | new writers/reader for the verification table |
| `diff_tools.py` | capture all four stages; rework patch application; timeouts; streamed compile |
| `run_parser.py` | extend the `CREATE TABLE IF NOT EXISTS` block so fresh databases match |
| `test_diff_tools.py` | new — recount and strip-level unit tests |
| `RUN_DATA_MAP.md` | Class 7 note updated once verification rows exist |

## Change 1 — schema: a `patch_verification` table

One row per **verification attempt**, not per run. A run can be verified more than
once — `handle_fuzzer_result` offers `[r]e-run` (`:112`), and any harness fix
invalidates prior attempts and invites a re-verification. Overwriting loses exactly
the history that makes a verdict auditable.

`run_events` is the precedent for a child table keyed by `run_id`. Follow it.

```sql
CREATE TABLE IF NOT EXISTS patch_verification (
    verification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    attempt           INTEGER NOT NULL,

    -- provenance
    started_at        TEXT,
    finished_at       TEXT,
    applier_sha256    TEXT,      -- sha256 of diff_tools.py as executed; see Considerations
    image_tag         TEXT,      -- n132/arvo:<vuln_id>-vul
    container_workdir TEXT,      -- the pwd probe at :171

    -- stage 1: baseline
    baseline_source   TEXT,      -- 'arvo.crash_output' | 'live'
    baseline_log      TEXT,

    -- stage 2: patch application
    patch_text        TEXT,      -- exact bytes fed to the applier
    patch_sha256      TEXT,
    patch_recounted   INTEGER,   -- count of hunk headers this run rewrote
    patch_strip       INTEGER,   -- 0 or 1, denormalised out of patch_argv
    patch_argv        TEXT,      -- JSON; the only durable record of the flags
    patch_rc          INTEGER,   -- worst rc across entries; see Change 3b
    patch_stdout      TEXT,      -- all entries, concatenated with a marker
    patch_stderr      TEXT,
    patch_hunks_ok    INTEGER,   -- summed over entries
    patch_hunks_failed INTEGER,
    patch_max_fuzz    INTEGER,   -- max over entries

    -- stage 3: compile
    compile_rc        INTEGER,
    compile_output_extract TEXT,   -- streams merged; see Considerations
    compile_log_path  TEXT,
    compile_log_bytes INTEGER,
    compile_duration_s REAL,
    compile_timed_out INTEGER,

    -- stage 4: patched POC
    poc_rc            INTEGER,
    poc_stdout        TEXT,
    poc_stderr        TEXT,
    poc_duration_s    REAL,
    poc_timed_out     INTEGER,

    -- adjudication
    is_crash_resolved BOOLEAN,
    adjudicated_by    TEXT,
    adjudicated_at    TEXT,
    adjudication_note TEXT,

    -- reserved for the downstream LLM pass; NULL until it runs
    compile_verified  INTEGER,
    compile_verdict_note TEXT,

    UNIQUE (run_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_patch_verification_run
    ON patch_verification(run_id);
```

`compile_verified` is deliberately present and NULL. The LLM pass needs somewhere
to write its judgement alongside the evidence it judged, and `compile_rc` is a
different claim from "a human or model confirmed this build is trustworthy."

**Backward compatibility.** `analysis/patch_eval.py:342`,
`analysis/command_analysis.py:319` and `analysis/resume_integrity.py:287` all read
`patch_data`. Keep writing `patch_data.is_crash_resolved`, `patch_crash_log` and
`compile_errors` from the latest attempt so those three keep working unchanged.
`patch_data` becomes a denormalised view of the newest attempt;
`patch_verification` is the record.

Migration lands as `patch_verification_upgrade.py` — `CREATE TABLE IF NOT EXISTS`
plus the index, no destructive statements, safe to re-run — and is mirrored into
`run_parser.py`'s init block so a rebuilt database has the table from the start.

## Change 2 — `diff_tools.py`: bound and stream the long stages

Prerequisite for capture, because a stage that never returns records nothing. No
call in either version passes a timeout; `arvo_tools.run_command` already accepts
one and `refuzz` already uses `timeout=60`.

| call site | timeout | rationale |
|---|---|---|
| `standby_container` (`:170`) | 1800 | implicit multi-GB `docker run` pull |
| `arvo compile` (`:224`) | 3600 | observed ffmpeg full rebuild is ~30 min for 435 targets |
| `arvo` (`:228`) | 120 | `refuzz` uses 60; POC replay is a single input |

On `subprocess.TimeoutExpired`, record the stage with `*_timed_out = 1` and the
partial output rather than letting the exception reach the broad `except Exception`
at `:238`, which currently logs one line and discards everything.

Stream the compile instead of buffering it. `arvo_tools.recompile_container` already
has the pattern — `Popen` with `stderr=STDOUT`, iterate lines, `deque(maxlen=N)`.
Extend it to tee: every line to `runs/<run_id>/compile_<attempt>.log`, a bounded
extract to the database, and a periodic progress line to the operator's terminal.

**The extract is the load-bearing detail.** `bash -eux /src/build.sh` traces every
command across 435 link steps; the full log may be hundreds of MB, against a
database already at 208 MB and ~107 runs still to adjudicate. So:

- full log to `runs/<run_id>/compile_<attempt>.log`, matching the existing
  `runs/<run_id>/agent_<run_id>.log` convention
- `compile_log_path` and `compile_log_bytes` in the row, so a log that has gone
  missing, been emptied, or come out implausibly small for a full rebuild is
  detectable (see Considerations for why no hash)
- in the database, a bounded extract: first 200 lines, last 2000 lines, and every
  line matching an error pattern (`error:`, `Error `, `undefined reference`,
  `No space left`, `fatal`), capped at a fixed byte budget with an explicit
  truncation marker

Measure the real sizes on the first ffmpeg run before fixing those numbers — see
Verification step 1.

## Change 3 — `diff_tools.py`: apply patches so the malformed class stops costing runs

Four changes to the application path, replacing `write_diff` and the `p0`/`p1`
retry.

**3a. Recount hunk headers in Python.** The only fix for the cause. For each hunk,
count body lines by prefix — space and bare-empty count toward both sides, minus
toward the old side, plus toward the new side, and a leading backslash
(the "No newline at end of file" marker) toward neither — then rewrite
`@@ -a,b +c,d @@` with the counted values, preserving the section heading after the
closing `@@`. Record how many headers were rewritten in `patch_recounted`.

Verified equivalent behaviour via git's purpose-built flag: on the short hunk from
`arvo-42541144-vul-1784216642-patch`, `git apply -p0` gives
`corrupt patch at line 12` and `git apply -p0 --recount` applies cleanly. Doing the
recount in Python rather than shelling to `git apply --recount` avoids depending on
`git` being present in every arvo image — an unverified assumption, see
Considerations.

**3b. One patch file per entry, applied in sequence.** Never bare-concatenate.
Concatenation is what lets a miscounted hunk reach into the next entry's header,
and it defeats `--recount` too: `git apply --recount` still mis-parses `--- b.c`
as a removal line, so per-entry application is required independently of 3a.

The entry-level results stay **aggregated into the single attempt row**: `patch_rc`
is the worst rc across entries, `patch_stdout` concatenates all entries with a
per-entry marker, and the three counters sum or max over them. No child table.

Justification: 110 of 127 patch runs are single-entry, and only 17 are multi-entry
(12 with two, 5 with three). More importantly, the entry is the wrong granularity
for the failures being tracked — `arvo-42541206-vul-1773874578-patch` is
single-entry and still goes `malformed`, because the shortfall in its first hunk
eats its second hunk's `@@`. Hunks fail, not entries, which is why
`patch_hunks_ok` / `patch_hunks_failed` / `patch_max_fuzz` are the queryable
summary and the per-hunk narrative stays in `patch_stdout` where GNU patch already
writes it (`Hunk #1 succeeded at 388 with fuzz 2`, `Hunk #2 FAILED at 412`).

`patch_entries` is cut with it: derivable from `result_json`, and the entry data is
clean enough that the derivation is faithful — across 127 runs there are **0**
entries with an empty diff, **0** missing a `---` header, **0** duplicate file
entries, and **0** where the entry's `file` field disagrees with its diff header.

**3c. Derive the strip level from the headers; stop applying twice.** The stored
diffs are mixed style — `libavcodec/mpegaudio_parser.c` needs `-p0`,
`a/libavcodec/mjpegdec.c` needs `-p1`. Inspect the file headers: if every path
carries an `a/` or `b/` prefix, use `-p1`, else `-p0`.
`analysis/loc_eval.norm_path` already encodes exactly this prefix set and should be
the shared source of truth.

This removes a live hazard. The current retry runs against a tree the failed first
attempt may have already mutated, with `--force` (which also enables reversed-patch
application) and `--no-backup-if-mismatch`. It happens to be harmless for
`a/`-prefixed diffs — `arvo-42540891-vul-1784232900-patch` logged
`No file to patch.  Skipping patch.` at `p0`, so nothing was touched before `p1`
succeeded — but a bare-path diff can partially apply and then fail, and the retry
then compounds it.

**3d. Dry run, then apply; drop `-F 3`.** Run `patch --dry-run` first and record
the result. Apply for real only if the dry run is clean. This makes application
effectively all-or-nothing and removes the partial-apply state entirely.

Drop `-F 3` and leave GNU patch at its default fuzz of 2. Do not set `-F 0`: some
fuzz is legitimate against real source drift, and forbidding it would reject valid
patches. Instead **record** it — parse `Hunk #N succeeded at L with fuzz F` and
`Hunk #N FAILED` from the applier output into `patch_max_fuzz`, `patch_hunks_ok`
and `patch_hunks_failed`, so analysis can filter on how much context was actually
verified rather than guessing.

**Measured effect.** Re-running all 127 stored diffs through the implemented path,
same synthetic-target method as the table above:

| outcome | original | `-F 3` revision | implemented |
|---|---|---|---|
| `ok` (context verified) | 67 | 67 | **89** |
| `ok-fuzz` | 32 | 39 | 28 |
| `fail` | 14 | 8 | 10 |
| `malformed` | 14 | 13 | **0** |

49 runs needed a recount; 63 hunk headers were rewritten. Per-run, 33 improved, 93
were unchanged, and **no run regressed from `ok` to `fail`** (step 2's requirement).
Note where the gain lands: the 22 additional clean applies are runs that previously
applied *fuzzily or not at all*, and max fuzz is now 2 with nothing at fuzz 3.

### The failure the rc-only table was hiding

One run changed `ok` to `ok-fuzz` in the per-run comparison, and chasing it found
something worse than a malformed patch. `arvo-42537769-vul-1784697711-patch`
declares `@@ -113,16 +113,18 @@` against a 17/19-line body, and under the old path
it applied **rc=0, no warnings, no fuzz** — while GNU patch read only the declared
16 lines and silently discarded the rest of each hunk. Starting from an identical
tree:

```
raw (old path)   rc=0  283 -> 285 lines
recounted        rc=0  283 -> 289 lines
```

The four lines the old path dropped are the fix:

```
-                                      int y_offset, int x_offset)
+                                      int y_offset, int x_offset,
+                                      int bw, int bh)
-    const uint16_t avg = avg_8x8_c(in, in_stride);
+    const uint16_t avg = avg_8x8_c(in, in_stride, bw, bh);
+                        const int bw = FFMIN(8, width - (x+xx));
+                        const int bh = FFMIN(8, height - (y+yy));
```

The bounds computation is the entire content of this heap-buffer-overflow patch. So
an undercounted header does not only cost runs — it can produce a **clean rc=0
apply of a patch with its substance removed**, which then compiles and gets
adjudicated as a result.

Scope, measured across all 127: **1 run** is affected this way (98 agreed between
the two paths, 28 did not return rc=0 under the old path). That one run is
**unadjudicated**, so no recorded verdict rests on it. The recount closes the
failure mode regardless, and `patch_recounted` now makes it visible when it occurs.

## Change 4 — `queries.py`: writers

- `start_patch_verification(run_id, **provenance) -> int` — INSERT, returns
  `verification_id`, computes `attempt` as `MAX(attempt) + 1` for that `run_id`.
  Needed because `_update_patch_data` (`:161`) is UPDATE-only; it works today only
  because `run_parser.py:310` pre-creates every `patch_data` row.
- `update_patch_verification(verification_id, updates: dict) -> bool` — mirrors
  `_update_patch_data`, keyed on `verification_id`. Called once per stage so a
  crashed or timed-out run still leaves the stages that completed.
- `get_patch_verification(run_id, attempt=None)` — latest attempt by default.
- Keep `update_patch_crash_results` and have it also mirror into `patch_data`.

Per-stage writes matter: a run that dies in `arvo compile` should still have its
baseline and patch-application evidence on disk. That is most of what is missing
today.

## Change 5 — logging

Three small fixes that cost nothing and remove the current blind spot.

- **`run_and_report` logs applier output at DEBUG** (`:39`–`:41`) while
  `basicConfig` is at INFO (`:143`), so `Hunk #1 succeeded at 388 with fuzz 2` is
  discarded. On `arvo-42540891-vul-1784232900-patch` the `p0` failure text survived
  only because `:210` re-logs it at INFO in the failure branch. Log applier stdout
  and stderr at INFO on both branches.
- **No terminal output until `:229`.** `setup_logger()` (`:14`) already builds the
  handler pair including a `StreamHandler`, and `main()` ignores it in favour of a
  file-only `basicConfig`. Call `setup_logger()` and give it the filename.
- **Log the container name, image tag and resolved timeouts at start**, so a log
  read after the fact identifies what it describes.

## Remediation of existing data

The 22 adjudicated runs keep their verdicts. Backfill them as `attempt = 0` rows so
the new table is the single place to read from, honouring the
`analysis/EVALUATION_PIPELINE.md` convention that **NULL means unknowable**:

| column | backfilled from |
|---|---|
| `is_crash_resolved` | `patch_data.is_crash_resolved` |
| `poc_stdout` | `patch_data.patch_crash_log` (stdout+stderr combined; leave `poc_stderr` NULL) |
| `compile_output_extract` | `patch_data.compile_errors` (stderr only at the time) |
| `baseline_log` | `arvo.crash_output` for the run's `vuln_id` |
| everything else | NULL — not recorded at the time |

`compile_rc`, `patch_rc`, `patch_text` and all provenance are NULL for these rows
and must stay NULL. A legacy row is distinguishable by `attempt = 0`, so analysis
can exclude pre-capture verdicts from any claim that depends on compile evidence.

As a rerunnable script, not applied by hand, so it survives a database rebuild.

## Considerations

- **Compile log volume is the main unknown.** The design above assumes the full
  compile log is too large for SQLite and belongs on disk. That assumption is
  unmeasured. Measure it on the first ffmpeg run and revisit the split if it is
  smaller than expected.
- **Compile stdout and stderr are merged into `compile_output_extract`.** The plan
  originally split them. Separating them while streaming needs two reader threads,
  and it destroys the property that makes the log worth reading: `build.sh` runs
  under `bash -eux`, so its trace and the compiler diagnostics interleave, and
  chronological order is what tells you *where* a build died. `compile_rc` is the
  authoritative success signal either way. The POC stage keeps `poc_stdout` and
  `poc_stderr` separate, because its output is small enough for a plain `run()` and
  the split is meaningful there — the fuzzer banner goes to stdout and the ASAN
  report to stderr.
- **The offline sweep numbers are not ground truth.** Target files are synthesised
  so each hunk's old side sits at its declared start line, which isolates parsing
  from source drift but makes the harness *easier* on short hunks: a truncated hunk
  has fewer real lines to satisfy in a filler-padded file. Against real source the
  `ok`/`ok-fuzz` split will differ, and fuzz will additionally be consumed by
  genuine drift. What the sweep does establish soundly is the parsing outcome —
  `malformed = 0`, no `ok` to `fail` regression — because that is decided entirely
  by the diff text.
- **Disk.** `diff_tools.py` uses `standby_container` against host docker, not
  `standby_dind`, so the image pruning added to the campaign runner does not
  protect this path. 435 ASAN binaries per ffmpeg rebuild is tens of GB. Record
  `df` output for `/src` and `/out` alongside the compile row; a build that dies on
  `No space left on device` must not read as a patch result.
- **The baseline is a stored artifact, not an execution.** `original_fuzzer_output`
  comes from `arvo.crash_output`. The comment at `:182`–`:184` explains the
  decision — running `arvo` to regenerate it can itself cause compilation errors
  that compromise the POC re-test. Preserve that decision and record it:
  `baseline_source = 'arvo.crash_output'`. The field exists so a future live
  baseline is distinguishable, not to invite one.
- **`arvo.crash_output` is not truncated, and `baseline_bytes` is therefore cut.**
  `queries.py:298`–`:300` warns that the field "is sometimes truncated ie 42513136."
  It is not. That row's log is complete at 3,648 bytes, ending in a normal
  `DEDUP_TOKEN` / `SUMMARY: AddressSanitizer` trailer. What it contains is embedded
  NUL bytes at offset 81 — binary data the target echoed
  (`/tmp/libfuzzer.8: \x00\x1b\x000057...`) — and SQLite's `length()` on TEXT stops
  at the first NUL, so it reports **81** for a 3,648-byte value. `length(CAST(x AS
  BLOB))` and a Python fetch both return 3,648.

  **Any measurement of these logs must use `length(CAST(x AS BLOB))`, never
  `length()`.** The artifact affects **99 of 6,138** `arvo` rows (1.6%) — currently
  **0 of the 60** patch-vuln baselines, but the ~107-run adjudication queue and
  future `--fill-gaps` selections can pull an affected vuln in at any time. No
  existing code trips on it: `analysis/patch_eval.py:329` reads the value into
  Python and regexes it, which is correct. `seed_repair_campaign.py:61` orders by
  `length(r.result_json)`, the one site using the pattern; 0 of the current
  `result_json` values contain a NUL, so it is latent rather than live.

  `baseline_bytes` is cut for three independent reasons: it is derivable from
  `baseline_log`; length does not indicate truncation (the 60 baselines span
  1,903–15,763 bytes, median 7,667, and **0 of 60** lack a report trailer, so there
  is no threshold to find); and computing it the obvious way would have propagated
  the NUL artifact into the schema, handing the LLM pass an "81-byte baseline,
  treat as unreliable" signal about an intact log. If a truncation check is ever
  wanted it is structural — absence of a `SUMMARY:` trailer — and computed at
  analysis time.
- **ASAN output is not byte-stable.** Addresses, PIDs and thread ids differ between
  executions of the same binary. Any comparison of baseline against patched output —
  whether by the LLM pass or a future automatic check — must normalise those first,
  or identical crashes will read as different ones. That belongs with the LLM pass,
  but the capture format should not make it harder.
- **`git` availability in arvo images is unverified.** Change 3a avoids depending on
  it. If `git apply --recount` is preferred later, confirm `git` is present across
  the image set first.
- **Applier identity is `applier_sha256`, not a commit SHA.** `is_crash_resolved` is
  a property of (patch, applier, compiler, POC), not of the agent's diff alone — the
  same 127 stored diffs yield `malformed` 14 / 13 / 0 under the three applier
  generations. So the verdict needs to name its applier. A commit SHA cannot do that
  here: the applier is routinely run from an untracked or modified file, and
  `git describe --always --dirty` reports `v0.1-24-gda78b28` — clean — while
  `diff_tools_updated.py` is untracked and absent from that commit, because
  `--dirty` only inspects tracked paths. Hashing the module actually imported is
  correct under any working-tree state. Add a commit SHA alongside it only once the
  applier is reliably committed before a verification batch.
- **`machine` omitted.** Single operator. Re-add if a second machine ever
  adjudicates, alongside the `CARO_LEDGER_MACHINE` convention the campaign runner
  already uses.
- **`patch_argv` is kept, and it is not redundant.** It looks derivable from
  `applier_sha256` plus `patch_strip`, since every other flag is a literal in the
  source. That derivation only holds while the source the hash names still exists —
  and the reason `applier_sha256` replaced a commit SHA is precisely that the
  applier is run from uncommitted files. An uncommitted file that is later edited
  leaves `applier_sha256` an orphan: it still proves two runs used identical code,
  but not what that code did. `patch_argv` is then the only surviving record that,
  say, `-F 3` was in play — the exact distinction that separates 32 fuzzy applies
  from 39. Eighty bytes to keep a verdict interpretable after the applier moves on.
  `patch_strip` is the redundant half of the pair (the argv already carries `-p0` /
  `-p1`) and is retained only as a denormalisation for grouping, the same trade
  already accepted between `patch_data` and `patch_verification`.
- **`compile_log_sha256` is cut; `compile_log_bytes` is kept.** The hash guards only
  against *post-capture* modification of `compile_log_path`, and the attempt-numbered
  filename plus `UNIQUE (run_id, attempt)` and `MAX(attempt) + 1` already prevent a
  path from being reused. It is also blind to the failure that actually threatens
  this workflow: a short write from a full disk during a 435-target build produces a
  truncated log whose hash matches it perfectly. `compile_log_bytes` catches the
  realistic cases — log missing, emptied, or implausibly small for a full rebuild —
  and is independently the measurement Verification step 1 needs.
- **Fuzz is recorded, not forbidden.** A deliberate choice: `-F 3` is removed and
  the default 2 retained, because zero-fuzz would reject patches that are correct
  against a drifted tree. The integrity claim comes from `patch_max_fuzz` being
  queryable, not from fuzz being impossible.
- **No `run_mode` change.** Verification is not a new run; it attaches to an
  existing `run_mode='patch'` row. Nothing in `runs` needs to change.
- **`dev/*.db` copies are not migrated.** The migration targets `queries.DB_PATH`
  only.

## Verification steps

1. Instrument `arvo compile` on one ffmpeg run and record actual stdout/stderr byte
   counts and wall time. Fix the extract budget and the 3600s timeout against that
   measurement rather than the estimate.
2. Run the recount over all 127 stored diffs offline and confirm the outcome table
   moves to `malformed = 0` with no run regressing from `ok` to `fail`.
3. Unit-test recount against the four shapes present in the data, expressed as the
   body's delta from the header:

   | run | delta | shape |
   |---|---|---|
   | `arvo-42541144-vul-1784216642-patch` | old −2, new −2 | body short, both sides |
   | `arvo-42532853-vul-1775168486-patch` | old +1, new +1 | body long, both sides |
   | `arvo-419085594-vul-1775194674-patch` | old 0, new −1 | body short, new side only |
   | `arvo-42540891-vul-1784232900-patch` | old 0, new 0 | already correct |

   The last must be left byte-identical. The third is the sharpest case: a
   new-side-only shortfall is exactly what the blank-line separator cannot absorb,
   because a blank line counts toward both sides — which is why that run stays
   `malformed` under `diff_tools_updated.py`.
4. Unit-test strip derivation on both header styles, asserting `-p1` for
   `a/libavcodec/mjpegdec.c` and `-p0` for `libavcodec/mpegaudio_parser.c`.
5. End-to-end on `arvo-42540891-vul-1784232900-patch`, which is known well-formed
   and known to apply: confirm one `patch_verification` row with non-NULL
   `patch_rc`, `compile_rc`, `poc_rc`, a `compile_log_path` that exists with
   `compile_log_bytes` matching it on disk, and `patch_data` mirrored.
6. End-to-end on a member of the malformed 13, e.g.
   `arvo-419085594-vul-1775194674-patch` (2 entries, 3 hunks each, one hunk per
   entry short by 1 on the new side): confirm it now applies, and that per-entry
   application produced two application records rather than one aggregate rc.
7. Kill a run during `arvo compile` and confirm the baseline and patch-application
   stages are already persisted.
8. Force a timeout with a deliberately low compile timeout and confirm
   `compile_timed_out = 1` with partial output retained.
9. Re-verify the same run twice and confirm two rows with `attempt` 1 and 2, and
   that `patch_data` reflects the second.
10. Re-run the migration and the backfill twice; assert no duplicate rows and no
    change on the second pass.
11. Re-run `analysis/patch_eval.py` and `analysis/command_analysis.py` against the
    migrated database and confirm identical output to a pre-migration run.

## Deferred — explicitly out of scope

**Automatic patch-failure reporting.** Apply failures will now be captured in
`patch_verification` with rc, applier output and the exact patch bytes, but nothing
in this plan classifies them, writes a verdict, or reports them to the ledger.
`RUN_DATA_MAP.md` Class 7 stays open. The capture is the prerequisite; the
reporting policy is a separate decision.

**Narrowing the compile to the single `fuzz_target`.** Deferred pending
verification that it does not compromise experiment accuracy. `arvo compile`
currently rebuilds all 435 decoder fuzzers to reach the one the vuln needs — for
`arvo-42540891` it was observed building `target_dec_fraps_fuzzer` while the vuln's
target is `ffmpeg_AV_CODEC_ID_JPEGLS_fuzzer`. Narrowing would cut ~30 min per run to
~1–2 min and remove the disk risk, so it is worth establishing. The accuracy
question to settle first is whether a narrowed build produces a byte-identical
target binary: build both ways for the same vuln and compare the target binary's
hash, and check whether `build.sh` performs any whole-set step — a shared archive
relink, a copy into `/out`, a post-build check — that a single-target `make` would
skip. Until that comparison exists the full rebuild is the conservative choice, and
the capture added here is what makes the comparison auditable.

## Related

- `RUN_DATA_MAP.md` Class 7 — unadjudicated patch outcomes, and why a failed apply
  is currently indistinguishable from an untested run.
- `analysis/EVALUATION_PIPELINE.md` — the NULL/0 convention and the
  self-describing-tables convention, both followed here.
- `RESUME_FIX_PROPOSAL.md` — `run_status` classification, if apply-failure labelling
  later wants a home.
