"""prepare_analysis_set.py

Build the analysis set: the subset of runs that actually represent their
experimental condition, with exactly one unit per vulnerability per arm.

The `runs` table is an operational log, not an analysis set. It records every
attempt, including ones destroyed by usage limits, failed resumes, expired
tokens and prompt-template drift. Counting it directly overstates the work and
mixes conditions. This script derives an analysis layer from it and leaves the
log untouched.

Two tables, rebuilt on every invocation:

* ``run_status``     - one row per run: what happened to it, and why it is or
  is not usable. Every run gets a row, including untagged pre-campaign work.
* ``analysis_units`` - one row per (vuln, arm) that has a usable unit, naming
  the loc and patch runs to analyse. This is what analysis should join to.

**Unit definitions.** The two arms have different shapes:

* ``discrete-loc-patch-pairs-fullmd`` - a unit is a localization run and a
  patch run that received its findings. Context reaches the patch run one of
  two ways: interpolated into the prompt (``prompt`` contains
  ``root_cause_summary``), or carried in session history on a resumed patch
  run (``--resume`` in the command). Both are valid; a resumed patch run has
  no loc sibling in its own invocation because the loc stage ran in the
  attempt that was interrupted.
* ``baseline-patch-envmd`` - patch-only by design; a unit is one patch run.
  Runs citing ``patch_agent.md`` instead of ``patch_agent_env.md`` received a
  materially richer persona than the arm defines and are excluded.

A run "produced its artifact" when ``result_json`` carries ``root_cause_summary``
(loc) or ``diff`` (patch). Use ``GLOB``, not ``LIKE``: SQLite ``LIKE`` is
case-insensitive and the patch template contains the phrase "localized
vulnerability findings", so ``LIKE '%LOCALIZED%'`` matches every full-md patch
run whether or not it received anything.

**Selection.** When a vuln has more than one usable unit in an arm, the
earliest is taken by default. Choosing the latest would bias toward vulns that
got extra attempts, which is a best-of-N effect rather than a condition
effect. ``--select last`` is available for comparison but is not the default.

**The gap report** lists (vuln, arm) with no usable unit. That is the rerun
scope, and it is the reason this script runs *before* seeding any repair
campaign: a vuln whose pair completed intact needs no rerun even when the same
vuln also carries several wrecked attempts.

Order of operations::

    python prepare_analysis_set.py                 # dry run: counts + gaps
    python prepare_analysis_set.py --apply         # write the two tables
    # ... rerun the gaps, then re-run with --apply; it is idempotent ...
    python prepare_analysis_set.py --apply         # picks up the new runs

Run::

    python prepare_analysis_set.py [--db ../arvo_loc_runs.db] [--apply]
                                   [--select first|last] [--verbose]
"""

from __future__ import annotations

import argparse
import re
import sqlite3
from collections import defaultdict

DB_PATH = "../arvo_loc_runs.db"

FULL_MD = "discrete-loc-patch-pairs-fullmd"
BASELINE = "baseline-patch-envmd"

REPORT_MARKER = "root_cause_summary"
DIFF_MARKER = "diff"

# The baseline arm is defined by patch_agent_env.md, an environment-only
# persona. A prompt citing the full patch_agent.md is a different condition.
BASELINE_PERSONA = "patch_agent_env.md"
CONTAMINANT_PERSONA = "patch_agent.md"

RESUME_SENTINEL = "continue where you left off"


def stem(run_id: str) -> str:
    """The invocation a run belongs to: 'arvo-<vuln>-vul-<epoch>[-loc|-patch]'."""
    match = re.match(r"^(.*?)-(?:loc|patch)$", run_id)
    return match.group(1) if match else run_id


def context_source(run: dict) -> str:
    """How localization findings reached a patch run, if at all."""
    if REPORT_MARKER in (run["prompt"] or ""):
        return "prompt"
    if "--resume" in (run["command"] or "") or "--continue" in (run["command"] or ""):
        return "session"
    return "none"


def classify_run(run: dict) -> dict:
    """Status and evidence flags for one run."""
    result = (run["result"] or "").lower()
    result_json = run["result_json"] or ""
    errored = run["result_error_flag"] == 1

    has_report = REPORT_MARKER in result_json
    has_diff = DIFF_MARKER in result_json
    produced = has_report if run["run_mode"] == "loc" else has_diff

    if errored and "hit your limit" in result:
        status = "usage_limited"
    elif errored and "failed to authenticate" in result:
        status = "auth_failed"
    elif errored:
        status = "error"
    elif produced:
        status = "complete"
    elif RESUME_SENTINEL in (run["prompt"] or "").lower() and \
            not ("--resume" in (run["command"] or "") or "--continue" in (run["command"] or "")):
        # asked to continue a session it was never attached to; recorded as a
        # success with an empty payload, so it must not count as a completed run
        status = "resume_failed"
    else:
        status = "empty"

    contaminated = (run["experiment_tag"] == BASELINE
                    and CONTAMINANT_PERSONA in (run["prompt"] or "")
                    and BASELINE_PERSONA not in (run["prompt"] or ""))

    return {
        "run_id": run["run_id"],
        "vuln_id": run["vuln_id"],
        "experiment_tag": run["experiment_tag"],
        "run_mode": run["run_mode"],
        "timestamp": run["timestamp"],
        "status": status,
        "has_report": int(has_report),
        "has_diff": int(has_diff),
        "context_source": context_source(run) if run["run_mode"] == "patch" else None,
        "contaminated": int(contaminated),
    }


def find_units(runs: list[dict], statuses: dict[str, dict], select: str) -> tuple[dict, dict]:
    """Return (selected units, all candidate units) keyed by (vuln_id, arm)."""
    by_stem: dict[str, dict] = defaultdict(dict)
    for run in runs:
        by_stem[stem(run["run_id"])][run["run_mode"]] = run

    candidates: dict[tuple, list] = defaultdict(list)
    for unit_stem, parts in by_stem.items():
        patch = parts.get("patch")
        if patch is None:
            continue  # a loc run with no patch stage is not a unit in either arm
        arm = patch["experiment_tag"]
        loc = parts.get("loc")
        patch_status = statuses[patch["run_id"]]

        if arm == FULL_MD:
            source = patch_status["context_source"]
            loc_complete = loc is not None and statuses[loc["run_id"]]["status"] == "complete"
            # 'prompt' needs a completed loc run in the same invocation;
            # 'session' carries its context in the resumed conversation
            usable = (patch_status["status"] == "complete"
                      and (source == "prompt" and loc_complete or source == "session"))
        elif arm == BASELINE:
            source = None
            usable = (patch_status["status"] == "complete"
                      and not patch_status["contaminated"])
        else:
            continue  # untagged: no recorded condition, cannot sit in an arm

        if usable:
            candidates[(patch["vuln_id"], arm)].append({
                "vuln_id": patch["vuln_id"], "experiment_tag": arm,
                "unit_stem": unit_stem,
                "loc_run_id": loc["run_id"] if loc else None,
                "patch_run_id": patch["run_id"],
                "context_source": source,
                "timestamp": patch["timestamp"],
            })

    selected = {}
    for key, options in candidates.items():
        options.sort(key=lambda u: u["timestamp"])
        chosen = options[-1] if select == "last" else options[0]
        selected[key] = dict(chosen, discarded_units=len(options) - 1)
    return selected, candidates


def write_tables(conn: sqlite3.Connection, statuses: dict, units: dict) -> None:
    conn.execute("DROP TABLE IF EXISTS run_status")
    conn.execute("""
        CREATE TABLE run_status (
            run_id         TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
            vuln_id        INTEGER,
            experiment_tag TEXT,
            run_mode       TEXT,
            timestamp      TEXT,
            status         TEXT,
            has_report     INTEGER,
            has_diff       INTEGER,
            context_source TEXT,
            contaminated   INTEGER
        )""")
    conn.executemany(
        "INSERT INTO run_status VALUES (:run_id, :vuln_id, :experiment_tag, :run_mode, "
        ":timestamp, :status, :has_report, :has_diff, :context_source, :contaminated)",
        list(statuses.values()))

    conn.execute("DROP TABLE IF EXISTS analysis_units")
    conn.execute("""
        CREATE TABLE analysis_units (
            vuln_id         INTEGER,
            experiment_tag  TEXT,
            unit_stem       TEXT,
            loc_run_id      TEXT,
            patch_run_id    TEXT,
            context_source  TEXT,
            timestamp       TEXT,
            discarded_units INTEGER,
            PRIMARY KEY (vuln_id, experiment_tag)
        )""")
    conn.executemany(
        "INSERT INTO analysis_units VALUES (:vuln_id, :experiment_tag, :unit_stem, "
        ":loc_run_id, :patch_run_id, :context_source, :timestamp, :discarded_units)",
        list(units.values()))
    conn.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--apply", action="store_true",
                        help="write run_status and analysis_units (default is a dry run)")
    parser.add_argument("--select", choices=("first", "last"), default="first",
                        help="which unit to take when a vuln has more than one (default: first)")
    parser.add_argument("--verbose", action="store_true", help="list the gap runs")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    runs = [dict(r) for r in conn.execute("""
        SELECT r.run_id, r.vuln_id, r.timestamp, r.run_mode, r.result, r.result_json,
               r.result_error_flag, r.prompt, r.command, e.experiment_tag
        FROM runs r LEFT JOIN experiments e ON e.experiment_id = r.experiment_id
        ORDER BY r.timestamp
    """)]

    statuses = {run["run_id"]: classify_run(run) for run in runs}
    units, candidates = find_units(runs, statuses, args.select)

    counts: dict[str, int] = defaultdict(int)
    for s in statuses.values():
        counts[s["status"]] += 1
    print(f"runs: {len(runs)}")
    for status, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {status:<15} {n}")

    print(f"\nanalysis units (select={args.select}):")
    for arm in (FULL_MD, BASELINE):
        got = {k[0] for k in units if k[1] == arm}
        print(f"  {arm:<34} {len(got)} vulns")
    full = {k[0] for k in units if k[1] == FULL_MD}
    base = {k[0] for k in units if k[1] == BASELINE}
    print(f"  {'matched (both arms)':<34} {len(full & base)} vulns")

    # gaps: a vuln that has runs in an arm but no usable unit there
    attempted: dict[str, set] = defaultdict(set)
    for run in runs:
        if run["experiment_tag"] in (FULL_MD, BASELINE):
            attempted[run["experiment_tag"]].add(run["vuln_id"])
    print("\ngaps — no usable unit, needs a rerun:")
    total_gap = 0
    for arm in (FULL_MD, BASELINE):
        missing = sorted(attempted[arm] - {k[0] for k in units if k[1] == arm})
        total_gap += len(missing)
        print(f"  {arm} ({len(missing)}):")
        for vuln in missing:
            print(f"    {vuln}")
    if not total_gap:
        print("  none — every attempted vuln has a usable unit in its arm.")

    untagged = sum(1 for s in statuses.values() if s["experiment_tag"] is None)
    print(f"\nexcluded from arms: {untagged} untagged runs (no recorded condition)")

    if args.apply:
        write_tables(conn, statuses, units)
        print(f"\nwrote run_status ({len(statuses)} rows) and "
              f"analysis_units ({len(units)} rows).")
    else:
        print("\nDry run — re-run with --apply to write the tables.")
    conn.close()


if __name__ == "__main__":
    main()
