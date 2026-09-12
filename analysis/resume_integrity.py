"""resume_integrity.py

Identify localization runs that were interrupted, failed to resume, and trace
what — if anything — subsequently produced a localization report for the same
vulnerability.

Three questions, answered against ``arvo_loc_runs.db``:

1. **Which loc runs were interrupted?** A run cut off by a usage limit records
   ``result_error_flag=1`` / ``stop_reason='stop_sequence'`` and an empty
   ``result_json``. Its ``session_id`` is the handle the next attempt needs.

2. **Which resume attempts failed to attach?** A resume attempt is identifiable
   by its prompt — the sentinel ``continue where you left off``. It attached
   only if the invocation actually carried ``--resume``/``--continue`` *and* the
   returned ``session_id`` matches the one requested. A sentinel prompt with no
   resume flag is a fresh session asked to continue work it never did
   (see RESUME_FIX_PROPOSAL.md — the caro.py:155 regression).

3. **Did a localization report follow?** A report means ``result_json`` carrying
   a ``root_cause_summary`` — the structural marker. Do not test with
   ``LIKE '%LOCALIZED%'``: SQLite ``LIKE`` is case-insensitive and the patch
   prompt template contains "localized vulnerability findings", so that matches
   every full-md patch run. ``GLOB`` is case-sensitive; use it.

   Reports are looked for in three places, because a run can lose one at each
   stage: the failed-resume run itself, the interrupted run's trajectory
   (``run_events``, in case a report was emitted before the cutoff and never
   captured into ``result_json``), and any later loc run for the same vuln.

Also reports the provenance hazard: ``patch_data.loc_source`` on the paired
patch run names the loc run it drew context from, and that pointer is written
even when the named run returned ``{}``. Joining patch runs to their loc source
therefore yields a row, not a report — the emptiness is only visible by
checking the target's ``result_json``.

``--depth`` emits the session-depth table in RUN_DATA_MAP.md (Class 3), which
ranks orphaned sessions by how far the analysis actually got rather than by
turn count. Regenerate and paste it back into the map when the run set changes.

Read-only; writes nothing. Run::

    python resume_integrity.py [--db ../arvo_loc_runs.db] [--verbose]
    python resume_integrity.py --depth        # markdown table for RUN_DATA_MAP.md
"""

from __future__ import annotations

import argparse
import re
import sqlite3

DB_PATH = "../arvo_loc_runs.db"

RESUME_SENTINEL = "continue where you left off"
REPORT_MARKER = "root_cause_summary"

# Prose markers, for spotting analysis that was in flight when a run was cut
# off. These are much weaker than REPORT_MARKER and will match ordinary
# mid-trajectory reasoning, so they establish "work was underway", never
# "a report exists".
TRAJECTORY_MARKERS = ("root cause", "root_cause", "vulnerable_line", "localization report")


def requested_session(command: str | None) -> str | None:
    """The session id the invocation asked to resume, if any."""
    match = re.search(r"--resume\s+(\S+)", command or "")
    return match.group(1) if match else None


def classify(row: sqlite3.Row) -> dict:
    command = row["command"] or ""
    prompt = (row["prompt"] or "").lower()
    result_json = row["result_json"] or ""

    requested = requested_session(command)
    has_flag = requested is not None or "--continue" in command

    info = {
        "run_id": row["run_id"],
        "vuln_id": row["vuln_id"],
        "timestamp": row["timestamp"],
        "session_id": row["session_id"],
        "num_turns": row["num_turns"],
        "interrupted": row["result_error_flag"] == 1,
        "is_resume_attempt": RESUME_SENTINEL in prompt,
        "has_resume_flag": has_flag,
        "requested_session": requested,
        "has_report": REPORT_MARKER in result_json,
    }

    # A resume failed if it was attempted but the flag never made it into the
    # invocation, or the flag was there and the agent came back on a different
    # session than the one requested.
    detached = requested is not None and requested != row["session_id"]
    info["resume_failed"] = info["is_resume_attempt"] and (not has_flag or detached)
    info["failure_kind"] = (
        "no-resume-flag" if info["is_resume_attempt"] and not has_flag
        else "session-mismatch" if detached
        else None
    )
    return info


def load(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT run_id, vuln_id, timestamp, session_id, command, prompt,
               result_json, result_error_flag, num_turns
        FROM runs
        WHERE run_mode = 'loc'
        ORDER BY timestamp
        """
    ).fetchall()
    return [classify(r) for r in rows]


def trajectory_work(conn: sqlite3.Connection, run_id: str) -> tuple[int, int]:
    """(events, prose-marker hits) for a run — did analysis get underway?"""
    clauses = " OR ".join("lower(event_text) LIKE ?" for _ in TRAJECTORY_MARKERS)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS n,
               SUM(CASE WHEN {clauses} THEN 1 ELSE 0 END) AS hits
        FROM run_events WHERE run_id = ?
        """,
        [f"%{m}%" for m in TRAJECTORY_MARKERS] + [run_id],
    ).fetchone()
    return row["n"] or 0, row["hits"] or 0


def captured_report_in_trajectory(conn: sqlite3.Connection, run_id: str) -> bool:
    """Did a structured report reach run_events even if result_json is empty?"""
    row = conn.execute(
        "SELECT 1 FROM run_events WHERE run_id = ? AND event_text GLOB ? LIMIT 1",
        (run_id, f"*{REPORT_MARKER}*"),
    ).fetchone()
    return row is not None


# Depth bands, keyed on reasoning volume — the characters the agent spent in
# `thinking` events. Turn count is a poor proxy: a run can burn 20+ turns on
# file reads without forming a hypothesis, so two sessions with the same turn
# count can differ several-fold in how much analysis is actually recoverable.
# Boundaries are drawn from the observed distribution, not from theory.
DEPTH_BANDS = ((25_000, "deep"), (5_000, "substantive"), (100, "shallow"), (0, "empty"))

# Phrases an agent uses when it has finished investigating and is about to
# write the report. Only meaningful late in a trajectory — the same words
# appear early as ordinary narration, so position is part of the signal.
READY_CUES = ("final analysis", "complete understanding", "full picture", "ready to compile")

LIMITED_SQL = ("result_error_flag = 1 "
               "AND lower(coalesce(result, '')) LIKE '%hit your limit%'")


def session_depth(conn: sqlite3.Connection, run_id: str, num_turns: int) -> dict:
    """How far did the analysis actually get before the cutoff?"""
    marker_clause = " OR ".join("lower(event_text) LIKE ?" for _ in TRAJECTORY_MARKERS)
    row = conn.execute(
        f"""
        SELECT COUNT(*) AS events,
               COALESCE(SUM(CASE WHEN event_type = 'tool_use' THEN 1 ELSE 0 END), 0) AS tools,
               COALESCE(SUM(CASE WHEN event_type = 'thinking'
                                 THEN length(event_text) ELSE 0 END), 0) AS reasoning,
               COALESCE(SUM(CASE WHEN {marker_clause} THEN 1 ELSE 0 END), 0) AS markers
        FROM run_events WHERE run_id = ?
        """,
        [f"%{m}%" for m in TRAJECTORY_MARKERS] + [run_id],
    ).fetchone()

    band = next(name for floor, name in DEPTH_BANDS if row["reasoning"] >= floor)

    # A readiness cue counts only in the last quarter of the trajectory.
    events = row["events"] or 0
    ready = False
    if events:
        threshold = events * 0.75
        for event in conn.execute(
            "SELECT event_num, event_text FROM run_events WHERE run_id = ? ORDER BY event_num",
            (run_id,),
        ):
            text = (event["event_text"] or "").lower()
            if event["event_num"] >= threshold and any(c in text for c in READY_CUES):
                ready = True
                break

    return {
        "run_id": run_id, "turns": num_turns, "events": events,
        "tools": row["tools"], "reasoning": row["reasoning"],
        "markers": row["markers"], "band": band, "ready": ready,
    }


def depth_table(conn: sqlite3.Connection) -> None:
    """Markdown table of orphaned loc sessions, ranked by recoverable analysis."""
    rows = conn.execute(
        f"""
        SELECT run_id, session_id, num_turns FROM runs
        WHERE run_mode = 'loc' AND {LIMITED_SQL}
          AND session_id IS NOT NULL AND session_id <> ''
        ORDER BY timestamp
        """
    ).fetchall()

    depths = [dict(session_depth(conn, r["run_id"], r["num_turns"]),
                   session=r["session_id"]) for r in rows]
    depths.sort(key=lambda d: d["reasoning"], reverse=True)

    print("| loc run | session | turns | reasoning | markers | depth |")
    print("|---|---|---|---|---|---|")
    for d in depths:
        band = f"**{d['band']}** — report-ready" if d["ready"] else d["band"]
        print(f"| `{d['run_id']}` | `{d['session']}` | {d['turns']} | "
              f"{d['reasoning']:,} | {d['markers']} | {band} |")

    print()
    counts: dict[str, int] = {}
    for d in depths:
        counts[d["band"]] = counts.get(d["band"], 0) + 1
    print("Bands by reasoning characters: " + ", ".join(
        f"{name} ≥ {floor:,}" for floor, name in DEPTH_BANDS if floor) + ", empty otherwise.")
    print("Distribution: " + ", ".join(f"{k} {v}" for k, v in counts.items()) + ".")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=DB_PATH)
    parser.add_argument("--verbose", action="store_true",
                        help="show interrupted runs that were never resumed at all")
    parser.add_argument("--depth", action="store_true",
                        help="emit the Class 3 session-depth table as markdown")
    args = parser.parse_args()

    if args.depth:
        conn = sqlite3.connect(args.db)
        conn.row_factory = sqlite3.Row
        depth_table(conn)
        conn.close()
        return

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    runs = load(conn)

    by_vuln: dict[int, list[dict]] = {}
    for run in runs:
        by_vuln.setdefault(run["vuln_id"], []).append(run)

    failed = [r for r in runs if r["resume_failed"]]
    interrupted = [r for r in runs if r["interrupted"]]

    print(f"loc runs: {len(runs)}   interrupted: {len(interrupted)}   "
          f"failed resumes: {len(failed)}")
    print()

    print("=" * 78)
    print("Interrupted -> failed resume -> did a report follow?")
    print("=" * 78)

    for run in failed:
        siblings = by_vuln[run["vuln_id"]]
        lost = [s for s in siblings
                if s["timestamp"] < run["timestamp"] and s["interrupted"]]
        later = [s for s in siblings if s["timestamp"] > run["timestamp"]]
        later_reports = [s for s in later if s["has_report"]]

        print(f"\n{run['run_id']}  ({run['failure_kind']})")
        if lost:
            orphan = lost[-1]
            events, hits = trajectory_work(conn, orphan["run_id"])
            recoverable = captured_report_in_trajectory(conn, orphan["run_id"])
            print(f"  orphaned session : {orphan['run_id']}")
            print(f"                     {orphan['session_id']}  "
                  f"{orphan['num_turns']} turns, {events} events, "
                  f"{hits} analysis markers")
            print(f"  report in that trajectory: "
                  f"{'YES - recoverable' if recoverable else 'no'}")
        print(f"  report from this run     : "
              f"{'YES' if run['has_report'] else 'no (empty result_json)'}")
        print(f"  later loc report for vuln: "
              f"{', '.join(s['run_id'] for s in later_reports) or 'NONE'}")

        # The paired patch run's recorded provenance.
        patch_id = run["run_id"].replace("-loc", "-patch")
        row = conn.execute(
            "SELECT loc_source FROM patch_data WHERE run_id = ?", (patch_id,)
        ).fetchone()
        if row:
            source = row["loc_source"]
            src = next((s for s in runs if s["run_id"] == source), None)
            state = ("empty" if src and not src["has_report"]
                     else "has report" if src else "unknown run")
            print(f"  paired patch provenance  : {patch_id}")
            print(f"                             loc_source={source} [{state}]")

    if args.verbose:
        print()
        print("=" * 78)
        print("Interrupted, no resume attempted — work abandoned, then rerun fresh")
        print("=" * 78)
        for run in interrupted:
            siblings = by_vuln[run["vuln_id"]]
            later = [s for s in siblings if s["timestamp"] > run["timestamp"]]
            if any(s["resume_failed"] for s in later):
                continue  # already covered above
            reports = [s["run_id"] for s in later if s["has_report"]]
            print(f"  {run['run_id']:<42} {run['num_turns']:>3} turns lost -> "
                  f"{', '.join(reports) or 'NEVER REPORTED'}")

    conn.close()


if __name__ == "__main__":
    main()
