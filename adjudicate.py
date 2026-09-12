"""Adjudicate captured patch verification attempts.

    python adjudicate.py --status     # what the proposal rules make of each run
    python adjudicate.py --auto       # confirm the unambiguous ones in bulk
    python adjudicate.py --review     # work the exception queue interactively
    python adjudicate.py --run-id <id>

Reads only the database, so it needs neither docker nor the artifact files and
can run anywhere, including while a batch is still executing.

The outcome is three-way. `poc_rc` separates clean from crashing perfectly, but
cannot tell the reported bug reproducing from a *new* bug appearing -- and that
is the distinction that decides whether a patch fixed what it was aimed at.
`DEDUP_TOKEN` makes it: it names the top stack frames rather than addresses, so
it is stable across executions where addresses, pids and thread ids are not.

See BATCH_VERIFICATION_PROPOSAL.md Phase 3 for the measurements behind the rules.
"""
import argparse
import getpass
import logging
import re
import sqlite3
import sys
from datetime import datetime, timezone

from queries import DB_PATH, update_patch_crash_results, update_patch_verification

logger = logging.getLogger(__name__)

# Bump when the rules change, so automatic verdicts stay attributable and a whole
# generation of them can be found and revisited.
RULE_VERSION = 'auto:v1'

ANSI = re.compile(r'\x1b\[[0-9;]*m')
DEDUP = re.compile(r'DEDUP_TOKEN:\s*(.+)')
SUMMARY = re.compile(r'SUMMARY:\s*\w+Sanitizer:\s*(.+)')

CLEAN = 'clean'
SAME = 'same_crash'
DIFFERENT = 'different_crash'
UNDETERMINED = 'undetermined'


def strip_ansi(text):
    return ANSI.sub('', text or '')


def dedup_token(text):
    """The sanitizer's own crash identity: top frames, no addresses."""
    m = DEDUP.search(strip_ansi(text))
    return m.group(1).strip() if m else None


def summary_line(text):
    m = SUMMARY.search(strip_ansi(text))
    return m.group(1).strip() if m else None


def poc_text(row):
    return (row['poc_stdout'] or '') + (row['poc_stderr'] or '')


def propose(row):
    """Derive (crash_outcome, is_crash_resolved, auto_ok, reasons) from a row.

    Pure over the stored fields so the rules are testable without a database.
    auto_ok means every signal agrees *and* the patch applied at fuzz 0 -- a
    hunk applied with context discarded may not have landed where the agent
    intended, so even a clean POC does not settle it.
    """
    reasons = []

    if row['patch_rc']:
        return UNDETERMINED, None, False, ['patch did not apply; there is no POC to judge']

    if row['compile_timed_out']:
        return UNDETERMINED, None, False, ['compile timed out; the POC never ran']

    if row['compile_rc']:
        dur = row['compile_duration_s'] or 0
        if dur < 5:
            return UNDETERMINED, None, False, [
                "arvo's own build.sh failed before compiling (harness patch "
                "re-applied to an image that already has it); not the agent's patch"]
        return UNDETERMINED, None, False, [f"compile failed (rc={row['compile_rc']})"]

    if row['poc_timed_out']:
        return UNDETERMINED, None, False, ['POC timed out']

    if row['poc_rc'] is None:
        return UNDETERMINED, None, False, ['no POC result recorded']

    p = poc_text(row)
    b_tok = dedup_token(row['baseline_log'])
    p_tok = dedup_token(p)
    clean_rc = (row['poc_rc'] == 0)

    # Signals must agree. A crash with no token, or a token with rc=0, means the
    # output is a shape these rules were not built on -- defer rather than guess.
    if clean_rc and p_tok:
        return UNDETERMINED, None, False, [
            'poc_rc=0 but the output carries a DEDUP_TOKEN; signals disagree']
    if not clean_rc and not p_tok:
        return UNDETERMINED, None, False, [
            f'poc_rc={row["poc_rc"]} but no DEDUP_TOKEN in the output; signals disagree']

    if clean_rc:
        outcome, resolved = CLEAN, True
        reasons.append('POC ran to completion with no sanitizer report')
    elif b_tok and p_tok == b_tok:
        outcome, resolved = SAME, False
        reasons.append('the baseline crash reproduces (DEDUP_TOKEN matches)')
    else:
        # The reported bug is gone but the POC still crashes somewhere else.
        # Whether that counts as resolved is a judgement, not a rule.
        outcome, resolved = DIFFERENT, None
        reasons.append('a different crash than the baseline (DEDUP_TOKEN differs)')
        if not b_tok:
            reasons.append('baseline has no DEDUP_TOKEN to compare against')

    auto_ok = outcome in (CLEAN, SAME)
    if auto_ok and row['patch_max_fuzz']:
        auto_ok = False
        reasons.append(f"applied at fuzz {row['patch_max_fuzz']}: that much context "
                       f"was discarded, so the patch may not have landed as written")
    return outcome, resolved, auto_ok, reasons


# --- persistence ------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def record(conn, row, outcome, resolved, by, note=None):
    """Write the verdict and the evidence it rested on, and mirror the boolean
    into patch_data so the analysis/ scripts keep working unchanged."""
    update_patch_verification(row['verification_id'], {
        'crash_outcome': outcome,
        'is_crash_resolved': resolved,
        'baseline_dedup_token': dedup_token(row['baseline_log']),
        'poc_dedup_token': dedup_token(poc_text(row)),
        'adjudicated_by': by,
        'adjudicated_at': _now(),
        'adjudication_note': note,
    }, conn=conn)

    if resolved is not None:
        update_patch_crash_results(
            run_id=row['run_id'],
            is_crash_resolved=resolved,
            patch_crash_log=poc_text(row),
            compile_errors=row['compile_output_extract'],
            conn=conn,
        )


SELECT = '''
    SELECT v.*, a.project, a.crash_type, a.fuzz_target
    FROM patch_verification v
    JOIN runs r ON r.run_id = v.run_id
    LEFT JOIN arvo a ON a.localId = r.vuln_id
    WHERE v.attempt > 0 {extra}
    ORDER BY v.run_id, v.attempt
'''


def fetch(conn, run_id=None, include_adjudicated=False):
    extra = '' if include_adjudicated else 'AND v.is_crash_resolved IS NULL'
    if run_id:
        extra += ' AND v.run_id = ?'
        return conn.execute(SELECT.format(extra=extra), (run_id,)).fetchall()
    return conn.execute(SELECT.format(extra=extra)).fetchall()


# --- presentation -----------------------------------------------------------

def show(row, outcome, resolved, reasons):
    p = poc_text(row)
    print('\n' + '=' * 78)
    print(f"{row['run_id']}   attempt {row['attempt']}   "
          f"{row['project'] or '?'} / {row['fuzz_target'] or '?'}")
    print('=' * 78)
    print(f"  proposed        : {outcome}"
          + (f"  (is_crash_resolved={resolved})" if resolved is not None else ''))
    for r in reasons:
        print(f"    - {r}")
    print(f"  patch           : rc={row['patch_rc']}  strip=-p{row['patch_strip']}  "
          f"hunks {row['patch_hunks_ok']} ok / {row['patch_hunks_failed']} failed  "
          f"fuzz={row['patch_max_fuzz']}  recounted={row['patch_recounted']}")
    print(f"  compile         : rc={row['compile_rc']}  "
          f"{row['compile_duration_s']}s  {row['compile_log_bytes']} bytes")
    print(f"  poc             : rc={row['poc_rc']}  {row['poc_duration_s']}s  "
          f"{len(p)} bytes")
    print(f"  baseline crash  : {summary_line(row['baseline_log']) or '(none)'}")
    print(f"  patched crash   : {summary_line(p) or '(none)'}")
    print(f"  baseline token  : {dedup_token(row['baseline_log']) or '(none)'}")
    print(f"  patched  token  : {dedup_token(p) or '(none)'}")
    if row['compile_verified'] is not None:
        print(f"  LLM compile check: {row['compile_verified']}  "
              f"{row['compile_verdict_note'] or ''}")
    if row['patch_max_fuzz']:
        print('\n  --- patch application (fuzz > 0, check where it landed) ---')
        for line in (row['patch_stdout'] or '').splitlines():
            if 'Hunk' in line or 'patching file' in line or line.startswith('==='):
                print('    ' + line)
    if row['transcript_path']:
        print(f"\n  transcript: {row['transcript_path']}")
        print(f"  compile log: {row['compile_log_path']}")


# --- modes ------------------------------------------------------------------

def cmd_status(conn, args):
    rows = fetch(conn, args.run_id, include_adjudicated=True)
    from collections import Counter
    done, pending, auto, manual = Counter(), Counter(), 0, 0
    for row in rows:
        if row['is_crash_resolved'] is not None or row['crash_outcome']:
            done[row['crash_outcome'] or 'recorded (pre-Phase-3)'] += 1
            continue
        outcome, resolved, auto_ok, _ = propose(row)
        pending[outcome] += 1
        auto += auto_ok
        manual += (not auto_ok)
    print(f'{len(rows)} captured attempts\n')
    if done:
        print('already adjudicated:')
        for k, v in done.most_common():
            print(f'   {k:<24} {v}')
        print()
    print('pending:')
    for k, v in pending.most_common():
        print(f'   {k:<24} {v}')
    print(f'\n   auto-confirmable : {auto}')
    print(f'   needs review     : {manual}')
    return 0


def cmd_auto(conn, args):
    rows = fetch(conn, args.run_id)
    n = 0
    for row in rows:
        outcome, resolved, auto_ok, reasons = propose(row)
        if not auto_ok:
            continue
        if args.dry_run:
            print(f'would record {outcome:<12} {row["run_id"]}')
        else:
            record(conn, row, outcome, resolved, RULE_VERSION,
                   note='; '.join(reasons))
            logger.info(f'{row["run_id"]}: {outcome} (auto)')
        n += 1
    print(f'{"would confirm" if args.dry_run else "confirmed"} {n} attempt(s) '
          f'as {RULE_VERSION}')
    if not args.dry_run and n:
        print('re-run with --review to work the remainder')
    return 0


def cmd_review(conn, args):
    rows = [r for r in fetch(conn, args.run_id)
            if not propose(r)[2] or args.all]
    if not rows:
        print('nothing to review')
        return 0
    print(f'{len(rows)} attempt(s) to review')
    for i, row in enumerate(rows, 1):
        if args.limit and i > args.limit:
            print(f'\nstopping at --limit {args.limit}')
            break
        outcome, resolved, _, reasons = propose(row)
        show(row, outcome, resolved, reasons)
        while True:
            opts = '[s]uccess  [u]nsuccessful  [k]ip  [q]uit'
            if resolved is not None:
                opts = f'[a]ccept ({outcome})  ' + opts
            choice = input(f'\n  {i}/{len(rows)}  {opts}: ').strip().lower()
            if choice == 'a' and resolved is not None:
                note = input('  note (optional): ').strip() or '; '.join(reasons)
                record(conn, row, outcome, resolved, getpass.getuser(), note)
                print(f'  recorded {outcome}')
                break
            if choice in ('s', 'u'):
                res = (choice == 's')
                note = input('  note (optional): ').strip() or None
                record(conn, row, outcome if outcome != UNDETERMINED else outcome,
                       res, getpass.getuser(), note)
                print(f'  recorded is_crash_resolved={res} (outcome {outcome})')
                break
            if choice == 'k':
                print('  skipped')
                break
            if choice == 'q':
                print('  stopping')
                return 0
            print('  invalid choice')
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--status', action='store_true', help='report, change nothing')
    mode.add_argument('--auto', action='store_true',
                      help='record verdicts where every signal agrees and fuzz is 0')
    mode.add_argument('--review', action='store_true',
                      help='work the exception queue interactively')
    p.add_argument('--run-id', help='restrict to one run')
    p.add_argument('--limit', type=int, help='stop after N runs (review)')
    p.add_argument('--all', action='store_true',
                   help='review every pending attempt, not just the exceptions')
    p.add_argument('--dry-run', action='store_true', help='--auto without writing')
    p.add_argument('--db', default=DB_PATH)
    args = p.parse_args(argv)

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        if args.status:
            return cmd_status(conn, args)
        if args.auto:
            return cmd_auto(conn, args)
        return cmd_review(conn, args)
    finally:
        conn.close()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('adjudicate.log'),
                  logging.StreamHandler(sys.stdout)],
    )
    sys.exit(main())
