"""Run a list of patch runs through diff_tools.py unattended.

Captures every artifact and enters no verdict; adjudication is a later pass over
the saved transcripts and compile logs. See BATCH_VERIFICATION_PROPOSAL.md.

    python verify_batch.py --ids-file phase1_batch.txt
    python verify_batch.py --ids arvo-... arvo-...
    python verify_batch.py --from-queue --dry-run
    python verify_batch.py --status
    python verify_batch.py --collect-artifacts ./for_llm

Runs are ordered by vuln id so each ~14 GB arvo image is pulled once and reused
by every queued run that shares it, then removed when the vuln changes. Serial,
resumable, and safe to interrupt: each diff_tools stage commits as it completes.
"""
import argparse
import itertools
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from arvo_tools import prune_host_images, run_command
from queries import DB_PATH

logger = logging.getLogger(__name__)

RUNS_DIR = Path('runs')
LOCK_PATH = RUNS_DIR / '.verify_batch.lock'

DEFAULT_COMPILE_TIMEOUT = 3600
DEFAULT_POC_TIMEOUT = 120
# Outer bound, independent of diff_tools' internal timeouts holding.
DEFAULT_RUN_SLACK = 1800
# Consecutive infrastructure failures before giving up on the batch.
DEFAULT_ABORT_AFTER = 3

# A compile that died for an environmental reason rather than because the patch
# was bad. These trip the circuit breaker; an ordinary bad-patch compile failure
# does not.
INFRA_PATTERNS = re.compile(
    r'No space left on device|Cannot connect to the Docker daemon|'
    r'device or resource busy|Out of memory|Killed|'
    r'failed to register layer|no such host', re.I)

# Outcomes that are results, not faults. A patch that does not apply is a real
# experimental outcome and must not stop the batch.
RESULT_OUTCOMES = {'artifacts_ready', 'patch_failed', 'compile_failed', 'poc_timeout'}


# --- lock -------------------------------------------------------------------

def _acquire_lock(lock_path: Path) -> None:
    """Mirrors run_experiments._acquire_lock so the two behave alike."""
    if lock_path.exists():
        raise SystemExit(
            f'Another batch appears to be active (lock: {lock_path}, '
            f'pid {lock_path.read_text().strip()}). Delete the lock file if it '
            f'is stale.')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(str(os.getpid()))


def _release_lock(lock_path: Path) -> None:
    if lock_path.exists():
        lock_path.unlink()


# --- run selection ----------------------------------------------------------

def class1_paired_patch_runs(conn) -> list:
    """Patch runs paired with a RUN_DATA_MAP.md Class 1 broken resume.

    Derived rather than hardcoded, using RESUME_FIX_PROPOSAL.md's detector: a loc
    run carrying the resume sentinel with neither --resume nor --continue in its
    recorded command, and an empty result. Reproduces the documented Class 1 set
    exactly, and stays correct if more broken resumes surface.

    The loc and patch runs of one invocation share the stem
    arvo-<vuln>-vul-<timestamp>-, which patch_data.loc_source confirms.
    """
    loc = [r[0] for r in conn.execute("""
        SELECT run_id FROM runs
        WHERE run_mode = 'loc'
          AND prompt = 'continue where you left off'
          AND command NOT LIKE '%--resume%'
          AND command NOT LIKE '%--continue%'
          AND (result_json IS NULL OR TRIM(result_json) = '{}')
    """)]
    return [r[:-4] + '-patch' for r in loc]


def queue_from_db(conn) -> list:
    """The Phase 1 filter: completed patch runs that produced a diff, carry no
    verification data in patch_data, and are not paired with a Class 1 resume."""
    excluded = class1_paired_patch_runs(conn)
    ph = ','.join('?' for _ in excluded) or "''"
    rows = conn.execute(f"""
        SELECT r.run_id
        FROM runs r
        JOIN patch_data p ON p.run_id = r.run_id
        WHERE r.run_mode = 'patch'
          AND r.result_error_flag = 0
          AND r.result_json GLOB '*diff*'
          AND p.is_crash_resolved IS NULL
          AND p.patch_crash_log  IS NULL
          AND p.compile_errors   IS NULL
          AND r.run_id NOT IN ({ph})
    """, excluded).fetchall()
    return [r[0] for r in rows]


def read_ids_file(path: Path) -> list:
    out = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            out.append(line)
    return out


def order_by_vuln(conn, run_ids: list) -> list:
    """(vuln_id, run_id) ordered so each vuln's runs are contiguous."""
    pairs = []
    for rid in run_ids:
        row = conn.execute('SELECT vuln_id FROM runs WHERE run_id = ?', (rid,)).fetchone()
        if row is None:
            logger.warning(f'{rid}: no such run, skipping')
            continue
        pairs.append((row[0], rid))
    pairs.sort()
    return pairs


# --- resume + outcome -------------------------------------------------------

def already_done(conn, run_id: str) -> bool:
    """A run is finished for batch purposes once an attempt reached a terminal
    state. attempt > 0 excludes the pre-capture backfill rows, which carry
    poc_stdout but no poc_rc and would otherwise read as completed work."""
    return conn.execute("""
        SELECT 1 FROM patch_verification
        WHERE run_id = ? AND attempt > 0
          AND (poc_rc IS NOT NULL
            OR poc_timed_out = 1
            OR patch_rc != 0
            OR (compile_rc IS NOT NULL AND compile_rc != 0))
        LIMIT 1
    """, (run_id,)).fetchone() is not None


def classify(conn, run_id: str, timed_out: bool) -> tuple:
    """Outcome from the database, not the exit code: diff_tools returning 1 for a
    patch that does not apply is a recorded result, not a batch error.

    Returns (outcome, is_infra_failure).
    """
    if timed_out:
        return 'driver_timeout', True

    row = conn.execute("""
        SELECT patch_rc, compile_rc, compile_timed_out, poc_rc, poc_timed_out,
               compile_output_extract
        FROM patch_verification
        WHERE run_id = ? AND attempt > 0
        ORDER BY attempt DESC LIMIT 1
    """, (run_id,)).fetchone()

    if row is None:
        return 'no_row', True

    patch_rc, compile_rc, compile_to, poc_rc, poc_to, extract = row

    if poc_rc is not None:
        return 'artifacts_ready', False
    if poc_to == 1:
        return 'poc_timeout', False
    if patch_rc is not None and patch_rc != 0:
        return 'patch_failed', False
    if compile_to == 1:
        return 'compile_failed', False
    if compile_rc is not None and compile_rc != 0:
        # Distinguish "this patch does not build" from "the machine is broken".
        infra = bool(INFRA_PATTERNS.search(extract or ''))
        return ('infra_failed' if infra else 'compile_failed'), infra
    return 'no_row', True


# --- execution --------------------------------------------------------------

def run_one(run_id: str, args) -> bool:
    """Invoke diff_tools.py for one run. Returns True if it hit the outer bound."""
    run_command(['docker', 'rm', '-f', run_id], check=False,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    cmd = [sys.executable, 'diff_tools.py',
           '--patch-run-id', run_id,
           '--no-adjudicate',
           '--compile-timeout', str(args.compile_timeout),
           '--poc-timeout', str(args.poc_timeout)]
    outer = args.run_timeout or (args.compile_timeout + args.poc_timeout + DEFAULT_RUN_SLACK)

    logger.info(f'--> {run_id} (outer timeout {outer}s)')
    started = time.monotonic()
    try:
        subprocess.run(cmd, timeout=outer)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        logger.error(f'{run_id}: exceeded the outer bound of {outer}s; killing')
        run_command(['docker', 'rm', '-f', run_id], check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    logger.info(f'<-- {run_id} in {time.monotonic() - started:.0f}s')
    return timed_out


def run_batch(pairs: list, args, conn) -> dict:
    from collections import Counter
    counts = Counter()
    consecutive_infra = 0
    executed = 0
    current_vuln = None

    for vuln_id, run_id in pairs:
        if args.max_runs is not None and executed >= args.max_runs:
            logger.info(f'Reached --max-runs {args.max_runs}; stopping')
            break

        if not args.force and already_done(conn, run_id):
            logger.info(f'skip {run_id} (already has artifacts)')
            counts['skipped'] += 1
            continue

        # Vuln changed: the previous image will not be needed again, because the
        # ordering guarantees each vuln's runs are contiguous.
        if current_vuln is not None and vuln_id != current_vuln and not args.no_prune:
            prune_host_images(keep_vuln_id=vuln_id)
        current_vuln = vuln_id

        timed_out = run_one(run_id, args)
        executed += 1

        outcome, infra = classify(conn, run_id, timed_out)
        counts[outcome] += 1
        logger.info(f'{run_id}: {outcome}')

        if infra:
            consecutive_infra += 1
            if consecutive_infra >= args.abort_after:
                logger.error(
                    f'{consecutive_infra} consecutive infrastructure failures '
                    f'({outcome}); aborting the batch. Fix the cause and re-run '
                    f'-- completed runs are skipped on resume.')
                counts['aborted'] = 1
                break
        else:
            consecutive_infra = 0

    if not args.no_prune and current_vuln is not None:
        prune_host_images(keep_vuln_id=current_vuln)

    return counts


# --- reporting --------------------------------------------------------------

def print_status(conn, pairs: list) -> None:
    done = sum(1 for _, r in pairs if already_done(conn, r))
    print(f'{len(pairs)} runs in the list, {done} already have artifacts, '
          f'{len(pairs) - done} remaining')
    rows = conn.execute("""
        SELECT run_id, attempt, patch_rc, compile_rc, poc_rc, patch_max_fuzz,
               patch_recounted, compile_duration_s, is_crash_resolved
        FROM patch_verification WHERE attempt > 0 ORDER BY run_id, attempt
    """).fetchall()
    if not rows:
        print('no verification attempts recorded yet')
        return
    print(f'\n{"run_id":<42} {"a":>2} {"pRC":>4} {"cRC":>4} {"poc":>4} '
          f'{"fuzz":>4} {"rcnt":>4} {"secs":>6} {"verdict":>7}')
    for r in rows:
        print(f'{r[0]:<42} {r[1]:>2} {str(r[2]):>4} {str(r[3]):>4} {str(r[4]):>4} '
              f'{str(r[5]):>4} {str(r[6]):>4} {str(r[7]):>6} {str(r[8]):>7}')


def collect_artifacts(conn, out_dir: Path) -> int:
    """Copy every attempt's transcript and compile log into one flat directory.

    Filenames already carry the run id, so they stay traceable once pooled. Both
    files are copied verbatim -- nothing is truncated for the LLM pass.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = conn.execute("""
        SELECT run_id, attempt, compile_log_path, transcript_path
        FROM patch_verification WHERE attempt > 0 ORDER BY run_id, attempt
    """).fetchall()
    copied = 0
    for run_id, attempt, compile_path, transcript_path in rows:
        for p in (transcript_path, compile_path):
            if not p:
                continue
            src = Path(p)
            if not src.exists():
                logger.warning(f'{run_id} a{attempt}: missing {src}')
                continue
            shutil.copy2(src, out_dir / src.name)
            copied += 1
    logger.info(f'Copied {copied} file(s) into {out_dir}')
    return copied


# --- cli --------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group()
    src.add_argument('--ids', nargs='+', help='run ids on the command line')
    src.add_argument('--ids-file', type=Path, help='one run id per line; # comments ok')
    src.add_argument('--from-queue', action='store_true',
                     help='recompute the Phase 1 filter from the database')

    p.add_argument('--max-runs', type=int, help='cap runs for this invocation')
    p.add_argument('--compile-timeout', type=int, default=DEFAULT_COMPILE_TIMEOUT)
    p.add_argument('--poc-timeout', type=int, default=DEFAULT_POC_TIMEOUT)
    p.add_argument('--run-timeout', type=int,
                   help='outer per-run bound; default compile+poc+1800')
    p.add_argument('--abort-after', type=int, default=DEFAULT_ABORT_AFTER,
                   help='consecutive infrastructure failures before aborting '
                        '(default 3); patch/compile failures do not count')
    p.add_argument('--force', action='store_true',
                   help='re-verify runs that already have artifacts, as a new attempt')
    p.add_argument('--no-prune', action='store_true',
                   help='keep arvo images between vulns (~14 GB each)')
    p.add_argument('--dry-run', action='store_true', help='print the plan, run nothing')
    p.add_argument('--status', action='store_true', help='progress only, run nothing')
    p.add_argument('--collect-artifacts', type=Path, metavar='DIR',
                   help='copy transcripts and compile logs into DIR, then exit')
    args = p.parse_args(argv)

    conn = sqlite3.connect(DB_PATH)
    try:
        if args.collect_artifacts:
            collect_artifacts(conn, args.collect_artifacts)
            return 0

        if args.ids:
            run_ids = args.ids
        elif args.ids_file:
            run_ids = read_ids_file(args.ids_file)
        else:
            run_ids = queue_from_db(conn)
            if not args.from_queue:
                logger.info('no --ids/--ids-file given; using the Phase 1 queue')

        pairs = order_by_vuln(conn, run_ids)
        if not pairs:
            logger.error('nothing to run')
            return 1

        groups = [(k, len(list(g))) for k, g in itertools.groupby(pairs, key=lambda x: x[0])]
        logger.info(f'{len(pairs)} runs across {len(groups)} vulns '
                    f'({len(groups)} image pulls)')

        if args.status:
            print_status(conn, pairs)
            return 0

        if args.dry_run:
            for vuln_id, g in itertools.groupby(pairs, key=lambda x: x[0]):
                g = list(g)
                print(f'vuln {vuln_id}  ({len(g)} run(s))')
                for _, rid in g:
                    mark = 'done' if already_done(conn, rid) else '    '
                    print(f'   [{mark}] {rid}')
            return 0

        _acquire_lock(LOCK_PATH)
        try:
            counts = run_batch(pairs, args, conn)
        finally:
            _release_lock(LOCK_PATH)

        logger.info('batch complete: ' + ', '.join(
            f'{k}={v}' for k, v in sorted(counts.items())) or 'nothing ran')
        return 1 if counts.get('aborted') else 0

    finally:
        conn.close()


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('verify_batch.log'),
                  logging.StreamHandler(sys.stdout)],
    )
    sys.exit(main())
