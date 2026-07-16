"""Campaign-based experiment runner (phase 1 of EXPERIMENT_RUNNER_PROPOSAL.md).

Runs batches of CARO experiments with durable progress tracking in
arvo_loc_runs.db. A campaign pairs an experiment_tag (prompt/markdown variant
from the experiments table) with a set of arvo vulnerability ids; item status
survives restarts, so the runner can be killed and re-invoked at any point.

Usage:
    python run_experiments.py enqueue --campaign baseline-jul02 \\
        --experiment-tag baseline-patch-envmd --patch-mode --ids 42531212 42531502
    python run_experiments.py run --campaign baseline-jul02 [--max-runs N] [--no-wait] [--max-attempts N]
    python run_experiments.py status --campaign baseline-jul02
    python run_experiments.py requeue --campaign baseline-jul02 --status error usage_limited
    python run_experiments.py list

Runs execute serially (caro.py uses fixed container names). When a run is cut
off by a usage limit, the runner parses the reset time from the result message,
waits it out (unless --no-wait), and resumes the agent session via caro's
is_resume/resume_id support, giving up after --max-attempts limited attempts.
While a limit is pending, other items are held back too -- the limit is
account-wide, so running them would only burn no-op runs.
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).parent
DB_PATH = str(REPO_ROOT / 'arvo_loc_runs.db')
DEFAULT_RUNS_DIR = REPO_ROOT / 'runs'
DEFAULT_RUN_TIMEOUT = 5400  # seconds
DEFAULT_MAX_ATTEMPTS = 2          # usage-limited attempts per item before giving up
RESUME_BUFFER_SECONDS = 300       # slack added past the parsed reset time
FALLBACK_RETRY_SECONDS = 2700     # retry interval when the reset time can't be parsed

ITEM_STATUSES = ('pending', 'running', 'complete', 'usage_limited', 'error', 'skipped')

# Matches the result text recorded for runs cut off by usage limits,
# e.g. "You've hit your limit · resets 7pm (UTC)"
USAGE_LIMIT_RE = re.compile(
    r"hit your limit.*?resets\s+(\d{1,2})(?::(\d{2}))?\s*([ap]m)\s*\(UTC\)",
    re.IGNORECASE | re.DOTALL
)


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _timestamp_now() -> str:
    # local naive isoformat, matching runs.timestamp written by agent_tools
    return datetime.now().isoformat(timespec='seconds')


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def init_campaign_tables(conn: sqlite3.Connection) -> None:
    conn.execute('''CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_tag   TEXT UNIQUE NOT NULL,
        experiment_id  INTEGER NOT NULL REFERENCES experiments(experiment_id),
        base_config    TEXT NOT NULL,
        selection_desc TEXT,
        created_at     TEXT
    )''')

    conn.execute('''CREATE TABLE IF NOT EXISTS campaign_items (
        item_id          INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id      INTEGER NOT NULL REFERENCES campaigns(campaign_id),
        vuln_id          INTEGER NOT NULL REFERENCES arvo(localId),
        status           TEXT NOT NULL DEFAULT 'pending',
        attempts         INTEGER NOT NULL DEFAULT 0,
        run_id           TEXT,
        session_id       TEXT,
        limited_stage    TEXT,
        resume_after     TEXT,
        config_overrides TEXT,
        last_error       TEXT,
        started_at       TEXT,
        updated_at       TEXT,
        UNIQUE (campaign_id, vuln_id)
    )''')
    conn.commit()


def _experiment_id_for_tag(conn: sqlite3.Connection, experiment_tag: str) -> Optional[int]:
    row = conn.execute(
        'SELECT experiment_id FROM experiments WHERE experiment_tag = ?', (experiment_tag,)
    ).fetchone()
    return row['experiment_id'] if row else None


def _get_campaign(conn: sqlite3.Connection, campaign_tag: str) -> sqlite3.Row:
    row = conn.execute('''
        SELECT c.*, e.experiment_tag
        FROM campaigns c JOIN experiments e ON c.experiment_id = e.experiment_id
        WHERE c.campaign_tag = ?
    ''', (campaign_tag,)).fetchone()
    if row is None:
        raise ValueError(f"Campaign '{campaign_tag}' not found.")
    return row


def _update_item(conn: sqlite3.Connection, item_id: int, updates: dict) -> None:
    updates = dict(updates, updated_at=_timestamp_now())
    set_clause = ', '.join(f'{col} = ?' for col in updates)
    conn.execute(
        f'UPDATE campaign_items SET {set_clause} WHERE item_id = ?',
        list(updates.values()) + [item_id]
    )
    conn.commit()


def enqueue(campaign_tag: str, experiment_tag: Optional[str], vuln_ids: list[int],
            base_config: dict, append: bool = False,
            conn: Optional[sqlite3.Connection] = None) -> dict:
    """Create a campaign (or append to one) and add vuln ids as pending items."""
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        init_campaign_tables(conn)

        campaign = conn.execute(
            'SELECT * FROM campaigns WHERE campaign_tag = ?', (campaign_tag,)
        ).fetchone()

        if campaign is not None and not append:
            raise ValueError(
                f"Campaign '{campaign_tag}' already exists. Use --append to add ids to it.")

        if campaign is None:
            if not experiment_tag:
                raise ValueError('--experiment-tag is required when creating a new campaign.')
            if not base_config.get('is_loc_mode') and not base_config.get('is_patch_mode'):
                raise ValueError('At least one of --loc-mode / --patch-mode is required.')
            experiment_id = _experiment_id_for_tag(conn, experiment_tag)
            if experiment_id is None:
                raise ValueError(f"Experiment tag '{experiment_tag}' not found in experiments table.")
            cursor = conn.execute('''
                INSERT INTO campaigns (campaign_tag, experiment_id, base_config, created_at)
                VALUES (?, ?, ?, ?)
            ''', (campaign_tag, experiment_id, json.dumps(base_config), _timestamp_now()))
            campaign_id = cursor.lastrowid
            logger.info(f"Created campaign '{campaign_tag}' (experiment: {experiment_tag})")
        else:
            campaign_id = campaign['campaign_id']
            if experiment_tag:
                existing_id = campaign['experiment_id']
                if _experiment_id_for_tag(conn, experiment_tag) != existing_id:
                    logger.warning(
                        f"--experiment-tag '{experiment_tag}' differs from campaign's existing "
                        f"experiment; keeping the existing one.")

        added, duplicates, unknown = 0, 0, []
        for vuln_id in vuln_ids:
            if conn.execute('SELECT 1 FROM arvo WHERE localId = ?', (vuln_id,)).fetchone() is None:
                unknown.append(vuln_id)
                continue
            try:
                conn.execute('''
                    INSERT INTO campaign_items (campaign_id, vuln_id, status, updated_at)
                    VALUES (?, ?, 'pending', ?)
                ''', (campaign_id, vuln_id, _timestamp_now()))
                added += 1
            except sqlite3.IntegrityError:
                duplicates += 1
        conn.commit()

        if unknown:
            logger.warning(f'Skipped ids not present in arvo table: {unknown}')
        if duplicates:
            logger.info(f'Skipped {duplicates} id(s) already in the campaign.')
        logger.info(f"Enqueued {added} item(s) in campaign '{campaign_tag}'.")
        return {'campaign_id': campaign_id, 'added': added,
                'duplicates': duplicates, 'unknown': unknown}
    finally:
        if should_close:
            conn.close()


def parse_reset_time(result_text: str, now: Optional[datetime] = None) -> Optional[str]:
    """Parse "resets 7pm (UTC)" from a usage-limit result into the next ISO UTC time."""
    match = USAGE_LIMIT_RE.search(result_text or '')
    if not match:
        return None
    hour = int(match.group(1)) % 12
    if match.group(3).lower() == 'pm':
        hour += 12
    minute = int(match.group(2) or 0)
    if now is None:
        now = _utcnow()
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate.isoformat(timespec='seconds')


def classify_outcome(conn: sqlite3.Connection, vuln_id: int, started_at: str,
                     stderr_tail: Optional[str] = None,
                     return_code: Optional[int] = None) -> dict:
    """Classify an item from the run rows caro.py produced for it.

    caro.py exits 0 even when the agent run fails, so the runs table -- not the
    exit code -- is the source of truth.
    """
    rows = conn.execute('''
        SELECT run_id, run_mode, result, result_error_flag, session_id
        FROM runs WHERE vuln_id = ? AND timestamp >= ?
        ORDER BY timestamp
    ''', (vuln_id, started_at)).fetchall()

    if not rows:
        detail = f'no run rows recorded (caro exit code {return_code})'
        if stderr_tail and stderr_tail.strip():
            detail += f'; stderr tail: {stderr_tail.strip()[-500:]}'
        return {'status': 'error', 'last_error': detail}

    # earliest usage-limited row wins: in a loc+patch pair a limited loc run
    # makes the following patch run fail immediately as well
    for row in rows:
        result = row['result'] or ''
        if row['result_error_flag'] and 'hit your limit' in result.lower():
            resume_after = parse_reset_time(result, _utcnow())
            if resume_after is None:
                resume_after = (_utcnow() + timedelta(seconds=FALLBACK_RETRY_SECONDS)
                                ).isoformat(timespec='seconds')
                logger.warning('Could not parse a reset time from the limit message; '
                               f'retrying after {FALLBACK_RETRY_SECONDS}s.')
            return {
                'status': 'usage_limited',
                'run_id': row['run_id'],
                'session_id': row['session_id'],
                'limited_stage': row['run_mode'],
                'resume_after': resume_after,
                'last_error': result[:200],
            }

    for row in rows:
        if row['result_error_flag']:
            return {
                'status': 'error',
                'run_id': row['run_id'],
                'session_id': row['session_id'],
                'last_error': (row['result'] or 'agent run errored')[:500],
            }

    final = rows[-1]
    return {'status': 'complete', 'run_id': final['run_id'], 'session_id': final['session_id']}


def _apply_outcome(conn: sqlite3.Connection, item_id: int, outcome: dict) -> None:
    updates = {'status': outcome['status']}
    for key in ('run_id', 'session_id', 'limited_stage', 'resume_after', 'last_error'):
        updates[key] = outcome.get(key)
    _update_item(conn, item_id, updates)


def build_item_config(campaign: sqlite3.Row, item: sqlite3.Row) -> dict:
    config = {'loc_run_id': '', 'is_resume': False, 'resume_id': ''}
    config.update(json.loads(campaign['base_config']))
    if item['config_overrides']:
        config.update(json.loads(item['config_overrides']))
    # authoritative fields, never overridable
    config['experiment_tag'] = campaign['experiment_tag']
    config['arvo_id'] = item['vuln_id']

    if item['status'] == 'usage_limited':
        if item['session_id']:
            config['is_resume'] = True
            config['resume_id'] = item['session_id']
            if item['limited_stage'] == 'patch':
                # loc already happened inside the resumed session; don't redo it
                config['is_loc_mode'] = False
        else:
            logger.warning(f"No session_id recorded for limited vuln {item['vuln_id']}; "
                           f"rerunning from scratch instead of resuming.")
    return config


def _invoke_caro(config_path: Path, timeout: int) -> tuple:
    """Run caro.py for one item. stdout is inherited so caro's live log stays visible."""
    proc = subprocess.run(
        [sys.executable, 'caro.py', '--config', str(config_path)],
        cwd=REPO_ROOT, stderr=subprocess.PIPE,
        text=True, encoding='utf-8', errors='replace', timeout=timeout
    )
    return proc.returncode, (proc.stderr or '')[-2000:]


def _reconcile_stale_items(conn: sqlite3.Connection, campaign_id: int) -> None:
    """Re-classify items a previous (killed) runner left in 'running'."""
    stale = conn.execute(
        "SELECT * FROM campaign_items WHERE campaign_id = ? AND status = 'running'",
        (campaign_id,)).fetchall()
    for item in stale:
        started_at = item['started_at'] or item['updated_at']
        outcome = classify_outcome(conn, item['vuln_id'], started_at,
                                   stderr_tail='runner interrupted before outcome was recorded')
        logger.warning(
            f"Item for vuln {item['vuln_id']} was left 'running'; "
            f"reclassified as '{outcome['status']}'.")
        _apply_outcome(conn, item['item_id'], outcome)


def _wait_until(target_iso: str, reason: str) -> None:
    """Sleep until target_iso (+ resume buffer). Ctrl+C aborts; item state is
    already persisted, so re-running the same command picks up where it left off."""
    target = datetime.fromisoformat(target_iso) + timedelta(seconds=RESUME_BUFFER_SECONDS)
    logger.info(f"Waiting until {target.isoformat(timespec='seconds')} ({reason}).")
    while True:
        remaining = (target - _utcnow()).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 600))


def _next_action(conn: sqlite3.Connection, campaign_id: int, max_attempts: int) -> tuple:
    """Decide the next step: ('run', item) | ('wait', resume_after_iso) | ('done', None).

    Usage-limited items whose reset has passed are resumed before pending items
    run. While any limited item's reset is still in the future, pending items
    are held back too -- the limit is account-wide, so they would fail the same way.
    """
    cursor = conn.execute('''
        UPDATE campaign_items SET status = 'error', last_error = ?, updated_at = ?
        WHERE campaign_id = ? AND status = 'usage_limited' AND attempts >= ?
    ''', (f'usage-limited; exceeded max attempts ({max_attempts})', _timestamp_now(),
          campaign_id, max_attempts))
    if cursor.rowcount:
        conn.commit()
        logger.warning(f'{cursor.rowcount} usage-limited item(s) exceeded max attempts '
                       f'({max_attempts}); marked as error.')

    now = _utcnow()
    limited = conn.execute('''
        SELECT * FROM campaign_items
        WHERE campaign_id = ? AND status = 'usage_limited' ORDER BY item_id
    ''', (campaign_id,)).fetchall()
    due = [item for item in limited
           if item['resume_after'] is None
           or datetime.fromisoformat(item['resume_after']) <= now]
    if due:
        return 'run', due[0]
    if limited:
        earliest = min(limited, key=lambda item: datetime.fromisoformat(item['resume_after']))
        return 'wait', earliest['resume_after']

    pending = conn.execute('''
        SELECT * FROM campaign_items
        WHERE campaign_id = ? AND status = 'pending' ORDER BY item_id LIMIT 1
    ''', (campaign_id,)).fetchone()
    if pending:
        return 'run', pending
    return 'done', None


def _acquire_lock(lock_path: Path) -> None:
    if lock_path.exists():
        raise ValueError(
            f'Another runner appears to be active (lock: {lock_path}, '
            f'pid {lock_path.read_text().strip()}). Delete the lock file if it is stale.')
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(str(os.getpid()))


def run_campaign(campaign_tag: str, conn: Optional[sqlite3.Connection] = None,
                 max_runs: Optional[int] = None, run_timeout: int = DEFAULT_RUN_TIMEOUT,
                 runs_dir: Optional[Path] = None, invoke=None,
                 no_wait: bool = False, max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> dict:
    """Work through runnable items serially, waiting out usage-limit resets and
    resuming cut-off sessions; returns final status counts."""
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    runs_dir = Path(runs_dir) if runs_dir else DEFAULT_RUNS_DIR
    if invoke is None:
        invoke = _invoke_caro

    try:
        init_campaign_tables(conn)
        campaign = _get_campaign(conn, campaign_tag)

        lock_path = runs_dir / '.run_experiments.lock'
        _acquire_lock(lock_path)
        try:
            _reconcile_stale_items(conn, campaign['campaign_id'])

            executed = 0
            while max_runs is None or executed < max_runs:
                action, payload = _next_action(conn, campaign['campaign_id'], max_attempts)
                if action == 'done':
                    break
                if action == 'wait':
                    if no_wait:
                        logger.info(
                            f"[{campaign_tag}] Usage limit active; earliest resume at "
                            f"{payload}. Exiting (--no-wait); re-run this command "
                            f"after the reset to resume.")
                        break
                    _wait_until(payload, 'usage limit reset')
                    continue

                item = payload
                resuming = item['status'] == 'usage_limited'
                config = build_item_config(campaign, item)
                config_dir = runs_dir / f'campaign_{campaign_tag}'
                config_dir.mkdir(parents=True, exist_ok=True)
                suffix = '' if item['attempts'] == 0 else f"_attempt{item['attempts'] + 1}"
                config_path = config_dir / f"config_{item['vuln_id']}{suffix}.json"
                config_path.write_text(json.dumps(config, indent=4), encoding='utf-8')

                started_at = _timestamp_now()
                _update_item(conn, item['item_id'],
                             {'status': 'running', 'started_at': started_at,
                              'attempts': item['attempts'] + 1})
                verb = 'Resuming' if resuming else 'Running'
                logger.info(f"[{campaign_tag}] {verb} vuln {item['vuln_id']} "
                            f"(attempt {item['attempts'] + 1}, config: {config_path})")

                try:
                    return_code, stderr_tail = invoke(config_path, run_timeout)
                except subprocess.TimeoutExpired:
                    outcome = {'status': 'error',
                               'last_error': f'timed out after {run_timeout}s'}
                else:
                    outcome = classify_outcome(conn, item['vuln_id'], started_at,
                                               stderr_tail=stderr_tail,
                                               return_code=return_code)

                _apply_outcome(conn, item['item_id'], outcome)
                executed += 1
                logger.info(f"[{campaign_tag}] Vuln {item['vuln_id']} -> {outcome['status']}")

            counts = _status_counts(conn, campaign['campaign_id'])
            logger.info(f"[{campaign_tag}] Session done ({executed} run(s)). "
                        + '  '.join(f'{s}: {counts.get(s, 0)}' for s in ITEM_STATUSES))
            return counts
        finally:
            lock_path.unlink(missing_ok=True)
    finally:
        if should_close:
            conn.close()


def _status_counts(conn: sqlite3.Connection, campaign_id: int) -> dict:
    rows = conn.execute('''
        SELECT status, COUNT(*) AS n FROM campaign_items
        WHERE campaign_id = ? GROUP BY status
    ''', (campaign_id,)).fetchall()
    return {row['status']: row['n'] for row in rows}


def get_campaign_status(campaign_tag: str, conn: Optional[sqlite3.Connection] = None) -> dict:
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        init_campaign_tables(conn)
        campaign = _get_campaign(conn, campaign_tag)
        items = conn.execute('''
            SELECT * FROM campaign_items WHERE campaign_id = ? ORDER BY item_id
        ''', (campaign['campaign_id'],)).fetchall()
        return {
            'campaign': dict(campaign),
            'counts': _status_counts(conn, campaign['campaign_id']),
            'items': [dict(item) for item in items],
        }
    finally:
        if should_close:
            conn.close()


def requeue(campaign_tag: str, statuses: list[str], vuln_ids: Optional[list[int]] = None,
            conn: Optional[sqlite3.Connection] = None) -> int:
    """Reset items in the given statuses back to pending; returns count requeued."""
    invalid = set(statuses) - set(ITEM_STATUSES)
    if invalid:
        raise ValueError(f'Invalid status(es): {sorted(invalid)}')

    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        init_campaign_tables(conn)
        campaign = _get_campaign(conn, campaign_tag)
        query = (f"UPDATE campaign_items SET status = 'pending', last_error = NULL, "
                 f"limited_stage = NULL, resume_after = NULL, "
                 f"updated_at = ? WHERE campaign_id = ? "
                 f"AND status IN ({', '.join('?' * len(statuses))})")
        params = [_timestamp_now(), campaign['campaign_id']] + list(statuses)
        if vuln_ids:
            query += f" AND vuln_id IN ({', '.join('?' * len(vuln_ids))})"
            params += list(vuln_ids)
        cursor = conn.execute(query, params)
        conn.commit()
        logger.info(f"Requeued {cursor.rowcount} item(s) in campaign '{campaign_tag}'.")
        return cursor.rowcount
    finally:
        if should_close:
            conn.close()


def list_campaigns(conn: Optional[sqlite3.Connection] = None) -> list[dict]:
    should_close = False
    if conn is None:
        conn = _get_connection()
        should_close = True
    try:
        init_campaign_tables(conn)
        rows = conn.execute('''
            SELECT c.campaign_tag, e.experiment_tag, c.created_at,
                   COUNT(i.item_id) AS total,
                   SUM(CASE WHEN i.status = 'complete' THEN 1 ELSE 0 END) AS complete,
                   SUM(CASE WHEN i.status = 'pending' THEN 1 ELSE 0 END) AS pending
            FROM campaigns c
            JOIN experiments e ON c.experiment_id = e.experiment_id
            LEFT JOIN campaign_items i ON i.campaign_id = c.campaign_id
            GROUP BY c.campaign_id ORDER BY c.campaign_id
        ''').fetchall()
        return [dict(row) for row in rows]
    finally:
        if should_close:
            conn.close()


# ----- CLI -----

def cmd_enqueue(args):
    if args.ids_file:
        ids = []
        with open(args.ids_file, 'r', encoding='utf-8') as f:
            for line in f:
                value = line.split('#')[0].strip()
                if value:
                    ids.append(int(value))
    else:
        ids = args.ids
    base_config = {
        'container_name': args.container,
        'agent': args.agent,
        'is_loc_mode': args.loc_mode,
        'is_patch_mode': args.patch_mode,
    }
    enqueue(args.campaign, args.experiment_tag, ids, base_config, append=args.append)


def cmd_run(args):
    run_campaign(args.campaign, max_runs=args.max_runs, run_timeout=args.run_timeout,
                 no_wait=args.no_wait, max_attempts=args.max_attempts)


def cmd_status(args):
    data = get_campaign_status(args.campaign)
    campaign = data['campaign']
    counts = data['counts']
    print(f"Campaign '{campaign['campaign_tag']}' (experiment: {campaign['experiment_tag']}, "
          f"created: {campaign['created_at']})")
    print(f"  base_config: {campaign['base_config']}")
    print('  ' + '  '.join(f'{s}: {counts.get(s, 0)}' for s in ITEM_STATUSES))
    print()
    print(f"{'vuln_id':<12} {'status':<14} {'att':<4} {'run_id':<38} detail")
    for item in data['items']:
        if item['status'] == 'usage_limited':
            detail = f"resume after {item['resume_after']}"
        else:
            detail = (item['last_error'] or '').replace('\n', ' ')[:60]
        print(f"{item['vuln_id']:<12} {item['status']:<14} {item['attempts']:<4} "
              f"{(item['run_id'] or '-'):<38} {detail}")


def cmd_requeue(args):
    requeue(args.campaign, args.status, vuln_ids=args.ids)


def cmd_list(args):
    campaigns = list_campaigns()
    if not campaigns:
        print('No campaigns found.')
        return
    print(f"{'campaign_tag':<28} {'experiment_tag':<32} {'created':<20} "
          f"{'total':<6} {'done':<6} pending")
    for c in campaigns:
        print(f"{c['campaign_tag']:<28} {c['experiment_tag']:<32} {c['created_at']:<20} "
              f"{c['total']:<6} {c['complete'] or 0:<6} {c['pending'] or 0}")


def main(argv=None):
    parser = argparse.ArgumentParser(description='Run CARO experiment campaigns.')
    sub = parser.add_subparsers(dest='command', required=True)

    p_enqueue = sub.add_parser('enqueue', help='Create a campaign and add vuln ids to it')
    p_enqueue.add_argument('--campaign', required=True, help='Campaign tag, e.g. baseline-jul02')
    p_enqueue.add_argument('--experiment-tag', help='Tag from the experiments table')
    id_group = p_enqueue.add_mutually_exclusive_group(required=True)
    id_group.add_argument('--ids', nargs='+', type=int, help='arvo vulnerability ids')
    id_group.add_argument('--ids-file', help='File with one arvo id per line (# comments ok)')
    p_enqueue.add_argument('--loc-mode', action='store_true')
    p_enqueue.add_argument('--patch-mode', action='store_true')
    p_enqueue.add_argument('--container', default='rootainer')
    p_enqueue.add_argument('--agent', default='claude')
    p_enqueue.add_argument('--append', action='store_true',
                           help='Add ids to an existing campaign')
    p_enqueue.set_defaults(func=cmd_enqueue)

    p_run = sub.add_parser('run', help='Run pending items in a campaign')
    p_run.add_argument('--campaign', required=True)
    p_run.add_argument('--max-runs', type=int, help='Cap runs for this invocation')
    p_run.add_argument('--run-timeout', type=int, default=DEFAULT_RUN_TIMEOUT,
                       help=f'Per-run timeout in seconds (default {DEFAULT_RUN_TIMEOUT})')
    p_run.add_argument('--no-wait', action='store_true',
                       help='Exit when a usage limit blocks progress instead of '
                            'waiting for the reset')
    p_run.add_argument('--max-attempts', type=int, default=DEFAULT_MAX_ATTEMPTS,
                       help=f'Give up on an item after this many usage-limited '
                            f'attempts (default {DEFAULT_MAX_ATTEMPTS})')
    p_run.set_defaults(func=cmd_run)

    p_status = sub.add_parser('status', help='Show campaign progress')
    p_status.add_argument('--campaign', required=True)
    p_status.set_defaults(func=cmd_status)

    p_requeue = sub.add_parser('requeue', help='Reset items back to pending')
    p_requeue.add_argument('--campaign', required=True)
    p_requeue.add_argument('--status', nargs='+', default=['error'],
                           choices=list(ITEM_STATUSES),
                           help='Statuses to requeue (default: error)')
    p_requeue.add_argument('--ids', nargs='+', type=int, help='Limit to these vuln ids')
    p_requeue.set_defaults(func=cmd_requeue)

    p_list = sub.add_parser('list', help='List campaigns')
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('run_experiments.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    main()
