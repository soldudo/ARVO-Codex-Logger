"""Git-backed run ledger for multi-machine experiment coverage.

Each machine appends minimal run facts (vuln, experiment_tag, model, outcome)
to its own JSONL file in a small shared git repository, and reads everyone
else's files to compute team-wide coverage. Detailed results never leave the
machine-local arvo_loc_runs.db; the ledger holds only what is needed to answer
"which (vuln x experiment_tag) cells still need a run?" and to queue the gaps.

Usage:
    python ledger.py init --ledger-dir ~/caro-ledger --remote git@github.com:team/caro-ledger.git
    python ledger.py report [--db arvo_loc_runs.db] [--machine NAME]
    python ledger.py coverage [--tag baseline-patch-envmd] [--json]
    python ledger.py gaps --tag baseline-patch-envmd --count 20 [--project ndpi ...]
    python ledger.py claim --tag baseline-patch-envmd --ids 101 102 [--campaign fill-jul19]

The ledger directory is resolved from --ledger-dir or the CARO_LEDGER_DIR env
var; the machine name from CARO_LEDGER_MACHINE or the hostname. Every command
tolerates being offline: facts are committed locally and pushed on the next
opportunity. See LEDGER.md for setup and the fact format.
"""

import argparse
import json
import logging
import os
import random
import re
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).parent
DEFAULT_DB_PATH = str(REPO_ROOT / 'arvo_loc_runs.db')
LEDGER_DIR_ENV = 'CARO_LEDGER_DIR'
MACHINE_ENV = 'CARO_LEDGER_MACHINE'
DEFAULT_CLAIM_TTL_DAYS = 3

RUN_OUTCOMES = ('success', 'error', 'usage_limited')


def default_ledger_dir() -> Optional[str]:
    return os.environ.get(LEDGER_DIR_ENV)


def machine_name() -> str:
    raw = os.environ.get(MACHINE_ENV) or socket.gethostname()
    return re.sub(r'[^A-Za-z0-9._-]', '-', raw) or 'unknown'


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ro_connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f'file:{Path(db_path).as_posix()}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    return conn


# ----- git plumbing -----

def _git(args: list, ledger_dir, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(['git'] + args, cwd=str(ledger_dir), capture_output=True,
                            text=True, encoding='utf-8', errors='replace')
    if check and result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def sync(ledger_dir) -> bool:
    """git pull --rebase; failure (offline, no remote yet) is tolerated."""
    result = _git(['pull', '--rebase'], ledger_dir, check=False)
    if result.returncode != 0:
        logger.warning(f'Ledger pull failed (offline?): {result.stderr.strip()}')
        return False
    return True


def _commit_and_push(ledger_dir, file_path: Path, message: str) -> None:
    # git runs with cwd=ledger_dir, so the pathspec must be repo-relative;
    # machine files always live at the ledger root
    pathspec = file_path.name
    _git(['add', '--', pathspec], ledger_dir)
    status = _git(['status', '--porcelain', '--', pathspec], ledger_dir)
    if not status.stdout.strip():
        return
    _git(['commit', '-m', message, '--', pathspec], ledger_dir)
    push = _git(['push', '-u', 'origin', 'HEAD'], ledger_dir, check=False)
    if push.returncode != 0:
        # one rebase-and-retry for the concurrent-push race, then give up quietly:
        # the commit stays local and goes out with the next successful push
        if sync(ledger_dir):
            push = _git(['push', '-u', 'origin', 'HEAD'], ledger_dir, check=False)
        if push.returncode != 0:
            logger.warning('Ledger push failed; facts are committed locally and will '
                           f'push next time: {push.stderr.strip()}')


def init_ledger(ledger_dir, remote: Optional[str] = None) -> None:
    ledger_dir = Path(ledger_dir)
    if (ledger_dir / '.git').exists():
        logger.info(f'{ledger_dir} is already a git repository.')
        return
    if remote:
        result = subprocess.run(['git', 'clone', remote, str(ledger_dir)],
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f'git clone failed: {result.stderr.strip()}')
    else:
        ledger_dir.mkdir(parents=True, exist_ok=True)
        _git(['init'], ledger_dir)
    logger.info(f'Ledger initialized at {ledger_dir}')


# ----- facts -----

def machine_file(ledger_dir, machine: str) -> Path:
    return Path(ledger_dir) / f'{machine}.jsonl'


def read_facts(ledger_dir) -> list:
    facts, corrupt = [], 0
    for path in sorted(Path(ledger_dir).glob('*.jsonl')):
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    facts.append(json.loads(line))
                except json.JSONDecodeError:
                    corrupt += 1
    if corrupt:
        logger.warning(f'Skipped {corrupt} corrupt ledger line(s).')
    return facts


def append_facts(ledger_dir, machine: str, new_facts: list, message: str) -> None:
    path = machine_file(ledger_dir, machine)
    if not new_facts:
        # still commit any lines a previous attempt wrote before its commit failed
        if path.exists():
            _commit_and_push(ledger_dir, path, f'{machine}: commit leftover facts')
        return
    with open(path, 'a', encoding='utf-8') as f:
        for fact in new_facts:
            f.write(json.dumps(fact, sort_keys=True) + '\n')
    _commit_and_push(ledger_dir, path, message)


# ----- reporting local runs (the outbox) -----

def classify_run_outcome(result_error_flag, result: Optional[str]) -> str:
    if result_error_flag:
        if 'hit your limit' in (result or '').lower():
            return 'usage_limited'
        return 'error'
    return 'success'


def report_new_runs(db_path: str = DEFAULT_DB_PATH, ledger_dir=None,
                    machine: Optional[str] = None, include_untagged: bool = False,
                    do_sync: bool = True) -> int:
    """Append facts for local runs not yet in this machine's ledger file.

    Idempotent (keyed on run_id), so it is safe to call after every run, from
    cron, or never until a backfill -- the first call reports all history.
    Returns the number of newly reported runs.
    """
    ledger_dir = ledger_dir or default_ledger_dir()
    if not ledger_dir:
        raise ValueError(f'Ledger directory not set; pass ledger_dir or set {LEDGER_DIR_ENV}.')
    machine = machine or machine_name()

    if do_sync:
        sync(ledger_dir)

    already_reported = set()
    own_file = machine_file(ledger_dir, machine)
    if own_file.exists():
        with open(own_file, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        fact = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if fact.get('type') == 'run':
                        already_reported.add(fact.get('run_id'))

    conn = _ro_connect(db_path)
    try:
        rows = conn.execute('''
            SELECT r.run_id, r.vuln_id, r.run_mode, r.agent_model, r.timestamp,
                   r.result, r.result_error_flag, e.experiment_tag
            FROM runs r LEFT JOIN experiments e ON r.experiment_id = e.experiment_id
            ORDER BY r.timestamp
        ''').fetchall()
    finally:
        conn.close()

    new_facts, skipped_untagged = [], 0
    reported_at = _utcnow().isoformat(timespec='seconds')
    for row in rows:
        if row['run_id'] in already_reported:
            continue
        if not row['experiment_tag'] and not include_untagged:
            skipped_untagged += 1
            continue
        new_facts.append({
            'type': 'run',
            'run_id': row['run_id'],
            'machine': machine,
            'vuln_id': row['vuln_id'],
            'experiment_tag': row['experiment_tag'],
            'run_mode': row['run_mode'],
            'model': row['agent_model'] or None,
            'outcome': classify_run_outcome(row['result_error_flag'], row['result']),
            'timestamp': row['timestamp'],
            'reported_at': reported_at,
        })

    if skipped_untagged:
        logger.info(f'Skipped {skipped_untagged} run(s) with no experiment_tag '
                    f'(use --include-untagged to report them).')
    append_facts(ledger_dir, machine, new_facts,
                 f'{machine}: report {len(new_facts)} run(s)')
    logger.info(f'Reported {len(new_facts)} new run(s) to the ledger.')
    return len(new_facts)


# ----- claims -----

def record_claims(ledger_dir, machine: str, vuln_ids: list, experiment_tag: str,
                  campaign: Optional[str] = None) -> None:
    """Record that this machine intends to run these vulns under this tag, so
    other machines' gap-fills skip them (until the claim expires)."""
    timestamp = _utcnow().isoformat(timespec='seconds')
    facts = [{
        'type': 'claim',
        'machine': machine,
        'vuln_id': vuln_id,
        'experiment_tag': experiment_tag,
        'campaign': campaign,
        'timestamp': timestamp,
    } for vuln_id in vuln_ids]
    append_facts(ledger_dir, machine, facts,
                 f'{machine}: claim {len(facts)} vuln(s) for {experiment_tag}')


def _active_claim_cutoff(claim_ttl_days: int, now: Optional[datetime]) -> datetime:
    return (now or _utcnow()) - timedelta(days=claim_ttl_days)


def _claim_time(fact: dict) -> Optional[datetime]:
    try:
        ts = datetime.fromisoformat(fact.get('timestamp') or '')
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# ----- coverage and gap selection -----

def coverage_report(facts: list, experiment_tag: Optional[str] = None,
                    claim_ttl_days: int = DEFAULT_CLAIM_TTL_DAYS,
                    now: Optional[datetime] = None) -> dict:
    """Aggregate facts into {tags: {tag: {counts..., cells: {vuln: cell}}}}.

    Cell status: 'covered' (a successful run exists) > 'claimed' (active claim,
    no success yet) > 'attempted' (only failed/limited runs).
    """
    cutoff = _active_claim_cutoff(claim_ttl_days, now)
    tags = {}

    def cell_for(tag, vuln):
        cells = tags.setdefault(tag, {})
        return cells.setdefault(vuln, {
            'success': 0, 'error': 0, 'usage_limited': 0,
            'models': set(), 'machines': set(), 'last_run': None, 'claimed': False,
        })

    for fact in facts:
        tag = fact.get('experiment_tag')
        if experiment_tag and tag != experiment_tag:
            continue
        vuln = fact.get('vuln_id')
        if fact.get('type') == 'run':
            cell = cell_for(tag, vuln)
            outcome = fact.get('outcome')
            cell[outcome if outcome in RUN_OUTCOMES else 'error'] += 1
            if fact.get('model'):
                cell['models'].add(fact['model'])
            if fact.get('machine'):
                cell['machines'].add(fact['machine'])
            ts = fact.get('timestamp')
            if ts and (cell['last_run'] is None or ts > cell['last_run']):
                cell['last_run'] = ts
        elif fact.get('type') == 'claim':
            claim_ts = _claim_time(fact)
            if claim_ts and claim_ts >= cutoff:
                cell_for(tag, vuln)['claimed'] = True

    report = {'generated_at': (now or _utcnow()).isoformat(timespec='seconds'), 'tags': {}}
    for tag, cells in tags.items():
        tag_report = {'covered': 0, 'attempted': 0, 'claimed': 0, 'cells': {}}
        for vuln, cell in sorted(cells.items()):
            if cell['success'] > 0:
                status = 'covered'
            elif cell['claimed']:
                status = 'claimed'
            else:
                status = 'attempted'
            tag_report[status] += 1
            tag_report['cells'][vuln] = {
                'status': status,
                'success': cell['success'],
                'error': cell['error'],
                'usage_limited': cell['usage_limited'],
                'models': sorted(cell['models']),
                'machines': sorted(cell['machines']),
                'last_run': cell['last_run'],
            }
        report['tags'][tag] = tag_report
    return report


def select_gaps(candidate_ids: list, experiment_tag: str, facts: list,
                count: Optional[int] = None, retry_failed: bool = False,
                claim_ttl_days: int = DEFAULT_CLAIM_TTL_DAYS,
                seed: Optional[int] = None, now: Optional[datetime] = None) -> list:
    """From candidate vuln ids, keep those with no coverage under this tag.

    Excludes successful cells and actively claimed cells always; excludes
    attempted-but-failed cells too unless retry_failed. When count is given,
    a (seedable) random sample of the gaps is returned, sorted.
    """
    cutoff = _active_claim_cutoff(claim_ttl_days, now)
    success, attempted, claimed = set(), set(), set()
    for fact in facts:
        if fact.get('experiment_tag') != experiment_tag:
            continue
        vuln = fact.get('vuln_id')
        if fact.get('type') == 'run':
            attempted.add(vuln)
            if fact.get('outcome') == 'success':
                success.add(vuln)
        elif fact.get('type') == 'claim':
            claim_ts = _claim_time(fact)
            if claim_ts and claim_ts >= cutoff:
                claimed.add(vuln)

    excluded = (success | claimed) if retry_failed else (success | attempted | claimed)
    gaps = [vuln for vuln in candidate_ids if vuln not in excluded]
    if count is not None and 0 <= count < len(gaps):
        gaps = sorted(random.Random(seed).sample(gaps, count))
    return gaps


def candidate_vulns(db_path: str, projects: Optional[list] = None,
                    id_min: Optional[int] = None, id_max: Optional[int] = None,
                    reproduced_only: bool = False) -> list:
    """Vuln ids from the local arvo table matching the filters, ascending."""
    clauses, params = [], []
    if projects:
        clauses.append(f"project IN ({', '.join('?' * len(projects))})")
        params += list(projects)
    if id_min is not None:
        clauses.append('localId >= ?')
        params.append(id_min)
    if id_max is not None:
        clauses.append('localId <= ?')
        params.append(id_max)
    if reproduced_only:
        clauses.append('reproduced = 1')
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ''

    conn = _ro_connect(db_path)
    try:
        return [row[0] for row in
                conn.execute(f'SELECT localId FROM arvo{where} ORDER BY localId', params)]
    finally:
        conn.close()


def gap_fill_ids(db_path: str, ledger_dir, experiment_tag: str,
                 count: Optional[int] = None, projects: Optional[list] = None,
                 id_min: Optional[int] = None, id_max: Optional[int] = None,
                 reproduced_only: bool = False, retry_failed: bool = False,
                 seed: Optional[int] = None,
                 claim_ttl_days: int = DEFAULT_CLAIM_TTL_DAYS,
                 do_sync: bool = True) -> list:
    """Sync the ledger and pick unrun vulns for this tag -- the enqueue feed."""
    if do_sync:
        sync(ledger_dir)
    facts = read_facts(ledger_dir)
    candidates = candidate_vulns(db_path, projects=projects, id_min=id_min,
                                 id_max=id_max, reproduced_only=reproduced_only)
    return select_gaps(candidates, experiment_tag, facts, count=count,
                       retry_failed=retry_failed, claim_ttl_days=claim_ttl_days, seed=seed)


# ----- CLI -----

def _resolve_ledger_dir(arg: Optional[str]) -> str:
    value = arg or default_ledger_dir()
    if not value:
        raise ValueError(f'Ledger directory not set; pass --ledger-dir or set {LEDGER_DIR_ENV}.')
    return value


def cmd_init(args):
    init_ledger(_resolve_ledger_dir(args.ledger_dir), remote=args.remote)


def cmd_report(args):
    report_new_runs(db_path=args.db, ledger_dir=_resolve_ledger_dir(args.ledger_dir),
                    machine=args.machine, include_untagged=args.include_untagged,
                    do_sync=not args.no_sync)


def cmd_coverage(args):
    ledger_dir = _resolve_ledger_dir(args.ledger_dir)
    if not args.no_sync:
        sync(ledger_dir)
    report = coverage_report(read_facts(ledger_dir), experiment_tag=args.tag,
                             claim_ttl_days=args.claim_ttl_days)
    if args.json:
        print(json.dumps(report, indent=2))
        return
    if not report['tags']:
        print('No facts in the ledger yet.')
        return
    for tag, data in sorted(report['tags'].items(), key=lambda kv: str(kv[0])):
        print(f"{tag or '(untagged)'}: covered {data['covered']}  "
              f"attempted {data['attempted']}  claimed {data['claimed']}")
        if args.tag:
            for vuln, cell in data['cells'].items():
                counts = f"s:{cell['success']} e:{cell['error']} l:{cell['usage_limited']}"
                print(f"  {vuln:<12} {cell['status']:<10} {counts:<14} "
                      f"models={','.join(cell['models']) or '-'} "
                      f"machines={','.join(cell['machines']) or '-'}")


def cmd_gaps(args):
    ids = gap_fill_ids(args.db, _resolve_ledger_dir(args.ledger_dir), args.tag,
                       count=args.count, projects=args.project, id_min=args.id_min,
                       id_max=args.id_max, reproduced_only=args.reproduced_only,
                       retry_failed=args.retry_failed, seed=args.seed,
                       claim_ttl_days=args.claim_ttl_days, do_sync=not args.no_sync)
    print(f'{len(ids)} gap(s):')
    for vuln_id in ids:
        print(f'  {vuln_id}')


def cmd_claim(args):
    ledger_dir = _resolve_ledger_dir(args.ledger_dir)
    if not args.no_sync:
        sync(ledger_dir)
    record_claims(ledger_dir, args.machine or machine_name(), args.ids, args.tag,
                  campaign=args.campaign)
    logger.info(f'Claimed {len(args.ids)} vuln(s) for {args.tag}.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Git-backed multi-machine run ledger.')
    sub = parser.add_subparsers(dest='command', required=True)

    def add_common(p):
        p.add_argument('--ledger-dir', default=None,
                       help=f'Ledger repo path (default: ${LEDGER_DIR_ENV})')
        p.add_argument('--no-sync', action='store_true',
                       help='Skip the git pull before reading/writing')

    p_init = sub.add_parser('init', help='Create or clone the ledger repository')
    p_init.add_argument('--ledger-dir', default=None)
    p_init.add_argument('--remote', help='Git URL of the shared ledger repo to clone')
    p_init.set_defaults(func=cmd_init)

    p_report = sub.add_parser('report', help="Push this machine's unreported runs to the ledger")
    add_common(p_report)
    p_report.add_argument('--db', default=DEFAULT_DB_PATH)
    p_report.add_argument('--machine', default=None,
                          help=f'Machine name (default: ${MACHINE_ENV} or hostname)')
    p_report.add_argument('--include-untagged', action='store_true',
                          help='Also report runs with no experiment_tag')
    p_report.set_defaults(func=cmd_report)

    p_cov = sub.add_parser('coverage', help='Show team-wide coverage per experiment_tag')
    add_common(p_cov)
    p_cov.add_argument('--tag', help='Limit to one experiment_tag and list per-vuln cells')
    p_cov.add_argument('--json', action='store_true')
    p_cov.add_argument('--claim-ttl-days', type=int, default=DEFAULT_CLAIM_TTL_DAYS)
    p_cov.set_defaults(func=cmd_coverage)

    p_gaps = sub.add_parser('gaps', help='Preview which vulns a gap-fill would pick')
    add_common(p_gaps)
    p_gaps.add_argument('--db', default=DEFAULT_DB_PATH)
    p_gaps.add_argument('--tag', required=True)
    p_gaps.add_argument('--count', type=int, help='Sample size (default: all gaps)')
    p_gaps.add_argument('--project', action='append')
    p_gaps.add_argument('--id-min', type=int)
    p_gaps.add_argument('--id-max', type=int)
    p_gaps.add_argument('--reproduced-only', action='store_true')
    p_gaps.add_argument('--retry-failed', action='store_true',
                        help='Include cells whose only runs failed')
    p_gaps.add_argument('--seed', type=int)
    p_gaps.add_argument('--claim-ttl-days', type=int, default=DEFAULT_CLAIM_TTL_DAYS)
    p_gaps.set_defaults(func=cmd_gaps)

    p_claim = sub.add_parser('claim', help='Manually claim vulns you are about to run')
    add_common(p_claim)
    p_claim.add_argument('--tag', required=True)
    p_claim.add_argument('--ids', nargs='+', type=int, required=True)
    p_claim.add_argument('--campaign', default=None)
    p_claim.add_argument('--machine', default=None)
    p_claim.set_defaults(func=cmd_claim)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (ValueError, RuntimeError) as e:
        logger.error(str(e))
        sys.exit(1)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('ledger.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    main()
