"""Tests for the batch driver's selection, resume and outcome logic.

Covers BATCH_VERIFICATION_PROPOSAL.md Phase 1 verification steps 6, 8 and the
circuit breaker. Nothing here touches docker.
"""
import sqlite3

import pytest

from schema import PATCH_VERIFICATION_DDL, PATCH_VERIFICATION_INDEX_DDL
from verify_batch import (already_done, class1_paired_patch_runs, classify,
                          order_by_vuln, queue_from_db, read_ids_file,
                          RESULT_OUTCOMES)


@pytest.fixture
def conn():
    c = sqlite3.connect(':memory:')
    c.executescript('''
        CREATE TABLE arvo (localId INTEGER PRIMARY KEY, project TEXT,
                           crash_output TEXT, fuzz_target TEXT);
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, vuln_id INTEGER,
                           run_mode TEXT, result_error_flag INTEGER,
                           result_json TEXT, prompt TEXT, command TEXT);
        CREATE TABLE patch_data (run_id TEXT PRIMARY KEY, loc_source TEXT,
                                 is_crash_resolved BOOLEAN, patch_crash_log TEXT,
                                 compile_errors TEXT);
    ''')
    c.execute(PATCH_VERIFICATION_DDL)
    c.execute(PATCH_VERIFICATION_INDEX_DDL)
    return c


def add_patch_run(c, run_id, vuln_id=1, err=0, rj='{"patches":[{"diff":"x"}]}',
                  resolved=None, crash_log=None, compile_errors=None):
    c.execute('INSERT INTO runs (run_id, vuln_id, run_mode, result_error_flag, '
              'result_json) VALUES (?,?,?,?,?)', (run_id, vuln_id, 'patch', err, rj))
    c.execute('INSERT INTO patch_data (run_id, is_crash_resolved, patch_crash_log, '
              'compile_errors) VALUES (?,?,?,?)',
              (run_id, resolved, crash_log, compile_errors))


def add_attempt(c, run_id, attempt=1, **cols):
    keys = ['run_id', 'attempt'] + list(cols)
    vals = [run_id, attempt] + list(cols.values())
    c.execute(f'INSERT INTO patch_verification ({",".join(keys)}) '
              f'VALUES ({",".join("?" * len(keys))})', vals)


# --- Class 1 exclusion ------------------------------------------------------

def test_class1_detector_finds_broken_resume(conn):
    conn.execute("INSERT INTO runs (run_id, vuln_id, run_mode, prompt, command, "
                 "result_json) VALUES ('arvo-1-vul-100-loc', 1, 'loc', "
                 "'continue where you left off', 'claude -p continue', '{}')")
    assert class1_paired_patch_runs(conn) == ['arvo-1-vul-100-patch']


def test_class1_detector_ignores_successful_resume(conn):
    conn.execute("INSERT INTO runs (run_id, vuln_id, run_mode, prompt, command, "
                 "result_json) VALUES ('arvo-1-vul-100-loc', 1, 'loc', "
                 "'continue where you left off', 'claude --resume abc', '{}')")
    assert class1_paired_patch_runs(conn) == []


def test_class1_detector_ignores_nonempty_result(conn):
    conn.execute("INSERT INTO runs (run_id, vuln_id, run_mode, prompt, command, "
                 "result_json) VALUES ('arvo-1-vul-100-loc', 1, 'loc', "
                 "'continue where you left off', 'claude -p continue', "
                 "'{\"findings\":1}')")
    assert class1_paired_patch_runs(conn) == []


def test_queue_excludes_class1_paired_patch_run(conn):
    add_patch_run(conn, 'arvo-1-vul-100-patch', vuln_id=1)
    add_patch_run(conn, 'arvo-1-vul-200-patch', vuln_id=1)
    conn.execute("INSERT INTO runs (run_id, vuln_id, run_mode, prompt, command, "
                 "result_json) VALUES ('arvo-1-vul-100-loc', 1, 'loc', "
                 "'continue where you left off', 'claude -p continue', '{}')")
    assert queue_from_db(conn) == ['arvo-1-vul-200-patch']


# --- queue filter -----------------------------------------------------------

def test_queue_requires_a_diff(conn):
    add_patch_run(conn, 'arvo-1-vul-1-patch', rj='{"patches":[]}')
    assert queue_from_db(conn) == []


def test_queue_excludes_errored_runs(conn):
    add_patch_run(conn, 'arvo-1-vul-1-patch', err=1)
    assert queue_from_db(conn) == []


def test_queue_excludes_already_adjudicated(conn):
    add_patch_run(conn, 'arvo-1-vul-1-patch', resolved=1)
    assert queue_from_db(conn) == []


def test_queue_excludes_rows_with_prior_verification_data(conn):
    add_patch_run(conn, 'arvo-1-vul-1-patch', crash_log='old log')
    assert queue_from_db(conn) == []
    add_patch_run(conn, 'arvo-1-vul-2-patch', compile_errors='old errors')
    assert queue_from_db(conn) == []


# --- ordering ---------------------------------------------------------------

def test_order_groups_each_vuln_contiguously(conn):
    for rid, v in [('a-3', 3), ('a-1', 1), ('b-3', 3), ('b-1', 1), ('a-2', 2)]:
        add_patch_run(conn, rid, vuln_id=v)
    pairs = order_by_vuln(conn, ['a-3', 'a-1', 'b-3', 'b-1', 'a-2'])
    vulns = [v for v, _ in pairs]
    assert vulns == sorted(vulns)
    # each vuln appears in exactly one contiguous block
    import itertools
    blocks = [k for k, _ in itertools.groupby(vulns)]
    assert len(blocks) == len(set(blocks))


def test_order_skips_unknown_run_ids(conn):
    add_patch_run(conn, 'known', vuln_id=1)
    assert order_by_vuln(conn, ['known', 'nonexistent']) == [(1, 'known')]


# --- resume -----------------------------------------------------------------

def test_not_done_without_any_attempt(conn):
    add_patch_run(conn, 'r1')
    assert not already_done(conn, 'r1')


def test_done_when_poc_ran(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', poc_rc=0)
    assert already_done(conn, 'r1')


def test_done_when_patch_failed(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=1)
    assert already_done(conn, 'r1')


def test_done_when_compile_failed(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=2)
    assert already_done(conn, 'r1')


def test_not_done_when_attempt_abandoned_midway(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0)          # applied, then died
    assert not already_done(conn, 'r1')


def test_backfill_rows_do_not_count_as_done(conn):
    """attempt=0 rows carry poc_stdout but no poc_rc and predate capture."""
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', attempt=0, poc_stdout='legacy log', is_crash_resolved=1)
    assert not already_done(conn, 'r1')


# --- outcome classification -------------------------------------------------

def test_driver_timeout_is_infra(conn):
    assert classify(conn, 'r1', timed_out=True) == ('driver_timeout', True)


def test_missing_row_is_infra(conn):
    assert classify(conn, 'r1', timed_out=False) == ('no_row', True)


def test_poc_present_is_artifacts_ready(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=0, poc_rc=1)
    assert classify(conn, 'r1', False) == ('artifacts_ready', False)


def test_patch_failure_is_a_result_not_a_fault(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=1)
    outcome, infra = classify(conn, 'r1', False)
    assert outcome == 'patch_failed' and infra is False
    assert outcome in RESULT_OUTCOMES


def test_ordinary_compile_failure_is_a_result(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1,
                compile_output_extract='error: undeclared identifier bw')
    assert classify(conn, 'r1', False) == ('compile_failed', False)


def test_disk_full_compile_failure_is_infra(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1,
                compile_output_extract='cc: No space left on device')
    assert classify(conn, 'r1', False) == ('infra_failed', True)


def test_dead_docker_daemon_is_infra(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1,
                compile_output_extract='Cannot connect to the Docker daemon')
    assert classify(conn, 'r1', False) == ('infra_failed', True)


def test_poc_timeout_is_a_result(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=0, poc_timed_out=1)
    assert classify(conn, 'r1', False) == ('poc_timeout', False)


def test_classify_reads_the_newest_attempt(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', attempt=1, patch_rc=1)
    add_attempt(conn, 'r1', attempt=2, patch_rc=0, compile_rc=0, poc_rc=0)
    assert classify(conn, 'r1', False) == ('artifacts_ready', False)


# --- ids file ---------------------------------------------------------------

def test_ids_file_skips_comments_and_blanks(tmp_path):
    f = tmp_path / 'ids.txt'
    f.write_text('# header\n\narvo-1-patch\n\n# --- group ---\narvo-2-patch\n',
                 encoding='utf-8')
    assert read_ids_file(f) == ['arvo-1-patch', 'arvo-2-patch']


def test_real_phase1_batch_file_parses():
    from pathlib import Path
    p = Path('phase1_batch.txt')
    if not p.exists():
        pytest.skip('phase1_batch.txt not present')
    ids = read_ids_file(p)
    assert len(ids) == len(set(ids))
    assert all(i.endswith('-patch') for i in ids)


# --- circuit breaker --------------------------------------------------------

class _Args:
    """Minimal stand-in for the argparse namespace run_batch reads."""
    def __init__(self, **kw):
        self.max_runs = None
        self.force = False
        self.no_prune = True          # keep docker out of the test
        self.abort_after = 3
        self.compile_timeout = 10
        self.poc_timeout = 5
        self.run_timeout = None
        self.__dict__.update(kw)


def _batch(conn, monkeypatch, outcomes, **argkw):
    """Drive run_batch with a scripted sequence of per-run outcomes."""
    import verify_batch as vb
    seq = iter(outcomes)
    attempted = []

    def fake_run_one(run_id, args):
        attempted.append(run_id)
        outcome, infra = next(seq)
        fake_run_one.pending[run_id] = (outcome, infra)
        return outcome == 'driver_timeout'

    fake_run_one.pending = {}
    monkeypatch.setattr(vb, 'run_one', fake_run_one)
    monkeypatch.setattr(vb, 'classify',
                        lambda c, rid, t: fake_run_one.pending[rid])

    pairs = []
    for i in range(len(outcomes)):
        rid = f'r{i}'
        add_patch_run(conn, rid, vuln_id=i)
        pairs.append((i, rid))
    counts = vb.run_batch(pairs, _Args(**argkw), conn)
    return counts, attempted


def test_breaker_aborts_after_consecutive_infra_failures(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch, [
        ('no_row', True), ('no_row', True), ('no_row', True),
        ('artifacts_ready', False),          # never reached
    ])
    assert counts['aborted'] == 1
    assert len(attempted) == 3


def test_breaker_resets_on_a_good_run(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch, [
        ('no_row', True), ('no_row', True),
        ('artifacts_ready', False),          # resets the streak
        ('no_row', True), ('no_row', True),
        ('artifacts_ready', False),
    ])
    assert 'aborted' not in counts
    assert len(attempted) == 6


def test_patch_failures_never_trip_the_breaker(conn, monkeypatch):
    """A patch that does not apply is a result, not an infrastructure fault."""
    counts, attempted = _batch(conn, monkeypatch,
                               [('patch_failed', False)] * 6)
    assert 'aborted' not in counts
    assert len(attempted) == 6
    assert counts['patch_failed'] == 6


def test_ordinary_compile_failures_never_trip_the_breaker(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch,
                               [('compile_failed', False)] * 5)
    assert 'aborted' not in counts
    assert len(attempted) == 5


def test_disk_full_trips_the_breaker(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch,
                               [('infra_failed', True)] * 4)
    assert counts['aborted'] == 1
    assert len(attempted) == 3


def test_abort_after_is_configurable(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch,
                               [('no_row', True)] * 5, abort_after=2)
    assert counts['aborted'] == 1
    assert len(attempted) == 2


def test_max_runs_caps_the_session(conn, monkeypatch):
    counts, attempted = _batch(conn, monkeypatch,
                               [('artifacts_ready', False)] * 5, max_runs=2)
    assert len(attempted) == 2


def test_completed_runs_are_skipped_on_resume(conn, monkeypatch):
    import verify_batch as vb
    add_patch_run(conn, 'done1', vuln_id=1)
    add_attempt(conn, 'done1', poc_rc=0)
    add_patch_run(conn, 'todo1', vuln_id=2)

    attempted = []
    monkeypatch.setattr(vb, 'run_one',
                        lambda rid, a: attempted.append(rid) or False)
    monkeypatch.setattr(vb, 'classify', lambda c, r, t: ('artifacts_ready', False))
    counts = vb.run_batch([(1, 'done1'), (2, 'todo1')], _Args(), conn)
    assert attempted == ['todo1']
    assert counts['skipped'] == 1


# --- harness build failures -------------------------------------------------

GEOS_EXTRACT = """[capture] 15 lines, 1048 bytes total
+ git apply ../patch.diff
error: patch failed: tests/CMakeLists.txt:10
error: tests/CMakeLists.txt: patch does not apply
error: tests/fuzz/CMakeLists.txt: already exists in working directory
error: tests/fuzz/fuzz_geo2.c: already exists in working directory"""


def test_harness_build_failure_is_not_a_compile_failure(conn):
    """ARVO's own build.sh re-applying its harness patch. Not the agent's patch,
    not a machine fault, and not fixable by retrying."""
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1, compile_duration_s=0.1,
                compile_output_extract=GEOS_EXTRACT)
    assert classify(conn, 'r1', False) == ('harness_build_failed', False)


def test_harness_build_failure_does_not_trip_the_breaker(conn):
    """It is a property of one image, so aborting the whole batch is wrong."""
    from verify_batch import RESULT_OUTCOMES
    assert 'harness_build_failed' in RESULT_OUTCOMES


def test_a_real_compile_failure_is_still_a_compile_failure(conn):
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1, compile_duration_s=1400.0,
                compile_output_extract='mjpegdec.c:399: error: undeclared identifier bw')
    assert classify(conn, 'r1', False) == ('compile_failed', False)


def test_disk_full_still_outranks_nothing(conn):
    """A disk-full compile failure has no harness markers, so it stays infra."""
    add_patch_run(conn, 'r1')
    add_attempt(conn, 'r1', patch_rc=0, compile_rc=1, compile_duration_s=900.0,
                compile_output_extract='cc: No space left on device')
    assert classify(conn, 'r1', False) == ('infra_failed', True)


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-v']))
