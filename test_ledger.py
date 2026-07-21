import json
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import ledger as lg

TAG = 'baseline-patch-envmd'
NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def run_fact(vuln_id, outcome='success', tag=TAG, machine='machine-a',
             run_id=None, model='claude-sonnet-4-6', timestamp='2026-07-18T10:00:00'):
    return {'type': 'run', 'run_id': run_id or f'run-{vuln_id}-{outcome}',
            'machine': machine, 'vuln_id': vuln_id, 'experiment_tag': tag,
            'run_mode': 'patch', 'model': model, 'outcome': outcome,
            'timestamp': timestamp, 'reported_at': timestamp}


def claim_fact(vuln_id, tag=TAG, machine='machine-b', age_days=0):
    ts = (NOW - timedelta(days=age_days)).isoformat(timespec='seconds')
    return {'type': 'claim', 'machine': machine, 'vuln_id': vuln_id,
            'experiment_tag': tag, 'campaign': 'campX', 'timestamp': ts}


def make_ledger_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    for args in (['init'], ['config', 'user.email', 'test@test'],
                 ['config', 'user.name', 'test']):
        subprocess.run(['git'] + args, cwd=str(path), capture_output=True, check=True)
    return path


@pytest.fixture
def ledger_dir(tmp_path):
    return make_ledger_repo(tmp_path / 'ledger')


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / 'arvo_loc_runs.db'
    conn = sqlite3.connect(str(path))
    conn.execute('''CREATE TABLE experiments (
        experiment_id INTEGER PRIMARY KEY, experiment_tag TEXT UNIQUE)''')
    conn.execute('''CREATE TABLE runs (
        run_id TEXT PRIMARY KEY, experiment_id INTEGER, vuln_id INTEGER,
        run_mode TEXT, agent_model TEXT, timestamp TEXT,
        result TEXT, result_error_flag BOOLEAN)''')
    conn.execute('''CREATE TABLE arvo (
        localId INTEGER PRIMARY KEY, project TEXT, reproduced BOOLEAN)''')
    conn.execute("INSERT INTO experiments VALUES (1, ?)", (TAG,))
    conn.executemany('INSERT INTO arvo VALUES (?, ?, ?)', [
        (101, 'libxml2', 1), (102, 'ndpi', 1), (103, 'ndpi', 0), (104, 'php', 1)])
    conn.commit()
    conn.close()
    return str(path)


def insert_db_run(db_path, run_id, vuln_id, result='done', error_flag=0,
                  experiment_id=1, model='claude-sonnet-4-6'):
    conn = sqlite3.connect(db_path)
    conn.execute('INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (run_id, experiment_id, vuln_id, 'patch', model,
                  '2026-07-18T10:00:00', result, error_flag))
    conn.commit()
    conn.close()


# ----- outcome classification / basics -----

def test_classify_run_outcome():
    assert lg.classify_run_outcome(0, 'patch done') == 'success'
    assert lg.classify_run_outcome(1, 'API error') == 'error'
    assert lg.classify_run_outcome(1, "You've hit your limit · resets 7pm (UTC)") == 'usage_limited'


def test_machine_name_sanitized(monkeypatch):
    monkeypatch.setenv(lg.MACHINE_ENV, 'my laptop (home)!')
    assert lg.machine_name() == 'my-laptop--home--'


def test_append_and_read_facts_roundtrip(ledger_dir):
    facts = [run_fact(101), claim_fact(102)]
    lg.append_facts(ledger_dir, 'machine-a', facts, 'test append')
    read_back = lg.read_facts(ledger_dir)
    assert read_back == facts  # append order preserved within a machine file
    # facts were committed (push fails without a remote, which is tolerated)
    log = subprocess.run(['git', 'log', '--oneline'], cwd=str(ledger_dir),
                         capture_output=True, text=True)
    assert 'test append' in log.stdout


# ----- reporting (outbox) -----

def test_report_new_runs_is_idempotent(ledger_dir, db_path):
    insert_db_run(db_path, 'r1', 101)
    insert_db_run(db_path, 'r2', 102, result="You've hit your limit · resets 7pm (UTC)",
                  error_flag=1)
    insert_db_run(db_path, 'r3', 103, experiment_id=None)  # untagged legacy run

    count = lg.report_new_runs(db_path, ledger_dir, machine='machine-a', do_sync=False)
    assert count == 2  # untagged run skipped by default

    facts = lg.read_facts(ledger_dir)
    by_run = {f['run_id']: f for f in facts}
    assert by_run['r1']['outcome'] == 'success'
    assert by_run['r1']['experiment_tag'] == TAG
    assert by_run['r1']['model'] == 'claude-sonnet-4-6'
    assert by_run['r2']['outcome'] == 'usage_limited'

    # second call reports nothing new
    assert lg.report_new_runs(db_path, ledger_dir, machine='machine-a', do_sync=False) == 0
    # a new run appears -> only it is reported
    insert_db_run(db_path, 'r4', 104)
    assert lg.report_new_runs(db_path, ledger_dir, machine='machine-a', do_sync=False) == 1


def test_report_include_untagged(ledger_dir, db_path):
    insert_db_run(db_path, 'r-legacy', 101, experiment_id=None)
    count = lg.report_new_runs(db_path, ledger_dir, machine='machine-a',
                               include_untagged=True, do_sync=False)
    assert count == 1
    assert lg.read_facts(ledger_dir)[0]['experiment_tag'] is None


# ----- gap selection -----

def test_select_gaps_excludes_covered_and_attempted():
    facts = [run_fact(101, 'success'), run_fact(102, 'error')]
    gaps = lg.select_gaps([101, 102, 103], TAG, facts, now=NOW)
    assert gaps == [103]


def test_select_gaps_retry_failed_includes_error_only_cells():
    facts = [run_fact(101, 'success'), run_fact(102, 'error'), run_fact(104, 'usage_limited')]
    gaps = lg.select_gaps([101, 102, 103, 104], TAG, facts, retry_failed=True, now=NOW)
    assert gaps == [102, 103, 104]


def test_select_gaps_other_tags_do_not_count():
    facts = [run_fact(101, 'success', tag='other-experiment')]
    assert lg.select_gaps([101], TAG, facts, now=NOW) == [101]


def test_select_gaps_claims_and_ttl():
    facts = [claim_fact(101, age_days=1), claim_fact(102, age_days=30)]
    # fresh claim excluded, expired claim is a gap again
    assert lg.select_gaps([101, 102], TAG, facts, now=NOW) == [102]


def test_select_gaps_count_sampling_is_seeded():
    candidates = list(range(1, 51))
    first = lg.select_gaps(candidates, TAG, [], count=5, seed=42, now=NOW)
    second = lg.select_gaps(candidates, TAG, [], count=5, seed=42, now=NOW)
    assert first == second
    assert len(first) == 5
    assert first == sorted(first)


def test_candidate_vulns_filters(db_path):
    assert lg.candidate_vulns(db_path) == [101, 102, 103, 104]
    assert lg.candidate_vulns(db_path, projects=['ndpi']) == [102, 103]
    assert lg.candidate_vulns(db_path, projects=['ndpi'], reproduced_only=True) == [102]
    assert lg.candidate_vulns(db_path, id_min=102, id_max=103) == [102, 103]


def test_gap_fill_ids_end_to_end(ledger_dir, db_path):
    lg.append_facts(ledger_dir, 'machine-a', [run_fact(101, 'success')], 'seed facts')
    ids = lg.gap_fill_ids(db_path, ledger_dir, TAG, reproduced_only=True, do_sync=False)
    assert ids == [102, 104]


# ----- claims -----

def test_record_claims_written(ledger_dir):
    lg.record_claims(ledger_dir, 'machine-a', [101, 102], TAG, campaign='fill-1')
    facts = lg.read_facts(ledger_dir)
    assert len(facts) == 2
    assert all(f['type'] == 'claim' and f['experiment_tag'] == TAG for f in facts)
    assert {f['vuln_id'] for f in facts} == {101, 102}
    assert facts[0]['campaign'] == 'fill-1'


# ----- coverage -----

def test_coverage_report_statuses():
    facts = [
        run_fact(101, 'success'), run_fact(101, 'error'),
        run_fact(102, 'error'), run_fact(102, 'usage_limited'),
        claim_fact(103, age_days=1),
        claim_fact(104, age_days=30),  # expired -> attempted (it has a failed run)
        run_fact(104, 'error'),
    ]
    report = lg.coverage_report(facts, now=NOW)
    tag_data = report['tags'][TAG]
    assert tag_data['covered'] == 1
    assert tag_data['attempted'] == 2
    assert tag_data['claimed'] == 1
    cells = tag_data['cells']
    assert cells[101]['status'] == 'covered'
    assert cells[101]['success'] == 1 and cells[101]['error'] == 1
    assert cells[102]['status'] == 'attempted'
    assert cells[102]['usage_limited'] == 1
    assert cells[103]['status'] == 'claimed'
    assert cells[104]['status'] == 'attempted'
    assert cells[101]['models'] == ['claude-sonnet-4-6']
    assert cells[101]['machines'] == ['machine-a']


def test_coverage_report_tag_filter():
    facts = [run_fact(101, 'success'), run_fact(102, 'success', tag='other')]
    report = lg.coverage_report(facts, experiment_tag=TAG, now=NOW)
    assert list(report['tags']) == [TAG]


# ----- multi-machine sync through a shared remote -----

def test_two_clones_share_facts_via_remote(tmp_path):
    bare = tmp_path / 'origin.git'
    bare.mkdir()
    subprocess.run(['git', 'init', '--bare'], cwd=str(bare), capture_output=True, check=True)

    def clone(name):
        path = tmp_path / name
        subprocess.run(['git', 'clone', str(bare), str(path)], capture_output=True, check=True)
        for args in (['config', 'user.email', 'test@test'], ['config', 'user.name', name]):
            subprocess.run(['git'] + args, cwd=str(path), capture_output=True, check=True)
        return path

    clone_a = clone('machine-a')
    clone_b = clone('machine-b')

    # machine A reports a run; the fact reaches machine B through the remote
    lg.append_facts(clone_a, 'machine-a', [run_fact(101, 'success')], 'a: report')
    assert lg.sync(clone_b) is True
    facts_on_b = lg.read_facts(clone_b)
    assert len(facts_on_b) == 1
    assert facts_on_b[0]['machine'] == 'machine-a'

    # machine B claims a vuln; A sees the claim and gap-fill skips both cells
    lg.record_claims(clone_b, 'machine-b', [102], TAG, campaign='fill-b')
    assert lg.sync(clone_a) is True
    gaps = lg.select_gaps([101, 102, 103], TAG, lg.read_facts(clone_a), now=NOW)
    assert gaps == [103]
