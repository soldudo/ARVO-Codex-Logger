import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import run_experiments as rx

BASE_CONFIG = {
    'container_name': 'rootainer',
    'agent': 'claude',
    'is_loc_mode': False,
    'is_patch_mode': True,
}

LIMIT_RESULT = "You've hit your limit · resets 7pm (UTC)"


@pytest.fixture
def conn():
    conn = sqlite3.connect(':memory:')
    conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE arvo (
        localId INTEGER PRIMARY KEY,
        project TEXT NOT NULL,
        reproduced BOOLEAN NOT NULL
    )''')
    conn.execute('''CREATE TABLE experiments (
        experiment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        experiment_tag TEXT UNIQUE NOT NULL,
        description TEXT,
        prompt_template TEXT,
        markdown_json TEXT
    )''')
    conn.execute('''CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        run_mode TEXT,
        vuln_id INTEGER,
        timestamp TEXT,
        result TEXT,
        result_error_flag BOOLEAN,
        session_id TEXT
    )''')
    conn.execute("INSERT INTO experiments (experiment_tag) VALUES ('baseline-patch-envmd')")
    conn.executemany(
        'INSERT INTO arvo (localId, project, reproduced) VALUES (?, ?, 1)',
        [(101, 'libxml2'), (102, 'ndpi'), (103, 'php')])
    rx.init_campaign_tables(conn)
    conn.commit()
    yield conn
    conn.close()


def insert_run(conn, run_id, vuln_id, result, error_flag, run_mode='patch',
               session_id='sess-1', timestamp=None):
    conn.execute(
        'INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)',
        (run_id, run_mode, vuln_id, timestamp or rx._timestamp_now(),
         result, error_flag, session_id))
    conn.commit()


def get_items(conn):
    return {row['vuln_id']: dict(row)
            for row in conn.execute('SELECT * FROM campaign_items').fetchall()}


# ----- enqueue -----

def test_enqueue_creates_campaign_and_items(conn):
    summary = rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102, 999],
                         BASE_CONFIG, conn=conn)
    assert summary['added'] == 2
    assert summary['unknown'] == [999]
    items = get_items(conn)
    assert set(items) == {101, 102}
    assert all(item['status'] == 'pending' for item in items.values())

    campaign = conn.execute('SELECT * FROM campaigns').fetchone()
    assert campaign['campaign_tag'] == 'camp1'
    assert json.loads(campaign['base_config']) == BASE_CONFIG


def test_enqueue_existing_campaign_requires_append(conn):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    with pytest.raises(ValueError, match='--append'):
        rx.enqueue('camp1', 'baseline-patch-envmd', [102], BASE_CONFIG, conn=conn)

    summary = rx.enqueue('camp1', None, [101, 102], BASE_CONFIG, append=True, conn=conn)
    assert summary['added'] == 1
    assert summary['duplicates'] == 1


def test_enqueue_unknown_experiment_tag(conn):
    with pytest.raises(ValueError, match='not found'):
        rx.enqueue('camp1', 'no-such-tag', [101], BASE_CONFIG, conn=conn)


def test_enqueue_requires_a_mode(conn):
    no_mode = dict(BASE_CONFIG, is_loc_mode=False, is_patch_mode=False)
    with pytest.raises(ValueError, match='loc-mode'):
        rx.enqueue('camp1', 'baseline-patch-envmd', [101], no_mode, conn=conn)


# ----- reset time parsing -----

def test_parse_reset_time_pm_later_today():
    now = datetime(2026, 7, 2, 15, 0, tzinfo=timezone.utc)
    assert rx.parse_reset_time(LIMIT_RESULT, now) == '2026-07-02T19:00:00+00:00'


def test_parse_reset_time_am_rolls_to_next_day():
    now = datetime(2026, 7, 2, 15, 0, tzinfo=timezone.utc)
    result = "You've hit your limit · resets 9am (UTC)"
    assert rx.parse_reset_time(result, now) == '2026-07-03T09:00:00+00:00'


def test_parse_reset_time_unparseable():
    assert rx.parse_reset_time('some other error') is None
    assert rx.parse_reset_time(None) is None


# ----- outcome classification -----

def test_classify_no_rows_is_error(conn):
    outcome = rx.classify_outcome(conn, 101, rx._timestamp_now(),
                                  stderr_tail='Traceback ...', return_code=1)
    assert outcome['status'] == 'error'
    assert 'exit code 1' in outcome['last_error']
    assert 'Traceback' in outcome['last_error']


def test_classify_usage_limited(conn):
    started = rx._timestamp_now()
    insert_run(conn, 'r1-loc', 101, LIMIT_RESULT, 1, run_mode='loc', session_id='sess-loc')
    insert_run(conn, 'r1-patch', 101, LIMIT_RESULT, 1, run_mode='patch', session_id='sess-patch')
    outcome = rx.classify_outcome(conn, 101, started)
    assert outcome['status'] == 'usage_limited'
    # earliest limited row wins
    assert outcome['limited_stage'] == 'loc'
    assert outcome['session_id'] == 'sess-loc'
    assert outcome['resume_after'] is not None


def test_classify_non_limit_error(conn):
    started = rx._timestamp_now()
    insert_run(conn, 'r1', 101, 'API error: overloaded', 1)
    outcome = rx.classify_outcome(conn, 101, started)
    assert outcome['status'] == 'error'
    assert 'overloaded' in outcome['last_error']


def test_classify_complete_uses_final_run(conn):
    started = rx._timestamp_now()
    insert_run(conn, 'r1-loc', 101, 'loc done', 0, run_mode='loc',
               timestamp='2026-07-02T10:00:00')
    insert_run(conn, 'r1-patch', 101, 'patch done', 0, run_mode='patch',
               timestamp='2026-07-02T10:30:00')
    outcome = rx.classify_outcome(conn, 101, '2026-07-02T09:00:00')
    assert outcome['status'] == 'complete'
    assert outcome['run_id'] == 'r1-patch'


def test_classify_ignores_runs_before_start(conn):
    insert_run(conn, 'old-run', 101, 'done', 0, timestamp='2026-07-01T10:00:00')
    outcome = rx.classify_outcome(conn, 101, '2026-07-02T09:00:00', return_code=0)
    assert outcome['status'] == 'error'
    assert 'no run rows' in outcome['last_error']


# ----- run loop -----

def make_invoke(conn, result=None, error_flag=0):
    """Fake caro invocation that records a run row for the configured vuln."""
    def invoke(config_path, timeout):
        config = json.loads(Path(config_path).read_text(encoding='utf-8'))
        vuln_id = config['arvo_id']
        insert_run(conn, f'arvo-{vuln_id}-vul-x-patch', vuln_id,
                   result if result is not None else 'patch done', error_flag)
        return (1 if error_flag else 0), ''
    return invoke


def test_run_campaign_completes_items(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102], BASE_CONFIG, conn=conn)
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path,
                             invoke=make_invoke(conn))
    assert counts == {'complete': 2}

    items = get_items(conn)
    assert items[101]['run_id'] == 'arvo-101-vul-x-patch'
    assert items[101]['attempts'] == 1

    config = json.loads((tmp_path / 'campaign_camp1' / 'config_101.json')
                        .read_text(encoding='utf-8'))
    assert config['arvo_id'] == 101
    assert config['experiment_tag'] == 'baseline-patch-envmd'
    assert config['is_patch_mode'] is True
    assert config['is_resume'] is False


def test_run_campaign_no_wait_stops_on_usage_limit(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102], BASE_CONFIG, conn=conn)
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path, no_wait=True,
                             invoke=make_invoke(conn, result=LIMIT_RESULT, error_flag=1))
    # first item marked, campaign stopped before touching the second
    assert counts == {'usage_limited': 1, 'pending': 1}
    items = get_items(conn)
    assert items[101]['status'] == 'usage_limited'
    assert items[101]['resume_after'] is not None
    assert items[102]['status'] == 'pending'
    assert not (tmp_path / '.run_experiments.lock').exists()


def test_run_campaign_max_runs(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102, 103], BASE_CONFIG, conn=conn)
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path,
                             invoke=make_invoke(conn), max_runs=2)
    assert counts == {'complete': 2, 'pending': 1}


def test_run_campaign_reconciles_stale_running_item(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    item = conn.execute('SELECT * FROM campaign_items').fetchone()
    rx._update_item(conn, item['item_id'],
                    {'status': 'running', 'started_at': '2026-07-02T09:00:00'})
    insert_run(conn, 'r-stale', 101, 'patch done', 0, timestamp='2026-07-02T09:30:00')

    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path,
                             invoke=make_invoke(conn))
    assert counts == {'complete': 1}
    assert get_items(conn)[101]['run_id'] == 'r-stale'


def test_run_campaign_lock_prevents_concurrent_runners(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    lock = tmp_path / '.run_experiments.lock'
    lock.write_text('12345')
    with pytest.raises(ValueError, match='lock'):
        rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path, invoke=make_invoke(conn))
    assert get_items(conn)[101]['status'] == 'pending'


# ----- usage-limit wait & resume -----

def make_sequenced_invoke(conn, outcomes):
    """Fake caro whose nth call yields outcomes[n] ('limited' or 'ok');
    records each config it was invoked with."""
    calls = []

    def invoke(config_path, timeout):
        config = json.loads(Path(config_path).read_text(encoding='utf-8'))
        calls.append(config)
        vuln_id = config['arvo_id']
        run_id = f'run-{vuln_id}-{len(calls)}'
        if outcomes[len(calls) - 1] == 'limited':
            insert_run(conn, run_id, vuln_id, LIMIT_RESULT, 1,
                       session_id=f'sess-{len(calls)}')
            return 1, ''
        insert_run(conn, run_id, vuln_id, 'patch done', 0)
        return 0, ''

    invoke.calls = calls
    return invoke


def test_run_campaign_waits_and_resumes(conn, tmp_path, monkeypatch):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)

    clock = {'now': datetime(2026, 7, 2, 15, 0, tzinfo=timezone.utc)}
    monkeypatch.setattr(rx, '_utcnow', lambda: clock['now'])
    # strictly increasing local timestamps so retries never share a second
    # with the failed run row they follow
    ticker = {'t': datetime(2026, 7, 2, 15, 0, 0)}

    def fake_timestamp_now():
        ticker['t'] += timedelta(seconds=1)
        return ticker['t'].isoformat(timespec='seconds')

    monkeypatch.setattr(rx, '_timestamp_now', fake_timestamp_now)

    waits = []

    def fake_wait(target_iso, reason):
        waits.append(target_iso)
        clock['now'] = (datetime.fromisoformat(target_iso)
                        + timedelta(seconds=rx.RESUME_BUFFER_SECONDS))

    monkeypatch.setattr(rx, '_wait_until', fake_wait)

    invoke = make_sequenced_invoke(conn, ['limited', 'ok'])
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path, invoke=invoke)

    assert counts == {'complete': 1}
    assert waits == ['2026-07-02T19:00:00+00:00']  # parsed from "resets 7pm (UTC)"

    resume_config = invoke.calls[1]
    assert resume_config['is_resume'] is True
    assert resume_config['resume_id'] == 'sess-1'
    assert resume_config['is_loc_mode'] is False  # patch-stage resume skips re-localization
    assert resume_config['is_patch_mode'] is True

    item = get_items(conn)[101]
    assert item['attempts'] == 2
    assert item['run_id'] == 'run-101-2'
    assert item['resume_after'] is None  # cleared once complete
    assert (tmp_path / 'campaign_camp1' / 'config_101_attempt2.json').exists()


def test_run_campaign_holds_pending_while_limit_active(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102], BASE_CONFIG, conn=conn)
    items = get_items(conn)
    rx._update_item(conn, items[101]['item_id'],
                    {'status': 'usage_limited', 'attempts': 1, 'session_id': 'sess-1',
                     'limited_stage': 'patch', 'resume_after': '2999-01-01T00:00:00+00:00'})

    invoke = make_invoke(conn)
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path,
                             invoke=invoke, no_wait=True)
    # nothing ran: the pending item is held back until the limit resets
    assert counts == {'usage_limited': 1, 'pending': 1}


def test_run_campaign_resumes_overdue_limited_item_first(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102], BASE_CONFIG, conn=conn)
    items = get_items(conn)
    rx._update_item(conn, items[102]['item_id'],
                    {'status': 'usage_limited', 'attempts': 1, 'session_id': 'sess-x',
                     'limited_stage': 'patch', 'resume_after': '2020-01-01T00:00:00+00:00'})

    invoke = make_sequenced_invoke(conn, ['ok', 'ok'])
    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path, invoke=invoke)
    assert counts == {'complete': 2}
    # the overdue limited item (102) ran before the pending one (101)
    assert invoke.calls[0]['arvo_id'] == 102
    assert invoke.calls[0]['is_resume'] is True
    assert invoke.calls[1]['arvo_id'] == 101
    assert invoke.calls[1]['is_resume'] is False


def test_run_campaign_expires_items_at_max_attempts(conn, tmp_path):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    item = get_items(conn)[101]
    rx._update_item(conn, item['item_id'],
                    {'status': 'usage_limited', 'attempts': 3, 'session_id': 'sess-1',
                     'resume_after': '2020-01-01T00:00:00+00:00'})

    counts = rx.run_campaign('camp1', conn=conn, runs_dir=tmp_path,
                             invoke=make_invoke(conn), max_attempts=3)
    assert counts == {'error': 1}
    assert 'max attempts' in get_items(conn)[101]['last_error']


def test_resume_config_for_loc_stage_keeps_loc_mode(conn):
    base = dict(BASE_CONFIG, is_loc_mode=True)
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], base, conn=conn)
    item = get_items(conn)[101]
    rx._update_item(conn, item['item_id'],
                    {'status': 'usage_limited', 'session_id': 'sess-loc',
                     'limited_stage': 'loc'})
    campaign = rx._get_campaign(conn, 'camp1')
    item = conn.execute('SELECT * FROM campaign_items').fetchone()

    config = rx.build_item_config(campaign, item)
    assert config['is_resume'] is True
    assert config['resume_id'] == 'sess-loc'
    # caro resumes the loc session, then chains a fresh patch run on its result
    assert config['is_loc_mode'] is True
    assert config['is_patch_mode'] is True


def test_resume_without_session_id_reruns_from_scratch(conn):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    item = get_items(conn)[101]
    rx._update_item(conn, item['item_id'],
                    {'status': 'usage_limited', 'limited_stage': 'patch'})
    campaign = rx._get_campaign(conn, 'camp1')
    item = conn.execute('SELECT * FROM campaign_items').fetchone()

    config = rx.build_item_config(campaign, item)
    assert config['is_resume'] is False
    assert config['is_patch_mode'] is True


def test_classify_unparseable_limit_uses_fallback_retry(conn, monkeypatch):
    fixed = datetime(2026, 7, 2, 15, 0, tzinfo=timezone.utc)
    monkeypatch.setattr(rx, '_utcnow', lambda: fixed)
    started = rx._timestamp_now()
    insert_run(conn, 'r1', 101, "You've hit your limit", 1)

    outcome = rx.classify_outcome(conn, 101, started)
    assert outcome['status'] == 'usage_limited'
    assert outcome['resume_after'] == '2026-07-02T15:30:00+00:00'


# ----- requeue / status -----

def test_requeue_resets_selected_statuses(conn):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102, 103], BASE_CONFIG, conn=conn)
    items = get_items(conn)
    rx._update_item(conn, items[101]['item_id'],
                    {'status': 'error', 'last_error': 'boom'})
    rx._update_item(conn, items[102]['item_id'],
                    {'status': 'usage_limited', 'limited_stage': 'patch',
                     'resume_after': '2026-07-02T19:00:00+00:00'})
    rx._update_item(conn, items[103]['item_id'], {'status': 'complete'})

    count = rx.requeue('camp1', ['error', 'usage_limited'], conn=conn)
    assert count == 2
    items = get_items(conn)
    assert items[101]['status'] == 'pending'
    assert items[101]['last_error'] is None
    assert items[102]['status'] == 'pending'
    assert items[102]['limited_stage'] is None
    assert items[102]['resume_after'] is None
    assert items[103]['status'] == 'complete'


def test_requeue_invalid_status(conn):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101], BASE_CONFIG, conn=conn)
    with pytest.raises(ValueError, match='Invalid status'):
        rx.requeue('camp1', ['bogus'], conn=conn)


def test_get_campaign_status(conn):
    rx.enqueue('camp1', 'baseline-patch-envmd', [101, 102], BASE_CONFIG, conn=conn)
    data = rx.get_campaign_status('camp1', conn=conn)
    assert data['campaign']['experiment_tag'] == 'baseline-patch-envmd'
    assert data['counts'] == {'pending': 2}
    assert [item['vuln_id'] for item in data['items']] == [101, 102]


def test_status_unknown_campaign(conn):
    with pytest.raises(ValueError, match='not found'):
        rx.get_campaign_status('nope', conn=conn)
