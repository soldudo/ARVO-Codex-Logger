"""Tests for the adjudication proposal rules.

The fixtures are shaped from real captured output: ARVO/ASAN reports carry a
DEDUP_TOKEN naming the top frames, which is what makes the same-vs-different
distinction possible without comparing addresses.
"""
import sqlite3

import pytest

from adjudicate import (CLEAN, DIFFERENT, SAME, UNDETERMINED, dedup_token,
                        propose, strip_ansi, summary_line)
from schema import PATCH_VERIFICATION_DDL

BASELINE = '''Reading 4379 bytes from /tmp/poc
=================================================================
==7==ERROR: AddressSanitizer: heap-use-after-free on address 0x621000003da5
    #0 0x4ea1dc in __asan_memcpy
    #1 0x5342de in av_packet_ref /src/ffmpeg/libavcodec/avpacket.c:614:13
DEDUP_TOKEN: __asan_memcpy--av_packet_ref--avcodec_send_packet
SUMMARY: AddressSanitizer: heap-use-after-free /src/ffmpeg/libavcodec/avpacket.c:614:13
==7==ABORTING
'''

SAME_CRASH = BASELINE
DIFFERENT_CRASH = BASELINE.replace(
    'DEDUP_TOKEN: __asan_memcpy--av_packet_ref--avcodec_send_packet',
    'DEDUP_TOKEN: get_bits--decode_frame--hls_coding_unit')
CLEAN_OUT = '''Reading 4379 bytes from /tmp/poc
Execution successful
'''
# 18 of 22 clean runs lacked the "Execution successful" marker, so the rules
# must not depend on it.
CLEAN_NO_MARKER = 'Reading 52 bytes from /tmp/poc\nRunning LLVMFuzzerInitialize ...\ncontinue...\n'


@pytest.fixture
def conn():
    c = sqlite3.connect(':memory:')
    c.row_factory = sqlite3.Row
    c.execute(PATCH_VERIFICATION_DDL)
    return c


def mkrow(conn, **cols):
    base = dict(run_id='r1', attempt=1, patch_rc=0, patch_max_fuzz=0,
                patch_recounted=0, patch_strip=0, patch_hunks_ok=1,
                patch_hunks_failed=0, compile_rc=0, compile_duration_s=900.0,
                compile_timed_out=0, compile_log_bytes=1000, poc_rc=0,
                poc_timed_out=0, poc_stdout='', poc_stderr='',
                baseline_log=BASELINE)
    base.update(cols)
    keys = list(base)
    conn.execute(f'INSERT INTO patch_verification ({",".join(keys)}) '
                 f'VALUES ({",".join("?" * len(keys))})', list(base.values()))
    return conn.execute('SELECT * FROM patch_verification ORDER BY verification_id '
                        'DESC LIMIT 1').fetchone()


# --- helpers ----------------------------------------------------------------

def test_dedup_token_extracted():
    assert dedup_token(BASELINE) == '__asan_memcpy--av_packet_ref--avcodec_send_packet'


def test_dedup_token_absent_from_clean_output():
    assert dedup_token(CLEAN_OUT) is None


def test_ansi_colour_does_not_hide_the_token():
    coloured = BASELINE.replace('DEDUP_TOKEN', '\x1b[1m\x1b[31mDEDUP_TOKEN')
    assert dedup_token(coloured) == '__asan_memcpy--av_packet_ref--avcodec_send_packet'
    assert '\x1b[' not in strip_ansi(coloured)


def test_summary_line_extracted():
    assert 'heap-use-after-free' in summary_line(BASELINE)


# --- the three outcomes -----------------------------------------------------

def test_clean_with_marker(conn):
    row = mkrow(conn, poc_rc=0, poc_stdout=CLEAN_OUT)
    outcome, resolved, auto_ok, _ = propose(row)
    assert (outcome, resolved, auto_ok) == (CLEAN, True, True)


def test_clean_without_marker(conn):
    """Most clean runs have no 'Execution successful' line."""
    row = mkrow(conn, poc_rc=0, poc_stdout=CLEAN_NO_MARKER)
    assert propose(row)[:3] == (CLEAN, True, True)


def test_same_crash(conn):
    row = mkrow(conn, poc_rc=1, poc_stderr=SAME_CRASH)
    outcome, resolved, auto_ok, reasons = propose(row)
    assert (outcome, resolved, auto_ok) == (SAME, False, True)
    assert 'reproduces' in reasons[0]


def test_different_crash_is_never_auto(conn):
    """The reported bug is gone but the POC still crashes: a human decides."""
    row = mkrow(conn, poc_rc=1, poc_stderr=DIFFERENT_CRASH)
    outcome, resolved, auto_ok, _ = propose(row)
    assert outcome == DIFFERENT
    assert resolved is None
    assert auto_ok is False


def test_different_crash_detected_despite_identical_crash_type(conn):
    """Both are heap-use-after-free; only the token separates them. Two real
    runs (PcapPlusPlus, ffmpeg hevc) have exactly this shape."""
    row = mkrow(conn, poc_rc=1, poc_stderr=DIFFERENT_CRASH)
    assert 'heap-use-after-free' in summary_line(DIFFERENT_CRASH)
    assert propose(row)[0] == DIFFERENT


def test_missing_baseline_token_forces_review(conn):
    row = mkrow(conn, poc_rc=1, poc_stderr=SAME_CRASH,
                baseline_log='no token here')
    outcome, resolved, auto_ok, reasons = propose(row)
    assert outcome == DIFFERENT and auto_ok is False
    assert any('no DEDUP_TOKEN' in r for r in reasons)


# --- fuzz gate --------------------------------------------------------------

def test_fuzz_blocks_auto_even_when_clean(conn):
    row = mkrow(conn, poc_rc=0, poc_stdout=CLEAN_OUT, patch_max_fuzz=2)
    outcome, resolved, auto_ok, reasons = propose(row)
    assert (outcome, resolved) == (CLEAN, True)
    assert auto_ok is False
    assert any('fuzz 2' in r for r in reasons)


def test_fuzz_blocks_auto_even_when_same_crash(conn):
    row = mkrow(conn, poc_rc=1, poc_stderr=SAME_CRASH, patch_max_fuzz=1)
    assert propose(row)[2] is False


def test_recount_alone_does_not_block_auto(conn):
    """A rewritten header is a repaired diff, not an uncertain application."""
    row = mkrow(conn, poc_rc=0, poc_stdout=CLEAN_OUT, patch_recounted=3)
    assert propose(row)[2] is True


# --- stages that produce nothing to judge -----------------------------------

def test_patch_failure_is_undetermined(conn):
    row = mkrow(conn, patch_rc=1, compile_rc=None, poc_rc=None)
    outcome, resolved, auto_ok, reasons = propose(row)
    assert (outcome, resolved, auto_ok) == (UNDETERMINED, None, False)
    assert 'did not apply' in reasons[0]


def test_harness_build_failure_is_called_out(conn):
    """geos: arvo's own build.sh re-applies its harness patch and aborts."""
    row = mkrow(conn, compile_rc=1, compile_duration_s=0.1, poc_rc=None)
    outcome, _, auto_ok, reasons = propose(row)
    assert outcome == UNDETERMINED and auto_ok is False
    assert "build.sh" in reasons[0]


def test_real_compile_failure_is_distinguished_from_harness(conn):
    row = mkrow(conn, compile_rc=1, compile_duration_s=1400.0, poc_rc=None)
    reasons = propose(row)[3]
    assert 'compile failed' in reasons[0]
    assert 'build.sh' not in reasons[0]


def test_compile_timeout_is_undetermined(conn):
    row = mkrow(conn, compile_timed_out=1, compile_rc=-9, poc_rc=None)
    assert propose(row)[0] == UNDETERMINED


def test_poc_timeout_is_undetermined(conn):
    row = mkrow(conn, poc_timed_out=1, poc_rc=None)
    assert propose(row)[0] == UNDETERMINED


def test_missing_poc_result_is_undetermined(conn):
    row = mkrow(conn, poc_rc=None)
    assert propose(row)[0] == UNDETERMINED


# --- signal disagreement ----------------------------------------------------

def test_clean_rc_with_a_crash_token_defers(conn):
    row = mkrow(conn, poc_rc=0, poc_stderr=SAME_CRASH)
    outcome, _, auto_ok, reasons = propose(row)
    assert outcome == UNDETERMINED and auto_ok is False
    assert 'disagree' in reasons[0]


def test_crash_rc_without_a_token_defers(conn):
    row = mkrow(conn, poc_rc=1, poc_stdout=CLEAN_NO_MARKER)
    outcome, _, auto_ok, reasons = propose(row)
    assert outcome == UNDETERMINED and auto_ok is False
    assert 'disagree' in reasons[0]


# --- against the live database ----------------------------------------------

def test_rules_reproduce_the_measured_split():
    """The proposal rules must agree with the hand analysis of the captured
    data: every poc_rc=0 run clean, every poc_rc=1 run same-or-different."""
    import os
    if not os.path.exists('arvo_loc_runs.db'):
        pytest.skip('no database')
    c = sqlite3.connect('arvo_loc_runs.db')
    c.row_factory = sqlite3.Row
    rows = c.execute('SELECT * FROM patch_verification WHERE attempt>0 '
                     'AND poc_rc IS NOT NULL').fetchall()
    if not rows:
        pytest.skip('no captured attempts')
    for row in rows:
        outcome, resolved, _, _ = propose(row)
        if row['poc_rc'] == 0:
            assert outcome == CLEAN, f'{row["run_id"]} rc=0 but {outcome}'
        else:
            assert outcome in (SAME, DIFFERENT), f'{row["run_id"]} rc!=0 but {outcome}'
    c.close()


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-v']))
