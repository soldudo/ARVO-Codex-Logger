"""Unit tests for the diff repair and applier-argv logic in diff_tools.

Covers PATCH_VERIFICATION_PROPOSAL.md verification steps 3 and 4. The four
recount shapes are taken from real runs in arvo_loc_runs.db.
"""
import json

import pytest

from diff_tools import (build_patch_argv, derive_strip_level, parse_patch_output,
                        recount_hunks)


# --- recount ----------------------------------------------------------------

# arvo-42541144-vul-1784216642-patch: header -7/+9, body -5/+7 (short by 2 both sides)
SHORT_BOTH = (
    '--- libavcodec/mpegaudio_parser.c\n'
    '+++ libavcodec/mpegaudio_parser.c\n'
    '@@ -98,7 +98,9 @@\n'
    '                     } else if (codec_id == AV_CODEC_ID_MP3ADU) {\n'
    '                         avpriv_report_missing_feature(avctx,\n'
    '                             "MP3ADU full parser");\n'
    '-                        return 0; /* parsers must not return error codes */\n'
    '+                        *poutbuf = NULL;\n'
    '+                        *poutbuf_size = 0;\n'
    '+                        return buf_size;\n'
    '                     }\n'
)

# arvo-42540891-vul-1784232900-patch: header -6/+15, body -6/+15 (already correct)
CORRECT = (
    '--- a/libavcodec/mjpegdec.c\n'
    '+++ b/libavcodec/mjpegdec.c\n'
    '@@ -388,3 +388,5 @@\n'
    '     }\n'
    '+    if (s->h_max % h_count[i])\n'
    '+        return AVERROR_INVALIDDATA;\n'
    '     /* if different size, realloc/alloc picture */\n'
    '     if (width != s->width || height != s->height)\n'
)


def test_short_on_both_sides_is_corrected():
    fixed, n = recount_hunks(SHORT_BOTH)
    assert n == 1
    assert '@@ -98,5 +98,7 @@' in fixed


def test_long_on_both_sides_is_corrected():
    """arvo-42532853-vul-1775168486-patch shape: body longer than declared."""
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -10,2 +10,2 @@\n'
        ' a\n b\n-c\n+C\n d\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 1
    assert '@@ -10,4 +10,4 @@' in fixed


def test_short_on_new_side_only_is_corrected():
    """arvo-419085594-vul-1775194674-patch shape. A blank-line separator cannot
    absorb this, because a blank line counts toward both sides."""
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,3 +1,5 @@\n'
        ' a\n b\n+NEW\n c\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 1
    assert '@@ -1,3 +1,4 @@' in fixed


def test_correct_diff_is_byte_identical():
    fixed, n = recount_hunks(CORRECT)
    assert n == 0
    assert fixed == CORRECT


def test_multiple_hunks_counted_independently():
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' a\n-b\n+B\n c\n'
        '@@ -50,3 +50,3 @@\n'
        ' d\n-e\n+E\n f\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 1                          # only the first was wrong
    assert '@@ -1,3 +1,3 @@' in fixed
    assert '@@ -50,3 +50,3 @@' in fixed


def test_bare_empty_line_counts_as_context():
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' a\n'
        '\n'
        '-b\n+B\n'
        ' c\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 1
    assert '@@ -1,4 +1,4 @@' in fixed      # blank counted on both sides


def test_no_newline_marker_counts_toward_neither():
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' a\n-b\n+B\n'
        '\\ No newline at end of file\n'
    )
    fixed, n = recount_hunks(diff)
    assert '@@ -1,2 +1,2 @@' in fixed


def test_section_heading_is_preserved():
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,9 +1,9 @@ static int decode(void)\n'
        ' a\n-b\n+B\n'
    )
    fixed, _ = recount_hunks(diff)
    assert '@@ -1,2 +1,2 @@ static int decode(void)' in fixed


def test_second_entry_header_is_not_eaten():
    """The failure the old bare concatenation produced: a short hunk consuming
    the next entry's ---/+++ pair and dying on its @@."""
    diff = (
        '--- a.c\n+++ a.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' a\n-b\n+B\n'
        '--- b.c\n+++ b.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' c\n-d\n+D\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 2
    assert fixed.count('@@ -1,2 +1,2 @@') == 2
    assert '--- b.c' in fixed and '+++ b.c' in fixed


def test_removal_line_beginning_with_dashes_is_not_a_header():
    """'--- ' only starts a header when a '+++ ' line follows it."""
    diff = (
        '--- x.c\n+++ x.c\n'
        '@@ -1,9 +1,9 @@\n'
        ' a\n'
        '--- not a header, just removed text\n'
        '+replacement\n'
        ' b\n'
    )
    fixed, n = recount_hunks(diff)
    assert n == 1
    assert '@@ -1,3 +1,3 @@' in fixed


def test_empty_diff_is_passed_through():
    assert recount_hunks('') == ('', 0)


def test_trailing_newline_is_added_when_missing():
    fixed, _ = recount_hunks('--- x.c\n+++ x.c\n@@ -1,9 +1,9 @@\n a\n-b\n+B')
    assert fixed.endswith('\n')
    assert not fixed.endswith('\n\n')


# --- strip level ------------------------------------------------------------

def test_git_style_headers_give_p1():
    assert derive_strip_level(CORRECT) == 1


def test_bare_paths_give_p0():
    assert derive_strip_level(SHORT_BOTH) == 0


def test_mixed_prefixes_fall_back_to_p0():
    diff = '--- a/x.c\n+++ y.c\n@@ -1,1 +1,1 @@\n-a\n+b\n'
    assert derive_strip_level(diff) == 0


def test_dev_null_is_ignored_when_deciding():
    diff = '--- /dev/null\n+++ b/new_file.c\n@@ -0,0 +1,1 @@\n+added\n'
    assert derive_strip_level(diff) == 1


def test_headerless_diff_defaults_to_p0():
    assert derive_strip_level('@@ -1,1 +1,1 @@\n-a\n+b\n') == 0


def test_tab_suffixed_paths_are_handled():
    diff = '--- a/x.c\t2026-01-01\n+++ b/x.c\t2026-01-02\n@@ -1,1 +1,1 @@\n-a\n+b\n'
    assert derive_strip_level(diff) == 1


# --- argv -------------------------------------------------------------------

def test_argv_adds_directory_only_at_src():
    assert build_patch_argv('ffmpeg', '/src', 0, False)[:3] == ['patch', '--directory', 'ffmpeg']
    assert build_patch_argv('ffmpeg', '/src/ffmpeg', 0, False)[0:2] == ['patch', '-p0']


def test_argv_carries_strip_and_dry_run():
    assert '-p1' in build_patch_argv('p', '/w', 1, False)
    assert '--dry-run' in build_patch_argv('p', '/w', 0, True)
    assert '--dry-run' not in build_patch_argv('p', '/w', 0, False)


def test_argv_does_not_raise_the_fuzz_ceiling():
    """-F 3 discards all context for the median 3-context-line agent hunk."""
    assert '-F' not in build_patch_argv('p', '/w', 0, False)


def test_argv_is_json_round_trippable():
    argv = build_patch_argv('ffmpeg', '/src', 1, False)
    assert json.loads(json.dumps(argv)) == argv


# --- applier output parsing -------------------------------------------------

def test_parses_hunk_counts_and_fuzz():
    out = ('patching file libavcodec/mjpegdec.c\n'
           'Hunk #1 succeeded at 388 with fuzz 2.\n'
           'Hunk #2 succeeded at 412.\n'
           'Hunk #3 FAILED at 500.\n')
    stats = parse_patch_output(out)
    assert stats == {'hunks_ok': 2, 'hunks_failed': 1, 'max_fuzz': 2, 'malformed': False}


def test_detects_malformed():
    stats = parse_patch_output('patch: **** malformed patch at line 14: @@ -1,3 +1,4 @@')
    assert stats['malformed'] is True


def test_clean_apply_reports_no_fuzz():
    stats = parse_patch_output('patching file x.c\n')
    assert stats['max_fuzz'] == 0
    assert stats['hunks_failed'] == 0


def test_handles_empty_output():
    assert parse_patch_output('')['hunks_ok'] == 0
    assert parse_patch_output(None)['max_fuzz'] == 0


# --- artifact paths and transcript ------------------------------------------

def test_artifact_paths_carry_the_run_id():
    """Filenames must stay traceable once pooled into one directory."""
    from diff_tools import artifact_paths
    c, t = artifact_paths('arvo-42540891-vul-1784232900-patch', 1)
    assert c.name == 'compile_arvo-42540891-vul-1784232900-patch_a1.log'
    assert t.name == 'verify_arvo-42540891-vul-1784232900-patch_a1.log'
    assert c.parent.name == 'arvo-42540891-vul-1784232900-patch'


def test_artifact_paths_distinguish_attempts():
    from diff_tools import artifact_paths
    a1, _ = artifact_paths('r', 1)
    a2, _ = artifact_paths('r', 2)
    assert a1 != a2 and a2.name.endswith('_a2.log')


def _meta(**over):
    m = {'run_id': 'r1', 'vuln_id': 42, 'project': 'ffmpeg',
         'fuzz_target': 'ffmpeg_X_fuzzer', 'crash_type': 'Heap-buffer-overflow',
         'attempt': 1, 'started_at': 'T0', 'finished_at': 'T1',
         'image_tag': 'n132/arvo:42-vul', 'applier_sha256': 'abc123',
         'container_workdir': '/src/ffmpeg', 'stopped_after': 'complete',
         'compile_log_file': 'compile_r1_a1.log',
         'baseline_source': 'arvo.crash_output',
         'baseline_log': 'BASELINE-ASAN-REPORT'}
    m.update(over)
    return m


APPLIED = {'patch_rc': 0, 'patch_strip': 1, 'patch_recounted': 2,
           'patch_hunks_ok': 3, 'patch_hunks_failed': 0, 'patch_max_fuzz': 0,
           'patch_stdout': 'PATCH-STDOUT', 'patch_stderr': None}
COMPILED = {'compile_rc': 0, 'compile_duration_s': 932.0, 'compile_timed_out': 0,
            'compile_log_bytes': 1955662, 'compile_output_extract': 'EXTRACT'}
POC = {'poc_rc': 0, 'poc_stdout': 'POC-STDOUT', 'poc_stderr': 'POC-STDERR',
       'poc_duration_s': 1.4, 'poc_timed_out': 0}


def test_transcript_has_all_three_sections(tmp_path):
    from diff_tools import write_transcript
    p = write_transcript(tmp_path / 't.log', _meta(), APPLIED, COMPILED, POC)
    text = p.read_text(encoding='utf-8')
    assert 'BASELINE-ASAN-REPORT' in text
    assert 'PATCH-STDOUT' in text
    assert 'POC-STDOUT' in text and 'POC-STDERR' in text
    assert '1. BASELINE POC OUTPUT' in text
    assert '2. PATCH APPLICATION' in text
    assert '3. PATCHED POC OUTPUT' in text


def test_transcript_carries_no_compile_output(tmp_path):
    """The full compile log is a separate artifact fed whole; duplicating an
    abridged copy would waste context and invite reasoning from the short one."""
    from diff_tools import write_transcript
    p = write_transcript(tmp_path / 't.log', _meta(), APPLIED, COMPILED, POC)
    text = p.read_text(encoding='utf-8')
    assert 'EXTRACT' not in text
    assert 'compile_r1_a1.log' in text          # cross-referenced by name instead


def test_transcript_scalars_are_machine_readable(tmp_path):
    from diff_tools import write_transcript
    p = write_transcript(tmp_path / 't.log', _meta(), APPLIED, COMPILED, POC)
    text = p.read_text(encoding='utf-8')
    for token in ('patch_rc 0', 'patch_max_fuzz 0', 'compile_rc 0', 'poc_rc 0',
                  'patch_recounted 2'):
        assert token in text


def test_transcript_written_when_patch_failed(tmp_path):
    """The stage that stopped the run is exactly the one a reviewer needs."""
    from diff_tools import write_transcript
    failed = dict(APPLIED, patch_rc=1, patch_hunks_failed=2,
                  patch_stdout='Hunk #1 FAILED at 98.')
    p = write_transcript(tmp_path / 't.log', _meta(stopped_after='patch_failed'),
                         failed, None, None)
    text = p.read_text(encoding='utf-8')
    assert 'stopped_after' in text and 'patch_failed' in text
    assert 'Hunk #1 FAILED' in text
    assert 'BASELINE-ASAN-REPORT' in text
    assert '(none)' in text                     # empty POC section


def test_transcript_written_with_nothing_but_the_baseline(tmp_path):
    from diff_tools import write_transcript
    p = write_transcript(tmp_path / 't.log', _meta(stopped_after='error'),
                         None, None, None)
    text = p.read_text(encoding='utf-8')
    assert 'BASELINE-ASAN-REPORT' in text
    assert text.rstrip().endswith('=== END ===')


def test_transcript_creates_missing_directories(tmp_path):
    from diff_tools import write_transcript
    p = write_transcript(tmp_path / 'a' / 'b' / 't.log', _meta(), APPLIED, COMPILED, POC)
    assert p.exists()


if __name__ == '__main__':
    raise SystemExit(pytest.main([__file__, '-v']))
